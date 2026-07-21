"""Alias-only resolution for repository-owned synthetic upload fixtures."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from agentforge.security.allowlist import TargetRejected, require_fixture_path
from agentforge.target.profile import TargetProfileV1


@dataclass(frozen=True, slots=True)
class ApprovedFixture:
    fixture_id: str
    path: Path
    media_type: str
    document_type: str
    size_bytes: int
    pages: int
    sha256: str


@dataclass(frozen=True, slots=True)
class ApprovedFixtureAuthorization:
    """Controller-owned fixture metadata; attacks still provide only ``fixture_id``."""

    fixture_id: str
    repository_relative_path: str
    document_type: str
    media_type: str
    size_bytes: int
    pages: int
    sha256: str


def resolve_approved_fixture(
    *,
    profile: TargetProfileV1,
    repository_root: Path,
    fixture_id: str,
    declared_media_type: str,
    authorization: ApprovedFixtureAuthorization,
    configured_max_bytes: int,
) -> ApprovedFixture:
    """Resolve an authorized fixture alias and revalidate its on-disk bytes."""

    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", fixture_id) is None:
        raise TargetRejected("fixture alias contains unsupported characters")
    if "/" in fixture_id or "\\" in fixture_id or fixture_id in {".", ".."}:
        raise TargetRejected("fixture aliases cannot contain paths")
    if authorization.fixture_id != fixture_id:
        raise TargetRejected("fixture alias does not match its controller authorization")
    if declared_media_type != authorization.media_type or declared_media_type != "application/pdf":
        raise TargetRejected("only the approved PDF media type is supported")
    if authorization.document_type not in profile.upload.allowed_document_types:
        raise TargetRejected("upload document type is not allowlisted")
    if ".pdf" not in profile.upload.allowed_extensions:
        raise TargetRejected("PDF fixtures are not enabled by the target profile")

    repository = repository_root.resolve()
    configured_root = repository / profile.upload.fixture_root
    if configured_root.is_symlink():
        raise TargetRejected("approved fixture root cannot be a symbolic link")
    fixture_root = configured_root.resolve()
    if fixture_root != repository and repository not in fixture_root.parents:
        raise TargetRejected("profile fixture root escapes the repository")
    relative_path = Path(authorization.repository_relative_path)
    if (
        relative_path.is_absolute()
        or ".." in relative_path.parts
        or "\\" in authorization.repository_relative_path
        or "\x00" in authorization.repository_relative_path
        or "://" in authorization.repository_relative_path
    ):
        raise TargetRejected("authorized fixture path is not repository-relative")
    candidate = repository / relative_path
    try:
        fixture_relative_path = candidate.relative_to(fixture_root)
    except ValueError as exc:
        raise TargetRejected("authorized fixture is outside the approved fixture root") from exc
    if candidate.suffix.lower() not in {
        extension.lower() for extension in profile.upload.allowed_extensions
    }:
        raise TargetRejected("authorized fixture extension is not allowlisted")
    inspected = candidate
    while inspected != fixture_root:
        if inspected.is_symlink():
            raise TargetRejected("approved fixtures cannot use symbolic links")
        inspected = inspected.parent
    path = require_fixture_path(fixture_relative_path.as_posix(), fixture_root)
    size = path.stat().st_size
    byte_limit = min(configured_max_bytes, profile.upload.max_bytes)
    if size <= 0 or size > byte_limit:
        raise TargetRejected("approved fixture violates the configured size limit")
    document = path.read_bytes()
    header = document[:5]
    digest = hashlib.sha256(document).hexdigest()
    if header != b"%PDF-":
        raise TargetRejected("approved fixture is not a PDF document")
    pages = len(re.findall(rb"/Type\s*/Page(?!s)\b", document))
    if pages <= 0 or pages > profile.upload.max_pages:
        raise TargetRejected("approved fixture violates the configured PDF page limit")
    if (
        size != authorization.size_bytes
        or pages != authorization.pages
        or digest != authorization.sha256
    ):
        raise TargetRejected("approved fixture bytes no longer match controller authorization")
    return ApprovedFixture(
        fixture_id=fixture_id,
        path=path,
        media_type=declared_media_type,
        document_type=authorization.document_type,
        size_bytes=size,
        pages=pages,
        sha256=digest,
    )


__all__ = [
    "ApprovedFixture",
    "ApprovedFixtureAuthorization",
    "resolve_approved_fixture",
]
