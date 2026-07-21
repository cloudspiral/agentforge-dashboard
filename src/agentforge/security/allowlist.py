from __future__ import annotations

from pathlib import Path
from urllib.parse import urljoin, urlparse


class TargetRejected(ValueError):
    pass


def require_allowed_url(
    url: str,
    allowed_hosts: list[str],
    *,
    base_url: str | None = None,
    allow_http: bool = True,
) -> str:
    resolved = urljoin(f"{base_url.rstrip('/')}/", url) if base_url else url
    parsed = urlparse(resolved)
    if parsed.scheme not in ({"https", "http"} if allow_http else {"https"}):
        raise TargetRejected("target URL must use an approved HTTP scheme")
    if parsed.username or parsed.password:
        raise TargetRejected("credentials are not permitted in target URLs")
    hostname = (parsed.hostname or "").lower()
    approved = {item.lower() for item in allowed_hosts}
    if hostname not in approved:
        raise TargetRejected(f"target host {hostname!r} is not allowlisted")
    return resolved


def require_fixture_path(path: str, fixture_root: Path) -> Path:
    root = fixture_root.resolve()
    candidate = (root / path).resolve()
    if candidate != root and root not in candidate.parents:
        raise TargetRejected("upload path escapes the approved fixture directory")
    if not candidate.is_file():
        raise TargetRejected("approved upload fixture does not exist")
    return candidate
