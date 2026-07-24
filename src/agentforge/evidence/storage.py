"""Atomic, verified exports of evidence whose source of truth is PostgreSQL."""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from agentforge.contracts.v1 import AttackEvidenceV1

MAX_SERIALIZED_EVIDENCE_BYTES = 5 * 1024 * 1024
_TEMP_PREFIX = ".agentforge-evidence-"
_TEMP_SUFFIX = ".tmp"


class EvidenceArtifactError(RuntimeError):
    """Base class for evidence artifact failures."""


class EvidenceArtifactTooLarge(EvidenceArtifactError):
    """The database payload would exceed the bounded evidence ceiling."""


class EvidenceArtifactMissing(EvidenceArtifactError):
    """No export exists for a matching database evidence record."""


class EvidenceArtifactCorrupt(EvidenceArtifactError):
    """An export exists but does not exactly match its database evidence record."""


class EvidenceArtifactExportFailed(EvidenceArtifactError):
    """A prepared database payload could not be exported atomically."""


@dataclass(frozen=True, slots=True)
class EvidenceArtifactPrepared:
    """One bounded evidence payload ready for a database commit and later export."""

    evidence: AttackEvidenceV1
    payload: dict[str, Any]
    serialized: bytes


def compute_evidence_hash(evidence: AttackEvidenceV1) -> str:
    canonical = json.dumps(
        evidence.model_dump(mode="json", exclude={"evidence_hash"}),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


def with_computed_evidence_hash(evidence: AttackEvidenceV1) -> AttackEvidenceV1:
    return AttackEvidenceV1.model_validate(
        {
            **evidence.model_dump(mode="python"),
            "evidence_hash": compute_evidence_hash(evidence),
        }
    )


class EvidenceArtifactStore:
    """Derive evidence JSON from typed database payloads without importing files."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    @staticmethod
    def prepare(evidence: AttackEvidenceV1) -> EvidenceArtifactPrepared:
        if evidence.evidence_hash != compute_evidence_hash(evidence):
            raise EvidenceArtifactCorrupt(
                "evidence hash does not match the canonical evidence contents"
            )
        payload = evidence.model_dump(mode="json")
        serialized = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(serialized) > MAX_SERIALIZED_EVIDENCE_BYTES:
            raise EvidenceArtifactTooLarge(
                "serialized evidence exceeds the 5 MiB persistence ceiling"
            )
        return EvidenceArtifactPrepared(
            evidence=evidence,
            payload=payload,
            serialized=serialized,
        )

    @staticmethod
    def prepare_payload(payload: dict[str, Any]) -> EvidenceArtifactPrepared:
        try:
            evidence = AttackEvidenceV1.model_validate_json(
                json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            )
        except (TypeError, ValueError, ValidationError) as exc:
            raise EvidenceArtifactCorrupt(
                "database evidence payload does not satisfy the v1 contract"
            ) from exc
        return EvidenceArtifactStore.prepare(evidence)

    def path_for(self, campaign_id: uuid.UUID, attempt_id: uuid.UUID) -> Path:
        campaign_segment = str(campaign_id)
        attempt_segment = str(attempt_id)
        destination = (self.root / campaign_segment / f"{attempt_segment}.json").resolve()
        if self.root not in destination.parents:
            raise ValueError("evidence artifact path escaped the configured root")
        return destination

    def export(self, prepared: EvidenceArtifactPrepared) -> Path:
        campaign_id, attempt_id = self._evidence_ids(prepared.evidence)
        destination = self.path_for(campaign_id, attempt_id)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                dir=destination.parent,
                prefix=_TEMP_PREFIX,
                suffix=_TEMP_SUFFIX,
            )
            temporary_path = Path(temporary_name)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(prepared.serialized)
                stream.flush()
                os.fsync(stream.fileno())
            self._verify_path(temporary_path, expected=prepared)
            os.replace(temporary_path, destination)
            temporary_path = None
            self._verify_path(destination, expected=prepared)
            return destination
        except EvidenceArtifactError:
            raise
        except OSError as exc:
            raise EvidenceArtifactExportFailed(
                "evidence artifact could not be exported atomically"
            ) from exc
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def load_verified(
        self,
        *,
        campaign_id: uuid.UUID,
        attempt_id: uuid.UUID,
        database_payload: dict[str, Any],
    ) -> bytes:
        path = self.path_for(campaign_id, attempt_id)
        if not path.is_file():
            raise EvidenceArtifactMissing("evidence artifact is unavailable")
        expected = self.prepare_payload(database_payload)
        expected_campaign_id, expected_attempt_id = self._evidence_ids(expected.evidence)
        if expected_campaign_id != campaign_id or expected_attempt_id != attempt_id:
            raise EvidenceArtifactCorrupt(
                "database evidence identifiers do not match the requested record"
            )
        self._verify_path(path, expected=expected)
        return expected.serialized

    def stale_temporary_paths(self) -> list[Path]:
        if not self.root.exists():
            return []
        return sorted(
            path for path in self.root.rglob(f"{_TEMP_PREFIX}*{_TEMP_SUFFIX}") if path.is_file()
        )

    def json_paths(self) -> list[Path]:
        if not self.root.exists():
            return []
        return sorted(path for path in self.root.glob("*/*.json") if path.is_file())

    def parse_path_ids(self, path: Path) -> tuple[uuid.UUID, uuid.UUID] | None:
        try:
            relative = path.resolve().relative_to(self.root)
            if len(relative.parts) != 2 or path.suffix != ".json":
                return None
            return uuid.UUID(relative.parts[0]), uuid.UUID(path.stem)
        except (ValueError, OSError):
            return None

    @staticmethod
    def _evidence_ids(evidence: AttackEvidenceV1) -> tuple[uuid.UUID, uuid.UUID]:
        try:
            return uuid.UUID(evidence.campaign_id), uuid.UUID(evidence.attempt_id)
        except ValueError as exc:
            raise EvidenceArtifactCorrupt(
                "evidence campaign and attempt identifiers must be UUIDs"
            ) from exc

    @staticmethod
    def _verify_path(path: Path, *, expected: EvidenceArtifactPrepared) -> None:
        try:
            serialized = path.read_bytes()
        except OSError as exc:
            raise EvidenceArtifactCorrupt("evidence artifact could not be read") from exc
        if len(serialized) > MAX_SERIALIZED_EVIDENCE_BYTES:
            raise EvidenceArtifactCorrupt("evidence artifact exceeds the 5 MiB ceiling")
        if serialized != expected.serialized:
            raise EvidenceArtifactCorrupt(
                "evidence artifact bytes do not match the database payload"
            )
        try:
            json.loads(serialized)
            artifact = AttackEvidenceV1.model_validate_json(serialized)
        except (json.JSONDecodeError, UnicodeDecodeError, ValidationError) as exc:
            raise EvidenceArtifactCorrupt(
                "evidence artifact does not satisfy the v1 contract"
            ) from exc
        for field in ("campaign_id", "attempt_id", "target_version", "evidence_hash"):
            if getattr(artifact, field) != getattr(expected.evidence, field):
                raise EvidenceArtifactCorrupt(
                    f"evidence artifact {field} does not match the database payload"
                )
