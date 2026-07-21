from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator, Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, fields, is_dataclass
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, SecretStr

LOGGER = logging.getLogger(__name__)

_CURRENT_TRACE_ID: ContextVar[str | None] = ContextVar(
    "agentforge_langfuse_trace_id",
    default=None,
)
_SENSITIVE_KEY = re.compile(
    r"(?:authorization|cookie|password|passwd|secret|token|api[_-]?key|credential|csrf|"
    r"session[_-]?cookie|shared[_-]?secret)",
    re.IGNORECASE,
)
_AUTH_HEADER = re.compile(r"(?im)\b(authorization|cookie|set-cookie|x-api-key)\s*:\s*[^\r\n]+")
_AUTH_VALUE = re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
_OPENAI_KEY = re.compile(r"(?<![A-Za-z0-9])(?:sk-(?:proj-|lf-)?|pk-lf-)[A-Za-z0-9_-]{8,}")
_QUERY_SECRET = re.compile(
    r"(?i)([?&](?:access_token|token|api[_-]?key|password|secret|csrf)\s*=)[^&#\s]+"
)
_URL_CREDENTIALS = re.compile(r"(?i)(://)[^/@:\s]+:[^/@\s]+@")
_MAX_DEPTH = 12
_MAX_METADATA_VALUE_LENGTH = 200
_MISSING = object()


def _redact_string(value: str) -> str:
    value = _AUTH_HEADER.sub(lambda match: f"{match.group(1)}: [REDACTED]", value)
    value = _AUTH_VALUE.sub(lambda match: f"{match.group(0).split()[0]} [REDACTED]", value)
    value = _OPENAI_KEY.sub("[REDACTED]", value)
    value = _QUERY_SECRET.sub(lambda match: f"{match.group(1)}[REDACTED]", value)
    return _URL_CREDENTIALS.sub(r"\1[REDACTED]@", value)


def redact_for_telemetry(
    value: Any,
    *,
    _depth: int = 0,
    _seen: set[int] | None = None,
) -> Any:
    """Create a bounded, non-mutating copy suitable for external telemetry.

    Unknown objects are represented by type instead of ``repr`` because object
    representations often contain credentials, HTTP headers, or connection URLs.
    """

    if _depth > _MAX_DEPTH:
        return "[TRUNCATED]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, SecretStr):
        return "[REDACTED]"
    if isinstance(value, str):
        return _redact_string(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"[BINARY {len(value)} bytes]"
    if isinstance(value, (datetime, date, UUID, Path)):
        return _redact_string(str(value))
    if isinstance(value, Enum):
        return redact_for_telemetry(value.value, _depth=_depth + 1, _seen=_seen)

    seen = _seen if _seen is not None else set()
    identity = id(value)
    if identity in seen:
        return "[CYCLE]"

    if isinstance(value, BaseModel):
        seen.add(identity)
        try:
            return redact_for_telemetry(
                value.model_dump(mode="json"),
                _depth=_depth + 1,
                _seen=seen,
            )
        finally:
            seen.discard(identity)

    if isinstance(value, Mapping):
        seen.add(identity)
        try:
            return {
                str(key): (
                    "[REDACTED]"
                    if _SENSITIVE_KEY.search(str(key))
                    else redact_for_telemetry(item, _depth=_depth + 1, _seen=seen)
                )
                for key, item in value.items()
            }
        finally:
            seen.discard(identity)

    if is_dataclass(value) and not isinstance(value, type):
        seen.add(identity)
        try:
            return {
                field.name: (
                    "[REDACTED]"
                    if _SENSITIVE_KEY.search(field.name)
                    else redact_for_telemetry(
                        getattr(value, field.name),
                        _depth=_depth + 1,
                        _seen=seen,
                    )
                )
                for field in fields(value)
            }
        finally:
            seen.discard(identity)

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        seen.add(identity)
        try:
            return [redact_for_telemetry(item, _depth=_depth + 1, _seen=seen) for item in value]
        finally:
            seen.discard(identity)

    if isinstance(value, (set, frozenset)):
        seen.add(identity)
        try:
            return [redact_for_telemetry(item, _depth=_depth + 1, _seen=seen) for item in value]
        finally:
            seen.discard(identity)

    return f"[{type(value).__name__}]"


def normalize_metadata(metadata: Mapping[str, Any] | None) -> dict[str, str]:
    """Normalize propagated Langfuse metadata to short, string-valued fields."""

    if not metadata:
        return {}

    normalized: dict[str, str] = {}
    for raw_key, raw_value in metadata.items():
        raw_key_text = str(raw_key)
        key = re.sub(r"[^A-Za-z0-9]", "", raw_key_text) or "field"
        safe_value = (
            "[REDACTED]" if _SENSITIVE_KEY.search(raw_key_text) else redact_for_telemetry(raw_value)
        )
        if isinstance(safe_value, str):
            rendered = safe_value
        elif safe_value is None or isinstance(safe_value, (bool, int, float)):
            rendered = str(safe_value)
        else:
            rendered = json.dumps(safe_value, sort_keys=True, separators=(",", ":"))
        normalized[key] = rendered[:_MAX_METADATA_VALUE_LENGTH]
    return normalized


def normalize_tags(tags: Sequence[str] | None) -> list[str]:
    """Return unique, redacted Langfuse tags within the documented length bound."""

    normalized: list[str] = []
    seen: set[str] = set()
    for tag in tags or ():
        safe_tag = _redact_string(str(tag))[:_MAX_METADATA_VALUE_LENGTH]
        if safe_tag and safe_tag not in seen:
            normalized.append(safe_tag)
            seen.add(safe_tag)
    return normalized


@dataclass(slots=True)
class ObservationHandle:
    """Safe façade over a Langfuse observation.

    Callers can attach a final summary without receiving the underlying exporter
    object, ensuring every manually supplied value passes through redaction.
    """

    trace_id: str | None
    _observation: Any = None

    @property
    def enabled(self) -> bool:
        return self._observation is not None

    def update(
        self,
        *,
        input: Any = _MISSING,
        output: Any = _MISSING,
        metadata: Mapping[str, Any] | None = None,
        status_message: str | None = None,
        level: Literal["DEBUG", "DEFAULT", "WARNING", "ERROR"] | None = None,
    ) -> bool:
        if self._observation is None:
            return False

        values: dict[str, Any] = {}
        if input is not _MISSING:
            values["input"] = redact_for_telemetry(input)
        if output is not _MISSING:
            values["output"] = redact_for_telemetry(output)
        if metadata is not None:
            values["metadata"] = redact_for_telemetry(metadata)
        if status_message is not None:
            values["status_message"] = _redact_string(status_message)
        if level is not None:
            values["level"] = level

        try:
            self._observation.update(**values)
        except Exception as exc:  # telemetry must never break campaign execution
            LOGGER.warning("Langfuse observation update failed (%s)", type(exc).__name__)
            return False
        return True

    def record_exception(self, exc: BaseException) -> bool:
        return self.update(
            metadata={"errorType": type(exc).__name__},
            status_message=f"{type(exc).__name__}: campaign operation failed",
            level="ERROR",
        )


def current_trace_id() -> str | None:
    return _CURRENT_TRACE_ID.get()


def _set_current_trace_id(trace_id: str | None) -> Any:
    return _CURRENT_TRACE_ID.set(trace_id)


def _reset_current_trace_id(token: Any) -> None:
    _CURRENT_TRACE_ID.reset(token)


def iter_required_metadata(
    *,
    campaign_id: str,
    attempt_id: str | None = None,
    agent_role: str | None = None,
    category: str | None = None,
    target_version: str | None = None,
    prompt_version: str | None = None,
    model: str | None = None,
) -> Iterator[tuple[str, str]]:
    """Yield the required low-cardinality trace linkage fields when present."""

    yield "campaignId", campaign_id
    optional = {
        "attemptId": attempt_id,
        "agentRole": agent_role,
        "category": category,
        "targetVersion": target_version,
        "promptVersion": prompt_version,
        "model": model,
    }
    for key, value in optional.items():
        if value is not None:
            yield key, value
