"""Shared primitives for the AgentForge v1 contracts."""

from __future__ import annotations

import math
import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Any

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    field_validator,
)

SCHEMA_VERSION_V1 = "v1"
SHA256_PATTERN = r"^[0-9a-f]{64}$"

Identifier = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=512)]
LongText = Annotated[str, StringConstraints(min_length=1, max_length=20_000)]
Sha256Hex = Annotated[str, StringConstraints(pattern=SHA256_PATTERN)]
Confidence = Annotated[float, Field(ge=0.0, le=1.0, allow_inf_nan=False)]
NonNegativeCost = Annotated[float, Field(ge=0.0, allow_inf_nan=False)]
PositiveMilliseconds = Annotated[float, Field(ge=0.0, allow_inf_nan=False)]

_FORBIDDEN_DETAIL_KEY = re.compile(
    r"(?:authorization|cookie|password|passwd|secret|api[_-]?key|"
    r"(?:access|auth|bearer|csrf|refresh|session)[_-]?token)",
    re.IGNORECASE,
)


class ContractModel(BaseModel):
    """Strict, immutable base for data crossing component boundaries."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class AttackSurfaceV1(StrEnum):
    API = "api"
    UI = "ui"
    UPLOAD = "upload"
    HYBRID = "hybrid"


class CampaignTypeV1(StrEnum):
    DISCOVERY = "discovery"
    REGRESSION = "regression"


class RequestedActionV1(StrEnum):
    NEW_ATTACK = "new_attack"
    MUTATION = "mutation"


class SeverityV1(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    NONE = "none"


class ExploitabilityV1(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NOT_APPLICABLE = "not_applicable"


class FindingStatusV1(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    REOPENED = "reopened"
    FALSE_POSITIVE = "false_positive"


class OwaspMappingsV1(ContractModel):
    """Explicitly versioned OWASP mappings; versions may not be implicit."""

    web_top_10_version: Identifier
    web_top_10: list[Identifier] = Field(default_factory=list, max_length=10)
    llm_top_10_version: Identifier
    llm_top_10: list[Identifier] = Field(default_factory=list, max_length=10)

    @field_validator("web_top_10", "llm_top_10")
    @classmethod
    def mappings_are_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("OWASP mappings must not contain duplicates")
        return value


class EvidenceReferenceKindV1(StrEnum):
    TRANSCRIPT = "transcript"
    HTTP_METADATA = "http_metadata"
    TOOL_CALL = "tool_call"
    ASSERTION = "assertion"
    SCREENSHOT = "screenshot"
    BROWSER_TRACE = "browser_trace"
    LANGFUSE_TRACE = "langfuse_trace"
    REPORT = "report"
    OTHER = "other"


class EvidenceReferenceV1(ContractModel):
    reference_id: Identifier
    kind: EvidenceReferenceKindV1
    artifact_path: str | None = Field(default=None, min_length=1, max_length=512)
    description: ShortText

    @field_validator("artifact_path")
    @classmethod
    def artifact_path_is_safe_and_relative(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if "\x00" in value or "\\" in value or "://" in value:
            raise ValueError("artifact_path must be a local POSIX-relative reference")
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("artifact_path must not be absolute or traverse directories")
        return value


class TokenUsageV1(ContractModel):
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cached_input_tokens: int = Field(default=0, ge=0)
    calls: int = Field(default=0, ge=0)


def validate_sanitized_mapping(value: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """Reject secret-shaped keys and non-finite numbers in free-form metadata."""

    def walk(item: Any, path: str) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if _FORBIDDEN_DETAIL_KEY.search(str(key)):
                    raise ValueError(
                        f"sensitive key is forbidden in sanitized metadata: {path}{key}"
                    )
                walk(child, f"{path}{key}.")
        elif isinstance(item, list):
            for index, child in enumerate(item):
                walk(child, f"{path}{index}.")
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("sanitized metadata cannot contain non-finite numbers")

    walk(value, "")
    return value


def utc_now() -> datetime:
    """Small utility for producers; contracts still require explicit timestamps."""

    return datetime.now(UTC)


__all__ = [
    "AwareDatetime",
    "AttackSurfaceV1",
    "CampaignTypeV1",
    "Confidence",
    "ContractModel",
    "EvidenceReferenceKindV1",
    "EvidenceReferenceV1",
    "ExploitabilityV1",
    "FindingStatusV1",
    "Identifier",
    "JsonValue",
    "LongText",
    "NonNegativeCost",
    "OwaspMappingsV1",
    "PositiveMilliseconds",
    "RequestedActionV1",
    "SCHEMA_VERSION_V1",
    "SeverityV1",
    "Sha256Hex",
    "ShortText",
    "TokenUsageV1",
    "validate_sanitized_mapping",
]
