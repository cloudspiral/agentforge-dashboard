"""Typed errors safe to cross API and component boundaries."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import AwareDatetime, Field, JsonValue, field_validator

from .common import (
    SCHEMA_VERSION_V1,
    ContractModel,
    Identifier,
    ShortText,
    validate_sanitized_mapping,
)


class AgentErrorCodeV1(StrEnum):
    TARGET_UNREACHABLE = "target_unreachable"
    BUDGET_EXCEEDED = "budget_exceeded"
    RATE_LIMITED = "rate_limited"
    INVALID_CONTRACT = "invalid_contract"
    ACTION_REJECTED = "action_rejected"
    AGENT_REFUSAL = "agent_refusal"
    AGENT_TIMEOUT = "agent_timeout"
    JUDGE_TIMEOUT = "judge_timeout"
    NO_FINDINGS_IN_WINDOW = "no_findings_in_window"
    DUPLICATE_FINDING = "duplicate_finding"
    REGRESSION_DETECTED = "regression_detected"
    AUTHENTICATION_FAILED = "authentication_failed"
    RESET_FAILED = "reset_failed"
    UNEXPECTED_INTERNAL_ERROR = "unexpected_internal_error"


class AgentErrorV1(ContractModel):
    schema_version: Literal[SCHEMA_VERSION_V1]
    code: AgentErrorCodeV1
    message: ShortText
    retryable: bool
    occurred_at: AwareDatetime
    correlation_id: Identifier
    campaign_id: Identifier | None = None
    attempt_id: Identifier | None = None
    sanitized_details: dict[str, JsonValue] = Field(default_factory=dict, max_length=50)

    @field_validator("sanitized_details")
    @classmethod
    def details_are_sanitized(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        return validate_sanitized_mapping(value)


__all__ = ["AgentErrorCodeV1", "AgentErrorV1"]
