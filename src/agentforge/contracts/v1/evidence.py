"""Sanitized execution-evidence contract."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import AwareDatetime, Field, JsonValue, field_validator, model_validator

from .actions import ApprovedHttpMethodV1, AttackActionV1
from .common import (
    SCHEMA_VERSION_V1,
    ContractModel,
    EvidenceReferenceV1,
    Identifier,
    LongText,
    PositiveMilliseconds,
    Sha256Hex,
    ShortText,
    validate_sanitized_mapping,
)
from .errors import AgentErrorV1


class ActionExecutionStatusV1(StrEnum):
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"
    FAILED = "failed"
    SKIPPED = "skipped"


class ExecutedActionV1(ContractModel):
    sequence_index: int = Field(ge=0, le=100)
    action: AttackActionV1
    status: ActionExecutionStatusV1
    started_at: AwareDatetime
    completed_at: AwareDatetime
    sanitized_result_summary: ShortText | None = None

    @model_validator(mode="after")
    def timestamps_are_ordered(self) -> ExecutedActionV1:
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        return self


class TranscriptRoleV1(StrEnum):
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"
    SYSTEM = "system"


class TranscriptTurnV1(ContractModel):
    turn_index: int = Field(ge=0, le=1_000)
    role: TranscriptRoleV1
    content: LongText
    observed_at: AwareDatetime

    @field_validator("content")
    @classmethod
    def content_has_no_nul(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("transcript content cannot contain NUL bytes")
        return value


class SanitizedHttpExchangeV1(ContractModel):
    exchange_id: Identifier
    method: ApprovedHttpMethodV1
    endpoint_id: Identifier
    response_status: int | None = Field(default=None, ge=100, le=599)
    response_content_type: str | None = Field(default=None, max_length=100)
    response_size_bytes: int = Field(default=0, ge=0, le=10_000_000)
    response_truncated: bool = False
    elapsed_ms: PositiveMilliseconds
    error_summary: ShortText | None = None


class ToolAuthorizationResultV1(StrEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class TargetVisibleToolCallV1(ContractModel):
    call_id: Identifier
    tool_name: Identifier
    sanitized_arguments: dict[str, JsonValue] = Field(default_factory=dict, max_length=50)
    authorization_result: ToolAuthorizationResultV1
    patient_context_alias: Identifier | None = None

    @field_validator("sanitized_arguments")
    @classmethod
    def arguments_are_sanitized(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        return validate_sanitized_mapping(value)


class SideEffectV1(ContractModel):
    effect_id: Identifier
    effect_type: Identifier
    description: ShortText
    observed: bool
    authorized: bool


class AssertionOutcomeV1(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


class DeterministicAssertionResultV1(ContractModel):
    assertion_id: Identifier
    invariant_id: Identifier
    outcome: AssertionOutcomeV1
    expected: ShortText
    observed: ShortText
    evidence_reference_ids: list[Identifier] = Field(default_factory=list, max_length=20)


class AttackEvidenceV1(ContractModel):
    schema_version: Literal[SCHEMA_VERSION_V1]
    target_id: Identifier
    campaign_id: Identifier
    attempt_id: Identifier
    target_version: ShortText
    executed_action_sequence: list[ExecutedActionV1] = Field(min_length=1, max_length=30)
    transcript: list[TranscriptTurnV1] = Field(default_factory=list, max_length=100)
    sanitized_http_metadata: list[SanitizedHttpExchangeV1] = Field(
        default_factory=list,
        max_length=100,
    )
    target_visible_tool_calls: list[TargetVisibleToolCallV1] = Field(
        default_factory=list,
        max_length=100,
    )
    side_effects: list[SideEffectV1] = Field(default_factory=list, max_length=50)
    deterministic_assertion_results: list[DeterministicAssertionResultV1] = Field(
        default_factory=list,
        max_length=100,
    )
    artifact_references: list[EvidenceReferenceV1] = Field(default_factory=list, max_length=100)
    started_at: AwareDatetime
    completed_at: AwareDatetime
    total_latency_ms: PositiveMilliseconds
    errors: list[AgentErrorV1] = Field(default_factory=list, max_length=20)
    langfuse_trace_id: Identifier | None = None
    evidence_hash: Sha256Hex

    @field_validator("executed_action_sequence")
    @classmethod
    def execution_indices_are_contiguous(
        cls,
        value: list[ExecutedActionV1],
    ) -> list[ExecutedActionV1]:
        indices = [item.sequence_index for item in value]
        if indices != list(range(len(value))):
            raise ValueError("executed action sequence indices must be contiguous and ordered")
        return value

    @field_validator("transcript")
    @classmethod
    def transcript_indices_are_contiguous(
        cls, value: list[TranscriptTurnV1]
    ) -> list[TranscriptTurnV1]:
        indices = [item.turn_index for item in value]
        if indices and indices != list(range(len(value))):
            raise ValueError("transcript turn indices must be contiguous and ordered")
        return value

    @model_validator(mode="after")
    def evidence_timestamps_are_consistent(self) -> AttackEvidenceV1:
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        for execution in self.executed_action_sequence:
            if execution.started_at < self.started_at or execution.completed_at > self.completed_at:
                raise ValueError("executed action timestamps must fall inside the evidence window")
        return self


__all__ = [
    "ActionExecutionStatusV1",
    "AssertionOutcomeV1",
    "AttackEvidenceV1",
    "DeterministicAssertionResultV1",
    "ExecutedActionV1",
    "SanitizedHttpExchangeV1",
    "SideEffectV1",
    "TargetVisibleToolCallV1",
    "ToolAuthorizationResultV1",
    "TranscriptRoleV1",
    "TranscriptTurnV1",
]
