"""Versioned security-invariant specifications used by deterministic replay."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from agentforge.contracts.v1 import SeverityV1

InvariantId = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"),
]


class InvariantModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class InvariantBaseV1(InvariantModel):
    invariant_id: InvariantId
    description: str = Field(min_length=1, max_length=512)
    severity_on_failure: SeverityV1


class ForeignValueKindV1(StrEnum):
    SYNTHETIC_CANARY = "foreign_synthetic_canary_absent"
    PATIENT_IDENTIFIER = "foreign_patient_identifier_absent"
    SOURCE_IDENTIFIER = "foreign_source_identifier_absent"


class ForeignValueAbsentInvariantV1(InvariantBaseV1):
    invariant_type: Literal[
        ForeignValueKindV1.SYNTHETIC_CANARY,
        ForeignValueKindV1.PATIENT_IDENTIFIER,
        ForeignValueKindV1.SOURCE_IDENTIFIER,
    ]
    forbidden_values: list[str] = Field(min_length=1, max_length=50)
    case_sensitive: bool = True

    @field_validator("forbidden_values")
    @classmethod
    def forbidden_values_are_bounded_and_unique(cls, value: list[str]) -> list[str]:
        if any(not item or len(item) > 500 or "\x00" in item for item in value):
            raise ValueError("forbidden synthetic values must contain 1-500 safe characters")
        if len(value) != len(set(value)):
            raise ValueError("forbidden synthetic values must be unique")
        return value


class CurrentPatientUnchangedInvariantV1(InvariantBaseV1):
    invariant_type: Literal["current_patient_unchanged"]
    expected_patient_alias: Literal["patient_a", "patient_b"]


class ToolScopeInvariantV1(InvariantBaseV1):
    invariant_type: Literal["tool_scope_enforced"]
    allowed_tool_names: list[InvariantId] = Field(min_length=1, max_length=100)
    prohibited_tool_names: list[InvariantId] = Field(default_factory=list, max_length=100)
    expected_patient_alias: Literal["patient_a", "patient_b"]
    expected_patient_external_id: str = Field(min_length=1, max_length=100)
    patient_parameter_keys: list[InvariantId] = Field(
        default_factory=lambda: ["patient_id", "patient_alias", "pid", "pubpid"],
        min_length=1,
        max_length=20,
    )

    @model_validator(mode="after")
    def tool_lists_are_unambiguous(self) -> ToolScopeInvariantV1:
        if len(self.allowed_tool_names) != len(set(self.allowed_tool_names)):
            raise ValueError("allowed tool names must be unique")
        if len(self.prohibited_tool_names) != len(set(self.prohibited_tool_names)):
            raise ValueError("prohibited tool names must be unique")
        if set(self.allowed_tool_names) & set(self.prohibited_tool_names):
            raise ValueError("a tool cannot be both allowed and prohibited")
        if len(self.patient_parameter_keys) != len(set(self.patient_parameter_keys)):
            raise ValueError("patient parameter keys must be unique")
        return self


class NoUnauthorizedSideEffectsInvariantV1(InvariantBaseV1):
    invariant_type: Literal["no_unauthorized_side_effects"]
    prohibited_effect_types: list[InvariantId] = Field(default_factory=list, max_length=50)


class ExecutionBoundsInvariantV1(InvariantBaseV1):
    invariant_type: Literal["execution_within_bounds"]
    max_latency_ms: float = Field(gt=0, le=1_200_000, allow_inf_nan=False)
    max_response_bytes: int = Field(gt=0, le=10_000_000)
    max_transcript_turns: int = Field(gt=0, le=1_000)
    max_tool_calls: int = Field(ge=0, le=1_000)


class TransportSucceededInvariantV1(InvariantBaseV1):
    invariant_type: Literal["transport_succeeded"]


class RequiredEvidenceChannelV1(StrEnum):
    TRANSCRIPT = "transcript"
    HTTP_METADATA = "http_metadata"
    TOOL_CALLS = "tool_calls"
    SIDE_EFFECTS = "side_effects"
    CURRENT_PATIENT_SELECTION = "current_patient_selection"
    SCREENSHOT = "screenshot"
    BROWSER_TRACE = "browser_trace"


class RequiredEvidenceInvariantV1(InvariantBaseV1):
    invariant_type: Literal["required_evidence_present"]
    required_channels: list[RequiredEvidenceChannelV1] = Field(min_length=1, max_length=7)

    @field_validator("required_channels")
    @classmethod
    def channels_are_unique(
        cls,
        value: list[RequiredEvidenceChannelV1],
    ) -> list[RequiredEvidenceChannelV1]:
        if len(value) != len(set(value)):
            raise ValueError("required evidence channels must be unique")
        return value


SecurityInvariantV1 = Annotated[
    ForeignValueAbsentInvariantV1
    | CurrentPatientUnchangedInvariantV1
    | ToolScopeInvariantV1
    | NoUnauthorizedSideEffectsInvariantV1
    | ExecutionBoundsInvariantV1
    | TransportSucceededInvariantV1
    | RequiredEvidenceInvariantV1,
    Field(discriminator="invariant_type"),
]


__all__ = [
    "CurrentPatientUnchangedInvariantV1",
    "ExecutionBoundsInvariantV1",
    "ForeignValueAbsentInvariantV1",
    "ForeignValueKindV1",
    "NoUnauthorizedSideEffectsInvariantV1",
    "RequiredEvidenceChannelV1",
    "RequiredEvidenceInvariantV1",
    "SecurityInvariantV1",
    "ToolScopeInvariantV1",
    "TransportSucceededInvariantV1",
]
