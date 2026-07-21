"""Campaign-objective and attack-proposal contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, JsonValue, field_validator, model_validator

from .actions import AttackActionV1
from .common import (
    SCHEMA_VERSION_V1,
    AttackSurfaceV1,
    CampaignTypeV1,
    ContractModel,
    Identifier,
    NonNegativeCost,
    OwaspMappingsV1,
    RequestedActionV1,
    Sha256Hex,
    ShortText,
)


class PriorAttemptOutcomeV1(StrEnum):
    EXPLOIT_CONFIRMED = "exploit_confirmed"
    PARTIAL_SIGNAL = "partial_signal"
    ATTACK_BLOCKED = "attack_blocked"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class PriorAttemptSummaryV1(ContractModel):
    attempt_id: Identifier
    attack_family_id: Identifier
    lineage_id: Identifier
    mutation_generation: int = Field(ge=0, le=20)
    outcome: PriorAttemptOutcomeV1
    summary: ShortText
    sequence_hash: Sha256Hex
    evidence_hash: Sha256Hex | None = None


class RemainingBudgetAndLimitsV1(ContractModel):
    remaining_cost_usd: NonNegativeCost | None
    remaining_attempts: int = Field(ge=0, le=10_000)
    remaining_duration_seconds: int = Field(ge=0, le=86_400)
    remaining_model_calls: int = Field(ge=0, le=10_000)
    remaining_input_tokens: int = Field(ge=0)
    remaining_output_tokens: int = Field(ge=0)
    max_mutations_per_lineage: int = Field(ge=0, le=20)
    max_consecutive_no_signal: int = Field(ge=1, le=100)


class CampaignObjectiveV1(ContractModel):
    schema_version: Literal[SCHEMA_VERSION_V1]
    campaign_id: Identifier
    campaign_type: CampaignTypeV1
    target_version: ShortText
    selected_category: Identifier
    selected_subcategory: Identifier
    owasp_mappings: OwaspMappingsV1
    attack_surface: AttackSurfaceV1
    objective: ShortText
    relevant_target_profile_subset: dict[str, JsonValue] = Field(max_length=100)
    relevant_prior_attempts: list[PriorAttemptSummaryV1] = Field(
        default_factory=list,
        max_length=20,
    )
    remaining_budget_and_limits: RemainingBudgetAndLimitsV1
    requested_action: RequestedActionV1
    mutation_source_attempt_id: Identifier | None = None

    @model_validator(mode="after")
    def mutation_has_a_known_source(self) -> CampaignObjectiveV1:
        if self.requested_action == RequestedActionV1.MUTATION:
            known_attempt_ids = {attempt.attempt_id for attempt in self.relevant_prior_attempts}
            if self.mutation_source_attempt_id is None:
                raise ValueError("mutation_source_attempt_id is required for a mutation")
            if self.mutation_source_attempt_id not in known_attempt_ids:
                raise ValueError("mutation source must be present in relevant_prior_attempts")
        elif self.mutation_source_attempt_id is not None:
            raise ValueError("mutation_source_attempt_id is only valid for a mutation")
        return self


class RiskFlagV1(StrEnum):
    MULTI_TURN = "multi_turn"
    CROSS_PATIENT_REFERENCE = "cross_patient_reference"
    FILE_UPLOAD = "file_upload"
    PARAMETER_TAMPERING = "parameter_tampering"
    COST_AMPLIFICATION = "cost_amplification"
    PRIVILEGE_BOUNDARY = "privilege_boundary"
    HUMAN_REVIEW_RECOMMENDED = "human_review_recommended"


class EstimatedCostClassV1(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ProposedAttackV1(ContractModel):
    schema_version: Literal[SCHEMA_VERSION_V1]
    proposal_id: Identifier
    category: Identifier
    subcategory: Identifier
    attack_family_id: Identifier
    lineage_id: Identifier
    parent_attempt_id: Identifier | None = None
    novelty_rationale: ShortText
    prerequisites: list[ShortText] = Field(default_factory=list, max_length=20)
    ordered_actions: list[AttackActionV1] = Field(min_length=1, max_length=30)
    expected_exploit_signals: list[ShortText] = Field(min_length=1, max_length=20)
    expected_safe_behavior: list[ShortText] = Field(min_length=1, max_length=20)
    stop_conditions: list[ShortText] = Field(min_length=1, max_length=20)
    risk_flags: list[RiskFlagV1] = Field(default_factory=list, max_length=10)
    estimated_turns: int = Field(ge=1, le=20)
    estimated_cost_class: EstimatedCostClassV1

    @field_validator("ordered_actions")
    @classmethod
    def action_ids_are_unique(cls, value: list[AttackActionV1]) -> list[AttackActionV1]:
        ids = [action.action_id for action in value]
        if len(ids) != len(set(ids)):
            raise ValueError("ordered action IDs must be unique")
        return value

    @field_validator(
        "expected_exploit_signals",
        "expected_safe_behavior",
        "stop_conditions",
        "risk_flags",
    )
    @classmethod
    def list_values_are_unique(cls, value: list[object]) -> list[object]:
        if len(value) != len(set(value)):
            raise ValueError("contract lists must not contain duplicate values")
        return value


__all__ = [
    "CampaignObjectiveV1",
    "EstimatedCostClassV1",
    "PriorAttemptOutcomeV1",
    "PriorAttemptSummaryV1",
    "ProposedAttackV1",
    "RemainingBudgetAndLimitsV1",
    "RiskFlagV1",
]
