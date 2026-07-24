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


class ExecutionSurfaceV2(StrEnum):
    """Controller-owned execution surfaces available to planning agents."""

    OPENEMR_UI = "openemr_ui"
    OPENEMR_SAME_ORIGIN_API = "openemr_same_origin_api"
    AGENT_SERVICE_API = "agent_service_api"
    STAGED_DOCUMENT = "staged_document"
    HYBRID = "hybrid"


class AttackTechniqueV2(StrEnum):
    SCENARIO = "scenario"
    FUZZING = "fuzzing"


class FuzzMutationOperatorV2(StrEnum):
    APPEND_FRAGMENT = "append_fragment"
    PREPEND_FRAGMENT = "prepend_fragment"
    REPLACE_VALUE = "replace_value"
    SPLIT_MULTI_TURN = "split_multi_turn"
    REMOVE_FIELD = "remove_field"
    ADD_EXTRA_FIELD = "add_extra_field"
    CHANGE_JSON_TYPE = "change_json_type"
    CORRELATION_MISMATCH = "correlation_mismatch"


class FuzzPlanV2(ContractModel):
    """Model-selected strategy whose concrete variants are expanded deterministically."""

    schema_version: Literal["v2"] = "v2"
    base_sequence: list[AttackActionV1] = Field(min_length=5, max_length=30)
    mutation_point_action_id: Identifier
    operator_ids: list[FuzzMutationOperatorV2] = Field(min_length=1, max_length=6)
    corpus_ids: list[Identifier] = Field(min_length=1, max_length=12)
    rng_seed: int = Field(ge=0, le=2**32 - 1)
    max_variants: int = Field(default=6, ge=1, le=6)

    @model_validator(mode="after")
    def mutation_point_is_in_base_sequence(self) -> FuzzPlanV2:
        action_ids = [action.action_id for action in self.base_sequence]
        if self.mutation_point_action_id not in action_ids:
            raise ValueError("fuzz mutation point must reference an action in base_sequence")
        if len(action_ids) != len(set(action_ids)):
            raise ValueError("fuzz base-sequence action IDs must be unique")
        if len(self.operator_ids) != len(set(self.operator_ids)):
            raise ValueError("fuzz operator IDs must be unique")
        if len(self.corpus_ids) != len(set(self.corpus_ids)):
            raise ValueError("fuzz corpus IDs must be unique")
        return self


class TaxonomyCoverageFactV2(ContractModel):
    """Raw, non-ranked durable facts for one taxonomy subcategory."""

    category: Identifier
    subcategory: Identifier
    description: ShortText
    applicable_surfaces: list[Identifier] = Field(min_length=1, max_length=10)
    expected_security_invariants: list[ShortText] = Field(min_length=1, max_length=20)
    attempted: int = Field(ge=0)
    executed: int = Field(ge=0)
    outcomes: dict[str, int] = Field(default_factory=dict, max_length=12)
    by_target_version: dict[str, int] = Field(default_factory=dict, max_length=50)
    by_surface: dict[str, int] = Field(default_factory=dict, max_length=10)
    by_technique: dict[str, int] = Field(default_factory=dict, max_length=10)
    by_provenance: dict[str, int] = Field(default_factory=dict, max_length=20)


class SurfaceCapabilityFactV2(ContractModel):
    surface: ExecutionSurfaceV2
    supported: bool
    endpoint_ids: list[Identifier] = Field(default_factory=list, max_length=30)
    blocked_reason: ShortText | None = None

    @model_validator(mode="after")
    def support_and_reason_are_consistent(self) -> SurfaceCapabilityFactV2:
        if self.supported and self.blocked_reason is not None:
            raise ValueError("supported surfaces cannot have a blocked reason")
        if not self.supported and self.blocked_reason is None:
            raise ValueError("unsupported surfaces require a blocked reason")
        return self


class FindingPlanningFactV2(ContractModel):
    finding_id: Identifier
    finding_key_hash: Sha256Hex | None = None
    category: Identifier
    subcategory: Identifier
    status: Identifier
    last_seen_target_version: ShortText


class OrchestratorDecisionContextV2(ContractModel):
    """Compact PostgreSQL-backed facts; ordering carries no priority signal."""

    schema_version: Literal["v2"] = "v2"
    campaign_id: Identifier
    target_version: ShortText
    taxonomy_version: ShortText
    taxonomy_coverage: list[TaxonomyCoverageFactV2] = Field(min_length=1, max_length=100)
    surface_capabilities: list[SurfaceCapabilityFactV2] = Field(min_length=1, max_length=10)
    pending_findings: list[FindingPlanningFactV2] = Field(default_factory=list, max_length=100)
    partial_signals: list[PriorAttemptSummaryV1] = Field(default_factory=list, max_length=20)
    prior_attack_families: list[Identifier] = Field(default_factory=list, max_length=100)
    eligible_mutation_attempt_ids: list[Identifier] = Field(default_factory=list, max_length=20)
    remaining_limits: RemainingBudgetAndLimitsV1
    allowed_surfaces: list[ExecutionSurfaceV2] = Field(min_length=1, max_length=5)
    allowed_techniques: list[AttackTechniqueV2] = Field(min_length=1, max_length=2)

    @field_validator(
        "prior_attack_families",
        "eligible_mutation_attempt_ids",
        "allowed_surfaces",
        "allowed_techniques",
    )
    @classmethod
    def context_lists_are_unique(cls, value: list[object]) -> list[object]:
        if len(value) != len(set(value)):
            raise ValueError("orchestrator context lists must not contain duplicates")
        return value


class OrchestratorDecisionV2(ContractModel):
    """Semantic next-step decision owned exclusively by the Orchestrator."""

    schema_version: Literal["v2"] = "v2"
    requested_action: RequestedActionV1
    selected_category: Identifier | None = None
    selected_subcategory: Identifier | None = None
    selected_surface: ExecutionSurfaceV2 | None = None
    selected_technique: AttackTechniqueV2 | None = None
    objective: ShortText | None = None
    mutation_source_attempt_id: Identifier | None = None
    mutation_source: ShortText | None = None
    rationale: ShortText | None = None

    @model_validator(mode="after")
    def action_has_required_fields(self) -> OrchestratorDecisionV2:
        semantic_fields = (
            self.selected_category,
            self.selected_subcategory,
            self.selected_surface,
            self.selected_technique,
            self.objective,
            self.mutation_source_attempt_id,
            self.mutation_source,
            self.rationale,
        )
        if self.requested_action == RequestedActionV1.STOP:
            if any(value is not None for value in semantic_fields):
                raise ValueError("stop cannot include an objective, rationale, or mutation source")
            return self
        if any(
            value is None
            for value in (
                self.selected_category,
                self.selected_subcategory,
                self.selected_surface,
                self.selected_technique,
                self.objective,
                self.rationale,
            )
        ):
            raise ValueError("new attacks and mutations require a complete V2 decision")
        if self.requested_action == RequestedActionV1.MUTATION:
            if self.mutation_source_attempt_id is None:
                raise ValueError("mutation_source_attempt_id is required for a mutation")
        elif self.mutation_source_attempt_id is not None:
            raise ValueError("mutation_source_attempt_id is only valid for a mutation")
        return self


class PriorAttemptOutcomeV1(StrEnum):
    EXPLOIT_CONFIRMED = "exploit_confirmed"
    PARTIAL_SIGNAL = "partial_signal"
    ATTACK_BLOCKED = "attack_blocked"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class PriorAttemptSummaryV1(ContractModel):
    attempt_id: Identifier
    attack_family_id: Identifier
    parent_attempt_id: Identifier | None = None
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


class OrchestratorDecisionV1(ContractModel):
    """The only semantic planning decision returned by the Orchestrator."""

    schema_version: Literal[SCHEMA_VERSION_V1]
    requested_action: RequestedActionV1
    selected_category: Identifier | None = None
    selected_subcategory: Identifier | None = None
    objective: ShortText | None = None
    mutation_source_attempt_id: Identifier | None = None

    @model_validator(mode="after")
    def action_has_required_fields(self) -> OrchestratorDecisionV1:
        if self.requested_action == RequestedActionV1.STOP:
            if any(
                value is not None
                for value in (
                    self.selected_category,
                    self.selected_subcategory,
                    self.objective,
                    self.mutation_source_attempt_id,
                )
            ):
                raise ValueError("stop cannot include an objective or mutation source")
            return self
        if not self.selected_category or not self.selected_subcategory or not self.objective:
            raise ValueError("new attacks and mutations require a complete objective")
        if self.requested_action == RequestedActionV1.MUTATION:
            if self.mutation_source_attempt_id is None:
                raise ValueError("mutation_source_attempt_id is required for a mutation")
        elif self.mutation_source_attempt_id is not None:
            raise ValueError("mutation_source_attempt_id is only valid for a mutation")
        return self


class CampaignObjectiveV1(ContractModel):
    schema_version: Literal[SCHEMA_VERSION_V1]
    campaign_id: Identifier
    campaign_type: CampaignTypeV1
    target_version: ShortText
    selected_category: Identifier
    selected_subcategory: Identifier
    owasp_mappings: OwaspMappingsV1
    attack_surface: AttackSurfaceV1
    execution_surface: ExecutionSurfaceV2 = ExecutionSurfaceV2.OPENEMR_UI
    technique: AttackTechniqueV2 = AttackTechniqueV2.SCENARIO
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
    execution_surface: ExecutionSurfaceV2 = ExecutionSurfaceV2.OPENEMR_UI
    technique: AttackTechniqueV2 = AttackTechniqueV2.SCENARIO
    attack_family_id: Identifier
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
    fuzz_plan: FuzzPlanV2 | None = None

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

    @model_validator(mode="after")
    def technique_and_fuzz_plan_are_consistent(self) -> ProposedAttackV1:
        if self.technique == AttackTechniqueV2.FUZZING:
            if self.fuzz_plan is None:
                raise ValueError("fuzzing proposals require a FuzzPlanV2")
            proposed = [action.model_dump(mode="json") for action in self.ordered_actions]
            base = [action.model_dump(mode="json") for action in self.fuzz_plan.base_sequence]
            if proposed != base:
                raise ValueError("fuzz plan base_sequence must equal ordered_actions")
        elif self.fuzz_plan is not None:
            raise ValueError("scenario proposals cannot include a fuzz plan")
        return self


__all__ = [
    "AttackTechniqueV2",
    "CampaignObjectiveV1",
    "EstimatedCostClassV1",
    "ExecutionSurfaceV2",
    "FindingPlanningFactV2",
    "FuzzMutationOperatorV2",
    "FuzzPlanV2",
    "OrchestratorDecisionContextV2",
    "OrchestratorDecisionV1",
    "OrchestratorDecisionV2",
    "PriorAttemptOutcomeV1",
    "PriorAttemptSummaryV1",
    "ProposedAttackV1",
    "RemainingBudgetAndLimitsV1",
    "RiskFlagV1",
    "SurfaceCapabilityFactV2",
    "TaxonomyCoverageFactV2",
]


OrchestratorDecisionContextV2.model_rebuild()
