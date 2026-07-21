"""Pure campaign and attack-lineage stopping decisions."""

from __future__ import annotations

from enum import StrEnum

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from .budgets import BudgetStateV1, account_has_capacity


class StopModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class StopReasonV1(StrEnum):
    ATTEMPT_LIMIT = "attempt_limit"
    DURATION_LIMIT = "duration_limit"
    NO_SIGNAL_LIMIT = "no_signal_limit"
    MUTATION_LIMIT = "mutation_limit"
    CANCELLATION_REQUESTED = "cancellation_requested"
    CLEANUP_FAILED = "cleanup_failed"
    GLOBAL_BUDGET_EXHAUSTED = "global_budget_exhausted"
    CAMPAIGN_BUDGET_EXHAUSTED = "campaign_budget_exhausted"


class CampaignStopStateV1(StopModel):
    attempts_completed: int = Field(ge=0)
    max_attempts: int = Field(gt=0)
    campaign_started_at: AwareDatetime
    evaluated_at: AwareDatetime
    max_duration_seconds: int = Field(gt=0, le=86_400)
    consecutive_no_signal_attempts: int = Field(ge=0)
    max_consecutive_no_signal_attempts: int = Field(gt=0)
    current_lineage_mutations: int = Field(ge=0)
    max_mutations_per_lineage: int = Field(ge=0)
    cancellation_requested: bool = False
    cleanup_failed: bool = False
    budget_state: BudgetStateV1

    @model_validator(mode="after")
    def evaluation_is_not_before_start(self) -> CampaignStopStateV1:
        if self.evaluated_at < self.campaign_started_at:
            raise ValueError("evaluated_at must not precede campaign_started_at")
        return self


class StopDecisionV1(StopModel):
    stop_campaign: bool
    stop_current_lineage: bool
    allow_new_attempt: bool
    allow_mutation: bool
    reasons: list[StopReasonV1]
    evaluated_at: AwareDatetime


def evaluate_stopping(state: CampaignStopStateV1) -> StopDecisionV1:
    """Evaluate hard campaign stops separately from a lineage mutation stop."""

    reasons: list[StopReasonV1] = []
    if state.cancellation_requested:
        reasons.append(StopReasonV1.CANCELLATION_REQUESTED)
    if state.cleanup_failed:
        reasons.append(StopReasonV1.CLEANUP_FAILED)
    if state.attempts_completed >= state.max_attempts:
        reasons.append(StopReasonV1.ATTEMPT_LIMIT)
    elapsed = (state.evaluated_at - state.campaign_started_at).total_seconds()
    if elapsed >= state.max_duration_seconds:
        reasons.append(StopReasonV1.DURATION_LIMIT)
    if state.consecutive_no_signal_attempts >= state.max_consecutive_no_signal_attempts:
        reasons.append(StopReasonV1.NO_SIGNAL_LIMIT)
    if state.current_lineage_mutations >= state.max_mutations_per_lineage:
        reasons.append(StopReasonV1.MUTATION_LIMIT)
    if not account_has_capacity(state.budget_state.global_account):
        reasons.append(StopReasonV1.GLOBAL_BUDGET_EXHAUSTED)
    if not account_has_capacity(state.budget_state.campaign_account):
        reasons.append(StopReasonV1.CAMPAIGN_BUDGET_EXHAUSTED)

    hard_reasons = set(reasons) - {StopReasonV1.MUTATION_LIMIT}
    stop_campaign = bool(hard_reasons)
    stop_lineage = StopReasonV1.MUTATION_LIMIT in reasons
    return StopDecisionV1(
        stop_campaign=stop_campaign,
        stop_current_lineage=stop_lineage,
        allow_new_attempt=not stop_campaign,
        allow_mutation=not stop_campaign and not stop_lineage,
        reasons=reasons,
        evaluated_at=state.evaluated_at,
    )


__all__ = [
    "CampaignStopStateV1",
    "StopDecisionV1",
    "StopReasonV1",
    "evaluate_stopping",
]
