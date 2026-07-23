"""Small, deterministic campaign lifecycle stop check."""

from __future__ import annotations

from decimal import Decimal
from enum import StrEnum

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class StopModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class StopReasonV1(StrEnum):
    ATTEMPT_LIMIT = "attempt_limit"
    DURATION_LIMIT = "duration_limit"
    CANCELLATION_REQUESTED = "cancellation_requested"
    CLEANUP_FAILED = "cleanup_failed"
    CAMPAIGN_BUDGET_EXHAUSTED = "campaign_budget_exhausted"


class CampaignStopStateV1(StopModel):
    attempts_completed: int = Field(ge=0)
    max_attempts: int = Field(gt=0)
    campaign_started_at: AwareDatetime
    evaluated_at: AwareDatetime
    max_duration_seconds: int = Field(gt=0, le=86_400)
    actual_cost_usd: Decimal = Field(ge=0)
    max_cost_usd: Decimal = Field(gt=0)
    cancellation_requested: bool = False
    cleanup_failed: bool = False

    @model_validator(mode="after")
    def evaluation_is_not_before_start(self) -> CampaignStopStateV1:
        if self.evaluated_at < self.campaign_started_at:
            raise ValueError("evaluated_at must not precede campaign_started_at")
        return self


class StopDecisionV1(StopModel):
    stop_campaign: bool
    allow_new_attempt: bool
    reasons: list[StopReasonV1]
    evaluated_at: AwareDatetime


def evaluate_stopping(state: CampaignStopStateV1) -> StopDecisionV1:
    reasons: list[StopReasonV1] = []
    if state.cancellation_requested:
        reasons.append(StopReasonV1.CANCELLATION_REQUESTED)
    if state.cleanup_failed:
        reasons.append(StopReasonV1.CLEANUP_FAILED)
    if state.attempts_completed >= state.max_attempts:
        reasons.append(StopReasonV1.ATTEMPT_LIMIT)
    if (
        state.evaluated_at - state.campaign_started_at
    ).total_seconds() >= state.max_duration_seconds:
        reasons.append(StopReasonV1.DURATION_LIMIT)
    if state.actual_cost_usd >= state.max_cost_usd:
        reasons.append(StopReasonV1.CAMPAIGN_BUDGET_EXHAUSTED)
    return StopDecisionV1(
        stop_campaign=bool(reasons),
        allow_new_attempt=not reasons,
        reasons=reasons,
        evaluated_at=state.evaluated_at,
    )


__all__ = [
    "CampaignStopStateV1",
    "StopDecisionV1",
    "StopReasonV1",
    "evaluate_stopping",
]
