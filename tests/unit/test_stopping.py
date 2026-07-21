from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from agentforge.orchestration.budgets import (
    BudgetAccountV1,
    BudgetLimitsV1,
    BudgetStateV1,
    BudgetUsageV1,
)
from agentforge.orchestration.stopping import (
    CampaignStopStateV1,
    StopReasonV1,
    evaluate_stopping,
)

NOW = datetime(2026, 7, 21, 9, tzinfo=UTC)


def budget_state(*, exhausted: str | None = None) -> BudgetStateV1:
    limits = BudgetLimitsV1(
        max_cost_usd=Decimal("2"),
        max_calls=10,
        max_input_tokens=10_000,
        max_output_tokens=10_000,
    )

    def account(scope: str) -> BudgetAccountV1:
        actual = BudgetUsageV1(cost_usd=Decimal("2")) if exhausted == scope else BudgetUsageV1()
        return BudgetAccountV1(limits=limits, actual=actual)

    return BudgetStateV1(global_account=account("global"), campaign_account=account("campaign"))


def stop_state(**updates: object) -> CampaignStopStateV1:
    values = {
        "attempts_completed": 0,
        "max_attempts": 10,
        "campaign_started_at": NOW,
        "evaluated_at": NOW + timedelta(minutes=1),
        "max_duration_seconds": 1_200,
        "consecutive_no_signal_attempts": 0,
        "max_consecutive_no_signal_attempts": 4,
        "current_lineage_mutations": 0,
        "max_mutations_per_lineage": 3,
        "cancellation_requested": False,
        "cleanup_failed": False,
        "budget_state": budget_state(),
    }
    values.update(updates)
    return CampaignStopStateV1(**values)


def test_campaign_may_continue_when_all_limits_have_capacity() -> None:
    decision = evaluate_stopping(stop_state())
    assert decision.stop_campaign is False
    assert decision.stop_current_lineage is False
    assert decision.allow_new_attempt is True
    assert decision.allow_mutation is True
    assert decision.reasons == []


def test_mutation_limit_stops_only_the_current_lineage() -> None:
    decision = evaluate_stopping(stop_state(current_lineage_mutations=3))
    assert decision.stop_campaign is False
    assert decision.stop_current_lineage is True
    assert decision.allow_new_attempt is True
    assert decision.allow_mutation is False
    assert decision.reasons == [StopReasonV1.MUTATION_LIMIT]


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        ({"attempts_completed": 10}, StopReasonV1.ATTEMPT_LIMIT),
        (
            {"evaluated_at": NOW + timedelta(minutes=20)},
            StopReasonV1.DURATION_LIMIT,
        ),
        ({"consecutive_no_signal_attempts": 4}, StopReasonV1.NO_SIGNAL_LIMIT),
        ({"cancellation_requested": True}, StopReasonV1.CANCELLATION_REQUESTED),
        ({"cleanup_failed": True}, StopReasonV1.CLEANUP_FAILED),
        (
            {"budget_state": budget_state(exhausted="global")},
            StopReasonV1.GLOBAL_BUDGET_EXHAUSTED,
        ),
        (
            {"budget_state": budget_state(exhausted="campaign")},
            StopReasonV1.CAMPAIGN_BUDGET_EXHAUSTED,
        ),
    ],
)
def test_hard_stop_conditions_end_the_campaign(
    updates: dict[str, object],
    reason: StopReasonV1,
) -> None:
    decision = evaluate_stopping(stop_state(**updates))
    assert decision.stop_campaign is True
    assert decision.allow_new_attempt is False
    assert reason in decision.reasons
