from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from agentforge.orchestration.stopping import (
    CampaignStopStateV1,
    StopReasonV1,
    evaluate_stopping,
)

NOW = datetime(2026, 7, 21, 9, tzinfo=UTC)


def stop_state(**updates: object) -> CampaignStopStateV1:
    values = {
        "attempts_completed": 0,
        "max_attempts": 10,
        "campaign_started_at": NOW,
        "evaluated_at": NOW + timedelta(minutes=1),
        "max_duration_seconds": 1_200,
        "actual_cost_usd": Decimal("0.25"),
        "max_cost_usd": Decimal("2"),
        "cancellation_requested": False,
        "cleanup_failed": False,
    }
    values.update(updates)
    return CampaignStopStateV1(**values)


def test_campaign_may_continue_when_all_limits_have_capacity() -> None:
    decision = evaluate_stopping(stop_state())
    assert decision.stop_campaign is False
    assert decision.allow_new_attempt is True
    assert decision.reasons == []


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        ({"attempts_completed": 10}, StopReasonV1.ATTEMPT_LIMIT),
        (
            {"evaluated_at": NOW + timedelta(minutes=21)},
            StopReasonV1.DURATION_LIMIT,
        ),
        ({"cancellation_requested": True}, StopReasonV1.CANCELLATION_REQUESTED),
        ({"cleanup_failed": True}, StopReasonV1.CLEANUP_FAILED),
        (
            {"actual_cost_usd": Decimal("2")},
            StopReasonV1.CAMPAIGN_BUDGET_EXHAUSTED,
        ),
    ],
)
def test_configured_stop_conditions_end_the_campaign(
    updates: dict[str, object],
    reason: StopReasonV1,
) -> None:
    decision = evaluate_stopping(stop_state(**updates))
    assert decision.stop_campaign is True
    assert decision.allow_new_attempt is False
    assert reason in decision.reasons


def test_stop_state_rejects_evaluation_before_campaign_start() -> None:
    with pytest.raises(ValueError, match="must not precede"):
        stop_state(evaluated_at=NOW - timedelta(seconds=1))
