from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from agentforge.orchestration.budgets import (
    BudgetAccountV1,
    BudgetBreachV1,
    BudgetLimitsV1,
    BudgetStateV1,
    TokenUsageV1,
    load_pricing_config,
    reconcile_actual_usage,
    release_reservation,
    reserve_worst_case,
)

ROOT = Path(__file__).parents[2]
NOW = datetime(2026, 7, 21, 9, tzinfo=UTC)


def limits(cost: str) -> BudgetLimitsV1:
    return BudgetLimitsV1(
        max_cost_usd=Decimal(cost),
        max_calls=100,
        max_input_tokens=1_000_000,
        max_output_tokens=1_000_000,
    )


def state(*, global_cost: str = "10", campaign_cost: str = "2") -> BudgetStateV1:
    return BudgetStateV1(
        global_account=BudgetAccountV1(limits=limits(global_cost)),
        campaign_account=BudgetAccountV1(limits=limits(campaign_cost)),
    )


def usage(
    *,
    model: str = "gpt-5.6-terra",
    input_tokens: int = 1_000,
    output_tokens: int = 1_000,
) -> TokenUsageV1:
    return TokenUsageV1(
        model=model,
        calls=1,
        input_tokens=input_tokens,
        cached_input_tokens=0,
        cache_write_tokens=0,
        output_tokens=output_tokens,
    )


def test_worst_case_is_reserved_then_actual_usage_is_reconciled() -> None:
    pricing = load_pricing_config(ROOT / "config/pricing.yaml")
    result = reserve_worst_case(
        state(),
        campaign_id="campaign-001",
        reservation_id="reservation-001",
        worst_case_by_model=[usage()],
        pricing=pricing,
        reserved_at=NOW,
    )

    assert result.approved is True
    assert result.reservation is not None
    assert result.reservation.worst_case_total.cost_usd == Decimal("0.0175")
    assert result.state.global_account.reserved.cost_usd == Decimal("0.0175")
    assert result.state.campaign_account.reserved.calls == 1

    reconciliation = reconcile_actual_usage(
        result.state,
        result.reservation,
        [usage(input_tokens=500, output_tokens=250)],
        pricing,
    )
    assert reconciliation.reservation_overrun is False
    assert reconciliation.ceiling_breaches == []
    assert reconciliation.state.global_account.reserved.cost_usd == 0
    assert reconciliation.state.campaign_account.actual.calls == 1
    assert reconciliation.state.campaign_account.actual.cost_usd == Decimal("0.005")


def test_reservation_enforces_campaign_and_global_ceiling() -> None:
    pricing = load_pricing_config(ROOT / "config/pricing.yaml")
    campaign_rejection = reserve_worst_case(
        state(campaign_cost="0.01"),
        campaign_id="campaign-001",
        reservation_id="reservation-001",
        worst_case_by_model=[usage()],
        pricing=pricing,
        reserved_at=NOW,
    )
    assert campaign_rejection.approved is False
    assert BudgetBreachV1.CAMPAIGN_COST in campaign_rejection.breaches

    global_rejection = reserve_worst_case(
        state(global_cost="0.01"),
        campaign_id="campaign-001",
        reservation_id="reservation-001",
        worst_case_by_model=[usage()],
        pricing=pricing,
        reserved_at=NOW,
    )
    assert global_rejection.approved is False
    assert BudgetBreachV1.GLOBAL_COST in global_rejection.breaches


def test_unknown_models_are_rejected_before_call() -> None:
    pricing = load_pricing_config(ROOT / "config/pricing.yaml")
    result = reserve_worst_case(
        state(),
        campaign_id="campaign-001",
        reservation_id="reservation-001",
        worst_case_by_model=[usage(model="unpriced-model")],
        pricing=pricing,
        reserved_at=NOW,
    )
    assert result.approved is False
    assert result.breaches == [BudgetBreachV1.UNKNOWN_MODEL]


def test_reservation_ids_cannot_be_reused_while_active() -> None:
    pricing = load_pricing_config(ROOT / "config/pricing.yaml")
    first = reserve_worst_case(
        state(),
        campaign_id="campaign-001",
        reservation_id="reservation-001",
        worst_case_by_model=[usage()],
        pricing=pricing,
        reserved_at=NOW,
    )
    second = reserve_worst_case(
        first.state,
        campaign_id="campaign-001",
        reservation_id="reservation-001",
        worst_case_by_model=[usage()],
        pricing=pricing,
        reserved_at=NOW,
    )
    assert second.approved is False
    assert second.breaches == [BudgetBreachV1.DUPLICATE_RESERVATION]


def test_actual_overrun_is_recorded_and_unused_reservation_can_be_released() -> None:
    pricing = load_pricing_config(ROOT / "config/pricing.yaml")
    reservation_result = reserve_worst_case(
        state(),
        campaign_id="campaign-001",
        reservation_id="reservation-001",
        worst_case_by_model=[usage(input_tokens=100, output_tokens=100)],
        pricing=pricing,
        reserved_at=NOW,
    )
    assert reservation_result.reservation is not None

    reconciliation = reconcile_actual_usage(
        reservation_result.state,
        reservation_result.reservation,
        [usage(input_tokens=200, output_tokens=200)],
        pricing,
    )
    assert reconciliation.reservation_overrun is True
    assert (
        reservation_result.reservation.reservation_id
        not in reconciliation.state.active_reservation_ids
    )

    released = release_reservation(reservation_result.state, reservation_result.reservation)
    assert released.global_account.reserved.cost_usd == 0
    assert released.campaign_account.reserved.calls == 0
    assert reservation_result.reservation.reservation_id not in released.active_reservation_ids
