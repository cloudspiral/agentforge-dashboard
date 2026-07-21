"""Deterministic worst-case budget reservation and usage reconciliation."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, HttpUrl, model_validator

Money = Annotated[Decimal, Field(ge=Decimal("0"), max_digits=18, decimal_places=9)]


class BudgetModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ModelPricingV1(BudgetModel):
    input: Money
    cached_input: Money
    cache_write: Money
    output: Money


class PricingPolicyV1(BudgetModel):
    reserve_maximum_output_before_call: Literal[True]
    unknown_model_behavior: Literal["reject_live_call"]
    refresh_required_after_days: int = Field(gt=0, le=365)


class PricingConfigV1(BudgetModel):
    schema_version: Literal["1.0"]
    currency: Literal["USD"]
    unit: Literal["per_1m_tokens"]
    source: HttpUrl
    verified_at: date
    models: dict[str, ModelPricingV1] = Field(min_length=1)
    policy: PricingPolicyV1


def load_pricing_config(path: Path) -> PricingConfigV1:
    """Load checked-in pricing while preserving exact decimal values."""

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["verified_at"] = date.fromisoformat(str(raw["verified_at"]))
    raw["source"] = HttpUrl(str(raw["source"]))
    for rates in raw.get("models", {}).values():
        for key in ("input", "cached_input", "cache_write", "output"):
            rates[key] = Decimal(str(rates[key]))
    return PricingConfigV1.model_validate(raw)


class TokenUsageV1(BudgetModel):
    """Mutually exclusive token buckets for one model across one or more calls."""

    model: str = Field(min_length=1, max_length=128)
    calls: int = Field(ge=0, le=100_000)
    input_tokens: int = Field(ge=0)
    cached_input_tokens: int = Field(ge=0)
    cache_write_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)

    @model_validator(mode="after")
    def nonempty_usage_has_a_call(self) -> TokenUsageV1:
        token_total = (
            self.input_tokens
            + self.cached_input_tokens
            + self.cache_write_tokens
            + self.output_tokens
        )
        if token_total and not self.calls:
            raise ValueError("nonzero token usage requires at least one model call")
        return self


class BudgetUsageV1(BudgetModel):
    calls: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    cached_input_tokens: int = Field(default=0, ge=0)
    cache_write_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cost_usd: Money = Decimal("0")


class BudgetLimitsV1(BudgetModel):
    max_cost_usd: Money
    max_calls: int = Field(gt=0)
    max_input_tokens: int = Field(gt=0)
    max_output_tokens: int = Field(gt=0)


class BudgetAccountV1(BudgetModel):
    limits: BudgetLimitsV1
    actual: BudgetUsageV1 = Field(default_factory=BudgetUsageV1)
    reserved: BudgetUsageV1 = Field(default_factory=BudgetUsageV1)


class BudgetStateV1(BudgetModel):
    global_account: BudgetAccountV1
    campaign_account: BudgetAccountV1
    active_reservation_ids: frozenset[str] = Field(default_factory=frozenset)


class BudgetBreachV1(StrEnum):
    UNKNOWN_MODEL = "unknown_model"
    DUPLICATE_RESERVATION = "duplicate_reservation"
    GLOBAL_COST = "global_cost"
    GLOBAL_CALLS = "global_calls"
    GLOBAL_INPUT_TOKENS = "global_input_tokens"
    GLOBAL_OUTPUT_TOKENS = "global_output_tokens"
    CAMPAIGN_COST = "campaign_cost"
    CAMPAIGN_CALLS = "campaign_calls"
    CAMPAIGN_INPUT_TOKENS = "campaign_input_tokens"
    CAMPAIGN_OUTPUT_TOKENS = "campaign_output_tokens"


class BudgetReservationV1(BudgetModel):
    reservation_id: str = Field(min_length=1, max_length=128)
    campaign_id: str = Field(min_length=1, max_length=128)
    worst_case_by_model: list[TokenUsageV1] = Field(min_length=1, max_length=20)
    worst_case_total: BudgetUsageV1
    reserved_at: AwareDatetime


class BudgetReservationResultV1(BudgetModel):
    approved: bool
    state: BudgetStateV1
    reservation: BudgetReservationV1 | None = None
    breaches: list[BudgetBreachV1] = Field(default_factory=list)

    @model_validator(mode="after")
    def approval_shape_is_consistent(self) -> BudgetReservationResultV1:
        if self.approved and (self.reservation is None or self.breaches):
            raise ValueError("approved reservations require a reservation and no breaches")
        if not self.approved and (self.reservation is not None or not self.breaches):
            raise ValueError("rejected reservations require breaches and no reservation")
        return self


class BudgetReconciliationV1(BudgetModel):
    state: BudgetStateV1
    actual_total: BudgetUsageV1
    reservation_overrun: bool
    ceiling_breaches: list[BudgetBreachV1] = Field(default_factory=list)


class UnknownModelPricingError(ValueError):
    """Raised when usage references a model absent from the pricing table."""


def _cost_usage(usage: TokenUsageV1, pricing: PricingConfigV1) -> BudgetUsageV1:
    rates = pricing.models.get(usage.model)
    if rates is None:
        raise UnknownModelPricingError(f"model is absent from pricing config: {usage.model}")
    million = Decimal(1_000_000)
    cost = (
        Decimal(usage.input_tokens) * rates.input
        + Decimal(usage.cached_input_tokens) * rates.cached_input
        + Decimal(usage.cache_write_tokens) * rates.cache_write
        + Decimal(usage.output_tokens) * rates.output
    ) / million
    return BudgetUsageV1(
        calls=usage.calls,
        input_tokens=usage.input_tokens,
        cached_input_tokens=usage.cached_input_tokens,
        cache_write_tokens=usage.cache_write_tokens,
        output_tokens=usage.output_tokens,
        cost_usd=cost,
    )


def _add(*values: BudgetUsageV1) -> BudgetUsageV1:
    return BudgetUsageV1(
        calls=sum(value.calls for value in values),
        input_tokens=sum(value.input_tokens for value in values),
        cached_input_tokens=sum(value.cached_input_tokens for value in values),
        cache_write_tokens=sum(value.cache_write_tokens for value in values),
        output_tokens=sum(value.output_tokens for value in values),
        cost_usd=sum((value.cost_usd for value in values), start=Decimal("0")),
    )


def _subtract(left: BudgetUsageV1, right: BudgetUsageV1) -> BudgetUsageV1:
    fields = {
        "calls": left.calls - right.calls,
        "input_tokens": left.input_tokens - right.input_tokens,
        "cached_input_tokens": left.cached_input_tokens - right.cached_input_tokens,
        "cache_write_tokens": left.cache_write_tokens - right.cache_write_tokens,
        "output_tokens": left.output_tokens - right.output_tokens,
        "cost_usd": left.cost_usd - right.cost_usd,
    }
    if any(value < 0 for value in fields.values()):
        raise ValueError("reservation is not present in the supplied budget state")
    return BudgetUsageV1(**fields)


def price_usage(usages: list[TokenUsageV1], pricing: PricingConfigV1) -> BudgetUsageV1:
    """Calculate exact configured price for a bounded collection of model usage."""

    if not usages:
        raise ValueError("at least one model usage record is required")
    return _add(*(_cost_usage(usage, pricing) for usage in usages))


def _account_breaches(
    account: BudgetAccountV1,
    additional: BudgetUsageV1,
    *,
    scope: Literal["global", "campaign"],
) -> list[BudgetBreachV1]:
    projected = _add(account.actual, account.reserved, additional)
    prefix = "GLOBAL" if scope == "global" else "CAMPAIGN"
    breaches: list[BudgetBreachV1] = []
    if projected.cost_usd > account.limits.max_cost_usd:
        breaches.append(BudgetBreachV1[f"{prefix}_COST"])
    if projected.calls > account.limits.max_calls:
        breaches.append(BudgetBreachV1[f"{prefix}_CALLS"])
    if projected.input_tokens + projected.cached_input_tokens + projected.cache_write_tokens > (
        account.limits.max_input_tokens
    ):
        breaches.append(BudgetBreachV1[f"{prefix}_INPUT_TOKENS"])
    if projected.output_tokens > account.limits.max_output_tokens:
        breaches.append(BudgetBreachV1[f"{prefix}_OUTPUT_TOKENS"])
    return breaches


def reserve_worst_case(
    state: BudgetStateV1,
    *,
    campaign_id: str,
    reservation_id: str,
    worst_case_by_model: list[TokenUsageV1],
    pricing: PricingConfigV1,
    reserved_at: AwareDatetime,
) -> BudgetReservationResultV1:
    """Reserve maximum calls/tokens/cost before any model call is made."""

    if reservation_id in state.active_reservation_ids:
        return BudgetReservationResultV1(
            approved=False,
            state=state,
            breaches=[BudgetBreachV1.DUPLICATE_RESERVATION],
        )
    try:
        total = price_usage(worst_case_by_model, pricing)
    except UnknownModelPricingError:
        return BudgetReservationResultV1(
            approved=False,
            state=state,
            breaches=[BudgetBreachV1.UNKNOWN_MODEL],
        )
    breaches = [
        *_account_breaches(state.global_account, total, scope="global"),
        *_account_breaches(state.campaign_account, total, scope="campaign"),
    ]
    if breaches:
        return BudgetReservationResultV1(approved=False, state=state, breaches=breaches)

    next_state = BudgetStateV1(
        global_account=state.global_account.model_copy(
            update={"reserved": _add(state.global_account.reserved, total)}
        ),
        campaign_account=state.campaign_account.model_copy(
            update={"reserved": _add(state.campaign_account.reserved, total)}
        ),
        active_reservation_ids=state.active_reservation_ids | {reservation_id},
    )
    reservation = BudgetReservationV1(
        reservation_id=reservation_id,
        campaign_id=campaign_id,
        worst_case_by_model=worst_case_by_model,
        worst_case_total=total,
        reserved_at=reserved_at,
    )
    return BudgetReservationResultV1(
        approved=True,
        state=next_state,
        reservation=reservation,
    )


def reconcile_actual_usage(
    state: BudgetStateV1,
    reservation: BudgetReservationV1,
    actual_by_model: list[TokenUsageV1],
    pricing: PricingConfigV1,
) -> BudgetReconciliationV1:
    """Release a reservation and atomically account for measured actual usage."""

    if reservation.reservation_id not in state.active_reservation_ids:
        raise ValueError("reservation is not active in the supplied budget state")
    actual = price_usage(actual_by_model, pricing)
    reservation_overrun = any(
        (
            actual.calls > reservation.worst_case_total.calls,
            actual.input_tokens > reservation.worst_case_total.input_tokens,
            actual.cached_input_tokens > reservation.worst_case_total.cached_input_tokens,
            actual.cache_write_tokens > reservation.worst_case_total.cache_write_tokens,
            actual.output_tokens > reservation.worst_case_total.output_tokens,
            actual.cost_usd > reservation.worst_case_total.cost_usd,
        )
    )
    global_reserved = _subtract(state.global_account.reserved, reservation.worst_case_total)
    campaign_reserved = _subtract(state.campaign_account.reserved, reservation.worst_case_total)
    next_state = BudgetStateV1(
        global_account=state.global_account.model_copy(
            update={
                "reserved": global_reserved,
                "actual": _add(state.global_account.actual, actual),
            }
        ),
        campaign_account=state.campaign_account.model_copy(
            update={
                "reserved": campaign_reserved,
                "actual": _add(state.campaign_account.actual, actual),
            }
        ),
        active_reservation_ids=state.active_reservation_ids - {reservation.reservation_id},
    )
    zero = BudgetUsageV1()
    ceiling_breaches = [
        *_account_breaches(next_state.global_account, zero, scope="global"),
        *_account_breaches(next_state.campaign_account, zero, scope="campaign"),
    ]
    return BudgetReconciliationV1(
        state=next_state,
        actual_total=actual,
        reservation_overrun=reservation_overrun,
        ceiling_breaches=ceiling_breaches,
    )


def release_reservation(
    state: BudgetStateV1,
    reservation: BudgetReservationV1,
) -> BudgetStateV1:
    """Release an unused reservation after a rejected/cancelled action."""

    if reservation.reservation_id not in state.active_reservation_ids:
        raise ValueError("reservation is not active in the supplied budget state")
    return BudgetStateV1(
        global_account=state.global_account.model_copy(
            update={
                "reserved": _subtract(
                    state.global_account.reserved,
                    reservation.worst_case_total,
                )
            }
        ),
        campaign_account=state.campaign_account.model_copy(
            update={
                "reserved": _subtract(
                    state.campaign_account.reserved,
                    reservation.worst_case_total,
                )
            }
        ),
        active_reservation_ids=state.active_reservation_ids - {reservation.reservation_id},
    )


def account_has_capacity(account: BudgetAccountV1) -> bool:
    """Return whether any future bounded work can still be admitted."""

    used = _add(account.actual, account.reserved)
    return (
        used.cost_usd < account.limits.max_cost_usd
        and used.calls < account.limits.max_calls
        and used.input_tokens + used.cached_input_tokens + used.cache_write_tokens
        < account.limits.max_input_tokens
        and used.output_tokens < account.limits.max_output_tokens
    )


__all__ = [
    "BudgetAccountV1",
    "BudgetBreachV1",
    "BudgetLimitsV1",
    "BudgetReconciliationV1",
    "BudgetReservationResultV1",
    "BudgetReservationV1",
    "BudgetStateV1",
    "BudgetUsageV1",
    "ModelPricingV1",
    "PricingConfigV1",
    "TokenUsageV1",
    "UnknownModelPricingError",
    "account_has_capacity",
    "load_pricing_config",
    "price_usage",
    "reconcile_actual_usage",
    "release_reservation",
    "reserve_worst_case",
]
