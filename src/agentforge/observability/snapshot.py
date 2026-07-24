"""Typed durable observability shared by operators and the Orchestrator."""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentforge.contracts.v1 import (
    AttackTechniqueV2,
    FindingPlanningFactV2,
    OrchestratorDecisionContextV2,
    PriorAttemptOutcomeV1,
    PriorAttemptSummaryV1,
    RemainingBudgetAndLimitsV1,
    SurfaceCapabilityFactV2,
    TaxonomyCoverageFactV2,
)
from agentforge.evaluation.catalog import SeedCaseV1, TaxonomyV1
from agentforge.persistence.models import (
    AgentRun,
    AttackAttempt,
    Campaign,
    Finding,
    JudgeVerdict,
    PlatformEvent,
    RegressionCase,
    RegressionReplay,
    RegressionResult,
    RegressionRun,
)


class ObservabilityModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CoverageRowV2(ObservabilityModel):
    category: str
    subcategory: str
    description: str
    seed_cases: int = Field(ge=0)
    discovery_attempts: int = Field(ge=0)
    fuzz_variants: int = Field(ge=0)
    regression_cases: int = Field(ge=0)
    regression_replays: int = Field(ge=0)
    attempted: int = Field(ge=0)
    executed: int = Field(ge=0)
    outcomes: dict[str, int]
    by_target_version: dict[str, int]
    by_surface: dict[str, int]
    by_technique: dict[str, int]
    by_provenance: dict[str, int]


class OutcomeLaneV2(ObservabilityModel):
    lane: str
    attempted: int = Field(ge=0)
    executed: int = Field(ge=0)
    outcomes: dict[str, int]
    no_verdict: int = Field(ge=0)
    errors: int = Field(ge=0)


class ResilienceTransitionV2(ObservabilityModel):
    previous_target_version: str
    target_version: str
    matched_case_count: int = Field(ge=0)
    improved: int = Field(ge=0)
    regressed: int = Field(ge=0)
    unchanged_secure: int = Field(ge=0)
    unchanged_reproduced: int = Field(ge=0)
    inconclusive_or_error: int = Field(ge=0)
    cross_category_regression: bool


class CostFactV2(ObservabilityModel):
    dimension: str
    key: str
    model_cost_usd: Decimal = Field(ge=0)
    calls: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)


class CampaignCostProjectionV2(ObservabilityModel):
    campaign_id: str
    actual_cost_usd: Decimal = Field(ge=0)
    completed_attempts: int = Field(ge=0)
    remaining_attempts: int = Field(ge=0)
    projected_remaining_cost_usd: Decimal = Field(ge=0)


class CostSummaryV2(ObservabilityModel):
    total_model_cost_usd: Decimal = Field(ge=0)
    completed_attempts: int = Field(ge=0)
    cost_per_completed_attempt_usd: Decimal = Field(ge=0)
    recent_marginal_cost_usd: Decimal = Field(ge=0)
    active_campaign_projections: list[CampaignCostProjectionV2]


class TimelineFactV2(ObservabilityModel):
    event_id: str
    occurred_at: datetime
    event_type: str
    actor: str
    campaign_id: str | None
    attempt_id: str | None
    finding_id: str | None
    regression_run_id: str | None
    role: str | None
    model: str | None
    prompt_version: str | None
    trace_id: str | None
    latency_ms: int | None
    cost_usd: Decimal
    details: dict[str, Any]


class PlatformObservabilitySnapshotV2(ObservabilityModel):
    schema_version: str = "v2"
    generated_at: datetime
    taxonomy_version: str
    surface_capabilities: list[SurfaceCapabilityFactV2]
    coverage: list[CoverageRowV2]
    outcome_lanes: list[OutcomeLaneV2]
    finding_lifecycle: dict[str, int]
    resilience_transitions: list[ResilienceTransitionV2]
    cost_summary: CostSummaryV2
    cost_facts: list[CostFactV2]
    timeline: list[TimelineFactV2]


def _finding_key_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _outcome_for(verdict: str | None, state: str) -> str:
    if verdict:
        return verdict
    return "error" if state == "failed" else "no_verdict"


def _attempt_lane(attempt: AttackAttempt, campaign_type: str) -> str:
    if campaign_type == "regression" or attempt.provenance == "regression_replay":
        return "regression"
    if attempt.technique == AttackTechniqueV2.FUZZING.value:
        return "fuzz"
    if attempt.seed_case_hash is not None or attempt.provenance in {
        "human_authored_seed",
        "curated_discovery_replay",
    }:
        return "seed"
    return "discovery"


class PlatformObservabilityService:
    """Produce neutral planning facts and human-facing summaries from the same rows."""

    def __init__(
        self,
        session: Session,
        *,
        taxonomy: TaxonomyV1,
        seed_cases: list[SeedCaseV1] | None = None,
        surface_capabilities: list[SurfaceCapabilityFactV2] | None = None,
    ) -> None:
        self.session = session
        self.taxonomy = taxonomy
        self.seed_cases = seed_cases or []
        self.surface_capabilities = surface_capabilities or []

    @property
    def neutral_taxonomy_pairs(self) -> list[tuple[str, str]]:
        """Stable alphabetical order; the order intentionally carries no priority."""

        return sorted(
            (category.id, subcategory.id)
            for category in self.taxonomy.categories
            for subcategory in category.subcategories
        )

    def _taxonomy_entry(self, category_id: str, subcategory_id: str) -> tuple[Any, Any]:
        category = next(item for item in self.taxonomy.categories if item.id == category_id)
        subcategory = next(item for item in category.subcategories if item.id == subcategory_id)
        return category, subcategory

    def _attempt_facts(
        self,
    ) -> dict[tuple[str, str], dict[str, Counter[str] | int]]:
        facts: dict[tuple[str, str], dict[str, Counter[str] | int]] = defaultdict(
            lambda: {
                "attempted": 0,
                "executed": 0,
                "outcomes": Counter(),
                "versions": Counter(),
                "surfaces": Counter(),
                "techniques": Counter(),
                "provenance": Counter(),
                "lanes": Counter(),
            }
        )
        statement = (
            select(
                AttackAttempt,
                Campaign.campaign_type,
                Campaign.target_version,
                JudgeVerdict.verdict,
            )
            .join(Campaign, Campaign.id == AttackAttempt.campaign_id)
            .outerjoin(JudgeVerdict, JudgeVerdict.attempt_id == AttackAttempt.id)
        )
        for attempt, campaign_type, target_version, verdict in self.session.execute(statement):
            key = (attempt.category, attempt.subcategory)
            item = facts[key]
            item["attempted"] = int(item["attempted"]) + 1
            if attempt.target_executed or attempt.evidence_hash is not None:
                item["executed"] = int(item["executed"]) + 1
            outcome = _outcome_for(verdict, attempt.state)
            for name, value in (
                ("outcomes", outcome),
                ("versions", target_version),
                ("surfaces", attempt.execution_surface),
                ("techniques", attempt.technique),
                ("provenance", attempt.provenance),
                ("lanes", _attempt_lane(attempt, campaign_type)),
            ):
                counter = item[name]
                assert isinstance(counter, Counter)
                counter[value] += 1
        return facts

    def coverage_rows(self) -> list[CoverageRowV2]:
        attempt_facts = self._attempt_facts()
        seed_counts = Counter((case.category, case.subcategory) for case in self.seed_cases)
        regression_counts = Counter(
            (category, subcategory)
            for category, subcategory in self.session.execute(
                select(RegressionCase.category, RegressionCase.subcategory).where(
                    RegressionCase.active.is_(True)
                )
            )
        )
        replay_counts = Counter(
            (category, subcategory)
            for category, subcategory in self.session.execute(
                select(RegressionCase.category, RegressionCase.subcategory)
                .join(RegressionResult, RegressionResult.case_id == RegressionCase.id)
                .join(RegressionReplay, RegressionReplay.result_id == RegressionResult.id)
            )
        )
        rows: list[CoverageRowV2] = []
        for key in self.neutral_taxonomy_pairs:
            category, subcategory = self._taxonomy_entry(*key)
            facts = attempt_facts.get(key, {})
            lanes = facts.get("lanes", Counter())
            assert isinstance(lanes, Counter)
            rows.append(
                CoverageRowV2(
                    category=category.id,
                    subcategory=subcategory.id,
                    description=subcategory.description,
                    seed_cases=seed_counts[key],
                    discovery_attempts=lanes["discovery"],
                    fuzz_variants=lanes["fuzz"],
                    regression_cases=regression_counts[key],
                    regression_replays=replay_counts[key],
                    attempted=int(facts.get("attempted", 0)),
                    executed=int(facts.get("executed", 0)),
                    outcomes=dict(facts.get("outcomes", Counter())),
                    by_target_version=dict(facts.get("versions", Counter())),
                    by_surface=dict(facts.get("surfaces", Counter())),
                    by_technique=dict(facts.get("techniques", Counter())),
                    by_provenance=dict(facts.get("provenance", Counter())),
                )
            )
        return rows

    def orchestrator_context(
        self,
        *,
        campaign: Campaign,
        remaining_limits: RemainingBudgetAndLimitsV1,
        surface_capabilities: list[SurfaceCapabilityFactV2],
    ) -> OrchestratorDecisionContextV2:
        rows = self.coverage_rows()
        partials: list[PriorAttemptSummaryV1] = []
        families: set[str] = set()
        eligible_mutations: list[str] = []
        recent = self.session.execute(
            select(AttackAttempt)
            .where(AttackAttempt.campaign_id == campaign.id)
            .order_by(AttackAttempt.created_at.desc(), AttackAttempt.id.desc())
            .limit(20)
        )
        for attempt in reversed(list(recent.scalars())):
            families.add(attempt.attack_family_id)
            verdict = attempt.verdict
            if (
                attempt.sequence_hash is None
                or verdict is None
                or verdict.verdict != PriorAttemptOutcomeV1.PARTIAL_SIGNAL.value
            ):
                continue
            summary = PriorAttemptSummaryV1(
                attempt_id=str(attempt.id),
                attack_family_id=attempt.attack_family_id,
                parent_attempt_id=(
                    str(attempt.parent_attempt_id)
                    if attempt.parent_attempt_id is not None
                    else None
                ),
                outcome=PriorAttemptOutcomeV1.PARTIAL_SIGNAL,
                summary=verdict.observed_behavior[:512],
                sequence_hash=attempt.sequence_hash,
                evidence_hash=attempt.evidence_hash,
            )
            partials.append(summary)
            eligible_mutations.append(str(attempt.id))
        findings = list(
            self.session.scalars(
                select(Finding)
                .where(Finding.status.in_({"pending_review", "open", "in_progress"}))
                .order_by(Finding.created_at, Finding.id)
                .limit(100)
            )
        )
        allowed_surfaces = [item.surface for item in surface_capabilities if item.supported]
        if not allowed_surfaces:
            raise ValueError("at least one execution surface must be supported")
        return OrchestratorDecisionContextV2(
            campaign_id=str(campaign.id),
            target_version=campaign.target_version,
            taxonomy_version=self.taxonomy.taxonomy_version,
            taxonomy_coverage=[
                TaxonomyCoverageFactV2(
                    category=row.category,
                    subcategory=row.subcategory,
                    description=row.description,
                    applicable_surfaces=self._taxonomy_entry(row.category, row.subcategory)[
                        1
                    ].applicable_surfaces,
                    expected_security_invariants=self._taxonomy_entry(
                        row.category, row.subcategory
                    )[0].expected_security_invariants,
                    attempted=row.attempted,
                    executed=row.executed,
                    outcomes=row.outcomes,
                    by_target_version=row.by_target_version,
                    by_surface=row.by_surface,
                    by_technique=row.by_technique,
                    by_provenance=row.by_provenance,
                )
                for row in rows
                if (campaign.category_scope is None or row.category == campaign.category_scope)
                and (
                    campaign.subcategory_scope is None
                    or row.subcategory == campaign.subcategory_scope
                )
            ],
            surface_capabilities=surface_capabilities,
            pending_findings=[
                FindingPlanningFactV2(
                    finding_id=str(item.id),
                    finding_key_hash=_finding_key_hash(item.finding_key),
                    category=item.category,
                    subcategory=item.subcategory,
                    status=item.status,
                    last_seen_target_version=item.last_seen_target_version,
                )
                for item in findings
            ],
            partial_signals=partials,
            prior_attack_families=sorted(families),
            eligible_mutation_attempt_ids=eligible_mutations,
            remaining_limits=remaining_limits,
            allowed_surfaces=allowed_surfaces,
            allowed_techniques=[
                AttackTechniqueV2.SCENARIO,
                AttackTechniqueV2.FUZZING,
            ],
        )

    def outcome_lanes(self) -> list[OutcomeLaneV2]:
        lane_facts: dict[str, Counter[str]] = {
            name: Counter() for name in ("seed", "discovery", "fuzz", "regression")
        }
        statement = (
            select(AttackAttempt, Campaign.campaign_type)
            .join(Campaign, Campaign.id == AttackAttempt.campaign_id)
            .order_by(AttackAttempt.created_at, AttackAttempt.id)
        )
        for attempt, campaign_type in self.session.execute(statement):
            lane = _attempt_lane(attempt, campaign_type)
            counts = lane_facts[lane]
            counts["attempted"] += 1
            if attempt.target_executed or attempt.evidence_hash is not None:
                counts["executed"] += 1
            verdict = attempt.verdict.verdict if attempt.verdict is not None else None
            counts[_outcome_for(verdict, attempt.state)] += 1
        return [
            OutcomeLaneV2(
                lane=lane,
                attempted=counts["attempted"],
                executed=counts["executed"],
                outcomes={
                    key: value
                    for key, value in counts.items()
                    if key not in {"attempted", "executed", "no_verdict", "error"}
                },
                no_verdict=counts["no_verdict"],
                errors=counts["error"],
            )
            for lane, counts in lane_facts.items()
        ]

    def resilience_transitions(self) -> list[ResilienceTransitionV2]:
        runs = list(
            self.session.scalars(
                select(RegressionRun)
                .where(RegressionRun.status == "completed")
                .order_by(RegressionRun.created_at, RegressionRun.id)
            )
        )
        results_by_run: dict[Any, dict[Any, str]] = defaultdict(dict)
        for run_id, case_id, outcome in self.session.execute(
            select(
                RegressionResult.run_id,
                RegressionResult.case_id,
                RegressionResult.outcome,
            )
        ):
            results_by_run[run_id][case_id] = outcome
        transitions: list[ResilienceTransitionV2] = []
        for current in runs:
            if not current.previous_target_version:
                continue
            previous = next(
                (
                    candidate
                    for candidate in reversed(runs)
                    if candidate.created_at < current.created_at
                    and candidate.target_version == current.previous_target_version
                    and (
                        current.cohort_hash is None or candidate.cohort_hash == current.cohort_hash
                    )
                ),
                None,
            )
            if previous is None:
                continue
            previous_results = results_by_run[previous.id]
            current_results = results_by_run[current.id]
            matched = sorted(set(previous_results) & set(current_results), key=str)
            counts: Counter[str] = Counter()
            for case_id in matched:
                before = previous_results[case_id]
                after = current_results[case_id]
                if before == "vulnerability_reproduced" and after == "secure_pass":
                    counts["improved"] += 1
                elif before == "secure_pass" and after == "vulnerability_reproduced":
                    counts["regressed"] += 1
                elif before == after == "secure_pass":
                    counts["unchanged_secure"] += 1
                elif before == after == "vulnerability_reproduced":
                    counts["unchanged_reproduced"] += 1
                else:
                    counts["inconclusive_or_error"] += 1
            transitions.append(
                ResilienceTransitionV2(
                    previous_target_version=previous.target_version,
                    target_version=current.target_version,
                    matched_case_count=len(matched),
                    improved=counts["improved"],
                    regressed=counts["regressed"],
                    unchanged_secure=counts["unchanged_secure"],
                    unchanged_reproduced=counts["unchanged_reproduced"],
                    inconclusive_or_error=counts["inconclusive_or_error"],
                    cross_category_regression=current.cross_category_regression,
                )
            )
        return transitions

    def cost_facts(self) -> list[CostFactV2]:
        facts: list[CostFactV2] = []
        dimensions = {
            "agent": AgentRun.role,
            "model": AgentRun.model,
            "campaign": AgentRun.campaign_id,
        }
        for dimension, column in dimensions.items():
            for key, cost, calls, input_tokens, output_tokens in self.session.execute(
                select(
                    column,
                    func.coalesce(func.sum(AgentRun.estimated_cost_usd), 0),
                    func.count(AgentRun.id),
                    func.coalesce(func.sum(AgentRun.input_tokens), 0),
                    func.coalesce(func.sum(AgentRun.output_tokens), 0),
                )
                .where(column.is_not(None))
                .group_by(column)
            ):
                facts.append(
                    CostFactV2(
                        dimension=dimension,
                        key=str(key),
                        model_cost_usd=Decimal(str(cost)),
                        calls=int(calls),
                        input_tokens=int(input_tokens),
                        output_tokens=int(output_tokens),
                    )
                )
        attempt_dimensions = {
            "category": AttackAttempt.category,
            "technique": AttackAttempt.technique,
            "surface": AttackAttempt.execution_surface,
            "target_version": Campaign.target_version,
        }
        for dimension, column in attempt_dimensions.items():
            for key, cost, calls, input_tokens, output_tokens in self.session.execute(
                select(
                    column,
                    func.coalesce(func.sum(AttackAttempt.estimated_cost_usd), 0),
                    func.count(AttackAttempt.id),
                    func.coalesce(func.sum(AttackAttempt.input_tokens), 0),
                    func.coalesce(func.sum(AttackAttempt.output_tokens), 0),
                )
                .join(Campaign, Campaign.id == AttackAttempt.campaign_id)
                .group_by(column)
            ):
                facts.append(
                    CostFactV2(
                        dimension=dimension,
                        key=str(key),
                        model_cost_usd=Decimal(str(cost)),
                        calls=int(calls),
                        input_tokens=int(input_tokens),
                        output_tokens=int(output_tokens),
                    )
                )
        for attempt in self.session.scalars(
            select(AttackAttempt).order_by(AttackAttempt.created_at, AttackAttempt.id)
        ):
            facts.append(
                CostFactV2(
                    dimension="attempt",
                    key=str(attempt.id),
                    model_cost_usd=attempt.estimated_cost_usd,
                    calls=1,
                    input_tokens=attempt.input_tokens,
                    output_tokens=attempt.output_tokens,
                )
            )
        for case_id, cost, replay_count in self.session.execute(
            select(
                RegressionCase.case_id,
                func.coalesce(func.sum(RegressionReplay.estimated_cost_usd), 0),
                func.count(RegressionReplay.id),
            )
            .join(RegressionResult, RegressionResult.case_id == RegressionCase.id)
            .join(RegressionReplay, RegressionReplay.result_id == RegressionResult.id)
            .group_by(RegressionCase.case_id)
        ):
            facts.append(
                CostFactV2(
                    dimension="regression_case",
                    key=case_id,
                    model_cost_usd=Decimal(str(cost)),
                    calls=int(replay_count),
                    input_tokens=0,
                    output_tokens=0,
                )
            )
        return sorted(facts, key=lambda item: (item.dimension, item.key))

    def cost_summary(self) -> CostSummaryV2:
        total = Decimal(
            str(
                self.session.scalar(select(func.coalesce(func.sum(AgentRun.estimated_cost_usd), 0)))
                or 0
            )
        )
        completed_attempts = int(
            self.session.scalar(
                select(func.count(AttackAttempt.id)).where(AttackAttempt.completed_at.is_not(None))
            )
            or 0
        )
        recent_costs = [
            Decimal(str(value))
            for value in self.session.scalars(
                select(AttackAttempt.estimated_cost_usd)
                .where(AttackAttempt.completed_at.is_not(None))
                .order_by(AttackAttempt.completed_at.desc())
                .limit(10)
            )
        ]
        recent_marginal = (
            sum(recent_costs, Decimal("0")) / len(recent_costs) if recent_costs else Decimal("0")
        )
        projections: list[CampaignCostProjectionV2] = []
        for campaign in self.session.scalars(
            select(Campaign)
            .where(Campaign.status.in_({"queued", "running"}))
            .order_by(Campaign.created_at, Campaign.id)
        ):
            remaining = max(0, campaign.max_attempts - campaign.actual_attempts)
            campaign_attempt_costs = [
                Decimal(str(value))
                for value in self.session.scalars(
                    select(AttackAttempt.estimated_cost_usd).where(
                        AttackAttempt.campaign_id == campaign.id,
                        AttackAttempt.completed_at.is_not(None),
                    )
                )
            ]
            unit = (
                sum(campaign_attempt_costs, Decimal("0")) / len(campaign_attempt_costs)
                if campaign_attempt_costs
                else recent_marginal
            )
            projections.append(
                CampaignCostProjectionV2(
                    campaign_id=str(campaign.id),
                    actual_cost_usd=campaign.actual_cost_usd,
                    completed_attempts=len(campaign_attempt_costs),
                    remaining_attempts=remaining,
                    projected_remaining_cost_usd=unit * remaining,
                )
            )
        return CostSummaryV2(
            total_model_cost_usd=total,
            completed_attempts=completed_attempts,
            cost_per_completed_attempt_usd=(
                total / completed_attempts if completed_attempts else Decimal("0")
            ),
            recent_marginal_cost_usd=recent_marginal,
            active_campaign_projections=projections,
        )

    def timeline(self, *, limit: int = 200) -> list[TimelineFactV2]:
        events = list(
            self.session.scalars(
                select(PlatformEvent)
                .order_by(PlatformEvent.created_at.desc(), PlatformEvent.id.desc())
                .limit(min(max(limit, 1), 1_000))
            )
        )
        return [
            TimelineFactV2(
                event_id=str(item.id),
                occurred_at=item.created_at,
                event_type=item.event_type,
                actor=item.actor,
                campaign_id=str(item.campaign_id) if item.campaign_id else None,
                attempt_id=str(item.attempt_id) if item.attempt_id else None,
                finding_id=str(item.finding_id) if item.finding_id else None,
                regression_run_id=(str(item.regression_run_id) if item.regression_run_id else None),
                role=item.role,
                model=item.model,
                prompt_version=item.prompt_version,
                trace_id=item.trace_id,
                latency_ms=item.latency_ms,
                cost_usd=item.cost_usd,
                details=item.details_json,
            )
            for item in reversed(events)
        ]

    def snapshot(self, *, timeline_limit: int = 200) -> PlatformObservabilitySnapshotV2:
        lifecycle = {
            status: int(count)
            for status, count in self.session.execute(
                select(Finding.status, func.count(Finding.id)).group_by(Finding.status)
            )
        }
        return PlatformObservabilitySnapshotV2(
            generated_at=datetime.now(UTC),
            taxonomy_version=self.taxonomy.taxonomy_version,
            surface_capabilities=self.surface_capabilities,
            coverage=self.coverage_rows(),
            outcome_lanes=self.outcome_lanes(),
            finding_lifecycle=lifecycle,
            resilience_transitions=self.resilience_transitions(),
            cost_summary=self.cost_summary(),
            cost_facts=self.cost_facts(),
            timeline=self.timeline(limit=timeline_limit),
        )


__all__ = [
    "CostFactV2",
    "CostSummaryV2",
    "CoverageRowV2",
    "OutcomeLaneV2",
    "PlatformObservabilityService",
    "PlatformObservabilitySnapshotV2",
    "ResilienceTransitionV2",
    "TimelineFactV2",
]
