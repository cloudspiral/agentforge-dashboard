"""Reproducible measured evidence and non-linear production cost projections."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentforge.persistence.models import (
    AgentRun,
    AttackAttempt,
    Campaign,
    Finding,
    FindingLifecycleEvent,
    FindingObservation,
    RegressionReplay,
)


class CostAnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ScenarioAssumptionsV1(CostAnalysisModel):
    workload_mix: dict[str, Decimal]
    attacker_model_usd: dict[str, Decimal]
    target_model_calls: dict[str, Decimal]
    target_model_usd_per_call: Decimal = Field(ge=0)
    retry_and_escalation_rate: Decimal = Field(ge=0)
    browser_share: Decimal = Field(ge=0, le=1)
    browser_seconds_per_execution: Decimal = Field(ge=0)
    api_seconds_per_execution: Decimal = Field(ge=0)
    worker_usd_per_vcpu_hour: Decimal = Field(ge=0)
    database_bytes_per_run: int = Field(ge=0)
    artifact_bytes_per_run: int = Field(ge=0)
    telemetry_events_per_run: Decimal = Field(ge=0)
    human_review_rate: Decimal = Field(ge=0, le=1)
    human_review_minutes: Decimal = Field(ge=0)
    fixed_platform_usd_by_scale: dict[int, Decimal]

    @model_validator(mode="after")
    def matching_workload_keys(self) -> ScenarioAssumptionsV1:
        keys = set(self.workload_mix)
        if keys != set(self.attacker_model_usd) or keys != set(self.target_model_calls):
            raise ValueError("workload, attacker model, and target call keys must match")
        if sum(self.workload_mix.values(), Decimal("0")) != Decimal("1"):
            raise ValueError("workload_mix must sum exactly to 1")
        return self


class CostModelAssumptionsV1(CostAnalysisModel):
    schema_version: str
    currency: str
    run_definition: str
    scales: list[int]
    storage: dict[str, Decimal]
    telemetry: dict[str, Decimal]
    labor: dict[str, Decimal]
    scenarios: dict[str, ScenarioAssumptionsV1]

    @model_validator(mode="after")
    def required_scenarios_and_scales(self) -> CostModelAssumptionsV1:
        if set(self.scenarios) != {"low", "base", "high"}:
            raise ValueError("cost model requires low, base, and high scenarios")
        if self.scales != [100, 1_000, 10_000, 100_000]:
            raise ValueError("cost model scales must be 100, 1K, 10K, and 100K")
        for scenario in self.scenarios.values():
            if set(scenario.fixed_platform_usd_by_scale) != set(self.scales):
                raise ValueError("every scenario needs a fixed platform value at every scale")
        return self


class AgentCallEvidenceV1(CostAnalysisModel):
    agent_run_id: str
    source_label: str
    campaign_id: str | None
    attempt_id: str | None
    role: str
    model: str
    status: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    sdk_attempts: int | None = Field(default=None, ge=0)
    estimated_cost_usd: Decimal = Field(ge=0)
    latency_ms: int | None
    trace_id: str | None


class UnitEconomicsFactV1(CostAnalysisModel):
    unit: str
    samples: int = Field(ge=0)
    measured_cost_usd: Decimal | None
    note: str


class SourceSpendV1(CostAnalysisModel):
    source_label: str
    calls: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    estimated_cost_usd: Decimal = Field(ge=0)


class CostEvidenceSnapshotV1(CostAnalysisModel):
    schema_version: str = "v1"
    generated_at: datetime
    source_labels: list[str]
    pricing_source: str
    pricing_verified_at: str
    agent_calls: list[AgentCallEvidenceV1]
    spend_by_source: list[SourceSpendV1]
    total_agentforge_model_cost_usd: Decimal = Field(ge=0)
    overnight_campaign_ids: list[str]
    overnight_campaign_cost_usd: Decimal = Field(ge=0)
    target_executions: int = Field(ge=0)
    target_inference_cost_status: str
    infrastructure_invoice_status: str
    provider_billing_reconciliation_status: str
    codex_subscription_status: str
    developer_labor_status: str
    unit_economics: list[UnitEconomicsFactV1]
    database_evidence_bytes: int = Field(ge=0)
    artifact_bytes: int = Field(ge=0)
    browser_seconds: Decimal = Field(ge=0)
    average_target_latency_ms: Decimal | None
    retry_rate: Decimal | None
    human_review_rate: Decimal | None
    counts: dict[str, int]


class ProjectionLineItemsV1(CostAnalysisModel):
    attacker_models: Decimal = Field(ge=0)
    target_models: Decimal = Field(ge=0)
    retries_and_escalations: Decimal = Field(ge=0)
    browser_and_api_workers: Decimal = Field(ge=0)
    postgresql: Decimal = Field(ge=0)
    artifact_storage: Decimal = Field(ge=0)
    telemetry: Decimal = Field(ge=0)
    fixed_platform: Decimal = Field(ge=0)
    human_triage: Decimal = Field(ge=0)
    total: Decimal = Field(ge=0)


class CostProjectionV1(CostAnalysisModel):
    scenario: str
    runs: int = Field(gt=0)
    workload_counts: dict[str, Decimal]
    line_items: ProjectionLineItemsV1


def load_cost_assumptions(path: Path) -> CostModelAssumptionsV1:
    return CostModelAssumptionsV1.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def _lane(attempt: AttackAttempt, campaign_type: str) -> str:
    if campaign_type == "regression" or attempt.provenance == "regression_replay":
        return "regression_replay"
    if attempt.technique == "fuzzing":
        return "fuzz_variant"
    if attempt.seed_case_hash is not None or attempt.provenance in {
        "human_authored_seed",
        "curated_discovery_replay",
    }:
        return "seed_evaluation"
    return "ordinary_discovery"


def _json_size(value: Any) -> int:
    if value is None:
        return 0
    return len(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    )


def _artifact_bytes(roots: list[Path]) -> int:
    total = 0
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file():
                total += path.stat().st_size
    return total


def _average(values: list[Decimal]) -> Decimal | None:
    return sum(values, Decimal("0")) / len(values) if values else None


def collect_cost_evidence(
    session: Session,
    *,
    source_label: str,
    pricing_source: str,
    pricing_verified_at: str,
    artifact_roots: list[Path] | None = None,
    overnight_campaign_ids: set[str] | None = None,
) -> CostEvidenceSnapshotV1:
    """Collect redacted cost inputs from durable rows; no prompts or outputs are exported."""

    runs = list(session.scalars(select(AgentRun).order_by(AgentRun.created_at, AgentRun.id)))
    calls = [
        AgentCallEvidenceV1(
            agent_run_id=str(run.id),
            source_label=source_label,
            campaign_id=str(run.campaign_id) if run.campaign_id else None,
            attempt_id=str(run.attempt_id) if run.attempt_id else None,
            role=run.role,
            model=run.model,
            status=run.status,
            input_tokens=run.input_tokens,
            output_tokens=run.output_tokens,
            sdk_attempts=run.sdk_attempts,
            estimated_cost_usd=run.estimated_cost_usd,
            latency_ms=run.latency_ms,
            trace_id=run.langfuse_trace_id,
        )
        for run in runs
    ]
    total_cost = sum((call.estimated_cost_usd for call in calls), Decimal("0"))
    overnight_ids = overnight_campaign_ids or set()
    overnight_cost = sum(
        (
            call.estimated_cost_usd
            for call in calls
            if call.campaign_id is not None and call.campaign_id in overnight_ids
        ),
        Decimal("0"),
    )

    attempt_rows = list(
        session.execute(
            select(AttackAttempt, Campaign.campaign_type)
            .join(Campaign, Campaign.id == AttackAttempt.campaign_id)
            .order_by(AttackAttempt.created_at, AttackAttempt.id)
        )
    )
    lane_costs: dict[str, list[Decimal]] = defaultdict(list)
    target_latencies: list[Decimal] = []
    browser_ms = Decimal("0")
    db_bytes = 0
    executed = 0
    for attempt, campaign_type in attempt_rows:
        lane_costs[_lane(attempt, campaign_type)].append(attempt.estimated_cost_usd)
        if attempt.target_executed:
            executed += 1
        if attempt.latency_ms is not None:
            target_latencies.append(Decimal(attempt.latency_ms))
            if attempt.execution_surface in {"openemr_ui", "staged_document", "hybrid"}:
                browser_ms += Decimal(attempt.latency_ms)
        db_bytes += sum(
            _json_size(value)
            for value in (
                attempt.proposed_sequence,
                attempt.executed_sequence,
                attempt.evidence_payload,
                attempt.failure,
                attempt.fuzz_plan,
            )
        )

    fuzz_campaign_ids = {
        str(attempt.campaign_id)
        for attempt, _campaign_type in attempt_rows
        if attempt.technique == "fuzzing"
    }
    fuzz_plan_costs = [
        call.estimated_cost_usd
        for call in calls
        if call.role == "attack_generator" and call.campaign_id in fuzz_campaign_ids
    ]
    confirmed_attempt_ids = {
        str(value) for value in session.scalars(select(FindingObservation.attempt_id))
    }
    confirmed_iteration_costs = [
        sum(
            (call.estimated_cost_usd for call in calls if call.attempt_id == attempt_id),
            Decimal("0"),
        )
        for attempt_id in sorted(confirmed_attempt_ids)
    ]
    replay_costs: list[Decimal] = []
    for result_id, count, cost in session.execute(
        select(
            RegressionReplay.result_id,
            func.count(RegressionReplay.id),
            func.coalesce(func.sum(RegressionReplay.estimated_cost_usd), 0),
        ).group_by(RegressionReplay.result_id)
    ):
        del result_id
        if int(count) >= 2:
            replay_costs.append(Decimal(str(cost)))

    unit_economics = [
        UnitEconomicsFactV1(
            unit=lane,
            samples=len(costs),
            measured_cost_usd=_average(costs),
            note="Mean model cost stored on the completed/gated attempt.",
        )
        for lane, costs in sorted(lane_costs.items())
        if lane in {"seed_evaluation", "ordinary_discovery", "fuzz_variant"}
    ]
    for lane in ("seed_evaluation", "ordinary_discovery", "fuzz_variant"):
        if lane not in lane_costs:
            unit_economics.append(
                UnitEconomicsFactV1(
                    unit=lane,
                    samples=0,
                    measured_cost_usd=None,
                    note="UNMEASURED: no durable sample in the selected data sources.",
                )
            )
    unit_economics.extend(
        [
            UnitEconomicsFactV1(
                unit="fuzz_plan",
                samples=len(fuzz_plan_costs),
                measured_cost_usd=_average(fuzz_plan_costs),
                note="Attack Generator calls in campaigns containing expanded fuzz variants.",
            ),
            UnitEconomicsFactV1(
                unit="confirmed_finding_iteration",
                samples=len(confirmed_iteration_costs),
                measured_cost_usd=_average(confirmed_iteration_costs),
                note=(
                    "Agent calls linked to a confirmed observation; campaign-level "
                    "Orchestrator planning remains reported separately."
                ),
            ),
            UnitEconomicsFactV1(
                unit="regression_case_two_replays",
                samples=len(replay_costs),
                measured_cost_usd=_average(replay_costs),
                note="Mean aggregate of durable regression results with at least two replays.",
            ),
        ]
    )

    measured_sdk_attempts = [call.sdk_attempts for call in calls if call.sdk_attempts is not None]
    controller_groups = Counter(
        (call.attempt_id, call.role)
        for call in calls
        if call.attempt_id is not None and call.sdk_attempts is not None
    )
    retries = sum(max(0, count - 1) for count in measured_sdk_attempts) + sum(
        max(0, count - 1) for count in controller_groups.values()
    )
    total_sdk_attempts = sum(measured_sdk_attempts)

    finding_count = int(session.scalar(select(func.count(Finding.id))) or 0)
    reviewed_findings = int(
        session.scalar(
            select(func.count(func.distinct(FindingLifecycleEvent.finding_id))).where(
                FindingLifecycleEvent.action.in_(
                    {
                        "confirm",
                        "begin_work",
                        "dismiss",
                        "resolve",
                        "manual_resolution_override",
                    }
                )
            )
        )
        or 0
    )
    counts = {
        "agent_calls": len(calls),
        "attempts": len(attempt_rows),
        "target_executions": executed,
        "findings": finding_count,
        "confirmed_observations": len(confirmed_attempt_ids),
        "regression_replays": int(session.scalar(select(func.count(RegressionReplay.id))) or 0),
        "human_reviewed_findings": reviewed_findings,
    }
    for lane, costs in lane_costs.items():
        counts[lane] = len(costs)

    return CostEvidenceSnapshotV1(
        generated_at=datetime.now(UTC),
        source_labels=[source_label],
        pricing_source=pricing_source,
        pricing_verified_at=pricing_verified_at,
        agent_calls=calls,
        spend_by_source=[
            SourceSpendV1(
                source_label=source_label,
                calls=len(calls),
                input_tokens=sum(call.input_tokens for call in calls),
                output_tokens=sum(call.output_tokens for call in calls),
                estimated_cost_usd=total_cost,
            )
        ],
        total_agentforge_model_cost_usd=total_cost,
        overnight_campaign_ids=sorted(overnight_ids),
        overnight_campaign_cost_usd=overnight_cost,
        target_executions=executed,
        target_inference_cost_status=(
            f"UNMEASURED: {executed} target executions observed without target-provider usage."
        ),
        infrastructure_invoice_status=(
            "UNMEASURED: Railway, PostgreSQL, and Langfuse invoices were not available."
        ),
        provider_billing_reconciliation_status=(
            "UNMEASURED: no project-scoped provider billing export was available."
        ),
        codex_subscription_status="UNMEASURED: Codex subscription usage is outside AgentRun.",
        developer_labor_status="UNMEASURED: developer labor was not time-tracked.",
        unit_economics=sorted(unit_economics, key=lambda item: item.unit),
        database_evidence_bytes=db_bytes,
        artifact_bytes=_artifact_bytes(artifact_roots or []),
        browser_seconds=browser_ms / Decimal("1000"),
        average_target_latency_ms=_average(target_latencies),
        retry_rate=(Decimal(retries) / Decimal(total_sdk_attempts) if total_sdk_attempts else None),
        human_review_rate=(
            Decimal(reviewed_findings) / Decimal(finding_count) if finding_count else None
        ),
        counts=counts,
    )


def merge_cost_evidence(
    snapshots: list[CostEvidenceSnapshotV1],
) -> CostEvidenceSnapshotV1:
    """Merge local/production snapshots and deduplicate copied AgentRun UUIDs."""

    if not snapshots:
        raise ValueError("at least one evidence snapshot is required")
    unique_calls: dict[str, AgentCallEvidenceV1] = {}
    for snapshot in snapshots:
        for call in snapshot.agent_calls:
            unique_calls.setdefault(call.agent_run_id, call)
    calls = sorted(unique_calls.values(), key=lambda item: (item.source_label, item.agent_run_id))
    spend: dict[str, list[AgentCallEvidenceV1]] = defaultdict(list)
    for call in calls:
        spend[call.source_label].append(call)
    overnight_ids = sorted(
        {campaign_id for item in snapshots for campaign_id in item.overnight_campaign_ids}
    )
    total_cost = sum((item.estimated_cost_usd for item in calls), Decimal("0"))
    base = snapshots[-1]
    return base.model_copy(
        update={
            "generated_at": datetime.now(UTC),
            "source_labels": sorted(spend),
            "agent_calls": calls,
            "spend_by_source": [
                SourceSpendV1(
                    source_label=source,
                    calls=len(source_calls),
                    input_tokens=sum(item.input_tokens for item in source_calls),
                    output_tokens=sum(item.output_tokens for item in source_calls),
                    estimated_cost_usd=sum(
                        (item.estimated_cost_usd for item in source_calls),
                        Decimal("0"),
                    ),
                )
                for source, source_calls in sorted(spend.items())
            ],
            "total_agentforge_model_cost_usd": total_cost,
            "overnight_campaign_ids": overnight_ids,
            "overnight_campaign_cost_usd": sum(
                (item.estimated_cost_usd for item in calls if item.campaign_id in overnight_ids),
                Decimal("0"),
            ),
            "database_evidence_bytes": sum(item.database_evidence_bytes for item in snapshots),
            "artifact_bytes": sum(item.artifact_bytes for item in snapshots),
        }
    )


def project_costs(
    assumptions: CostModelAssumptionsV1,
) -> list[CostProjectionV1]:
    projections: list[CostProjectionV1] = []
    gb = Decimal(1024**3)
    for scenario_name, scenario in assumptions.scenarios.items():
        for scale in assumptions.scales:
            runs = Decimal(scale)
            workload_counts = {key: runs * share for key, share in scenario.workload_mix.items()}
            attacker = sum(
                (
                    workload_counts[key] * scenario.attacker_model_usd[key]
                    for key in workload_counts
                ),
                Decimal("0"),
            )
            target_calls = sum(
                (
                    workload_counts[key] * scenario.target_model_calls[key]
                    for key in workload_counts
                ),
                Decimal("0"),
            )
            target = target_calls * scenario.target_model_usd_per_call
            retries = (attacker + target) * scenario.retry_and_escalation_rate
            browser_runs = runs * scenario.browser_share
            api_runs = runs - browser_runs
            worker_hours = (
                browser_runs * scenario.browser_seconds_per_execution
                + api_runs * scenario.api_seconds_per_execution
            ) / Decimal(3600)
            workers = worker_hours * scenario.worker_usd_per_vcpu_hour
            database = (
                runs
                * Decimal(scenario.database_bytes_per_run)
                / gb
                * assumptions.storage["database_usd_per_gb_month"]
                * assumptions.storage["retention_months"]
            )
            artifacts = (
                runs
                * Decimal(scenario.artifact_bytes_per_run)
                / gb
                * assumptions.storage["artifact_usd_per_gb_month"]
                * assumptions.storage["retention_months"]
            )
            telemetry = (
                runs
                * scenario.telemetry_events_per_run
                / Decimal(1000)
                * assumptions.telemetry["usd_per_1000_events"]
            )
            human = (
                runs
                * scenario.human_review_rate
                * scenario.human_review_minutes
                / Decimal(60)
                * assumptions.labor["reviewer_hourly_usd"]
            )
            fixed = scenario.fixed_platform_usd_by_scale[scale]
            components = {
                "attacker_models": attacker,
                "target_models": target,
                "retries_and_escalations": retries,
                "browser_and_api_workers": workers,
                "postgresql": database,
                "artifact_storage": artifacts,
                "telemetry": telemetry,
                "fixed_platform": fixed,
                "human_triage": human,
            }
            projections.append(
                CostProjectionV1(
                    scenario=scenario_name,
                    runs=scale,
                    workload_counts=workload_counts,
                    line_items=ProjectionLineItemsV1(
                        **components,
                        total=sum(components.values(), Decimal("0")),
                    ),
                )
            )
    return projections


def _money(value: Decimal | None) -> str:
    return "UNMEASURED" if value is None else f"${value.quantize(Decimal('0.000001'))}"


def render_cost_analysis(
    evidence: CostEvidenceSnapshotV1,
    assumptions: CostModelAssumptionsV1,
    *,
    pricing_models: dict[str, dict[str, Decimal | float | int]],
) -> str:
    projections = project_costs(assumptions)
    lines = [
        "# AI Cost Analysis",
        "",
        (
            f"Generated from durable evidence at `{evidence.generated_at.isoformat()}` using "
            f"assumptions schema `{assumptions.schema_version}`. One projected run means: "
            f"{assumptions.run_definition}"
        ),
        "",
        "## 1. Actual development and testing spend",
        "",
        "| Source | Unique AgentForge calls | Input tokens | Output tokens | Configured cost |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    lines.extend(
        (
            f"| {item.source_label} | {item.calls:,} | {item.input_tokens:,} | "
            f"{item.output_tokens:,} | {_money(item.estimated_cost_usd)} |"
        )
        for item in evidence.spend_by_source
    )
    lines.extend(
        [
            (
                f"| **Deduplicated total** | **{len(evidence.agent_calls):,}** | "
                f"**{sum(item.input_tokens for item in evidence.agent_calls):,}** | "
                f"**{sum(item.output_tokens for item in evidence.agent_calls):,}** | "
                f"**{_money(evidence.total_agentforge_model_cost_usd)}** |"
            ),
            "",
            (
                f"Final overnight campaign spend: "
                f"`{_money(evidence.overnight_campaign_cost_usd)}` across "
                f"{len(evidence.overnight_campaign_ids)} explicitly selected campaigns."
            ),
            "",
            (
                "- Provider billing reconciliation — "
                f"**{evidence.provider_billing_reconciliation_status}**"
            ),
            f"- Target OpenEMR model inference — **{evidence.target_inference_cost_status}**",
            f"- Railway/Langfuse/infrastructure — **{evidence.infrastructure_invoice_status}**",
            f"- Codex subscription usage — **{evidence.codex_subscription_status}**",
            f"- Developer labor — **{evidence.developer_labor_status}**",
            "",
            "### Versioned pricing inputs",
            "",
            (
                f"Verified `{evidence.pricing_verified_at}` from "
                f"[the official OpenAI API pricing page]({evidence.pricing_source})."
            ),
            "",
            "| Model | Input / 1M | Cached input / 1M | Cache write / 1M | Output / 1M |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for model, prices in pricing_models.items():
        lines.append(
            f"| `{model}` | ${prices['input']} | ${prices['cached_input']} | "
            f"${prices['cache_write']} | ${prices['output']} |"
        )
    lines.extend(
        [
            "",
            "## 2. Observed unit economics",
            "",
            "| Unit | Samples | Measured AgentForge model cost | Interpretation |",
            "| --- | ---: | ---: | --- |",
        ]
    )
    lines.extend(
        f"| {item.unit.replace('_', ' ')} | {item.samples} | "
        f"{_money(item.measured_cost_usd)} | {item.note} |"
        for item in evidence.unit_economics
    )
    lines.extend(
        [
            "",
            f"- Database evidence payload: `{evidence.database_evidence_bytes:,}` bytes.",
            f"- Artifact files: `{evidence.artifact_bytes:,}` bytes.",
            f"- Browser time: `{evidence.browser_seconds}` seconds.",
            (
                "- Mean target latency: "
                + (
                    f"`{evidence.average_target_latency_ms}` ms."
                    if evidence.average_target_latency_ms is not None
                    else "**UNMEASURED**."
                )
            ),
            (
                "- Bounded model retry rate: "
                + (
                    f"`{(evidence.retry_rate * 100).quantize(Decimal('0.01'))}%`."
                    if evidence.retry_rate is not None
                    else "**UNMEASURED**."
                )
            ),
            (
                "- Human-review rate: "
                + (
                    f"`{(evidence.human_review_rate * 100).quantize(Decimal('0.01'))}%`."
                    if evidence.human_review_rate is not None
                    else "**UNMEASURED**."
                )
            ),
            "",
            "## 3. Production projections at 100 / 1K / 10K / 100K runs",
            "",
            (
                "These projections use workload mixes and include attacker models, estimated "
                "target inference, retries/escalations, browser/API workers, PostgreSQL, "
                "artifact storage, telemetry, fixed platform floors, and human triage. "
                "They are not cost-per-token multiplied by run count."
            ),
            "",
            "| Scenario | Runs | Attacker models | Target models | Retries | Workers | "
            "PostgreSQL | Artifacts | Telemetry | Fixed | Human triage | Total |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for projection in projections:
        item = projection.line_items
        lines.append(
            f"| {projection.scenario} | {projection.runs:,} | {_money(item.attacker_models)} | "
            f"{_money(item.target_models)} | {_money(item.retries_and_escalations)} | "
            f"{_money(item.browser_and_api_workers)} | {_money(item.postgresql)} | "
            f"{_money(item.artifact_storage)} | {_money(item.telemetry)} | "
            f"{_money(item.fixed_platform)} | {_money(item.human_triage)} | "
            f"**{_money(item.total)}** |"
        )
    lines.extend(
        [
            "",
            "### Sensitivities",
            "",
            (
                "- Finding yield changes Documentation calls, regression-case creation, "
                "and human triage."
            ),
            (
                "- Replay multiplier changes target/model work non-linearly; a secure pass "
                "requires two valid consistent replays."
            ),
            "- Retention changes PostgreSQL and object-storage totals independently.",
            "- Concurrency changes worker floors and target-aware backpressure requirements.",
            "- Target inference is **ESTIMATED** until OpenEMR exposes provider usage and billing.",
            "",
            "## 4. Architecture required at each scale",
            "",
            "- **100 runs:** one worker, direct measurement, and complete evidence retention.",
            "- **1K runs:** target-aware backpressure, prompt-cache analysis, retention jobs, and "
            "finding deduplication.",
            "- **10K runs:** split API/browser/model worker pools, queue quotas, object storage, "
            "trace sampling, selective human review, and latency-insensitive Batch/Flex evaluation "
            "where semantics permit.",
            (
                "- **100K runs:** distributed scheduling, target/tenant quotas, calibrated "
                "smaller-model routing with Judge escalation, provider failover, partitioned "
                "audit tables, formal retention, and triage SLOs."
            ),
            "",
            "## Reproducibility and limitations",
            "",
            (
                "The evidence JSON contains only identifiers, usage counters, latency, and cost; "
                "it excludes prompts, outputs, credentials, and patient data. AgentRun UUIDs are "
                "deduplicated when local and production snapshots are merged. Pricing and all "
                "non-model inputs are versioned configuration. `UNMEASURED` and `ESTIMATED` labels "
                "are intentionally retained instead of presenting unsupported precision."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def evidence_digest(snapshot: CostEvidenceSnapshotV1) -> str:
    payload = snapshot.model_dump(mode="json", exclude={"generated_at"})
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def load_cost_evidence_snapshot(path: Path) -> CostEvidenceSnapshotV1:
    """Load a generated snapshot and verify its optional integrity digest."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    supplied_digest = payload.pop("evidence_digest", None)
    snapshot = CostEvidenceSnapshotV1.model_validate(payload)
    if supplied_digest is not None and (
        not isinstance(supplied_digest, str)
        or not hmac.compare_digest(supplied_digest, evidence_digest(snapshot))
    ):
        raise ValueError(f"cost evidence digest mismatch: {path}")
    return snapshot


__all__ = [
    "CostEvidenceSnapshotV1",
    "CostModelAssumptionsV1",
    "CostProjectionV1",
    "collect_cost_evidence",
    "evidence_digest",
    "load_cost_evidence_snapshot",
    "load_cost_assumptions",
    "merge_cost_evidence",
    "project_costs",
    "render_cost_analysis",
]
