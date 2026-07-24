"""Agent-driven campaign controller with deterministic safety plumbing only.

The Orchestrator chooses an objective, the Attack Generator creates the exact
sequence, the runner returns raw structured observations, and the Judge alone
classifies their security meaning. Deterministic code validates scope, executes
authorized actions, persists lifecycle state, and enforces campaign ceilings.
"""

from __future__ import annotations

import json
import re
import uuid
from collections import Counter
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Protocol

import httpx
from sqlalchemy import func, select

from agentforge.agents.base import AgentInvocationResult
from agentforge.contracts.v1 import (
    ActionTypeV1,
    AttackEvidenceV1,
    AttackTechniqueV2,
    CampaignObjectiveV1,
    ConfirmedFindingSnapshotV1,
    DocumentationRequestV1,
    EstimatedCostClassV1,
    ExecutionSurfaceV2,
    FindingStatusV1,
    FixValidationResultV1,
    JudgeVerdictKindV1,
    JudgeVerdictV1,
    OrchestratorDecisionV2,
    PriorAttemptOutcomeV1,
    PriorAttemptSummaryV1,
    ProposedAttackV1,
    RemainingBudgetAndLimitsV1,
    RequestedActionV1,
    SeverityV1,
    SurfaceCapabilityFactV2,
    VulnerabilityReportV1,
)
from agentforge.contracts.v1.common import utc_now
from agentforge.evaluation import (
    JudgeRubricV1,
    TaxonomyV1,
    expand_fuzz_plan,
    load_fuzz_corpus,
    load_seed_cases,
    minimize_confirmed_fuzz_variant,
)
from agentforge.evidence import (
    EvidenceArtifactError,
    EvidenceArtifactStore,
    EvidenceArtifactTooLarge,
)
from agentforge.observability import (
    AgentForgeMetrics,
    LangfuseTelemetry,
    PlatformObservabilityService,
    metrics,
)
from agentforge.orchestration.execution_gate import (
    ApprovedFixtureV1,
    CampaignExecutionContextV1,
    GateLimitsV1,
    GateRejectionV1,
    ValidatedAttackV1,
    validate_attack,
)
from agentforge.orchestration.objectives import (
    build_objective,
    canonical_hash,
    endpoint_bindings,
    surface_capability_facts,
    validate_objective_choice_v2,
)
from agentforge.orchestration.stopping import CampaignStopStateV1, evaluate_stopping
from agentforge.orchestration.worker import CampaignProcessResult
from agentforge.persistence import Database
from agentforge.persistence.models import (
    AgentRun,
    AttackAttempt,
    Campaign,
    Finding,
    JudgeVerdict,
    RegressionCase,
    RegressionReplay,
    RegressionResult,
    RegressionRun,
    TargetVersion,
)
from agentforge.persistence.repositories import (
    FindingRepository,
    PlatformEventRepository,
    RegressionCaseRepository,
    RegressionRunRepository,
    ReportRepository,
)
from agentforge.regression import (
    RegressionCaseV2,
    RegressionResultV1,
    aggregate_regression_replays,
    build_regression_case,
    build_regression_judge_payload,
    evaluate_regression,
)
from agentforge.reports import (
    create_report_lifecycle_version,
    export_stored_report,
    render_vulnerability_report,
)
from agentforge.runners import CompositeAttackRunner
from agentforge.runners.base import TargetExecutionContext
from agentforge.security.redaction import redact
from agentforge.settings import Settings
from agentforge.target import LoadedTargetProfile
from agentforge.target.auth import credentials_from_settings
from agentforge.target.fixtures import load_approved_fixture_authorizations
from agentforge.target.profile import ResolvedTargetAlias
from agentforge.target.version import (
    UNRESOLVED_TARGET_VERSIONS,
    DiscoveredTargetVersion,
    discover_target_version,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
_HEX_SHA = re.compile(r"^[0-9a-fA-F]{7,64}$")
_CONTROLLER_PROMPT_VERSION = "controller-policy-v3-2026-07-24"
_UPLOAD_SURFACE_ID = "clinical_document_upload"
_UPLOAD_STAGE_ENDPOINT_ID = "document_stage"
_UPLOAD_REJECT_ENDPOINT_ID = "document_reject"
_MAX_PLANNING_REJECTIONS = 12

PROPOSAL_AGENT_GENERATED = "agent_generated"
PROPOSAL_AGENT_GENERATED_MUTATION = "agent_generated_mutation"
OBJECTIVE_ORCHESTRATOR_SELECTED = "orchestrator_selected"
FIXED_REGRESSION_CASE = "fixed_regression_case"
FUZZ_MINIMIZATION_PROVENANCE = "agent_fuzz_minimization"
_FUZZ_MINIMIZATION_PROMPT_VERSION = "deterministic-fuzz-minimization-v1"


class VersionDiscoverer(Protocol):
    async def __call__(
        self,
        loaded_profile: LoadedTargetProfile,
        target_alias: ResolvedTargetAlias,
    ) -> DiscoveredTargetVersion: ...


class _EvidencePersistenceFailure(RuntimeError):
    def __init__(self, *, code: str, message: str, retryable: bool) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


def _project_path(path: Path) -> Path:
    return path if path.is_absolute() else PROJECT_ROOT / path


def _decimal(value: float | Decimal | int) -> Decimal:
    return Decimal(str(value))


def _json(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _validation_diagnostics(exc: Exception) -> list[dict[str, str]]:
    errors = getattr(exc, "errors", None)
    if not callable(errors):
        return []
    return [
        {
            "location": ".".join(str(part) for part in item.get("loc", ())),
            "type": str(item.get("type", "validation_error")),
        }
        for item in errors(include_url=False, include_input=False)[:10]
    ]


async def _discover_version(
    loaded_profile: LoadedTargetProfile,
    target_alias: ResolvedTargetAlias,
) -> DiscoveredTargetVersion:
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(30.0),
        verify=target_alias.verify_tls,
        follow_redirects=False,
    ) as client:
        return await discover_target_version(
            client=client,
            profile=loaded_profile.profile,
            target_alias=target_alias,
        )


class CampaignController:
    """Run one claimed campaign with agents owning every semantic decision."""

    def __init__(
        self,
        *,
        database: Database,
        settings: Settings,
        loaded_profile: LoadedTargetProfile,
        taxonomy: TaxonomyV1,
        rubric: JudgeRubricV1,
        orchestrator: Any,
        attack_generator: Any,
        judge: Any,
        documentation: Any,
        runner: Any,
        telemetry: LangfuseTelemetry | None = None,
        metric_registry: AgentForgeMetrics | None = None,
        version_discoverer: VersionDiscoverer = _discover_version,
        repository_root: Path = PROJECT_ROOT,
        evidence_store: EvidenceArtifactStore | None = None,
    ) -> None:
        self.database = database
        self.settings = settings
        self.loaded_profile = loaded_profile
        self.taxonomy = taxonomy
        self.rubric = rubric
        self.orchestrator = orchestrator
        self.attack_generator = attack_generator
        self.judge = judge
        self.documentation = documentation
        self.runner = runner
        self.telemetry = telemetry
        self.metrics = metric_registry or metrics
        self.version_discoverer = version_discoverer
        self.repository_root = repository_root.resolve()
        artifacts_dir = (
            settings.artifacts_dir
            if settings.artifacts_dir.is_absolute()
            else self.repository_root / settings.artifacts_dir
        )
        self.evidence_store = evidence_store or EvidenceArtifactStore(artifacts_dir / "evidence")
        self.rubric_hash = canonical_hash(rubric.model_dump(mode="json"))
        self.allowed_categories = {
            category.id: [subcategory.id for subcategory in category.subcategories]
            for category in taxonomy.categories
        }
        self.seed_cases = load_seed_cases(PROJECT_ROOT / "evals" / "seed-cases")
        self.fuzz_corpus = load_fuzz_corpus(PROJECT_ROOT / "config" / "fuzz-corpus.yaml")
        (
            self.approved_fixture_catalog_version,
            self.approved_fixtures,
        ) = load_approved_fixture_authorizations(PROJECT_ROOT / "config" / "approved-fixtures.yaml")

    def _commit_and_export_evidence(
        self,
        session: Any,
        *,
        campaign: Campaign,
        attempt: AttackAttempt,
        evidence: AttackEvidenceV1,
    ) -> None:
        try:
            prepared = self.evidence_store.prepare(evidence)
        except EvidenceArtifactTooLarge as exc:
            self._fail_attempt(
                attempt,
                stage="evidence",
                code="evidence_too_large",
                retryable=False,
            )
            session.commit()
            raise _EvidencePersistenceFailure(
                code="evidence_too_large",
                message="runner evidence exceeded the 5 MiB persistence ceiling",
                retryable=False,
            ) from exc
        except EvidenceArtifactError as exc:
            self._fail_attempt(
                attempt,
                stage="evidence",
                code="evidence_integrity_failed",
                retryable=False,
            )
            session.commit()
            raise _EvidencePersistenceFailure(
                code="evidence_integrity_failed",
                message="runner evidence failed canonical integrity validation",
                retryable=False,
            ) from exc

        attempt.executed_sequence = {
            "actions": [item.model_dump(mode="json") for item in evidence.executed_action_sequence]
        }
        attempt.evidence_payload = prepared.payload
        attempt.evidence_hash = evidence.evidence_hash
        attempt.latency_ms = round(evidence.total_latency_ms)
        attempt.langfuse_trace_id = evidence.langfuse_trace_id
        session.commit()

        try:
            self.evidence_store.export(prepared)
        except Exception as exc:
            self._fail_attempt(
                attempt,
                stage="evidence",
                code="evidence_export_failed",
                retryable=True,
            )
            session.commit()
            raise _EvidencePersistenceFailure(
                code="evidence_export_failed",
                message="database evidence was saved but its verified JSON export failed",
                retryable=True,
            ) from exc

    async def process(self, campaign_id: uuid.UUID) -> CampaignProcessResult:
        with self.database.session_factory() as session:
            campaign = session.get(Campaign, campaign_id)
            if campaign is None:
                return CampaignProcessResult(
                    status="failed",
                    sanitized_error={
                        "code": "campaign_not_found",
                        "message": "campaign was not found",
                    },
                )
            if campaign.started_at is None:
                campaign.started_at = utc_now()
                campaign.status = "running"
                session.commit()
            try:
                target_alias = self.loaded_profile.resolve_alias(
                    campaign.target_alias,
                    self.settings,
                )
                discovered = await self.version_discoverer(
                    self.loaded_profile,
                    target_alias,
                )
            except Exception as exc:
                return self._failed_result(
                    campaign,
                    code="target_version_discovery_failed",
                    message="approved target health/version discovery failed",
                    error_type=type(exc).__name__,
                    retryable=True,
                )
            campaign.target_version = discovered.version
            self._record_target_version(session, campaign, discovered)
            session.commit()
            campaign_type = campaign.campaign_type
            category = campaign.category_scope
            target_version = campaign.target_version
            target_alias_name = campaign.target_alias

        scope = (
            self.telemetry.campaign(
                campaign_id=str(campaign_id),
                campaign_type=campaign_type,
                category=category,
                target_version=target_version,
                input={"target_alias": target_alias_name, "bounded": True},
            )
            if self.telemetry is not None
            else nullcontext(None)
        )
        with scope as observation:
            try:
                if campaign_type == "regression":
                    result = await self._process_regression(campaign_id, target_alias)
                else:
                    result = await self._process_discovery(campaign_id, target_alias)
            except Exception as exc:
                with self.database.session_factory() as session:
                    campaign = session.get(Campaign, campaign_id)
                    for attempt in session.scalars(
                        select(AttackAttempt)
                        .where(AttackAttempt.campaign_id == campaign_id)
                        .where(AttackAttempt.state.in_({"pending", "running"}))
                    ):
                        self._fail_attempt(
                            attempt,
                            stage="controller",
                            code="controller_workflow_failed",
                            retryable=True,
                        )
                    session.commit()
                    result = self._failed_result(
                        campaign,
                        code="controller_workflow_failed",
                        message="campaign workflow failed before a terminal result",
                        error_type=type(exc).__name__,
                        validation_errors=_validation_diagnostics(exc),
                        retryable=True,
                    )
            if observation is not None:
                observation.update(
                    output={
                        "status": result.status,
                        "actual_cost_usd": str(result.actual_cost_usd),
                    }
                )
            return result

    @staticmethod
    def _failed_result(
        campaign: Campaign | None,
        *,
        code: str,
        message: str,
        error_type: str | None = None,
        validation_errors: list[dict[str, str]] | None = None,
        retryable: bool,
    ) -> CampaignProcessResult:
        error: dict[str, Any] = {
            "code": code,
            "message": message,
            "retryable": retryable,
        }
        if error_type is not None:
            error["type"] = error_type
        if validation_errors:
            error["validation_errors"] = validation_errors
        return CampaignProcessResult(
            status="failed",
            actual_cost_usd=campaign.actual_cost_usd if campaign is not None else Decimal("0"),
            sanitized_error=redact(error),
        )

    def _record_target_version(
        self,
        session: Any,
        campaign: Campaign,
        discovered: DiscoveredTargetVersion,
    ) -> None:
        label = f"{campaign.target_alias}:{discovered.version}"
        target = session.scalar(select(TargetVersion).where(TargetVersion.version_label == label))
        metadata = {
            "version_endpoint_id": discovered.endpoint_id,
            "version_status_code": discovered.status_code,
            "authorized_scope": "synthetic-only",
        }
        if target is None:
            session.add(
                TargetVersion(
                    environment=self.settings.environment,
                    version_label=label,
                    git_sha=(
                        discovered.version if _HEX_SHA.fullmatch(discovered.version) else None
                    ),
                    deployment_id=None,
                    base_url_alias=campaign.target_alias,
                    target_profile_hash=self.loaded_profile.profile_hash,
                    metadata_json=metadata,
                )
            )
        else:
            target.target_profile_hash = self.loaded_profile.profile_hash
            target.metadata_json = metadata

    def _persist_agent_result(
        self,
        session: Any,
        *,
        campaign: Campaign,
        result: AgentInvocationResult[Any],
        attempt: AttackAttempt | None = None,
        finding: Finding | None = None,
        status: str | None = None,
        typed_error: dict[str, Any] | None = None,
        input_payload: Any | None = None,
    ) -> AgentRun:
        run_status = status or ("succeeded" if result.succeeded else "failed")
        run = AgentRun(
            campaign_id=campaign.id,
            attempt_id=attempt.id if attempt is not None else None,
            finding_id=finding.id if finding is not None else None,
            role=result.role,
            prompt_version=result.prompt_version,
            model=result.model,
            status=run_status,
            input_tokens=result.usage.tokens.input_tokens,
            output_tokens=result.usage.tokens.output_tokens,
            sdk_attempts=result.sdk_attempts,
            estimated_cost_usd=_decimal(result.estimated_cost_usd),
            latency_ms=round(result.latency_ms),
            langfuse_trace_id=result.langfuse_trace_id,
            input_payload=(redact(_json(input_payload)) if input_payload is not None else None),
            output_payload=redact(_json(result.output)) if result.output is not None else None,
            typed_error=redact(typed_error if typed_error is not None else _json(result.error))
            if typed_error is not None or result.error is not None
            else None,
        )
        session.add(run)
        PlatformEventRepository(session).record(
            event_type="agent_run",
            actor=f"agentforge:{result.role}",
            campaign_id=campaign.id,
            attempt_id=attempt.id if attempt is not None else None,
            finding_id=finding.id if finding is not None else None,
            role=result.role,
            model=result.model,
            prompt_version=result.prompt_version,
            trace_id=result.langfuse_trace_id,
            latency_ms=round(result.latency_ms),
            cost_usd=_decimal(result.estimated_cost_usd),
            details={
                "status": run_status,
                "sdk_attempts": result.sdk_attempts,
                "output": redact(_json(result.output)) if result.output is not None else None,
                "typed_error": redact(
                    typed_error if typed_error is not None else _json(result.error)
                )
                if typed_error is not None or result.error is not None
                else None,
            },
        )
        campaign.actual_cost_usd += _decimal(result.estimated_cost_usd)
        if attempt is not None:
            attempt.input_tokens += result.usage.tokens.input_tokens
            attempt.output_tokens += result.usage.tokens.output_tokens
            attempt.estimated_cost_usd += _decimal(result.estimated_cost_usd)
            if result.langfuse_trace_id:
                attempt.langfuse_trace_id = result.langfuse_trace_id
        self.metrics.agent_latency_seconds.labels(
            role=result.role,
            model=result.model,
            status=run_status,
        ).observe(result.latency_ms / 1_000)
        for token_type, count in (
            ("input", result.usage.tokens.input_tokens),
            ("cached_input", result.usage.tokens.cached_input_tokens),
            ("output", result.usage.tokens.output_tokens),
        ):
            self.metrics.agent_tokens_total.labels(
                role=result.role,
                model=result.model,
                token_type=token_type,
            ).inc(count)
        self.metrics.agent_estimated_cost_usd_total.labels(
            role=result.role,
            model=result.model,
        ).inc(result.estimated_cost_usd)
        session.flush()
        return run

    def _global_cost(self, session: Any) -> Decimal:
        value = session.scalar(select(func.coalesce(func.sum(AgentRun.estimated_cost_usd), 0)))
        return _decimal(value or 0)

    @staticmethod
    def _planning_rejection_limit(campaign: Campaign) -> int:
        return min(_MAX_PLANNING_REJECTIONS, max(3, campaign.max_attempts))

    def _planning_rejection_result(
        self,
        session: Any,
        *,
        campaign: Campaign,
        stage: str,
        code: str,
    ) -> CampaignProcessResult | None:
        """Record a bounded replan request without consuming a target attempt."""

        rejection_count = int(
            session.scalar(
                select(func.count())
                .select_from(AgentRun)
                .where(AgentRun.campaign_id == campaign.id)
                .where(AgentRun.role == "attack_generator")
                .where(AgentRun.status == "rejected")
            )
            or 0
        )
        rejection_limit = self._planning_rejection_limit(campaign)
        PlatformEventRepository(session).record(
            event_type="attack_plan_rejected",
            actor="agentforge:controller",
            campaign_id=campaign.id,
            role="attack_generator",
            details={
                "stage": stage,
                "code": code,
                "rejection_count": rejection_count,
                "rejection_limit": rejection_limit,
                "target_attempt_consumed": False,
                "will_replan": rejection_count < rejection_limit,
            },
        )
        session.commit()
        if rejection_count < rejection_limit:
            return None
        return self._failed_result(
            campaign,
            code="planning_rejection_limit_reached",
            message=(
                "Attack Generator proposals reached the bounded pre-execution "
                f"rejection limit after {code}"
            ),
            retryable=True,
        )

    @staticmethod
    def _planning_rejection_facts(
        session: Any,
        *,
        campaign_id: uuid.UUID,
    ) -> list[dict[str, Any]]:
        """Return bounded raw validation feedback for the next model replan."""

        runs = list(
            session.scalars(
                select(AgentRun)
                .where(AgentRun.campaign_id == campaign_id)
                .where(AgentRun.role == "attack_generator")
                .where(AgentRun.status == "rejected")
                .order_by(AgentRun.created_at.desc())
                .limit(3)
            )
        )
        facts: list[dict[str, Any]] = []
        for run in runs:
            error = run.typed_error or {}
            facts.append(
                {
                    "stage": str(error.get("stage", "unknown"))[:64],
                    "code": str(error.get("code", "unknown"))[:128],
                    "detail": str(error.get("detail", "No additional validation detail."))[:512],
                }
            )
        return facts

    def _projected_regression_reserve(self, session: Any) -> Decimal:
        active_cases = int(
            session.scalar(
                select(func.count(RegressionCase.id)).where(RegressionCase.active.is_(True))
            )
            or 0
        )
        observed_replay_cost = _decimal(
            session.scalar(
                select(func.avg(RegressionReplay.estimated_cost_usd)).where(
                    RegressionReplay.estimated_cost_usd > 0
                )
            )
            or 0
        )
        if observed_replay_cost == 0:
            observed_replay_cost = _decimal(
                session.scalar(
                    select(func.avg(AgentRun.estimated_cost_usd)).where(
                        AgentRun.role == "judge",
                        AgentRun.status == "succeeded",
                        AgentRun.estimated_cost_usd > 0,
                    )
                )
                or 0
            )
        projected_suite_cost = Decimal(active_cases * 2) * observed_replay_cost
        configured_minimum = _decimal(self.settings.regression_reserve_min_usd)
        return max(
            configured_minimum,
            projected_suite_cost * _decimal(self.settings.regression_reserve_multiplier),
        )

    @staticmethod
    def _agent_call_reservation(*agents: Any) -> Decimal:
        """Sum declared worst-case call costs for provider-backed adapters."""

        reservation = Decimal("0")
        for agent in agents:
            try:
                configured = getattr(agent, "maximum_invocation_cost_usd", 0)
                reservation += _decimal(configured)
            except (TypeError, ValueError):
                continue
        return reservation

    def _global_call_capacity(
        self,
        session: Any,
        *agents: Any,
    ) -> tuple[bool, Decimal, Decimal]:
        current = self._global_cost(session)
        call_reservation = self._agent_call_reservation(*agents)
        ceiling = _decimal(self.settings.global_max_cost_usd)
        return current + call_reservation <= ceiling, current, call_reservation

    def _discovery_cost_capacity(
        self,
        session: Any,
        *agents: Any,
        additional_cost_usd: Decimal = Decimal("0"),
    ) -> tuple[bool, Decimal, Decimal]:
        current = self._global_cost(session)
        reserve = self._projected_regression_reserve(session)
        call_reservation = self._agent_call_reservation(*agents)
        ceiling = _decimal(self.settings.global_max_cost_usd)
        return (
            current + reserve + call_reservation + additional_cost_usd <= ceiling,
            current,
            reserve,
        )

    def _stop_decision(self, session: Any, campaign: Campaign):
        session.refresh(campaign)
        started = _aware(campaign.started_at or campaign.created_at)
        return evaluate_stopping(
            CampaignStopStateV1(
                attempts_completed=campaign.actual_attempts,
                max_attempts=campaign.max_attempts,
                campaign_started_at=started,
                evaluated_at=utc_now(),
                max_duration_seconds=campaign.max_duration_seconds,
                actual_cost_usd=campaign.actual_cost_usd,
                max_cost_usd=campaign.max_cost_usd,
                cancellation_requested=campaign.cancellation_requested,
                cleanup_failed=False,
            )
        )

    def _limits_result(
        self,
        campaign: Campaign,
        decision: Any,
    ) -> CampaignProcessResult:
        reasons = {reason.value for reason in decision.reasons}
        if "cancellation_requested" in reasons:
            return CampaignProcessResult(
                status="cancelled",
                actual_cost_usd=campaign.actual_cost_usd,
            )
        if "cleanup_failed" in reasons:
            return self._failed_result(
                campaign,
                code="cleanup_failed",
                message="safe cleanup did not complete",
                retryable=False,
            )
        return CampaignProcessResult(
            status="completed",
            actual_cost_usd=campaign.actual_cost_usd,
        )

    def _prior_attempts(
        self,
        session: Any,
        campaign_id: uuid.UUID,
    ) -> list[PriorAttemptSummaryV1]:
        rows = session.execute(
            select(AttackAttempt, JudgeVerdict)
            .outerjoin(JudgeVerdict, JudgeVerdict.attempt_id == AttackAttempt.id)
            .where(AttackAttempt.campaign_id == campaign_id)
            .order_by(AttackAttempt.created_at.desc())
            .limit(20)
        )
        summaries: list[PriorAttemptSummaryV1] = []
        for attempt, verdict in reversed(list(rows)):
            if attempt.sequence_hash is None:
                continue
            if verdict is not None:
                outcome = PriorAttemptOutcomeV1(verdict.verdict)
                summary = verdict.observed_behavior
            else:
                outcome = PriorAttemptOutcomeV1.ERROR
                summary = str((attempt.failure or {}).get("code", "attempt failed"))
            summaries.append(
                PriorAttemptSummaryV1(
                    attempt_id=str(attempt.id),
                    attack_family_id=attempt.attack_family_id,
                    parent_attempt_id=(
                        str(attempt.parent_attempt_id)
                        if attempt.parent_attempt_id is not None
                        else None
                    ),
                    outcome=outcome,
                    summary=summary[:512],
                    sequence_hash=attempt.sequence_hash,
                    evidence_hash=attempt.evidence_hash,
                )
            )
        return summaries

    def _allowed_objectives(self, campaign: Campaign) -> set[tuple[str, str]]:
        """Return neutral in-scope membership; never rank or shortlist it."""

        return {
            (category.id, subcategory.id)
            for category in self.taxonomy.categories
            if campaign.category_scope is None or category.id == campaign.category_scope
            for subcategory in category.subcategories
            if (campaign.subcategory_scope is None or subcategory.id == campaign.subcategory_scope)
        }

    def _surface_capabilities(self) -> list[SurfaceCapabilityFactV2]:
        return surface_capability_facts(self.loaded_profile.profile)

    def _execution_surface_for_actions(self, actions: list[Any]) -> ExecutionSurfaceV2:
        bindings = endpoint_bindings(self.loaded_profile.profile)
        document_purposes = {
            "document_extract",
            "document_validate",
            "document_outcome",
            "upload_stage",
            "upload_status",
            "upload_reject",
            "upload_confirm",
            "staged_document",
        }
        surfaces: set[ExecutionSurfaceV2] = set()
        for action in actions:
            if action.action_type == ActionTypeV1.SEND_CHAT_MESSAGE:
                surfaces.add(ExecutionSurfaceV2.OPENEMR_UI)
            elif action.action_type == ActionTypeV1.UPLOAD_APPROVED_FIXTURE:
                surfaces.add(ExecutionSurfaceV2.STAGED_DOCUMENT)
            elif action.action_type == ActionTypeV1.INVOKE_APPROVED_API_REQUEST:
                binding = bindings.get(action.endpoint_id)
                if binding is None:
                    raise ValueError("saved regression sequence references an unknown endpoint")
                if binding.purpose.value in document_purposes:
                    surfaces.add(ExecutionSurfaceV2.STAGED_DOCUMENT)
                elif binding.surface == "ui":
                    surfaces.add(ExecutionSurfaceV2.OPENEMR_SAME_ORIGIN_API)
                else:
                    surfaces.add(ExecutionSurfaceV2.AGENT_SERVICE_API)
        if not surfaces:
            raise ValueError("saved regression sequence has no target operation")
        return next(iter(surfaces)) if len(surfaces) == 1 else ExecutionSurfaceV2.HYBRID

    def _new_attempt(
        self,
        *,
        attempt_id: uuid.UUID,
        campaign: Campaign,
        objective: CampaignObjectiveV1,
        proposal: ProposedAttackV1,
        prompt_version: str,
        proposal_source: str,
        objective_source: str,
        sequence_hash: str,
        provenance: str | None = None,
        orchestrator_rationale: str | None = None,
        fuzz_variant_id: str | None = None,
        fuzz_variant_index: int | None = None,
        exact_payload_hash: str | None = None,
    ) -> AttackAttempt:
        parent_attempt_id = (
            uuid.UUID(proposal.parent_attempt_id)
            if proposal.parent_attempt_id is not None
            else None
        )
        return AttackAttempt(
            id=attempt_id,
            campaign_id=campaign.id,
            attack_family_id=proposal.attack_family_id,
            parent_attempt_id=parent_attempt_id,
            proposal_source=proposal_source,
            objective_source=objective_source,
            provenance=provenance
            or (
                "agent_fuzz"
                if objective.technique == AttackTechniqueV2.FUZZING
                else "agent_scenario"
            ),
            execution_surface=objective.execution_surface.value,
            technique=objective.technique.value,
            orchestrator_rationale=orchestrator_rationale,
            fuzz_plan=(
                proposal.fuzz_plan.model_dump(mode="json")
                if proposal.fuzz_plan is not None
                else None
            ),
            fuzz_variant_id=fuzz_variant_id,
            fuzz_variant_index=fuzz_variant_index,
            exact_payload_hash=exact_payload_hash,
            sequence_hash=sequence_hash,
            category=proposal.category,
            subcategory=proposal.subcategory,
            owasp_mappings=objective.owasp_mappings.model_dump(mode="json"),
            objective=objective.objective,
            proposed_sequence=proposal.model_dump(mode="json"),
            taxonomy_version=self.taxonomy.taxonomy_version,
            profile_version=self.loaded_profile.profile.profile_version,
            prompt_version=prompt_version,
            state="pending",
            started_at=utc_now(),
        )

    def _gate_context(
        self,
        *,
        campaign: Campaign,
        objective: CampaignObjectiveV1,
        sequence_counts: Counter[str],
        max_sequence_repetitions: int = 1,
        patient_alias: str = "patient_a",
        identity_alias: str = "physician_test",
        expected_role: str = "physician",
    ) -> CampaignExecutionContextV1:
        started = _aware(campaign.started_at or campaign.created_at)
        deadline = started + timedelta(seconds=campaign.max_duration_seconds)
        return CampaignExecutionContextV1(
            campaign_id=str(campaign.id),
            target_alias=campaign.target_alias,
            selected_category=objective.selected_category,
            selected_subcategory=objective.selected_subcategory,
            allowed_category_subcategories=self.allowed_categories,
            current_patient_alias=patient_alias,
            test_identity_alias=identity_alias,
            test_role=expected_role,
            endpoint_bindings=endpoint_bindings(self.loaded_profile.profile),
            chat_endpoint_id="copilot_chat_proxy",
            upload_surface_id=_UPLOAD_SURFACE_ID,
            upload_stage_endpoint_id=_UPLOAD_STAGE_ENDPOINT_ID,
            upload_reject_endpoint_id=_UPLOAD_REJECT_ENDPOINT_ID,
            approved_fixtures={
                fixture_id: ApprovedFixtureV1(
                    fixture_id=authorization.fixture_id,
                    repository_relative_path=authorization.repository_relative_path,
                    document_type=authorization.document_type,
                    extension=Path(authorization.repository_relative_path).suffix,
                    media_type=authorization.media_type,
                    size_bytes=authorization.size_bytes,
                    pages=authorization.pages,
                    sha256=authorization.sha256,
                )
                for fixture_id, authorization in self.approved_fixtures.items()
            },
            max_persistent_writes=(
                1
                if objective.execution_surface
                in {
                    ExecutionSurfaceV2.STAGED_DOCUMENT,
                    ExecutionSurfaceV2.HYBRID,
                }
                else 0
            ),
            retained_synthetic_artifact_allowed=(
                objective.execution_surface
                in {
                    ExecutionSurfaceV2.STAGED_DOCUMENT,
                    ExecutionSurfaceV2.HYBRID,
                }
            ),
            limits=GateLimitsV1(
                max_actions=30,
                max_turns=20,
                max_total_wait_seconds=600,
                max_total_message_bytes=20_000,
                max_upload_count=(
                    1
                    if objective.execution_surface
                    in {
                        ExecutionSurfaceV2.STAGED_DOCUMENT,
                        ExecutionSurfaceV2.HYBRID,
                    }
                    else 0
                ),
                max_total_upload_bytes=(
                    self.settings.max_upload_bytes
                    if objective.execution_surface
                    in {
                        ExecutionSurfaceV2.STAGED_DOCUMENT,
                        ExecutionSurfaceV2.HYBRID,
                    }
                    else 0
                ),
                max_sequence_repetitions=max_sequence_repetitions,
            ),
            campaign_started_at=started,
            campaign_deadline_at=deadline,
            attempted_sequence_counts=dict(sequence_counts),
            cancellation_requested=campaign.cancellation_requested,
            cleanup_succeeded=True,
        )

    def _execution_context(
        self,
        *,
        campaign: Campaign,
        attempt_id: uuid.UUID,
        target_alias: ResolvedTargetAlias,
        validated: ValidatedAttackV1,
    ) -> TargetExecutionContext:
        credentials = credentials_from_settings(
            profile=self.loaded_profile.profile,
            settings=self.settings,
            identity_alias="physician_test",
            expected_role="physician",
        )
        artifacts = self.settings.artifacts_dir
        artifacts_dir = artifacts if artifacts.is_absolute() else self.repository_root / artifacts
        return TargetExecutionContext(
            target_id=self.loaded_profile.profile.name,
            campaign_id=str(campaign.id),
            attempt_id=str(attempt_id),
            target_version=campaign.target_version,
            selected_patient_alias=validated.selected_patient_alias,
            loaded_profile=self.loaded_profile,
            target_alias=target_alias,
            repository_root=self.repository_root,
            artifacts_dir=artifacts_dir,
            credentials=credentials,
            agent_shared_secret=self.settings.target_agent_shared_secret,
            test_user_id=self.settings.target_test_user_id,
            test_auth_username=self.settings.target_test_username,
            synthetic_patient_ids={
                alias: value
                for alias, value in {
                    "patient_a": self.settings.target_test_patient_a_id,
                    "patient_b": self.settings.target_test_patient_b_id,
                }.items()
                if value
            },
            max_upload_bytes=self.settings.max_upload_bytes,
            approved_fixtures=self.approved_fixtures,
        )

    @staticmethod
    def _fail_attempt(
        attempt: AttackAttempt,
        *,
        stage: str,
        code: str,
        retryable: bool,
    ) -> None:
        attempt.state = "failed"
        attempt.failure = {
            "stage": stage,
            "code": code,
            "retryable": retryable,
        }
        attempt.completed_at = utc_now()

    @staticmethod
    def _evidence_matches_execution(
        evidence: AttackEvidenceV1,
        *,
        campaign: Campaign,
        attempt: AttackAttempt,
        validated: ValidatedAttackV1,
    ) -> bool:
        if (
            evidence.campaign_id != str(campaign.id)
            or evidence.attempt_id != str(attempt.id)
            or evidence.target_version != campaign.target_version
        ):
            return False
        expected = validated.proposal.ordered_actions
        executed = evidence.executed_action_sequence
        return len(expected) == len(executed) and all(
            expected_action.model_dump(mode="json")
            == executed_action.action.model_dump(mode="json")
            for expected_action, executed_action in zip(expected, executed, strict=True)
        )

    async def _judge_evidence(
        self,
        *,
        campaign: Campaign,
        attempt: AttackAttempt,
        objective: CampaignObjectiveV1,
        proposal: ProposedAttackV1,
        evidence: AttackEvidenceV1,
        regression_case: RegressionCaseV2 | None = None,
    ) -> tuple[JudgeVerdictV1 | None, AgentInvocationResult[Any], dict[str, Any]]:
        rubric_category = (
            self.rubric.categories[proposal.category].model_dump(mode="json")
            if proposal.category in self.rubric.categories
            else None
        )
        if regression_case is None:
            payload = {
                "objective": objective.model_dump(mode="json"),
                "proposal": proposal.model_dump(mode="json"),
                "evidence": evidence.model_dump(mode="json"),
                "rubric": {
                    "version": self.rubric.rubric_version,
                    "hash": self.rubric_hash,
                    "global_rules": self.rubric.global_rules,
                    "category": rubric_category,
                },
            }
        else:
            payload = build_regression_judge_payload(
                objective=objective,
                proposal=proposal,
                evidence=evidence,
                regression_case=regression_case,
                rubric_version=self.rubric.rubric_version,
                rubric_hash=self.rubric_hash,
                rubric_global_rules=self.rubric.global_rules,
                rubric_category=rubric_category,
            )
        result = await self.judge.invoke(
            payload,
            campaign_id=str(campaign.id),
            attempt_id=str(attempt.id),
            correlation_id=f"judge-{attempt.id}",
            category=proposal.category,
            target_version=evidence.target_version,
            escalate_to_sol=regression_case is not None,
        )
        if result.output is None:
            return None, result, payload
        verdict = JudgeVerdictV1.model_validate(
            {
                **result.output.model_dump(mode="python"),
                "rubric_version": self.rubric.rubric_version,
                "rubric_hash": self.rubric_hash,
            }
        )
        return verdict, result, payload

    def _persist_verdict(
        self,
        session: Any,
        *,
        attempt: AttackAttempt,
        verdict: JudgeVerdictV1,
    ) -> None:
        session.add(
            JudgeVerdict(
                attempt_id=attempt.id,
                verdict=verdict.verdict.value,
                severity=verdict.severity.value,
                exploitability=verdict.exploitability.value,
                confidence=verdict.confidence,
                finding_key=verdict.finding_key,
                violated_invariants=verdict.violated_security_invariants,
                observed_behavior=verdict.observed_behavior,
                expected_behavior=verdict.expected_behavior,
                rubric_hash=self.rubric_hash,
                rubric_version=self.rubric.rubric_version,
            )
        )
        self.metrics.attempts_total.labels(
            category=attempt.category,
            verdict=verdict.verdict.value,
        ).inc()

    def _maybe_replace_minimized_regression_case(
        self,
        session: Any,
        *,
        finding: Finding,
        attempt: AttackAttempt,
        proposal: ProposedAttackV1,
        validated: ValidatedAttackV1,
        evidence: AttackEvidenceV1,
        verdict: JudgeVerdictV1,
    ) -> Any | None:
        """Promote only a separately confirmed, strictly smaller fuzz replay."""

        if (
            attempt.provenance != FUZZ_MINIMIZATION_PROVENANCE
            or finding.current_regression_case_id is None
        ):
            return None
        current = session.get(RegressionCase, finding.current_regression_case_id)
        if current is None:
            return None
        current_payload = json.dumps(
            current.ordered_sequence,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        candidate_actions = [action.model_dump(mode="json") for action in proposal.ordered_actions]
        candidate_payload = json.dumps(
            candidate_actions,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        if len(candidate_payload) >= len(current_payload):
            PlatformEventRepository(session).record(
                event_type="fuzz_minimization_not_promoted",
                actor="agentforge:fuzz_minimizer",
                campaign_id=attempt.campaign_id,
                attempt_id=attempt.id,
                finding_id=finding.id,
                details={
                    "reason": "candidate_not_smaller_than_active_regression_case",
                    "candidate_payload_bytes": len(candidate_payload),
                    "active_payload_bytes": len(current_payload),
                },
            )
            return None
        try:
            with session.begin_nested():
                previous_report = ReportRepository(session).latest_for_finding(finding.id)
                report = VulnerabilityReportV1.model_validate_json(
                    json.dumps(previous_report.structured_report)
                )
                affected_versions = list(report.affected_target_versions)
                if evidence.target_version not in affected_versions:
                    affected_versions.append(evidence.target_version)
                minimized_report = report.model_copy(
                    update={
                        "status": FindingStatusV1(finding.status),
                        "affected_target_versions": affected_versions,
                        "minimal_reproducible_attack_sequence": proposal.ordered_actions,
                        "source_attempt_id": str(attempt.id),
                        "evidence_hash": evidence.evidence_hash,
                        "exact_transcript": evidence.transcript,
                        "updated_at": utc_now(),
                    }
                )
                next_case_version = (
                    session.scalar(
                        select(func.coalesce(func.max(RegressionCase.case_version), 0)).where(
                            RegressionCase.finding_id == finding.id
                        )
                    )
                    or 0
                ) + 1
                regression_case = build_regression_case(
                    finding_id=str(finding.id),
                    report=minimized_report,
                    judge_verdict=verdict,
                    source_evidence=evidence,
                    validated_attack=validated,
                    case_version=next_case_version,
                    created_at=utc_now(),
                    source_provenance=attempt.provenance,
                )
                stored_case = RegressionCaseRepository(session).create_versioned(
                    finding_id=finding.id,
                    case_payload=regression_case.model_dump(mode="python"),
                )
                finding.current_regression_case_id = stored_case.id
                markdown = render_vulnerability_report(
                    minimized_report,
                    _project_path(Path("config/report-template.md")),
                )
                stored_report = ReportRepository(session).create_versioned(
                    finding_id=finding.id,
                    structured_report=minimized_report.model_dump(mode="json"),
                    markdown_body=markdown,
                    validation_summary={
                        "event": "confirmed_fuzz_payload_minimized",
                        "source_attempt_id": str(attempt.id),
                        "old_regression_case_id": str(current.id),
                        "new_regression_case_id": str(stored_case.id),
                        "old_payload_bytes": len(current_payload),
                        "new_payload_bytes": len(candidate_payload),
                        "judge_verdict": verdict.model_dump(mode="json"),
                    },
                    prompt_version=_FUZZ_MINIMIZATION_PROMPT_VERSION,
                    status=finding.status,
                )
                PlatformEventRepository(session).record(
                    event_type="fuzz_regression_payload_minimized",
                    actor="agentforge:fuzz_minimizer",
                    campaign_id=attempt.campaign_id,
                    attempt_id=attempt.id,
                    finding_id=finding.id,
                    trace_id=attempt.langfuse_trace_id,
                    details={
                        "old_regression_case_id": str(current.id),
                        "new_regression_case_id": str(stored_case.id),
                        "old_payload_bytes": len(current_payload),
                        "new_payload_bytes": len(candidate_payload),
                        "exact_payload_hash": attempt.exact_payload_hash,
                    },
                )
                return stored_report
        except (LookupError, TypeError, ValueError) as exc:
            PlatformEventRepository(session).record(
                event_type="fuzz_minimization_not_promoted",
                actor="agentforge:fuzz_minimizer",
                campaign_id=attempt.campaign_id,
                attempt_id=attempt.id,
                finding_id=finding.id,
                details={
                    "reason": "candidate_case_validation_failed",
                    "error_type": type(exc).__name__,
                },
            )
            return None

    async def promote_confirmed_finding(
        self,
        *,
        session: Any,
        campaign: Campaign,
        attempt: AttackAttempt,
        objective: CampaignObjectiveV1,
        proposal: ProposedAttackV1,
        validated: ValidatedAttackV1,
        evidence: AttackEvidenceV1,
        verdict: JudgeVerdictV1,
    ) -> CampaignProcessResult | None:
        if verdict.finding_key is None:
            self._fail_attempt(
                attempt,
                stage="promotion",
                code="confirmed_exploit_missing_finding_key",
                retryable=True,
            )
            session.commit()
            return self._failed_result(
                campaign,
                code="confirmed_exploit_missing_finding_key",
                message="Judge confirmation lacked the required semantic finding key",
                retryable=True,
            )
        fingerprint = canonical_hash(
            {
                "finding_key": verdict.finding_key,
                "category": proposal.category,
                "subcategory": proposal.subcategory,
                "violated_invariants": sorted(verdict.violated_security_invariants),
            }
        )
        repository = FindingRepository(session)
        existing = repository.get_by_fingerprint(fingerprint)
        if existing is not None:
            repository.record_observation(
                finding=existing,
                attempt_id=attempt.id,
                target_version=campaign.target_version,
                provenance=attempt.provenance,
                evidence_hash=evidence.evidence_hash,
                judge_verdict=verdict.model_dump(mode="json"),
                observation_kind="rediscovery",
            )
            attempt.state = "completed"
            attempt.failure = None
            attempt.completed_at = utc_now()
            PlatformEventRepository(session).record(
                event_type="finding_rediscovered",
                actor="agentforge:promotion",
                campaign_id=campaign.id,
                attempt_id=attempt.id,
                finding_id=existing.id,
                trace_id=attempt.langfuse_trace_id,
                details={
                    "fingerprint": fingerprint,
                    "finding_key_hash": canonical_hash(verdict.finding_key),
                    "evidence_hash": evidence.evidence_hash,
                    "provenance": attempt.provenance,
                },
            )
            minimized_report = self._maybe_replace_minimized_regression_case(
                session,
                finding=existing,
                attempt=attempt,
                proposal=proposal,
                validated=validated,
                evidence=evidence,
                verdict=verdict,
            )
            session.commit()
            if minimized_report is not None:
                try:
                    reports_dir = (
                        self.settings.reports_dir
                        if self.settings.reports_dir.is_absolute()
                        else self.repository_root / self.settings.reports_dir
                    )
                    minimized_report.markdown_path = str(
                        export_stored_report(
                            minimized_report,
                            vulnerability_id=existing.vulnerability_id,
                            reports_dir=reports_dir,
                        )
                    )
                    session.commit()
                except Exception as exc:
                    PlatformEventRepository(session).record(
                        event_type="report_export_failed",
                        actor="agentforge:fuzz_minimizer",
                        campaign_id=campaign.id,
                        attempt_id=attempt.id,
                        finding_id=existing.id,
                        details={
                            "code": "minimized_report_export_failed",
                            "error_type": type(exc).__name__,
                        },
                    )
                    session.commit()
            return None
        vulnerability_id = f"AF-{fingerprint[:12].upper()}"
        title = f"{proposal.subcategory.replace('_', ' ').title()} Judge-confirmed security finding"
        finding = repository.create_confirmed(
            fingerprint=fingerprint,
            finding_key=verdict.finding_key,
            provenance=attempt.provenance,
            source_attempt_id=attempt.id,
            vulnerability_id=vulnerability_id,
            title=title,
            category=proposal.category,
            subcategory=proposal.subcategory,
            severity=verdict.severity.value,
            description=verdict.observed_behavior,
            clinical_impact=verdict.observed_behavior,
            expected_behavior=verdict.expected_behavior,
            observed_behavior=verdict.observed_behavior,
            target_version=campaign.target_version,
        )
        repository.record_observation(
            finding=finding,
            attempt_id=attempt.id,
            target_version=campaign.target_version,
            provenance=attempt.provenance,
            evidence_hash=evidence.evidence_hash,
            judge_verdict=verdict.model_dump(mode="json"),
        )
        PlatformEventRepository(session).record(
            event_type="finding_promoted",
            actor="agentforge:promotion",
            campaign_id=campaign.id,
            attempt_id=attempt.id,
            finding_id=finding.id,
            trace_id=attempt.langfuse_trace_id,
            details={
                "fingerprint": fingerprint,
                "finding_key_hash": canonical_hash(verdict.finding_key),
                "provenance": attempt.provenance,
                "status": "pending_review",
            },
        )
        session.commit()

        snapshot = ConfirmedFindingSnapshotV1(
            finding_id=str(finding.id),
            vulnerability_id=finding.vulnerability_id,
            source_attempt_id=str(attempt.id),
            source_fingerprint=finding.fingerprint,
            title=finding.title,
            severity=SeverityV1(finding.severity),
            status=FindingStatusV1(finding.status),
            category=finding.category,
            subcategory=finding.subcategory,
            owasp_mappings=objective.owasp_mappings,
            description=finding.description,
            clinical_impact=finding.clinical_impact,
            observed_behavior=finding.observed_behavior,
            expected_behavior=finding.expected_behavior,
            first_seen_target_version=finding.first_seen_target_version,
            last_seen_target_version=finding.last_seen_target_version,
            frozen_at=utc_now(),
        )
        request = DocumentationRequestV1(
            schema_version="v1",
            confirmed_finding_snapshot=snapshot,
            exact_action_sequence=proposal.ordered_actions,
            evidence=evidence,
            judge_verdict=verdict,
            target_versions=[campaign.target_version],
            existing_validation_history=[],
            required_report_status=snapshot.status,
        )
        has_capacity, current_cost, call_reservation = self._global_call_capacity(
            session,
            self.documentation,
        )
        if not has_capacity:
            self._fail_attempt(
                attempt,
                stage="documentation",
                code="global_cost_ceiling_reached",
                retryable=False,
            )
            session.commit()
            return self._failed_result(
                campaign,
                code="global_cost_ceiling_reached",
                message=(
                    "global model-cost ceiling prevents the reserved Documentation "
                    f"call after {current_cost} measured spend and "
                    f"{call_reservation} reserved spend"
                ),
                retryable=False,
            )
        documentation_result = await self.documentation.invoke(
            request,
            campaign_id=str(campaign.id),
            attempt_id=str(attempt.id),
            correlation_id=f"documentation-{attempt.id}",
            category=proposal.category,
            target_version=campaign.target_version,
        )
        self._persist_agent_result(
            session,
            campaign=campaign,
            attempt=attempt,
            finding=finding,
            result=documentation_result,
            input_payload=request,
        )
        if documentation_result.output is None:
            self._fail_attempt(
                attempt,
                stage="documentation",
                code="documentation_failed",
                retryable=True,
            )
            self.metrics.report_generation_failures_total.labels(error_type="typed_failure").inc()
            session.commit()
            return self._failed_result(
                campaign,
                code="documentation_failed",
                message="documentation role returned a typed failure",
                retryable=True,
            )

        report_output = documentation_result.output
        if (
            report_output.vulnerability_id != finding.vulnerability_id
            or report_output.category != finding.category
            or report_output.subcategory != finding.subcategory
            or report_output.source_attempt_id != str(attempt.id)
            or report_output.evidence_hash != evidence.evidence_hash
            or campaign.target_version not in report_output.affected_target_versions
            or report_output.status != FindingStatusV1.PENDING_REVIEW
        ):
            self._fail_attempt(
                attempt,
                stage="documentation",
                code="documentation_identity_mismatch",
                retryable=False,
            )
            session.commit()
            return self._failed_result(
                campaign,
                code="documentation_identity_mismatch",
                message="documentation report did not match the confirmed finding",
                retryable=False,
            )

        # Transcript provenance is controller-owned. The documentation model may
        # neither summarize nor replace the exact committed evidence turns.
        report_output = report_output.model_copy(update={"exact_transcript": evidence.transcript})
        finding.title = report_output.title
        finding.severity = report_output.severity.value
        finding.description = report_output.description
        finding.clinical_impact = report_output.clinical_impact
        finding.observed_behavior = report_output.observed_behavior
        finding.expected_behavior = report_output.expected_behavior
        markdown = render_vulnerability_report(
            report_output,
            _project_path(Path("config/report-template.md")),
        )
        stored_report = ReportRepository(session).create_versioned(
            finding_id=finding.id,
            structured_report=report_output.model_dump(mode="json"),
            markdown_body=markdown,
            validation_summary=verdict.model_dump(mode="json"),
            prompt_version=documentation_result.prompt_version,
        )
        # PostgreSQL is canonical: both structured output and rendered Markdown
        # become durable before any filesystem export is attempted.
        session.commit()
        try:
            report_path = export_stored_report(
                stored_report,
                vulnerability_id=finding.vulnerability_id,
                reports_dir=(
                    self.settings.reports_dir
                    if self.settings.reports_dir.is_absolute()
                    else self.repository_root / self.settings.reports_dir
                ),
            )
        except Exception as exc:
            self._fail_attempt(
                attempt,
                stage="documentation",
                code="report_export_failed",
                retryable=True,
            )
            session.commit()
            self.metrics.report_generation_failures_total.labels(error_type="artifact_export").inc()
            return self._failed_result(
                campaign,
                code="report_export_failed",
                message=(
                    "confirmed finding and report were saved, but generated Markdown export failed"
                ),
                error_type=type(exc).__name__,
                retryable=True,
            )
        stored_report.markdown_path = str(report_path)
        session.commit()

        try:
            next_case_version = (
                session.scalar(
                    select(func.coalesce(func.max(RegressionCase.case_version), 0)).where(
                        RegressionCase.finding_id == finding.id
                    )
                )
                or 0
            ) + 1
            regression_case = build_regression_case(
                finding_id=str(finding.id),
                report=report_output,
                judge_verdict=verdict,
                source_evidence=evidence,
                validated_attack=validated,
                case_version=next_case_version,
                created_at=utc_now(),
                source_provenance=attempt.provenance,
            )
            stored_case = RegressionCaseRepository(session).create_versioned(
                finding_id=finding.id,
                case_payload=regression_case.model_dump(mode="python"),
            )
            finding.current_regression_case_id = stored_case.id
            attempt.state = "completed"
            attempt.failure = None
            attempt.completed_at = utc_now()
            session.commit()
            return None
        except Exception as exc:
            session.rollback()
            attempt = session.get(AttackAttempt, attempt.id)
            campaign = session.get(Campaign, campaign.id)
            self._fail_attempt(
                attempt,
                stage="regression",
                code="regression_case_creation_failed",
                retryable=True,
            )
            session.commit()
            return self._failed_result(
                campaign,
                code="regression_case_creation_failed",
                message="confirmed finding report was saved but regression creation failed",
                error_type=type(exc).__name__,
                retryable=True,
            )

    async def _execute_discovery_variant(
        self,
        *,
        session: Any,
        campaign: Campaign,
        target_alias: ResolvedTargetAlias,
        objective: CampaignObjectiveV1,
        proposal: ProposedAttackV1,
        orchestrator_rationale: str,
        attack_result: AgentInvocationResult[Any],
        attack_payload: dict[str, Any],
        persist_attack_run: bool,
        fuzz_variant_id: str | None = None,
        fuzz_variant_index: int | None = None,
        exact_payload_hash: str | None = None,
        provenance: str | None = None,
    ) -> CampaignProcessResult | None:
        stop = self._stop_decision(session, campaign)
        if stop.stop_campaign:
            if persist_attack_run:
                self._persist_agent_result(
                    session,
                    campaign=campaign,
                    result=attack_result,
                    input_payload=attack_payload,
                    status="rejected",
                    typed_error={
                        "stage": "controller",
                        "code": "campaign_limit_reached_before_execution",
                        "retryable": False,
                    },
                )
            session.commit()
            return self._limits_result(campaign, stop)
        has_capacity, current_cost, regression_reserve = self._discovery_cost_capacity(
            session,
            self.judge,
            self.documentation,
            additional_cost_usd=(
                _decimal(attack_result.estimated_cost_usd) if persist_attack_run else Decimal("0")
            ),
        )
        if not has_capacity:
            if persist_attack_run:
                self._persist_agent_result(
                    session,
                    campaign=campaign,
                    result=attack_result,
                    input_payload=attack_payload,
                    status="rejected",
                    typed_error={
                        "stage": "controller",
                        "code": "global_cost_ceiling_reached",
                        "retryable": False,
                        "current_cost_usd": str(current_cost),
                        "regression_reserve_usd": str(regression_reserve),
                    },
                )
            session.commit()
            return self._failed_result(
                campaign,
                code="global_cost_ceiling_reached",
                message="global model-cost ceiling prevents target execution",
                retryable=False,
            )

        latest_version = await self.version_discoverer(
            self.loaded_profile,
            target_alias,
        )
        if latest_version.version != campaign.target_version:
            if persist_attack_run:
                self._persist_agent_result(
                    session,
                    campaign=campaign,
                    result=attack_result,
                    input_payload=attack_payload,
                    status="rejected",
                    typed_error={
                        "stage": "controller",
                        "code": "target_version_drift",
                        "retryable": False,
                    },
                )
            session.commit()
            return self._failed_result(
                campaign,
                code="target_version_drift",
                message="target version changed during the campaign",
                retryable=False,
            )

        sequence_counts = Counter(
            value
            for value in session.scalars(
                select(AttackAttempt.sequence_hash).where(AttackAttempt.campaign_id == campaign.id)
            )
            if value
        )
        candidate_hash = canonical_hash(
            [action.model_dump(mode="json") for action in proposal.ordered_actions]
        )
        attempt = self._new_attempt(
            attempt_id=uuid.uuid4(),
            campaign=campaign,
            objective=objective,
            proposal=proposal,
            prompt_version=attack_result.prompt_version,
            proposal_source=(
                PROPOSAL_AGENT_GENERATED_MUTATION
                if proposal.parent_attempt_id is not None
                else PROPOSAL_AGENT_GENERATED
            ),
            objective_source=OBJECTIVE_ORCHESTRATOR_SELECTED,
            sequence_hash=candidate_hash,
            orchestrator_rationale=orchestrator_rationale,
            fuzz_variant_id=fuzz_variant_id,
            fuzz_variant_index=fuzz_variant_index,
            exact_payload_hash=exact_payload_hash,
            provenance=provenance,
        )
        session.add(attempt)
        session.flush()
        if persist_attack_run:
            self._persist_agent_result(
                session,
                campaign=campaign,
                attempt=attempt,
                result=attack_result,
                input_payload=attack_payload,
            )

        validated = validate_attack(
            proposal,
            self.loaded_profile.profile,
            self._gate_context(
                campaign=campaign,
                objective=objective,
                sequence_counts=sequence_counts,
            ),
            now=utc_now(),
        )
        if isinstance(validated, GateRejectionV1):
            self._fail_attempt(
                attempt,
                stage="authorization",
                code=validated.code.value,
                retryable=validated.retryable_after_revision,
            )
            PlatformEventRepository(session).record(
                event_type="execution_gate_rejected",
                actor="agentforge:execution_gate",
                campaign_id=campaign.id,
                attempt_id=attempt.id,
                details={
                    "code": validated.code.value,
                    "surface": objective.execution_surface.value,
                    "technique": objective.technique.value,
                },
            )
            session.commit()
            return None

        attempt.sequence_hash = validated.sequence_hash
        campaign.actual_attempts += 1
        attempt.state = "running"
        PlatformEventRepository(session).record(
            event_type="execution_gate_approved",
            actor="agentforge:execution_gate",
            campaign_id=campaign.id,
            attempt_id=attempt.id,
            details={
                "sequence_hash": validated.sequence_hash,
                "surface": objective.execution_surface.value,
                "technique": objective.technique.value,
            },
        )
        session.commit()

        try:
            evidence = await self.runner.execute(
                validated,
                self._execution_context(
                    campaign=campaign,
                    attempt_id=attempt.id,
                    target_alias=target_alias,
                    validated=validated,
                ),
            )
            attempt.target_executed = True
            PlatformEventRepository(session).record(
                event_type="target_execution_completed",
                actor="agentforge:runner",
                campaign_id=campaign.id,
                attempt_id=attempt.id,
                trace_id=evidence.langfuse_trace_id,
                latency_ms=round(evidence.total_latency_ms),
                details={
                    "surface": objective.execution_surface.value,
                    "technique": objective.technique.value,
                    "evidence_hash": evidence.evidence_hash,
                    "errors": len(evidence.errors),
                },
            )
        except Exception:
            attempt = session.get(AttackAttempt, attempt.id)
            self._fail_attempt(
                attempt,
                stage="runner",
                code="runner_failed",
                retryable=True,
            )
            PlatformEventRepository(session).record(
                event_type="target_execution_error",
                actor="agentforge:runner",
                campaign_id=campaign.id,
                attempt_id=attempt.id,
                details={"code": "runner_failed"},
            )
            session.commit()
            return None
        if not self._evidence_matches_execution(
            evidence,
            campaign=campaign,
            attempt=attempt,
            validated=validated,
        ):
            self._fail_attempt(
                attempt,
                stage="runner",
                code="evidence_correlation_mismatch",
                retryable=False,
            )
            session.commit()
            return None

        try:
            self._commit_and_export_evidence(
                session,
                campaign=campaign,
                attempt=attempt,
                evidence=evidence,
            )
        except _EvidencePersistenceFailure as exc:
            return self._failed_result(
                campaign,
                code=exc.code,
                message=exc.message,
                retryable=exc.retryable,
            )

        verdict, judge_result, judge_payload = await self._judge_evidence(
            campaign=campaign,
            attempt=attempt,
            objective=objective,
            proposal=proposal,
            evidence=evidence,
        )
        self._persist_agent_result(
            session,
            campaign=campaign,
            attempt=attempt,
            result=judge_result,
            input_payload=judge_payload,
        )
        if verdict is None:
            self._fail_attempt(
                attempt,
                stage="judge",
                code="judge_failed",
                retryable=True,
            )
            session.commit()
            return None
        self._persist_verdict(session, attempt=attempt, verdict=verdict)
        if verdict.verdict == JudgeVerdictKindV1.EXPLOIT_CONFIRMED:
            session.commit()
            terminal = await self.promote_confirmed_finding(
                session=session,
                campaign=campaign,
                attempt=attempt,
                objective=objective,
                proposal=proposal,
                validated=validated,
                evidence=evidence,
                verdict=verdict,
            )
            if (
                terminal is not None
                or attempt.provenance != "agent_fuzz"
                or proposal.fuzz_plan is None
            ):
                return terminal
            candidates = minimize_confirmed_fuzz_variant(
                proposal,
                parent_attempt_id=str(attempt.id),
                maximum_candidates=3,
            )
            PlatformEventRepository(session).record(
                event_type="fuzz_minimization_planned",
                actor="agentforge:fuzz_minimizer",
                campaign_id=campaign.id,
                attempt_id=attempt.id,
                finding_id=(
                    session.scalar(
                        select(Finding.id).where(Finding.source_attempt_id == attempt.id)
                    )
                ),
                details={
                    "candidate_count": len(candidates),
                    "candidate_ids": [item.candidate_id for item in candidates],
                    "maximum_candidates": 3,
                },
            )
            session.commit()
            for candidate in candidates:
                terminal = await self._execute_discovery_variant(
                    session=session,
                    campaign=campaign,
                    target_alias=target_alias,
                    objective=objective,
                    proposal=candidate.proposal,
                    orchestrator_rationale=(
                        f"{orchestrator_rationale} Deterministic minimization replay "
                        f"{candidate.candidate_index + 1} of {len(candidates)}."
                    ),
                    attack_result=attack_result,
                    attack_payload=attack_payload,
                    persist_attack_run=False,
                    fuzz_variant_id=candidate.candidate_id,
                    fuzz_variant_index=candidate.candidate_index,
                    exact_payload_hash=candidate.exact_payload_hash,
                    provenance=FUZZ_MINIMIZATION_PROVENANCE,
                )
                if terminal is not None:
                    return terminal
            return None
        attempt.state = "completed"
        attempt.failure = None
        attempt.completed_at = utc_now()
        session.commit()
        return None

    async def _process_discovery(
        self,
        campaign_id: uuid.UUID,
        target_alias: ResolvedTargetAlias,
    ) -> CampaignProcessResult:
        while True:
            with self.database.session_factory() as session:
                campaign = session.scalar(
                    select(Campaign).where(Campaign.id == campaign_id).with_for_update()
                )
                if campaign is None:
                    return CampaignProcessResult(
                        status="failed",
                        sanitized_error={
                            "code": "campaign_not_found",
                            "message": "campaign not found",
                        },
                    )
                stop = self._stop_decision(session, campaign)
                if stop.stop_campaign:
                    return self._limits_result(campaign, stop)
                has_capacity, current_cost, regression_reserve = self._discovery_cost_capacity(
                    session,
                    self.orchestrator,
                )
                if not has_capacity:
                    return self._failed_result(
                        campaign,
                        code="global_cost_ceiling_reached",
                        message=(
                            "global model-cost ceiling plus the projected regression "
                            f"reserve ({regression_reserve}) prevents another iteration "
                            f"after {current_cost} measured spend"
                        ),
                        retryable=False,
                    )

                priors = self._prior_attempts(session, campaign.id)
                planning_rejections = self._planning_rejection_facts(
                    session,
                    campaign_id=campaign.id,
                )
                allowed = self._allowed_objectives(campaign)
                eligible_mutations = {
                    item.attempt_id
                    for item in priors
                    if item.outcome == PriorAttemptOutcomeV1.PARTIAL_SIGNAL
                }
                started = _aware(campaign.started_at or campaign.created_at)
                elapsed = int((utc_now() - started).total_seconds())
                remaining_duration = max(0, campaign.max_duration_seconds - elapsed)
                remaining_attempts = max(
                    0,
                    campaign.max_attempts - campaign.actual_attempts,
                )
                remaining_cost = max(
                    Decimal("0"),
                    campaign.max_cost_usd - campaign.actual_cost_usd,
                )
                planning_id = uuid.uuid4()
                surface_capabilities = self._surface_capabilities()
                decision_context = PlatformObservabilityService(
                    session,
                    taxonomy=self.taxonomy,
                    seed_cases=self.seed_cases,
                ).orchestrator_context(
                    campaign=campaign,
                    remaining_limits=RemainingBudgetAndLimitsV1(
                        remaining_cost_usd=float(remaining_cost),
                        remaining_attempts=remaining_attempts,
                        remaining_duration_seconds=remaining_duration,
                        remaining_model_calls=remaining_attempts * 4,
                        remaining_input_tokens=remaining_attempts * 32_000,
                        remaining_output_tokens=remaining_attempts * 5_000,
                    ),
                    surface_capabilities=surface_capabilities,
                )
                orchestrator_payload = {
                    "schema_version": "v2",
                    "decision_context": decision_context.model_dump(mode="json"),
                    "controller_authority": {
                        "authorized_scope": "synthetic-only",
                        "target_alias": campaign.target_alias,
                        "patient_aliases": ["patient_a", "patient_b"],
                        "models_never_receive_secrets": True,
                        "persistent_synthetic_write_limit": 1,
                    },
                    "prior_planning_rejections": planning_rejections,
                }

                orchestrator_result = await self.orchestrator.invoke(
                    orchestrator_payload,
                    campaign_id=str(campaign.id),
                    attempt_id=str(planning_id),
                    correlation_id=f"orchestrator-{planning_id}",
                    category=campaign.category_scope,
                    target_version=campaign.target_version,
                )
                orchestrator_run = self._persist_agent_result(
                    session,
                    campaign=campaign,
                    result=orchestrator_result,
                    input_payload=orchestrator_payload,
                )
                if orchestrator_result.output is None:
                    session.commit()
                    return self._failed_result(
                        campaign,
                        code="orchestrator_failed",
                        message="Orchestrator returned no valid decision after bounded retries",
                        retryable=True,
                    )
                decision: OrchestratorDecisionV2 = orchestrator_result.output
                if decision.requested_action == RequestedActionV1.STOP:
                    session.commit()
                    return CampaignProcessResult(
                        status="completed",
                        actual_cost_usd=campaign.actual_cost_usd,
                    )
                if not validate_objective_choice_v2(
                    decision,
                    allowed_pairs=allowed,
                    allowed_surfaces=set(decision_context.allowed_surfaces),
                    allowed_techniques=set(decision_context.allowed_techniques),
                    allowed_mutation_source_ids=eligible_mutations,
                ):
                    orchestrator_run.status = "rejected"
                    orchestrator_run.typed_error = {
                        "stage": "orchestrator",
                        "code": "invalid_objective_selection",
                        "retryable": True,
                    }
                    session.commit()
                    return self._failed_result(
                        campaign,
                        code="invalid_objective_selection",
                        message="Orchestrator selected an objective outside the supplied options",
                        retryable=True,
                    )

                objective = build_objective(
                    campaign_id=str(campaign.id),
                    campaign_type=campaign.campaign_type,
                    target_version=campaign.target_version,
                    taxonomy=self.taxonomy,
                    category_id=str(decision.selected_category),
                    subcategory_id=str(decision.selected_subcategory),
                    remaining_cost_usd=remaining_cost,
                    remaining_attempts=remaining_attempts,
                    remaining_duration_seconds=remaining_duration,
                    relevant_prior_attempts=priors,
                    requested_action=decision.requested_action,
                    mutation_source_attempt_id=decision.mutation_source_attempt_id,
                    objective_text=decision.objective,
                    execution_surface=decision.selected_surface,
                    technique=decision.selected_technique,
                )
                bindings = endpoint_bindings(self.loaded_profile.profile)
                allowed_endpoint_bindings = [
                    item.model_dump(mode="json")
                    for item in bindings.values()
                    if (
                        objective.execution_surface == ExecutionSurfaceV2.OPENEMR_SAME_ORIGIN_API
                        and item.surface == "ui"
                    )
                    or (
                        objective.execution_surface == ExecutionSurfaceV2.AGENT_SERVICE_API
                        and item.surface in {"agent_service", "status"}
                    )
                    or (
                        objective.execution_surface == ExecutionSurfaceV2.STAGED_DOCUMENT
                        and "document" in item.endpoint_id
                    )
                    or objective.execution_surface == ExecutionSurfaceV2.HYBRID
                ]
                target_action_types = {
                    ExecutionSurfaceV2.OPENEMR_UI: ["send_chat_message"],
                    ExecutionSurfaceV2.OPENEMR_SAME_ORIGIN_API: ["invoke_approved_api_request"],
                    ExecutionSurfaceV2.AGENT_SERVICE_API: ["invoke_approved_api_request"],
                    ExecutionSurfaceV2.STAGED_DOCUMENT: (
                        ["invoke_approved_api_request"]
                        if objective.technique == AttackTechniqueV2.FUZZING
                        else [
                            "invoke_approved_api_request",
                            "upload_approved_fixture",
                        ]
                    ),
                    ExecutionSurfaceV2.HYBRID: [
                        "send_chat_message",
                        "invoke_approved_api_request",
                        "upload_approved_fixture",
                    ],
                }[objective.execution_surface]
                attack_payload = {
                    "schema_version": "v2",
                    "objective": objective.model_dump(mode="json"),
                    "allowed_action_types": [
                        "reset_session",
                        "authenticate",
                        "select_synthetic_patient",
                        *target_action_types,
                        "wait_for_response",
                        "collect_evidence",
                    ],
                    "selected_execution_surface": objective.execution_surface.value,
                    "selected_technique": objective.technique.value,
                    "allowed_endpoint_bindings": allowed_endpoint_bindings,
                    "fuzz_catalog": {
                        "corpus_version": self.fuzz_corpus.corpus_version,
                        "entries": [
                            {
                                "corpus_id": item.corpus_id,
                                "payload_kind": item.payload_kind,
                                "operators": [operator.value for operator in item.operators],
                                "description": item.description,
                            }
                            for item in self.fuzz_corpus.entries
                        ],
                        "max_variants": 6,
                    },
                    "target_constraints": {
                        **objective.relevant_target_profile_subset,
                        "required_sequence_grammar": {
                            "prefix": [
                                "reset_session",
                                "authenticate",
                                "select_synthetic_patient",
                            ],
                            "operation_rule": (
                                "each send_chat_message, invoke_approved_api_request, "
                                "or upload_approved_fixture must be followed immediately "
                                "by wait_for_response"
                            ),
                            "suffix": ["collect_evidence"],
                            "collect_evidence_count": 1,
                        },
                        "selected_surface_action_contract": {
                            "permitted_target_action_types": target_action_types,
                            "hybrid_requires_two_distinct_surfaces": (
                                objective.execution_surface == ExecutionSurfaceV2.HYBRID
                            ),
                            "fuzz_mutation_point_action_types": [
                                "send_chat_message",
                                "invoke_approved_api_request",
                            ],
                            "staged_document_fuzz_rule": (
                                "Use invoke_approved_api_request with one supplied "
                                "document endpoint binding as the mutation point. "
                                "Upload actions are scenario-only because fixed approved "
                                "fixtures are immutable."
                            ),
                            "staged_document_scenario_rule": (
                                "Do not add send_chat_message on staged_document. An upload "
                                "plus UI chat sequence is hybrid, while staged_document "
                                "uses only approved document upload or endpoint operations."
                            ),
                        },
                        "exact_controller_owned_values": {
                            "reset_strategy_id": (self.loaded_profile.profile.reset.conversation),
                            "require_clean_context": True,
                            "session_source": "environment_credentials",
                            "test_identity_alias": "physician_test",
                            "expected_role": "physician",
                            "patient_alias": "patient_a",
                            "verify_selected_context": True,
                            "upload_surface_id": _UPLOAD_SURFACE_ID,
                            "upload_stage_endpoint_id": _UPLOAD_STAGE_ENDPOINT_ID,
                            "upload_reject_endpoint_id": _UPLOAD_REJECT_ENDPOINT_ID,
                            "wait_expected_event": "copilot_response_complete",
                            "evidence_kinds": [
                                "transcript",
                                "http_metadata",
                                "tool_calls",
                                "side_effects",
                            ],
                            "capture_on": "always",
                        },
                        "uploads_allowed": (
                            objective.execution_surface
                            in {
                                ExecutionSurfaceV2.STAGED_DOCUMENT,
                                ExecutionSurfaceV2.HYBRID,
                            }
                        ),
                        "approved_fixture_catalog": {
                            "version": self.approved_fixture_catalog_version,
                            "fixtures": [
                                {
                                    "fixture_id": item.fixture_id,
                                    "document_type": item.document_type,
                                    "media_type": item.media_type,
                                    "size_bytes": item.size_bytes,
                                    "pages": item.pages,
                                    "sha256": item.sha256,
                                }
                                for item in self.approved_fixtures.values()
                            ],
                        },
                        "persistent_writes_allowed": (
                            objective.execution_surface
                            in {
                                ExecutionSurfaceV2.STAGED_DOCUMENT,
                                ExecutionSurfaceV2.HYBRID,
                            }
                        ),
                        "credential_modes": [
                            "endpoint_default",
                            "missing",
                            "invalid",
                            "valid",
                        ],
                        "correlation_modes": [
                            "valid",
                            "missing",
                            "invalid",
                            "mismatch",
                        ],
                    },
                    "prior_planning_rejections": planning_rejections,
                    "prior_outcomes": [item.model_dump(mode="json") for item in priors],
                }
                has_capacity, current_cost, regression_reserve = self._discovery_cost_capacity(
                    session,
                    self.attack_generator,
                )
                if not has_capacity:
                    session.commit()
                    return self._failed_result(
                        campaign,
                        code="global_cost_ceiling_reached",
                        message=(
                            "global model-cost ceiling plus the projected regression "
                            f"reserve ({regression_reserve}) prevents the Attack Generator "
                            f"call after {current_cost} measured spend"
                        ),
                        retryable=False,
                    )
                attack_result = await self.attack_generator.invoke(
                    attack_payload,
                    campaign_id=str(campaign.id),
                    attempt_id=str(planning_id),
                    correlation_id=f"attack-generator-{planning_id}",
                    category=objective.selected_category,
                    target_version=campaign.target_version,
                )
                if attack_result.output is None:
                    self._persist_agent_result(
                        session,
                        campaign=campaign,
                        result=attack_result,
                        input_payload=attack_payload,
                    )
                    session.commit()
                    return self._failed_result(
                        campaign,
                        code="attack_generator_failed",
                        message="Attack Generator returned no valid proposal after bounded retries",
                        retryable=True,
                    )
                proposal: ProposedAttackV1 = attack_result.output
                expected_parent = (
                    decision.mutation_source_attempt_id
                    if decision.requested_action == RequestedActionV1.MUTATION
                    else None
                )
                if (
                    proposal.category != objective.selected_category
                    or proposal.subcategory != objective.selected_subcategory
                    or proposal.parent_attempt_id != expected_parent
                    or proposal.execution_surface != objective.execution_surface
                    or proposal.technique != objective.technique
                ):
                    self._persist_agent_result(
                        session,
                        campaign=campaign,
                        result=attack_result,
                        input_payload=attack_payload,
                        status="rejected",
                        typed_error={
                            "stage": "attack_generator",
                            "code": "proposal_scope_mismatch",
                            "retryable": True,
                        },
                    )
                    terminal = self._planning_rejection_result(
                        session,
                        campaign=campaign,
                        stage="attack_generator",
                        code="proposal_scope_mismatch",
                    )
                    if terminal is not None:
                        return terminal
                    continue

                if objective.technique == AttackTechniqueV2.FUZZING:
                    try:
                        expanded = expand_fuzz_plan(proposal, self.fuzz_corpus)
                    except ValueError as exc:
                        self._persist_agent_result(
                            session,
                            campaign=campaign,
                            result=attack_result,
                            input_payload=attack_payload,
                            status="rejected",
                            typed_error={
                                "stage": "fuzz_expansion",
                                "code": "invalid_fuzz_plan",
                                "detail": str(exc)[:512],
                                "retryable": True,
                            },
                        )
                        terminal = self._planning_rejection_result(
                            session,
                            campaign=campaign,
                            stage="fuzz_expansion",
                            code="invalid_fuzz_plan",
                        )
                        if terminal is not None:
                            return terminal
                        continue
                    expanded = expanded[:remaining_attempts]
                    PlatformEventRepository(session).record(
                        event_type="fuzz_plan_expanded",
                        actor="agentforge:fuzz_expander",
                        campaign_id=campaign.id,
                        role="attack_generator",
                        model=attack_result.model,
                        prompt_version=attack_result.prompt_version,
                        trace_id=attack_result.langfuse_trace_id,
                        details={
                            "corpus_version": self.fuzz_corpus.corpus_version,
                            "variant_count": len(expanded),
                            "rng_seed": proposal.fuzz_plan.rng_seed
                            if proposal.fuzz_plan is not None
                            else None,
                            "variant_ids": [item.variant_id for item in expanded],
                        },
                    )
                    session.commit()
                    for index, variant in enumerate(expanded):
                        terminal = await self._execute_discovery_variant(
                            session=session,
                            campaign=campaign,
                            target_alias=target_alias,
                            objective=objective,
                            proposal=variant.proposal,
                            orchestrator_rationale=decision.rationale or "",
                            attack_result=attack_result,
                            attack_payload=attack_payload,
                            persist_attack_run=index == 0,
                            fuzz_variant_id=variant.variant_id,
                            fuzz_variant_index=variant.variant_index,
                            exact_payload_hash=variant.exact_payload_hash,
                        )
                        if terminal is not None:
                            return terminal
                    continue

                stop = self._stop_decision(session, campaign)
                if stop.stop_campaign:
                    self._persist_agent_result(
                        session,
                        campaign=campaign,
                        result=attack_result,
                        input_payload=attack_payload,
                        status="rejected",
                        typed_error={
                            "stage": "controller",
                            "code": "campaign_limit_reached_before_execution",
                            "retryable": False,
                        },
                    )
                    session.commit()
                    return self._limits_result(campaign, stop)
                has_capacity, current_cost, regression_reserve = self._discovery_cost_capacity(
                    session,
                    self.judge,
                    self.documentation,
                    additional_cost_usd=_decimal(attack_result.estimated_cost_usd),
                )
                if not has_capacity:
                    self._persist_agent_result(
                        session,
                        campaign=campaign,
                        result=attack_result,
                        input_payload=attack_payload,
                        status="rejected",
                        typed_error={
                            "stage": "controller",
                            "code": "global_cost_ceiling_reached",
                            "retryable": False,
                            "current_cost_usd": str(current_cost),
                            "regression_reserve_usd": str(regression_reserve),
                        },
                    )
                    session.commit()
                    return self._failed_result(
                        campaign,
                        code="global_cost_ceiling_reached",
                        message="global model-cost ceiling prevents target execution",
                        retryable=False,
                    )

                latest_version = await self.version_discoverer(
                    self.loaded_profile,
                    target_alias,
                )
                if latest_version.version != campaign.target_version:
                    self._persist_agent_result(
                        session,
                        campaign=campaign,
                        result=attack_result,
                        input_payload=attack_payload,
                        status="rejected",
                        typed_error={
                            "stage": "controller",
                            "code": "target_version_drift",
                            "retryable": False,
                        },
                    )
                    session.commit()
                    return self._failed_result(
                        campaign,
                        code="target_version_drift",
                        message="target version changed during the campaign",
                        retryable=False,
                    )

                sequence_counts = Counter(
                    value
                    for value in session.scalars(
                        select(AttackAttempt.sequence_hash).where(
                            AttackAttempt.campaign_id == campaign.id
                        )
                    )
                    if value
                )
                gate_context = self._gate_context(
                    campaign=campaign,
                    objective=objective,
                    sequence_counts=sequence_counts,
                )
                validated = validate_attack(
                    proposal,
                    self.loaded_profile.profile,
                    gate_context,
                    now=utc_now(),
                )
                if isinstance(validated, GateRejectionV1):
                    self._persist_agent_result(
                        session,
                        campaign=campaign,
                        result=attack_result,
                        input_payload=attack_payload,
                        status="rejected",
                        typed_error={
                            "stage": "authorization",
                            "code": validated.code.value,
                            "detail": validated.reason,
                            "retryable": validated.retryable_after_revision,
                        },
                    )
                    if validated.retryable_after_revision:
                        terminal = self._planning_rejection_result(
                            session,
                            campaign=campaign,
                            stage="authorization",
                            code=validated.code.value,
                        )
                        if terminal is not None:
                            return terminal
                        continue
                    session.commit()
                    return self._failed_result(
                        campaign,
                        code="execution_gate_rejected",
                        message=f"execution gate rejected proposal: {validated.code.value}",
                        retryable=validated.retryable_after_revision,
                    )

                attempt = self._new_attempt(
                    attempt_id=uuid.uuid4(),
                    campaign=campaign,
                    objective=objective,
                    proposal=proposal,
                    prompt_version=attack_result.prompt_version,
                    proposal_source=(
                        PROPOSAL_AGENT_GENERATED_MUTATION
                        if proposal.parent_attempt_id is not None
                        else PROPOSAL_AGENT_GENERATED
                    ),
                    objective_source=OBJECTIVE_ORCHESTRATOR_SELECTED,
                    sequence_hash=validated.sequence_hash,
                    orchestrator_rationale=decision.rationale,
                )
                session.add(attempt)
                session.flush()
                self._persist_agent_result(
                    session,
                    campaign=campaign,
                    attempt=attempt,
                    result=attack_result,
                    input_payload=attack_payload,
                )
                campaign.actual_attempts += 1
                attempt.state = "running"
                session.commit()

                try:
                    evidence = await self.runner.execute(
                        validated,
                        self._execution_context(
                            campaign=campaign,
                            attempt_id=attempt.id,
                            target_alias=target_alias,
                            validated=validated,
                        ),
                    )
                    attempt.target_executed = True
                    PlatformEventRepository(session).record(
                        event_type="target_execution_completed",
                        actor="agentforge:runner",
                        campaign_id=campaign.id,
                        attempt_id=attempt.id,
                        trace_id=evidence.langfuse_trace_id,
                        latency_ms=round(evidence.total_latency_ms),
                        details={
                            "surface": objective.execution_surface.value,
                            "technique": objective.technique.value,
                            "evidence_hash": evidence.evidence_hash,
                            "errors": len(evidence.errors),
                        },
                    )
                except Exception as exc:
                    attempt = session.get(AttackAttempt, attempt.id)
                    campaign = session.get(Campaign, campaign.id)
                    self._fail_attempt(
                        attempt,
                        stage="runner",
                        code="runner_failed",
                        retryable=True,
                    )
                    session.commit()
                    return self._failed_result(
                        campaign,
                        code="runner_failed",
                        message="authorized target execution failed before evidence was returned",
                        error_type=type(exc).__name__,
                        retryable=True,
                    )
                if not self._evidence_matches_execution(
                    evidence,
                    campaign=campaign,
                    attempt=attempt,
                    validated=validated,
                ):
                    self._fail_attempt(
                        attempt,
                        stage="runner",
                        code="evidence_correlation_mismatch",
                        retryable=False,
                    )
                    session.commit()
                    return self._failed_result(
                        campaign,
                        code="evidence_correlation_mismatch",
                        message="runner evidence did not match the authorized execution",
                        retryable=False,
                    )

                try:
                    self._commit_and_export_evidence(
                        session,
                        campaign=campaign,
                        attempt=attempt,
                        evidence=evidence,
                    )
                except _EvidencePersistenceFailure as exc:
                    return self._failed_result(
                        campaign,
                        code=exc.code,
                        message=exc.message,
                        retryable=exc.retryable,
                    )

                verdict, judge_result, judge_payload = await self._judge_evidence(
                    campaign=campaign,
                    attempt=attempt,
                    objective=objective,
                    proposal=proposal,
                    evidence=evidence,
                )
                self._persist_agent_result(
                    session,
                    campaign=campaign,
                    attempt=attempt,
                    result=judge_result,
                    input_payload=judge_payload,
                )
                if verdict is None:
                    self._fail_attempt(
                        attempt,
                        stage="judge",
                        code="judge_failed",
                        retryable=True,
                    )
                    session.commit()
                    return self._failed_result(
                        campaign,
                        code="judge_failed",
                        message="Judge returned no valid verdict after bounded retries",
                        retryable=True,
                    )
                self._persist_verdict(session, attempt=attempt, verdict=verdict)
                if verdict.verdict == JudgeVerdictKindV1.EXPLOIT_CONFIRMED:
                    session.commit()
                    failure = await self.promote_confirmed_finding(
                        session=session,
                        campaign=campaign,
                        attempt=attempt,
                        objective=objective,
                        proposal=proposal,
                        validated=validated,
                        evidence=evidence,
                        verdict=verdict,
                    )
                    if failure is not None:
                        return failure
                else:
                    attempt.state = "completed"
                    attempt.failure = None
                    attempt.completed_at = utc_now()
                    session.commit()

    @staticmethod
    def _regression_case(row: RegressionCase, finding: Finding) -> RegressionCaseV2:
        return RegressionCaseV2.model_validate_json(
            json.dumps(
                {
                    "schema_version": "v2",
                    "case_id": row.case_id,
                    "finding_id": str(row.finding_id),
                    "vulnerability_id": finding.vulnerability_id,
                    "finding_key": row.finding_key,
                    "source_provenance": row.source_provenance,
                    "required_replays": row.required_replays,
                    "case_version": row.case_version,
                    "active": row.active,
                    "category": row.category,
                    "subcategory": row.subcategory,
                    "owasp_mappings": row.owasp_mappings,
                    "setup": row.setup,
                    "exact_ordered_sequence": row.ordered_sequence,
                    "judge_context": row.judge_context,
                    "expected_behavior": row.expected_behavior,
                    "target_requirements": row.target_requirements,
                    "created_from_evidence_hash": row.created_from_evidence_hash,
                    "sequence_hash": row.sequence_hash,
                    "fingerprint": row.fingerprint,
                    "created_at": row.created_at,
                },
                default=str,
            )
        )

    async def _process_regression(
        self,
        campaign_id: uuid.UUID,
        target_alias: ResolvedTargetAlias,
    ) -> CampaignProcessResult:
        """Run the active cohort with separate Judge-authoritative replicated replays."""

        with self.database.session_factory() as session:
            campaign = session.scalar(
                select(Campaign).where(Campaign.id == campaign_id).with_for_update()
            )
            if campaign is None:
                return CampaignProcessResult(
                    status="failed",
                    sanitized_error={
                        "code": "campaign_not_found",
                        "message": "campaign not found",
                    },
                )
            try:
                run = RegressionRunRepository(session).for_campaign(campaign.id)
            except LookupError:
                return self._failed_result(
                    campaign,
                    code="regression_run_not_found",
                    message="regression campaign has no associated run",
                    retryable=False,
                )
            # Manual deployed runs are queued before asynchronous target-version
            # discovery, so their initial run record carries a transparent
            # pending placeholder. Keep the run and its campaign synchronized
            # to the exact controller-discovered version before any cohort
            # comparison, replay, event, or dashboard result is produced.
            run.target_version = campaign.target_version
            rows = RegressionCaseRepository(session).active()
            cohort_hash = canonical_hash([(str(item.id), item.case_version) for item in rows])
            previous = session.scalar(
                select(RegressionRun)
                .where(RegressionRun.id != run.id)
                .where(RegressionRun.status == "completed")
                .where(RegressionRun.target_version != campaign.target_version)
                .where(RegressionRun.target_version.not_in(UNRESOLVED_TARGET_VERSIONS))
                .where(RegressionRun.cohort_hash == cohort_hash)
                .order_by(RegressionRun.completed_at.desc(), RegressionRun.id.desc())
                .limit(1)
            )
            run.previous_target_version = previous.target_version if previous is not None else None
            run.cohort_hash = cohort_hash
            run.status = "running"
            run.started_at = utc_now()
            run.total_cases = len(rows)
            PlatformEventRepository(session).record(
                event_type="regression_run_started",
                actor="agentforge:regression_harness",
                campaign_id=campaign.id,
                regression_run_id=run.id,
                details={
                    "target_version": campaign.target_version,
                    "previous_target_version": run.previous_target_version,
                    "cohort_hash": cohort_hash,
                    "active_case_count": len(rows),
                },
            )
            session.commit()
            outcomes: Counter[str] = Counter()

            for row in rows:
                finding = session.get(Finding, row.finding_id)
                if finding is None:
                    outcomes["error"] += 1
                    continue
                case = self._regression_case(row, finding)
                aggregate_row = RegressionRunRepository(session).add_result(
                    run_id=run.id,
                    case_id=row.id,
                    case_version=row.case_version,
                    outcome="inconclusive",
                    judge_result=None,
                    evidence_hash=None,
                    estimated_cost_usd=Decimal("0"),
                    latency_ms=None,
                    trace_id=None,
                    changed_target_version=(
                        campaign.target_version != case.target_requirements.source_target_version
                    ),
                    aggregate_reason="Replay aggregate has not completed.",
                )
                session.commit()
                replay_results: list[RegressionResultV1] = []
                replay_cost = Decimal("0")
                replay_latency = 0
                latest_trace_id: str | None = None

                for replay_index in range(case.required_replays):
                    attempt: AttackAttempt | None = None
                    evidence: AttackEvidenceV1 | None = None
                    try:
                        stop = self._stop_decision(session, campaign)
                        if stop.stop_campaign:
                            raise RuntimeError("regression campaign limit reached")
                        has_capacity, _current_cost, _call_reservation = self._global_call_capacity(
                            session, self.judge
                        )
                        if not has_capacity:
                            raise RuntimeError("global model-cost ceiling reached")
                        latest_version = await self.version_discoverer(
                            self.loaded_profile,
                            target_alias,
                        )
                        if latest_version.version != campaign.target_version:
                            raise RuntimeError("target version changed during regression")
                        if (
                            case.target_requirements.target_profile_version
                            != self.loaded_profile.profile.profile_version
                        ):
                            raise RuntimeError(
                                "saved case target profile version is no longer active"
                            )
                        surface = self._execution_surface_for_actions(case.exact_ordered_sequence)
                        operation_count = sum(
                            action.action_type
                            in {
                                ActionTypeV1.SEND_CHAT_MESSAGE,
                                ActionTypeV1.UPLOAD_APPROVED_FIXTURE,
                                ActionTypeV1.INVOKE_APPROVED_API_REQUEST,
                            }
                            for action in case.exact_ordered_sequence
                        )
                        proposal = ProposedAttackV1(
                            schema_version="v1",
                            proposal_id=f"replay-{case.case_id}-{replay_index + 1}",
                            category=case.category,
                            subcategory=case.subcategory,
                            execution_surface=surface,
                            technique=AttackTechniqueV2.SCENARIO,
                            attack_family_id=case.case_id,
                            novelty_rationale=(
                                "Exact deterministic replay of a Judge-confirmed exploit."
                            ),
                            prerequisites=["Approved synthetic regression setup"],
                            ordered_actions=case.exact_ordered_sequence,
                            expected_exploit_signals=[
                                "The Judge observes the saved violated invariants"
                            ],
                            expected_safe_behavior=[case.expected_behavior[:512]],
                            stop_conditions=["Stop after the exact bounded replay"],
                            risk_flags=[],
                            estimated_turns=max(1, operation_count),
                            estimated_cost_class=EstimatedCostClassV1.LOW,
                        )
                        objective = build_objective(
                            campaign_id=str(campaign.id),
                            campaign_type="regression",
                            target_version=campaign.target_version,
                            taxonomy=self.taxonomy,
                            category_id=case.category,
                            subcategory_id=case.subcategory,
                            remaining_cost_usd=max(
                                Decimal("0"),
                                campaign.max_cost_usd - campaign.actual_cost_usd,
                            ),
                            remaining_attempts=max(
                                0,
                                campaign.max_attempts - campaign.actual_attempts,
                            ),
                            remaining_duration_seconds=campaign.max_duration_seconds,
                            objective_text=case.expected_behavior[:512],
                            execution_surface=surface,
                            technique=AttackTechniqueV2.SCENARIO,
                        )
                        validated = validate_attack(
                            proposal,
                            self.loaded_profile.profile,
                            self._gate_context(
                                campaign=campaign,
                                objective=objective,
                                sequence_counts=Counter(),
                                max_sequence_repetitions=10,
                                patient_alias=case.setup.selected_patient_alias,
                                identity_alias=case.setup.test_identity_alias,
                                expected_role=case.setup.expected_role,
                            ),
                            now=utc_now(),
                        )
                        if isinstance(validated, GateRejectionV1):
                            raise RuntimeError(
                                f"regression gate rejected case: {validated.code.value}"
                            )
                        attempt = self._new_attempt(
                            attempt_id=uuid.uuid4(),
                            campaign=campaign,
                            objective=objective,
                            proposal=proposal,
                            prompt_version=_CONTROLLER_PROMPT_VERSION,
                            proposal_source=FIXED_REGRESSION_CASE,
                            objective_source=FIXED_REGRESSION_CASE,
                            sequence_hash=validated.sequence_hash,
                            provenance="regression_replay",
                            orchestrator_rationale=(
                                "Active confirmed-exploit cohort replay requested by "
                                "the regression harness."
                            ),
                        )
                        session.add(attempt)
                        campaign.actual_attempts += 1
                        attempt.state = "running"
                        session.commit()
                        evidence = await self.runner.execute(
                            validated,
                            self._execution_context(
                                campaign=campaign,
                                attempt_id=attempt.id,
                                target_alias=target_alias,
                                validated=validated,
                            ),
                        )
                        attempt.target_executed = True
                        if not self._evidence_matches_execution(
                            evidence,
                            campaign=campaign,
                            attempt=attempt,
                            validated=validated,
                        ):
                            raise RuntimeError("regression evidence correlation failed")
                        self._commit_and_export_evidence(
                            session,
                            campaign=campaign,
                            attempt=attempt,
                            evidence=evidence,
                        )
                        verdict, judge_result, judge_payload = await self._judge_evidence(
                            campaign=campaign,
                            attempt=attempt,
                            objective=objective,
                            proposal=proposal,
                            evidence=evidence,
                            regression_case=case,
                        )
                        self._persist_agent_result(
                            session,
                            campaign=campaign,
                            attempt=attempt,
                            finding=finding,
                            result=judge_result,
                            input_payload=judge_payload,
                        )
                        replay = evaluate_regression(
                            case,
                            evidence,
                            judge_verdict=verdict,
                        )
                        if verdict is not None:
                            self._persist_verdict(
                                session,
                                attempt=attempt,
                                verdict=verdict,
                            )
                        attempt.state = "completed" if replay.outcome.value != "error" else "failed"
                        attempt.failure = (
                            None
                            if attempt.state == "completed"
                            else {
                                "stage": "judge",
                                "code": "regression_judge_failed",
                                "retryable": True,
                            }
                        )
                        attempt.completed_at = utc_now()
                        cost = _decimal(judge_result.estimated_cost_usd)
                        replay_cost += cost
                        replay_latency += round(evidence.total_latency_ms)
                        latest_trace_id = (
                            judge_result.langfuse_trace_id
                            or evidence.langfuse_trace_id
                            or latest_trace_id
                        )
                        RegressionRunRepository(session).add_replay(
                            result_id=aggregate_row.id,
                            attempt_id=attempt.id,
                            replay_index=replay_index,
                            target_version=campaign.target_version,
                            valid_replay=replay.outcome.value != "error",
                            judge_verdict=(
                                verdict.model_dump(mode="json") if verdict is not None else None
                            ),
                            evidence_hash=evidence.evidence_hash,
                            error=(
                                None
                                if replay.outcome.value != "error"
                                else {"code": "regression_replay_projection_error"}
                            ),
                            estimated_cost_usd=cost,
                            latency_ms=round(evidence.total_latency_ms),
                            trace_id=latest_trace_id,
                        )
                        replay_results.append(replay)
                        PlatformEventRepository(session).record(
                            event_type="regression_replay_judged",
                            actor="agentforge:regression_harness",
                            campaign_id=campaign.id,
                            attempt_id=attempt.id,
                            finding_id=finding.id,
                            regression_run_id=run.id,
                            trace_id=latest_trace_id,
                            latency_ms=round(evidence.total_latency_ms),
                            cost_usd=cost,
                            details={
                                "case_id": case.case_id,
                                "replay_index": replay_index,
                                "judge_verdict": (
                                    verdict.verdict.value if verdict is not None else None
                                ),
                                "projected_outcome": replay.outcome.value,
                            },
                        )
                        session.commit()
                        if replay.outcome.value in {
                            "vulnerability_reproduced",
                            "error",
                        }:
                            break
                    except _EvidencePersistenceFailure as exc:
                        # Evidence metadata is already committed by
                        # _commit_and_export_evidence. Preserve its specific
                        # failure classification in the replay instead of
                        # collapsing it into a generic regression error.
                        session.expire_all()
                        aggregate_row = session.get(RegressionResult, aggregate_row.id)
                        campaign = session.get(Campaign, campaign.id)
                        run = session.get(RegressionRun, run.id)
                        attempt = (
                            session.get(AttackAttempt, attempt.id) if attempt is not None else None
                        )
                        RegressionRunRepository(session).add_replay(
                            result_id=aggregate_row.id,
                            attempt_id=attempt.id if attempt is not None else None,
                            replay_index=replay_index,
                            target_version=campaign.target_version,
                            valid_replay=False,
                            judge_verdict=None,
                            evidence_hash=(attempt.evidence_hash if attempt is not None else None),
                            error={
                                "code": exc.code,
                                "message": exc.message,
                                "retryable": exc.retryable,
                            },
                            estimated_cost_usd=Decimal("0"),
                            latency_ms=(attempt.latency_ms if attempt is not None else None),
                            trace_id=(attempt.langfuse_trace_id if attempt is not None else None),
                        )
                        session.commit()
                        break
                    except Exception as exc:
                        session.rollback()
                        aggregate_row = session.get(RegressionResult, aggregate_row.id)
                        campaign = session.get(Campaign, campaign.id)
                        run = session.get(RegressionRun, run.id)
                        finding = session.get(Finding, row.finding_id)
                        if attempt is not None:
                            attempt = session.get(AttackAttempt, attempt.id)
                            if attempt is not None:
                                self._fail_attempt(
                                    attempt,
                                    stage="regression",
                                    code="regression_execution_error",
                                    retryable=True,
                                )
                        RegressionRunRepository(session).add_replay(
                            result_id=aggregate_row.id,
                            attempt_id=attempt.id if attempt is not None else None,
                            replay_index=replay_index,
                            target_version=campaign.target_version,
                            valid_replay=False,
                            judge_verdict=None,
                            evidence_hash=(
                                evidence.evidence_hash if evidence is not None else None
                            ),
                            error={
                                "code": "regression_execution_error",
                                "type": type(exc).__name__,
                                "validation_errors": _validation_diagnostics(exc),
                            },
                            estimated_cost_usd=Decimal("0"),
                            latency_ms=(
                                round(evidence.total_latency_ms) if evidence is not None else None
                            ),
                            trace_id=(evidence.langfuse_trace_id if evidence is not None else None),
                        )
                        session.commit()
                        break

                aggregate = aggregate_regression_replays(case, replay_results)
                aggregate_row = session.get(RegressionResult, aggregate_row.id)
                aggregate_row.outcome = aggregate.outcome.value
                aggregate_row.judge_result = {
                    "aggregate": aggregate.model_dump(mode="json"),
                    "replay_verdicts": [
                        replay.judge_verdict.model_dump(mode="json")
                        if replay.judge_verdict is not None
                        else None
                        for replay in replay_results
                    ],
                }
                aggregate_row.evidence_hash = (
                    canonical_hash(aggregate.evidence_hashes) if aggregate.evidence_hashes else None
                )
                aggregate_row.estimated_cost_usd = replay_cost
                aggregate_row.latency_ms = replay_latency or None
                aggregate_row.trace_id = latest_trace_id
                aggregate_row.changed_target_version = aggregate.changed_target_version
                aggregate_row.aggregate_reason = aggregate.summary
                outcomes[aggregate.outcome.value] += 1
                if aggregate.reopen_finding:
                    FindingRepository(session).reopen_from_regression(
                        finding.id,
                        actor="agentforge:regression_harness",
                        evidence_reference=str(aggregate_row.id),
                    )
                report_version = create_report_lifecycle_version(
                    session,
                    finding=finding,
                    template_path=_project_path(Path("config/report-template.md")),
                    event_details={
                        "action": "regression_validation",
                        "actor": "agentforge:regression_harness",
                        "regression_run_id": str(run.id),
                        "regression_result_id": str(aggregate_row.id),
                    },
                    validation_result=FixValidationResultV1(
                        target_version=campaign.target_version,
                        outcome=aggregate.outcome,
                        validated_at=utc_now(),
                        regression_run_id=str(run.id),
                        evidence_hash=aggregate_row.evidence_hash,
                        summary=aggregate.summary,
                    ),
                )
                PlatformEventRepository(session).record(
                    event_type="regression_case_aggregated",
                    actor="agentforge:regression_harness",
                    campaign_id=campaign.id,
                    finding_id=finding.id,
                    regression_run_id=run.id,
                    trace_id=latest_trace_id,
                    cost_usd=replay_cost,
                    details=aggregate.model_dump(mode="json"),
                )
                session.commit()
                if report_version is not None:
                    reports_dir = (
                        self.settings.reports_dir
                        if self.settings.reports_dir.is_absolute()
                        else self.repository_root / self.settings.reports_dir
                    )
                    report_version.markdown_path = str(
                        export_stored_report(
                            report_version,
                            vulnerability_id=finding.vulnerability_id,
                            reports_dir=reports_dir,
                        )
                    )
                    session.commit()

            run = session.get(RegressionRun, run.id)
            campaign = session.get(Campaign, campaign.id)
            run.passed_cases = outcomes["secure_pass"]
            run.reproduced_cases = outcomes["vulnerability_reproduced"]
            run.inconclusive_cases = outcomes["inconclusive"]
            run.error_cases = outcomes["error"]
            run.estimated_cost_usd = campaign.actual_cost_usd
            current_results = {
                case_id: outcome
                for case_id, outcome in session.execute(
                    select(RegressionResult.case_id, RegressionResult.outcome).where(
                        RegressionResult.run_id == run.id
                    )
                )
            }
            improved_categories: set[str] = set()
            regressed_categories: set[str] = set()
            if previous is not None:
                prior_results = {
                    case_id: outcome
                    for case_id, outcome in session.execute(
                        select(
                            RegressionResult.case_id,
                            RegressionResult.outcome,
                        ).where(RegressionResult.run_id == previous.id)
                    )
                }
                category_by_case = {item.id: item.category for item in rows}
                for case_id in set(prior_results) & set(current_results):
                    before = prior_results[case_id]
                    after = current_results[case_id]
                    if before == "vulnerability_reproduced" and after == "secure_pass":
                        run.improved_cases += 1
                        improved_categories.add(category_by_case[case_id])
                    elif before == "secure_pass" and after == "vulnerability_reproduced":
                        run.regressed_cases += 1
                        regressed_categories.add(category_by_case[case_id])
            run.cross_category_regression = any(
                improved != regressed
                for improved in improved_categories
                for regressed in regressed_categories
            )
            run.status = "completed"
            run.completed_at = utc_now()
            PlatformEventRepository(session).record(
                event_type="regression_run_completed",
                actor="agentforge:regression_harness",
                campaign_id=campaign.id,
                regression_run_id=run.id,
                cost_usd=run.estimated_cost_usd,
                details={
                    "outcomes": dict(outcomes),
                    "improved_cases": run.improved_cases,
                    "regressed_cases": run.regressed_cases,
                    "cross_category_regression": run.cross_category_regression,
                },
            )
            session.commit()
            return CampaignProcessResult(
                status="completed",
                actual_cost_usd=campaign.actual_cost_usd,
            )


def build_campaign_controller(
    *,
    database: Database,
    settings: Settings,
    metrics: AgentForgeMetrics | None = None,
    telemetry: LangfuseTelemetry | None = None,
) -> CampaignController:
    """Construct the production controller without performing external calls."""

    from agentforge.agents import (
        AttackGeneratorAgent,
        DocumentationAgent,
        JudgeAgent,
        OrchestratorAgent,
    )
    from agentforge.evaluation import load_judge_rubric, load_taxonomy
    from agentforge.target import load_target_profile

    return CampaignController(
        database=database,
        settings=settings,
        loaded_profile=load_target_profile(_project_path(settings.target_profile_path)),
        taxonomy=load_taxonomy(_project_path(settings.attack_taxonomy_path)),
        rubric=load_judge_rubric(_project_path(settings.judge_rubric_path)),
        orchestrator=OrchestratorAgent(settings=settings, telemetry=telemetry),
        attack_generator=AttackGeneratorAgent(settings=settings, telemetry=telemetry),
        judge=JudgeAgent(settings=settings, telemetry=telemetry),
        documentation=DocumentationAgent(settings=settings, telemetry=telemetry),
        runner=CompositeAttackRunner(),
        telemetry=telemetry,
        metric_registry=metrics,
    )


__all__ = ["CampaignController", "build_campaign_controller"]
