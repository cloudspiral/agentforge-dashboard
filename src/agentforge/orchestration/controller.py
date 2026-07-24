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
    AttackEvidenceV1,
    CampaignObjectiveV1,
    ConfirmedFindingSnapshotV1,
    DocumentationRequestV1,
    EstimatedCostClassV1,
    FindingStatusV1,
    JudgeVerdictKindV1,
    JudgeVerdictV1,
    OrchestratorDecisionV1,
    PriorAttemptOutcomeV1,
    PriorAttemptSummaryV1,
    ProposedAttackV1,
    RequestedActionV1,
    SeverityV1,
)
from agentforge.contracts.v1.common import utc_now
from agentforge.evaluation import JudgeRubricV1, TaxonomyV1
from agentforge.evidence import (
    EvidenceArtifactError,
    EvidenceArtifactStore,
    EvidenceArtifactTooLarge,
)
from agentforge.observability import AgentForgeMetrics, LangfuseTelemetry, metrics
from agentforge.orchestration.execution_gate import (
    CampaignExecutionContextV1,
    GateLimitsV1,
    GateRejectionV1,
    ValidatedAttackV1,
    validate_attack,
)
from agentforge.orchestration.objectives import (
    build_objective,
    canonical_hash,
    deterministic_shortlist,
    endpoint_bindings,
    validate_objective_choice,
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
    RegressionRun,
    TargetVersion,
)
from agentforge.persistence.repositories import (
    FindingRepository,
    RegressionCaseRepository,
    RegressionRunRepository,
    ReportRepository,
)
from agentforge.regression import RegressionCaseV1, build_regression_case, evaluate_regression
from agentforge.reports import export_stored_report, render_vulnerability_report
from agentforge.runners import CompositeAttackRunner
from agentforge.runners.base import TargetExecutionContext
from agentforge.security.redaction import redact
from agentforge.settings import Settings
from agentforge.target import LoadedTargetProfile
from agentforge.target.auth import credentials_from_settings
from agentforge.target.profile import ResolvedTargetAlias
from agentforge.target.version import DiscoveredTargetVersion, discover_target_version

PROJECT_ROOT = Path(__file__).resolve().parents[3]
_HEX_SHA = re.compile(r"^[0-9a-fA-F]{7,64}$")
_CONTROLLER_PROMPT_VERSION = "controller-policy-v2-2026-07-23"

PROPOSAL_AGENT_GENERATED = "agent_generated"
PROPOSAL_AGENT_GENERATED_MUTATION = "agent_generated_mutation"
OBJECTIVE_ORCHESTRATOR_SELECTED = "orchestrator_selected"
FIXED_REGRESSION_CASE = "fixed_regression_case"


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
        retryable: bool,
    ) -> CampaignProcessResult:
        error: dict[str, Any] = {
            "code": code,
            "message": message,
            "retryable": retryable,
        }
        if error_type is not None:
            error["type"] = error_type
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
            estimated_cost_usd=_decimal(result.estimated_cost_usd),
            latency_ms=round(result.latency_ms),
            langfuse_trace_id=result.langfuse_trace_id,
            output_payload=redact(_json(result.output)) if result.output is not None else None,
            typed_error=redact(typed_error if typed_error is not None else _json(result.error))
            if typed_error is not None or result.error is not None
            else None,
        )
        session.add(run)
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

    def _coverage_counts(self, session: Any) -> dict[tuple[str, str], int]:
        return {
            (category, subcategory): int(count)
            for category, subcategory, count in session.execute(
                select(
                    AttackAttempt.category,
                    AttackAttempt.subcategory,
                    func.count(AttackAttempt.id),
                ).group_by(AttackAttempt.category, AttackAttempt.subcategory)
            )
        }

    def _allowed_objectives(
        self,
        campaign: Campaign,
        coverage: dict[tuple[str, str], int],
    ) -> tuple[list[tuple[str, str]], list[dict[str, Any]]]:
        allowed = deterministic_shortlist(
            self.taxonomy,
            category_scope=campaign.category_scope,
            subcategory_scope=campaign.subcategory_scope,
            coverage_counts=coverage,
        )
        details: list[dict[str, Any]] = []
        for category_id, subcategory_id in allowed:
            category = next(item for item in self.taxonomy.categories if item.id == category_id)
            subcategory = next(item for item in category.subcategories if item.id == subcategory_id)
            details.append(
                {
                    "category": category_id,
                    "subcategory": subcategory_id,
                    "description": subcategory.description,
                    "coverage_priority": category.coverage_priority,
                    "prior_attempt_count": coverage.get(
                        (category_id, subcategory_id),
                        0,
                    ),
                    "owasp_web": category.owasp_web,
                    "owasp_llm": category.owasp_llm,
                }
            )
        return allowed, details

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
            upload_surface_id="clinical_document_upload",
            upload_stage_endpoint_id="document_stage",
            upload_reject_endpoint_id="document_reject",
            approved_fixtures={},
            limits=GateLimitsV1(
                max_actions=30,
                max_turns=20,
                max_total_wait_seconds=600,
                max_total_message_bytes=20_000,
                max_upload_count=0,
                max_total_upload_bytes=0,
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
            max_upload_bytes=self.settings.max_upload_bytes,
            approved_fixtures={},
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
    ) -> tuple[JudgeVerdictV1 | None, AgentInvocationResult[Any]]:
        payload = {
            "objective": objective.model_dump(mode="json"),
            "proposal": proposal.model_dump(mode="json"),
            "evidence": evidence.model_dump(mode="json"),
            "rubric": {
                "version": self.rubric.rubric_version,
                "hash": self.rubric_hash,
                "global_rules": self.rubric.global_rules,
                "category": (
                    self.rubric.categories[proposal.category].model_dump(mode="json")
                    if proposal.category in self.rubric.categories
                    else None
                ),
            },
        }
        result = await self.judge.invoke(
            payload,
            campaign_id=str(campaign.id),
            attempt_id=str(attempt.id),
            correlation_id=f"judge-{attempt.id}",
            category=proposal.category,
            target_version=evidence.target_version,
            escalate_to_sol=False,
        )
        if result.output is None:
            return None, result
        verdict = JudgeVerdictV1.model_validate(
            {
                **result.output.model_dump(mode="python"),
                "rubric_version": self.rubric.rubric_version,
                "rubric_hash": self.rubric_hash,
            }
        )
        return verdict, result

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

    async def _document_finding(
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
        fingerprint = canonical_hash(
            {
                "attempt_id": str(attempt.id),
                "evidence_hash": evidence.evidence_hash,
            }
        )
        vulnerability_id = f"AF-{fingerprint[:12].upper()}"
        title = f"{proposal.subcategory.replace('_', ' ').title()} Judge-confirmed security finding"
        finding = FindingRepository(session).create_confirmed(
            fingerprint=fingerprint,
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
                if self._global_cost(session) >= _decimal(self.settings.global_max_cost_usd):
                    return self._failed_result(
                        campaign,
                        code="global_cost_ceiling_reached",
                        message="global model-cost ceiling prevents another iteration",
                        retryable=False,
                    )

                priors = self._prior_attempts(session, campaign.id)
                coverage = self._coverage_counts(session)
                allowed, allowed_details = self._allowed_objectives(campaign, coverage)
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
                orchestrator_payload = {
                    "schema_version": "v1",
                    "campaign_id": str(campaign.id),
                    "target_version": campaign.target_version,
                    "allowed_objectives": allowed_details,
                    "prior_attempts": [item.model_dump(mode="json") for item in priors],
                    "eligible_mutation_attempt_ids": sorted(eligible_mutations),
                    "remaining_limits": {
                        "attempts": remaining_attempts,
                        "duration_seconds": remaining_duration,
                        "cost_usd": str(remaining_cost),
                    },
                    "target_constraints": {
                        "authorized_scope": "synthetic-only",
                        "target_alias": campaign.target_alias,
                        "selected_patient_alias": "patient_a",
                        "persistent_writes": False,
                        "uploads": False,
                    },
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
                )
                if orchestrator_result.output is None:
                    session.commit()
                    return self._failed_result(
                        campaign,
                        code="orchestrator_failed",
                        message="Orchestrator returned no valid decision after bounded retries",
                        retryable=True,
                    )
                decision: OrchestratorDecisionV1 = orchestrator_result.output
                if decision.requested_action == RequestedActionV1.STOP:
                    session.commit()
                    return CampaignProcessResult(
                        status="completed",
                        actual_cost_usd=campaign.actual_cost_usd,
                    )
                if not validate_objective_choice(
                    decision,
                    campaign_id=str(campaign.id),
                    target_version=campaign.target_version,
                    shortlist=allowed,
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
                )
                attack_payload = {
                    "schema_version": "v1",
                    "objective": objective.model_dump(mode="json"),
                    "allowed_action_types": [
                        "reset_session",
                        "authenticate",
                        "select_synthetic_patient",
                        "send_chat_message",
                        "wait_for_response",
                        "collect_evidence",
                    ],
                    "target_constraints": {
                        **objective.relevant_target_profile_subset,
                        "required_sequence_grammar": {
                            "prefix": [
                                "reset_session",
                                "authenticate",
                                "select_synthetic_patient",
                            ],
                            "operation_rule": (
                                "each send_chat_message must be followed immediately "
                                "by wait_for_response"
                            ),
                            "suffix": ["collect_evidence"],
                            "collect_evidence_count": 1,
                        },
                        "exact_controller_owned_values": {
                            "reset_strategy_id": (self.loaded_profile.profile.reset.conversation),
                            "require_clean_context": True,
                            "session_source": "environment_credentials",
                            "test_identity_alias": "physician_test",
                            "expected_role": "physician",
                            "patient_alias": "patient_a",
                            "verify_selected_context": True,
                            "wait_expected_event": "copilot_response_complete",
                            "evidence_kinds": [
                                "transcript",
                                "http_metadata",
                                "tool_calls",
                                "side_effects",
                            ],
                            "capture_on": "always",
                        },
                        "uploads_allowed": False,
                        "persistent_writes_allowed": False,
                    },
                    "prior_outcomes": [item.model_dump(mode="json") for item in priors],
                }
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
                ):
                    self._persist_agent_result(
                        session,
                        campaign=campaign,
                        result=attack_result,
                        status="rejected",
                        typed_error={
                            "stage": "attack_generator",
                            "code": "proposal_scope_mismatch",
                            "retryable": True,
                        },
                    )
                    session.commit()
                    return self._failed_result(
                        campaign,
                        code="proposal_scope_mismatch",
                        message="Attack Generator proposal did not match its objective",
                        retryable=True,
                    )

                stop = self._stop_decision(session, campaign)
                if stop.stop_campaign:
                    self._persist_agent_result(
                        session,
                        campaign=campaign,
                        result=attack_result,
                        status="rejected",
                        typed_error={
                            "stage": "controller",
                            "code": "campaign_limit_reached_before_execution",
                            "retryable": False,
                        },
                    )
                    session.commit()
                    return self._limits_result(campaign, stop)
                if self._global_cost(session) >= _decimal(self.settings.global_max_cost_usd):
                    self._persist_agent_result(
                        session,
                        campaign=campaign,
                        result=attack_result,
                        status="rejected",
                        typed_error={
                            "stage": "controller",
                            "code": "global_cost_ceiling_reached",
                            "retryable": False,
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
                        status="rejected",
                        typed_error={
                            "stage": "authorization",
                            "code": validated.code.value,
                            "retryable": validated.retryable_after_revision,
                        },
                    )
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
                )
                session.add(attempt)
                session.flush()
                self._persist_agent_result(
                    session,
                    campaign=campaign,
                    attempt=attempt,
                    result=attack_result,
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

                verdict, judge_result = await self._judge_evidence(
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
                    failure = await self._document_finding(
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
    def _regression_case(row: RegressionCase, finding: Finding) -> RegressionCaseV1:
        return RegressionCaseV1.model_validate_json(
            json.dumps(
                {
                    "schema_version": "v1",
                    "case_id": row.case_id,
                    "finding_id": str(row.finding_id),
                    "vulnerability_id": finding.vulnerability_id,
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
            rows = RegressionCaseRepository(session).active()
            run.status = "running"
            run.started_at = utc_now()
            run.total_cases = len(rows)
            session.commit()
            outcomes: Counter[str] = Counter()

            for row in rows:
                finding = session.get(Finding, row.finding_id)
                attempt: AttackAttempt | None = None
                evidence: AttackEvidenceV1 | None = None
                judge_result: AgentInvocationResult[Any] | None = None
                try:
                    if finding is None:
                        raise ValueError("regression finding is missing")
                    stop = self._stop_decision(session, campaign)
                    if stop.stop_campaign:
                        break
                    latest_version = await self.version_discoverer(
                        self.loaded_profile,
                        target_alias,
                    )
                    if latest_version.version != campaign.target_version:
                        raise ValueError("target version changed during regression")
                    case = self._regression_case(row, finding)
                    if (
                        case.target_requirements.target_profile_version
                        != self.loaded_profile.profile.profile_version
                    ):
                        raise ValueError("saved case target profile version is no longer active")
                    proposal = ProposedAttackV1(
                        schema_version="v1",
                        proposal_id=f"replay-{case.case_id}",
                        category=case.category,
                        subcategory=case.subcategory,
                        attack_family_id=case.case_id,
                        novelty_rationale="Explicit replay of a saved regression case.",
                        prerequisites=["Approved synthetic regression setup"],
                        ordered_actions=case.exact_ordered_sequence,
                        expected_exploit_signals=[
                            "The Judge observes the saved vulnerability behavior"
                        ],
                        expected_safe_behavior=[case.expected_behavior[:512]],
                        stop_conditions=["Stop after the exact bounded replay"],
                        risk_flags=[],
                        estimated_turns=max(1, len(case.exact_ordered_sequence) - 4),
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
                        raise ValueError(f"regression gate rejected case: {validated.code.value}")
                    attempt = self._new_attempt(
                        attempt_id=uuid.uuid4(),
                        campaign=campaign,
                        objective=objective,
                        proposal=proposal,
                        prompt_version=_CONTROLLER_PROMPT_VERSION,
                        proposal_source=FIXED_REGRESSION_CASE,
                        objective_source=FIXED_REGRESSION_CASE,
                        sequence_hash=validated.sequence_hash,
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
                    if not self._evidence_matches_execution(
                        evidence,
                        campaign=campaign,
                        attempt=attempt,
                        validated=validated,
                    ):
                        raise ValueError("regression evidence correlation failed")
                    self._commit_and_export_evidence(
                        session,
                        campaign=campaign,
                        attempt=attempt,
                        evidence=evidence,
                    )
                    verdict, judge_result = await self._judge_evidence(
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
                        finding=finding,
                        result=judge_result,
                    )
                    result = evaluate_regression(
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
                    attempt.state = "completed" if result.outcome.value != "error" else "failed"
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
                    RegressionRunRepository(session).add_result(
                        run_id=run.id,
                        case_id=row.id,
                        case_version=row.case_version,
                        outcome=result.outcome.value,
                        judge_result=(
                            result.judge_verdict.model_dump(mode="json")
                            if result.judge_verdict is not None
                            else None
                        ),
                        evidence_hash=result.evidence_hash,
                        estimated_cost_usd=(
                            _decimal(judge_result.estimated_cost_usd)
                            if judge_result is not None
                            else Decimal("0")
                        ),
                        latency_ms=round(evidence.total_latency_ms),
                        trace_id=evidence.langfuse_trace_id,
                    )
                    if result.reopen_finding:
                        FindingRepository(session).reopen(finding.id)
                    outcomes[result.outcome.value] += 1
                    session.commit()
                except _EvidencePersistenceFailure as exc:
                    session.rollback()
                    run = session.get(RegressionRun, run.id)
                    campaign = session.get(Campaign, campaign.id)
                    persisted_attempt = (
                        session.get(AttackAttempt, attempt.id) if attempt is not None else None
                    )
                    RegressionRunRepository(session).add_result(
                        run_id=run.id,
                        case_id=row.id,
                        case_version=row.case_version,
                        outcome="error",
                        judge_result={
                            "code": exc.code,
                            "message": exc.message,
                        },
                        evidence_hash=(
                            persisted_attempt.evidence_hash
                            if persisted_attempt is not None
                            else None
                        ),
                        estimated_cost_usd=Decimal("0"),
                        latency_ms=(
                            persisted_attempt.latency_ms if persisted_attempt is not None else None
                        ),
                        trace_id=(
                            persisted_attempt.langfuse_trace_id
                            if persisted_attempt is not None
                            else None
                        ),
                    )
                    run.status = "failed"
                    run.error_cases = outcomes["error"] + 1
                    run.completed_at = utc_now()
                    session.commit()
                    return self._failed_result(
                        campaign,
                        code=exc.code,
                        message=exc.message,
                        retryable=exc.retryable,
                    )
                except Exception as exc:
                    session.rollback()
                    if attempt is not None:
                        attempt = session.get(AttackAttempt, attempt.id)
                        if attempt is not None:
                            self._fail_attempt(
                                attempt,
                                stage="regression",
                                code="regression_execution_error",
                                retryable=True,
                            )
                    outcomes["error"] += 1
                    RegressionRunRepository(session).add_result(
                        run_id=run.id,
                        case_id=row.id,
                        case_version=row.case_version,
                        outcome="error",
                        judge_result={
                            "code": "regression_execution_error",
                            "type": type(exc).__name__,
                            "message": "saved regression case could not be completed",
                            "validation_errors": _validation_diagnostics(exc),
                        },
                        evidence_hash=evidence.evidence_hash if evidence is not None else None,
                        estimated_cost_usd=Decimal("0"),
                        latency_ms=(
                            round(evidence.total_latency_ms) if evidence is not None else None
                        ),
                        trace_id=(evidence.langfuse_trace_id if evidence is not None else None),
                    )
                    session.commit()

            run = session.get(RegressionRun, run.id)
            campaign = session.get(Campaign, campaign.id)
            run.passed_cases = outcomes["secure_pass"]
            run.reproduced_cases = outcomes["vulnerability_reproduced"]
            run.inconclusive_cases = outcomes["inconclusive"]
            run.error_cases = outcomes["error"]
            run.estimated_cost_usd = campaign.actual_cost_usd
            run.status = "completed"
            run.completed_at = utc_now()
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
