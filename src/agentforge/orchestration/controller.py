"""Authoritative hub-and-spoke campaign controller.

Agents may recommend objectives, attacks, verdicts, and report prose.  This
module alone owns target-version discovery, budget reservation, execution-gate
authorization, target execution, deterministic evaluation, and persistence.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections import Counter
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime, timedelta
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
    EvidenceReferenceKindV1,
    EvidenceReferenceV1,
    ExploitabilityV1,
    FindingStatusV1,
    JudgeRecommendedActionV1,
    JudgeVerdictKindV1,
    JudgeVerdictV1,
    MinimalEvidencePackageV1,
    PriorAttemptOutcomeV1,
    PriorAttemptSummaryV1,
    ProposedAttackV1,
    RequestedActionV1,
    SeverityV1,
)
from agentforge.contracts.v1.common import utc_now
from agentforge.evaluation import (
    JudgeRubricV1,
    SeedCaseV1,
    TaxonomyV1,
)
from agentforge.evaluation.deterministic import (
    DeterministicEvaluationV1,
    evaluate_deterministically,
)
from agentforge.evaluation.judge_service import reconcile_judge_verdict
from agentforge.observability import AgentForgeMetrics, LangfuseTelemetry, metrics
from agentforge.orchestration.budgets import (
    BudgetAccountV1,
    BudgetLimitsV1,
    BudgetStateV1,
    BudgetUsageV1,
    PricingConfigV1,
    TokenUsageV1,
    load_pricing_config,
    reconcile_actual_usage,
    release_reservation,
    reserve_worst_case,
)
from agentforge.orchestration.execution_gate import (
    CampaignExecutionContextV1,
    GateLimitsV1,
    GateRejectionV1,
    ValidatedAttackV1,
    proposal_sequence_hash,
    validate_attack,
)
from agentforge.orchestration.objectives import (
    build_objective,
    build_security_invariants,
    canonical_hash,
    choose_seed_case,
    deterministic_shortlist,
    endpoint_bindings,
    proposal_from_seed,
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
_CONTROLLER_PROMPT_VERSION = "controller-policy-v1-2026-07-21"
_MAX_INPUT_PER_CALL = 8_000

PROPOSAL_AGENT_GENERATED = "agent_generated"
PROPOSAL_AGENT_GENERATED_MUTATION = "agent_generated_mutation"
PROPOSAL_DETERMINISTIC_FALLBACK = "deterministic_seed_fallback"
OBJECTIVE_ORCHESTRATOR_SELECTED = "orchestrator_selected"
OBJECTIVE_DETERMINISTIC_FALLBACK = "deterministic_ranked_fallback"


@dataclass(frozen=True, slots=True)
class DiscoveryIterationResult:
    terminal_result: CampaignProcessResult | None = None
    prior_attempt: PriorAttemptSummaryV1 | None = None
    mutation_candidate: bool = False
    deterministic_fallback_candidate: bool = False
    no_signal: bool = False
    gate_rejected: bool = False


class VersionDiscoverer(Protocol):
    async def __call__(
        self,
        loaded_profile: LoadedTargetProfile,
        target_alias: ResolvedTargetAlias,
    ) -> DiscoveredTargetVersion: ...


def _project_path(path: Path) -> Path:
    return path if path.is_absolute() else PROJECT_ROOT / path


def _decimal(value: float | Decimal | int) -> Decimal:
    return Decimal(str(value))


def _json(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value


def _rehash_evidence(
    evidence: AttackEvidenceV1,
    *,
    assertion_results: list[Any] | None = None,
    trace_id: str | None = None,
) -> AttackEvidenceV1:
    values = evidence.model_dump(mode="python")
    if assertion_results is not None:
        values["deterministic_assertion_results"] = assertion_results
    if trace_id is not None:
        values["langfuse_trace_id"] = trace_id
    values["evidence_hash"] = "0" * 64
    draft = AttackEvidenceV1.model_validate(values)
    canonical = json.dumps(
        draft.model_dump(mode="json", exclude={"evidence_hash"}),
        sort_keys=True,
        separators=(",", ":"),
    )
    return AttackEvidenceV1.model_validate(
        {
            **draft.model_dump(mode="python"),
            "evidence_hash": hashlib.sha256(canonical.encode()).hexdigest(),
        }
    )


def _normalized_actions(proposal: ProposedAttackV1) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for action in proposal.ordered_actions:
        value = action.model_dump(mode="json")
        value.pop("action_id", None)
        value.pop("description", None)
        value.pop("conversation_alias", None)
        normalized.append(value)
    return normalized


def _finding_fingerprint(
    proposal: ProposedAttackV1,
    deterministic: DeterministicEvaluationV1,
) -> str:
    return canonical_hash(
        {
            "category": proposal.category,
            "subcategory": proposal.subcategory,
            "actions": _normalized_actions(proposal),
            "violated_invariants": sorted(deterministic.proven_violation_ids),
        }
    )


def _usage_from_result(result: AgentInvocationResult[Any]) -> TokenUsageV1:
    usage = result.usage
    cached = usage.tokens.cached_input_tokens
    cache_write = usage.cache_write_input_tokens
    total_input = usage.tokens.input_tokens
    return TokenUsageV1(
        model=result.model,
        calls=max(usage.tokens.calls, result.sdk_attempts),
        input_tokens=max(0, total_input - cached - cache_write),
        cached_input_tokens=cached,
        cache_write_tokens=cache_write,
        output_tokens=usage.tokens.output_tokens,
    )


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
    """Run one already-claimed campaign within hard deterministic bounds."""

    def __init__(
        self,
        *,
        database: Database,
        settings: Settings,
        loaded_profile: LoadedTargetProfile,
        taxonomy: TaxonomyV1,
        rubric: JudgeRubricV1,
        seeds: list[SeedCaseV1],
        pricing: PricingConfigV1,
        orchestrator: Any,
        attack_generator: Any,
        judge: Any,
        documentation: Any,
        runner: Any,
        telemetry: LangfuseTelemetry | None = None,
        metric_registry: AgentForgeMetrics | None = None,
        version_discoverer: VersionDiscoverer = _discover_version,
        repository_root: Path = PROJECT_ROOT,
    ) -> None:
        self.database = database
        self.settings = settings
        self.loaded_profile = loaded_profile
        self.taxonomy = taxonomy
        self.rubric = rubric
        self.seeds = seeds
        self.pricing = pricing
        self.orchestrator = orchestrator
        self.attack_generator = attack_generator
        self.judge = judge
        self.documentation = documentation
        self.runner = runner
        self.telemetry = telemetry
        self.metrics = metric_registry or metrics
        self.version_discoverer = version_discoverer
        self.repository_root = repository_root.resolve()
        self.rubric_hash = canonical_hash(rubric.model_dump(mode="json"))
        self.allowed_categories = {
            category.id: [subcategory.id for subcategory in category.subcategories]
            for category in taxonomy.categories
        }

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
                    campaign.target_alias, self.settings
                )
                discovered = await self.version_discoverer(self.loaded_profile, target_alias)
            except Exception as exc:
                return CampaignProcessResult(
                    status="failed",
                    actual_cost_usd=campaign.actual_cost_usd,
                    sanitized_error=redact(
                        {
                            "code": "target_version_discovery_failed",
                            "type": type(exc).__name__,
                            "message": "approved target health/version discovery failed",
                        }
                    ),
                )
            campaign.target_version = discovered.version
            self._record_target_version(session, campaign, discovered)
            session.commit()

        scope = (
            self.telemetry.campaign(
                campaign_id=str(campaign_id),
                campaign_type=campaign.campaign_type,
                category=campaign.category_scope,
                target_version=discovered.version,
                input={"target_alias": campaign.target_alias, "bounded": True},
            )
            if self.telemetry is not None
            else nullcontext(None)
        )
        with scope as observation:
            try:
                if campaign.campaign_type == "regression":
                    result = await self._process_regression(campaign_id, target_alias)
                else:
                    result = await self._process_discovery(campaign_id, target_alias)
            except Exception as exc:
                with self.database.session_factory() as failure_session:
                    unfinished = list(
                        failure_session.scalars(
                            select(AttackAttempt)
                            .where(AttackAttempt.campaign_id == campaign_id)
                            .where(
                                AttackAttempt.status.in_(
                                    {"proposed", "executing", "evaluating", "documenting"}
                                )
                            )
                        )
                    )
                    for attempt in unfinished:
                        attempt.status = "error"
                        attempt.completed_at = utc_now()
                    failure_session.commit()
                result = CampaignProcessResult(
                    status="failed",
                    actual_cost_usd=campaign.actual_cost_usd,
                    sanitized_error=redact(
                        {
                            "code": "controller_workflow_failed",
                            "type": type(exc).__name__,
                            "message": "campaign workflow failed before a terminal result",
                            "retryable": True,
                        }
                    ),
                )
            if observation is not None:
                observation.update(
                    output={"status": result.status, "actual_cost_usd": str(result.actual_cost_usd)}
                )
            return result

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
                    git_sha=discovered.version if _HEX_SHA.fullmatch(discovered.version) else None,
                    deployment_id=None,
                    base_url_alias=campaign.target_alias,
                    target_profile_hash=self.loaded_profile.profile_hash,
                    metadata_json=metadata,
                )
            )
        else:
            target.target_profile_hash = self.loaded_profile.profile_hash
            target.metadata_json = metadata

    def _initial_budget_state(self, session: Any, campaign: Campaign) -> BudgetStateV1:
        global_row = session.execute(
            select(
                func.count(AgentRun.id),
                func.coalesce(func.sum(AgentRun.input_tokens), 0),
                func.coalesce(func.sum(AgentRun.output_tokens), 0),
                func.coalesce(func.sum(AgentRun.estimated_cost_usd), 0),
            )
        ).one()
        campaign_row = session.execute(
            select(
                func.count(AgentRun.id),
                func.coalesce(func.sum(AgentRun.input_tokens), 0),
                func.coalesce(func.sum(AgentRun.output_tokens), 0),
                func.coalesce(func.sum(AgentRun.estimated_cost_usd), 0),
            ).where(AgentRun.campaign_id == campaign.id)
        ).one()

        def usage(row: Any) -> BudgetUsageV1:
            return BudgetUsageV1(
                calls=int(row[0]),
                input_tokens=int(row[1]),
                output_tokens=int(row[2]),
                cost_usd=_decimal(row[3]),
            )

        return BudgetStateV1(
            global_account=BudgetAccountV1(
                limits=BudgetLimitsV1(
                    max_cost_usd=_decimal(self.settings.global_max_cost_usd),
                    max_calls=10_000,
                    max_input_tokens=100_000_000,
                    max_output_tokens=20_000_000,
                ),
                actual=usage(global_row),
            ),
            campaign_account=BudgetAccountV1(
                limits=BudgetLimitsV1(
                    max_cost_usd=campaign.max_cost_usd,
                    max_calls=max(5, campaign.max_attempts * 5),
                    max_input_tokens=max(40_000, campaign.max_attempts * 40_000),
                    max_output_tokens=max(6_100, campaign.max_attempts * 6_100),
                ),
                actual=usage(campaign_row),
            ),
        )

    def _worst_case_usage(self, *, include_generation: bool = True) -> list[TokenUsageV1]:
        roles: list[tuple[str, int]] = []
        if include_generation:
            roles.extend(
                [
                    (self.settings.openai_orchestrator_model, 900),
                    (self.settings.openai_attack_model, 1_200),
                    (self.settings.openai_attack_model, 1_200),
                ]
            )
        roles.append((self.settings.openai_judge_model, 1_000))
        if include_generation:
            roles.append((self.settings.openai_documentation_model, 1_800))
        return [
            TokenUsageV1(
                model=model,
                calls=1,
                input_tokens=_MAX_INPUT_PER_CALL,
                cached_input_tokens=0,
                cache_write_tokens=0,
                output_tokens=output_tokens,
            )
            for model, output_tokens in roles
        ]

    def _persist_agent_runs(
        self,
        session: Any,
        *,
        campaign_id: uuid.UUID,
        attempt_id: uuid.UUID | None,
        finding_id: uuid.UUID | None,
        results: list[AgentInvocationResult[Any]],
    ) -> None:
        for result in results:
            session.add(
                AgentRun(
                    campaign_id=campaign_id,
                    attempt_id=attempt_id,
                    finding_id=finding_id,
                    role=result.role,
                    prompt_version=result.prompt_version,
                    model=result.model,
                    status="succeeded" if result.succeeded else "failed",
                    input_tokens=result.usage.tokens.input_tokens,
                    output_tokens=result.usage.tokens.output_tokens,
                    estimated_cost_usd=_decimal(result.estimated_cost_usd),
                    latency_ms=round(result.latency_ms),
                    langfuse_trace_id=result.langfuse_trace_id,
                    typed_error=_json(result.error) if result.error else None,
                )
            )
            status = "succeeded" if result.succeeded else "failed"
            self.metrics.agent_latency_seconds.labels(
                role=result.role, model=result.model, status=status
            ).observe(result.latency_ms / 1_000)
            for token_type, count in (
                ("input", result.usage.tokens.input_tokens),
                ("cached_input", result.usage.tokens.cached_input_tokens),
                ("output", result.usage.tokens.output_tokens),
            ):
                self.metrics.agent_tokens_total.labels(
                    role=result.role, model=result.model, token_type=token_type
                ).inc(count)
            self.metrics.agent_estimated_cost_usd_total.labels(
                role=result.role, model=result.model
            ).inc(result.estimated_cost_usd)

    @staticmethod
    def _update_attempt_usage(
        attempt: AttackAttempt,
        results: list[AgentInvocationResult[Any]],
    ) -> None:
        attempt.input_tokens = sum(result.usage.tokens.input_tokens for result in results)
        attempt.output_tokens = sum(result.usage.tokens.output_tokens for result in results)
        attempt.estimated_cost_usd = sum(
            (_decimal(result.estimated_cost_usd) for result in results),
            start=Decimal("0"),
        )

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
        fallback_reason: str | None,
        mutation_generation: int,
        sequence_hash: str,
    ) -> AttackAttempt:
        parent_attempt_id: uuid.UUID | None = None
        if proposal.parent_attempt_id is not None:
            try:
                parent_attempt_id = uuid.UUID(proposal.parent_attempt_id)
            except ValueError:
                parent_attempt_id = None
        return AttackAttempt(
            id=attempt_id,
            campaign_id=campaign.id,
            attack_family_id=proposal.attack_family_id,
            lineage_id=proposal.lineage_id,
            parent_attempt_id=parent_attempt_id,
            mutation_generation=mutation_generation,
            proposal_source=proposal_source,
            objective_source=objective_source,
            proposal_fallback_reason=fallback_reason,
            sequence_hash=sequence_hash,
            category=proposal.category,
            subcategory=proposal.subcategory,
            owasp_mappings=objective.owasp_mappings.model_dump(mode="json"),
            objective=objective.objective,
            proposed_sequence=proposal.model_dump(mode="json"),
            taxonomy_version=self.taxonomy.taxonomy_version,
            profile_version=self.loaded_profile.profile.profile_version,
            prompt_version=prompt_version,
            status="proposed",
            started_at=utc_now(),
        )

    def _gate_context(
        self,
        *,
        campaign: Campaign,
        objective: CampaignObjectiveV1,
        budget_state: BudgetStateV1,
        reservation: Any,
        deadline: datetime,
        sequence_counts: Counter[str],
        patient_alias: str = "patient_a",
        identity_alias: str = "physician_test",
        expected_role: str = "physician",
    ) -> CampaignExecutionContextV1:
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
                max_worst_case_cost_usd=reservation.worst_case_total.cost_usd,
                max_total_wait_seconds=600,
                max_total_message_bytes=20_000,
                max_upload_count=0,
                max_total_upload_bytes=0,
                max_sequence_repetitions=1,
            ),
            campaign_started_at=campaign.started_at,
            campaign_deadline_at=deadline,
            budget_state=budget_state,
            budget_reservation=reservation,
            attempted_sequence_counts=dict(sequence_counts),
            cancellation_requested=campaign.cancellation_requested,
            cleanup_succeeded=True,
        )

    def _fallback_judge(
        self,
        *,
        expected_behavior: str,
        deterministic_override: bool = False,
    ) -> JudgeVerdictV1:
        return JudgeVerdictV1(
            schema_version="v1",
            verdict=JudgeVerdictKindV1.INCONCLUSIVE,
            severity=SeverityV1.NONE,
            exploitability=ExploitabilityV1.NOT_APPLICABLE,
            confidence=0.0,
            supporting_evidence_references=[],
            violated_security_invariants=[],
            observed_behavior=(
                "Semantic judgment was unavailable; deterministic evidence remains authoritative."
            ),
            expected_behavior=expected_behavior,
            recommended_next_action=JudgeRecommendedActionV1.REPRODUCE,
            reproduce_again=True,
            create_or_update_finding=False,
            add_regression_candidate=False,
            rubric_version=self.rubric.rubric_version,
            rubric_hash=self.rubric_hash,
            deterministic_override_applied=deterministic_override,
            deterministic_override_assertion_ids=(
                ["semantic-judgment-unavailable"] if deterministic_override else []
            ),
        )

    async def _judge_evidence(
        self,
        *,
        campaign: Campaign,
        attempt_id: uuid.UUID,
        objective: CampaignObjectiveV1,
        proposal: ProposedAttackV1,
        evidence: AttackEvidenceV1,
        deterministic: DeterministicEvaluationV1,
        invariants: list[Any],
    ) -> tuple[JudgeVerdictV1, AgentInvocationResult[Any]]:
        evidence_reference = EvidenceReferenceV1(
            reference_id=f"evidence-{evidence.evidence_hash[:16]}",
            kind=EvidenceReferenceKindV1.OTHER,
            artifact_path=None,
            description="Frozen sanitized evidence package persisted for this attempt.",
        )
        payload = {
            "objective": objective.model_dump(mode="json"),
            "executed_sequence": [
                item.model_dump(mode="json") for item in evidence.executed_action_sequence
            ],
            "sanitized_transcript": [item.model_dump(mode="json") for item in evidence.transcript],
            "http_metadata": [
                item.model_dump(mode="json") for item in evidence.sanitized_http_metadata
            ],
            "target_visible_tool_calls": [
                item.model_dump(mode="json") for item in evidence.target_visible_tool_calls
            ],
            "side_effects": [item.model_dump(mode="json") for item in evidence.side_effects],
            "deterministic_evaluation": deterministic.model_dump(mode="json"),
            "security_invariants": [item.model_dump(mode="json") for item in invariants],
            "rubric": {
                "version": self.rubric.rubric_version,
                "hash": self.rubric_hash,
                "global_rules": self.rubric.global_rules,
                "category": self.rubric.categories.get(proposal.category).model_dump(mode="json")
                if proposal.category in self.rubric.categories
                else None,
            },
            "allowed_evidence_references": [evidence_reference.model_dump(mode="json")],
            "target_version": evidence.target_version,
        }
        result = await self.judge.invoke(
            payload,
            campaign_id=str(campaign.id),
            attempt_id=str(attempt_id),
            correlation_id=f"judge-{attempt_id}",
            category=proposal.category,
            target_version=evidence.target_version,
            escalate_to_sol=False,
        )
        semantic = self._fallback_judge(expected_behavior=objective.objective)
        if result.output is not None:
            known_refs = {
                evidence_reference.reference_id,
                *(f"assertion-{item.invariant_id}" for item in deterministic.assertion_results),
            }
            if all(
                reference.reference_id in known_refs
                for reference in result.output.supporting_evidence_references
            ):
                semantic = JudgeVerdictV1.model_validate(
                    {
                        **result.output.model_dump(mode="python"),
                        "rubric_version": self.rubric.rubric_version,
                        "rubric_hash": self.rubric_hash,
                    }
                )
        return reconcile_judge_verdict(semantic, deterministic, invariants), result

    def _persist_verdict(
        self,
        session: Any,
        *,
        attempt_id: uuid.UUID,
        verdict: JudgeVerdictV1,
    ) -> None:
        session.add(
            JudgeVerdict(
                attempt_id=attempt_id,
                verdict=verdict.verdict.value,
                severity=verdict.severity.value,
                exploitability=verdict.exploitability.value,
                confidence=verdict.confidence,
                evidence_references=[
                    item.reference_id for item in verdict.supporting_evidence_references
                ],
                violated_invariants=verdict.violated_security_invariants,
                next_recommendation=verdict.recommended_next_action.value,
                rubric_hash=self.rubric_hash,
                rubric_version=self.rubric.rubric_version,
                deterministic_override_applied=verdict.deterministic_override_applied,
                deterministic_override_reason=(
                    "Deterministic invariant evidence controlled the final verdict."
                    if verdict.deterministic_override_applied
                    else None
                ),
            )
        )

    def _execution_context(
        self,
        *,
        campaign: Campaign,
        attempt_id: uuid.UUID,
        target_alias: ResolvedTargetAlias,
        target_version: str,
        validated: ValidatedAttackV1,
    ) -> TargetExecutionContext:
        fixtures = {
            fixture.fixture_id: __import__(
                "agentforge.target.fixtures", fromlist=["ApprovedFixtureAuthorization"]
            ).ApprovedFixtureAuthorization(
                fixture_id=fixture.fixture_id,
                repository_relative_path=fixture.repository_relative_path,
                document_type=fixture.document_type,
                media_type=fixture.media_type,
                size_bytes=fixture.size_bytes,
                pages=fixture.pages,
                sha256=fixture.sha256,
            )
            for fixture in validated.authorized_fixtures
        }
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
            target_version=target_version,
            selected_patient_alias=validated.selected_patient_alias,
            loaded_profile=self.loaded_profile,
            target_alias=target_alias,
            repository_root=self.repository_root,
            artifacts_dir=artifacts_dir,
            credentials=credentials,
            max_upload_bytes=self.settings.max_upload_bytes,
            approved_fixtures=fixtures,
        )

    def _reconcile_budget(
        self,
        *,
        campaign: Campaign,
        budget_state: BudgetStateV1,
        reservation: Any,
        results: list[AgentInvocationResult[Any]],
    ) -> Decimal:
        if results:
            reconciliation = reconcile_actual_usage(
                budget_state,
                reservation,
                [_usage_from_result(result) for result in results],
                self.pricing,
            )
            campaign.actual_cost_usd += reconciliation.actual_total.cost_usd
        else:
            release_reservation(budget_state, reservation)
        return campaign.actual_cost_usd

    @staticmethod
    def _evidence_reference(evidence: AttackEvidenceV1) -> EvidenceReferenceV1:
        return EvidenceReferenceV1(
            reference_id=f"evidence-{evidence.evidence_hash[:16]}",
            kind=EvidenceReferenceKindV1.OTHER,
            artifact_path=None,
            description="Frozen sanitized evidence package persisted for this attempt.",
        )

    @staticmethod
    def _prior_attempt_summary(
        attempt: AttackAttempt,
        *,
        outcome: PriorAttemptOutcomeV1,
        summary: str,
    ) -> PriorAttemptSummaryV1:
        if attempt.sequence_hash is None:
            raise ValueError("completed discovery attempt is missing its sequence hash")
        return PriorAttemptSummaryV1(
            attempt_id=str(attempt.id),
            attack_family_id=attempt.attack_family_id,
            lineage_id=attempt.lineage_id or attempt.attack_family_id,
            mutation_generation=attempt.mutation_generation,
            outcome=outcome,
            summary=summary[:1_000],
            sequence_hash=attempt.sequence_hash,
            evidence_hash=attempt.evidence_hash,
        )

    @staticmethod
    def _action_stop_reason(
        session: Any,
        campaign: Campaign,
        deadline: datetime,
    ) -> str | None:
        session.refresh(campaign)
        if campaign.cancellation_requested:
            return "cancellation_requested"
        if utc_now() >= deadline:
            return "campaign_deadline_exceeded"
        return None

    async def _process_discovery(
        self,
        campaign_id: uuid.UUID,
        target_alias: ResolvedTargetAlias,
    ) -> CampaignProcessResult:
        prior_attempts: list[PriorAttemptSummaryV1] = []
        consecutive_no_signal = 0
        current_lineage_mutations = 0
        mutation_source: PriorAttemptSummaryV1 | None = None
        force_deterministic_fallback = False
        had_target_result = False
        last_gate_rejection: dict[str, Any] | None = None
        with self.database.session_factory() as session:
            sequence_counts: Counter[str] = Counter(
                value
                for value in session.scalars(
                    select(AttackAttempt.sequence_hash)
                    .where(AttackAttempt.campaign_id == campaign_id)
                    .where(AttackAttempt.sequence_hash.is_not(None))
                )
                if value is not None
            )

        while True:
            with self.database.session_factory() as session:
                campaign = session.get(Campaign, campaign_id)
                if campaign is None:
                    return CampaignProcessResult(
                        status="failed",
                        sanitized_error={
                            "code": "campaign_not_found",
                            "message": "campaign not found",
                        },
                    )
                if campaign.started_at is None:
                    return CampaignProcessResult(
                        status="failed",
                        actual_cost_usd=campaign.actual_cost_usd,
                        sanitized_error={
                            "code": "campaign_not_started",
                            "message": "campaign has no controller start time",
                        },
                    )
                budget_state = self._initial_budget_state(session, campaign)
                stop = evaluate_stopping(
                    CampaignStopStateV1(
                        attempts_completed=campaign.actual_attempts,
                        max_attempts=campaign.max_attempts,
                        campaign_started_at=campaign.started_at,
                        evaluated_at=utc_now(),
                        max_duration_seconds=campaign.max_duration_seconds,
                        consecutive_no_signal_attempts=consecutive_no_signal,
                        max_consecutive_no_signal_attempts=campaign.no_signal_limit,
                        current_lineage_mutations=current_lineage_mutations,
                        max_mutations_per_lineage=campaign.max_mutations,
                        cancellation_requested=campaign.cancellation_requested,
                        cleanup_failed=False,
                        budget_state=budget_state,
                    )
                )
                if stop.stop_current_lineage:
                    mutation_source = None
                    current_lineage_mutations = 0
                if stop.stop_campaign:
                    if campaign.cancellation_requested:
                        return CampaignProcessResult(
                            status="cancelled",
                            actual_cost_usd=campaign.actual_cost_usd,
                            sanitized_error={
                                "code": "cancellation_requested",
                                "message": "campaign cancellation was requested",
                            },
                        )
                    if had_target_result:
                        return CampaignProcessResult(
                            status="completed",
                            actual_cost_usd=campaign.actual_cost_usd,
                        )
                    return CampaignProcessResult(
                        status="failed",
                        actual_cost_usd=campaign.actual_cost_usd,
                        sanitized_error=last_gate_rejection
                        or {
                            "code": "campaign_stopped",
                            "message": "campaign limits prevented an executable attempt",
                            "reasons": [reason.value for reason in stop.reasons],
                        },
                    )

            iteration = await self._process_discovery_iteration(
                campaign_id,
                target_alias,
                prior_attempts=prior_attempts,
                mutation_source=mutation_source,
                force_deterministic_fallback=force_deterministic_fallback,
                current_lineage_mutations=current_lineage_mutations,
                consecutive_no_signal=consecutive_no_signal,
                sequence_counts=sequence_counts,
            )
            if iteration.terminal_result is not None:
                return iteration.terminal_result
            if iteration.prior_attempt is not None:
                prior_attempts.append(iteration.prior_attempt)
                prior_attempts = prior_attempts[-20:]
                sequence_counts[iteration.prior_attempt.sequence_hash] += 1
            if iteration.gate_rejected:
                last_gate_rejection = {
                    "code": "execution_gate_rejected",
                    "message": "the deterministic execution gate rejected every proposal",
                }
            else:
                had_target_result = had_target_result or iteration.prior_attempt is not None
            consecutive_no_signal = consecutive_no_signal + 1 if iteration.no_signal else 0
            force_deterministic_fallback = iteration.deterministic_fallback_candidate
            if iteration.mutation_candidate and iteration.prior_attempt is not None:
                mutation_source = iteration.prior_attempt
                current_lineage_mutations = iteration.prior_attempt.mutation_generation
            else:
                mutation_source = None
                current_lineage_mutations = 0

    async def _process_discovery_iteration(
        self,
        campaign_id: uuid.UUID,
        target_alias: ResolvedTargetAlias,
        *,
        prior_attempts: list[PriorAttemptSummaryV1],
        mutation_source: PriorAttemptSummaryV1 | None,
        force_deterministic_fallback: bool,
        current_lineage_mutations: int,
        consecutive_no_signal: int,
        sequence_counts: Counter[str],
    ) -> DiscoveryIterationResult:
        attempt_id = uuid.uuid4()
        agent_results: list[AgentInvocationResult[Any]] = []
        with self.database.session_factory() as session:
            campaign = session.scalar(
                select(Campaign).where(Campaign.id == campaign_id).with_for_update()
            )
            if campaign is None:
                return DiscoveryIterationResult(
                    terminal_result=CampaignProcessResult(
                        status="failed",
                        sanitized_error={
                            "code": "campaign_not_found",
                            "message": "campaign not found",
                        },
                    )
                )
            deadline = campaign.started_at + timedelta(seconds=campaign.max_duration_seconds)
            budget_state = self._initial_budget_state(session, campaign)

            reservation_result = reserve_worst_case(
                budget_state,
                campaign_id=str(campaign.id),
                reservation_id=f"discovery-{attempt_id}",
                worst_case_by_model=self._worst_case_usage(),
                pricing=self.pricing,
                reserved_at=utc_now(),
            )
            if not reservation_result.approved or reservation_result.reservation is None:
                return DiscoveryIterationResult(
                    terminal_result=CampaignProcessResult(
                        status="failed",
                        actual_cost_usd=campaign.actual_cost_usd,
                        sanitized_error={
                            "code": "budget_reservation_rejected",
                            "message": "campaign budget could not reserve bounded role usage",
                            "breaches": [item.value for item in reservation_result.breaches],
                        },
                    )
                )
            budget_state = reservation_result.state
            reservation = reservation_result.reservation

            coverage = {
                (category, subcategory): count
                for category, subcategory, count in session.execute(
                    select(
                        AttackAttempt.category,
                        AttackAttempt.subcategory,
                        func.count(AttackAttempt.id),
                    ).group_by(AttackAttempt.category, AttackAttempt.subcategory)
                )
            }
            shortlist = deterministic_shortlist(
                self.taxonomy,
                category_scope=campaign.category_scope,
                subcategory_scope=campaign.subcategory_scope,
                coverage_counts=coverage,
            )
            if not shortlist:
                return DiscoveryIterationResult(
                    terminal_result=CampaignProcessResult(
                        status="failed",
                        actual_cost_usd=campaign.actual_cost_usd,
                        sanitized_error={
                            "code": "empty_objective_scope",
                            "message": "campaign scope does not match the loaded taxonomy",
                        },
                    )
                )
            source_attempt = (
                session.get(AttackAttempt, uuid.UUID(mutation_source.attempt_id))
                if mutation_source is not None
                else None
            )
            mutation_is_allowed = bool(
                source_attempt is not None
                and source_attempt.mutation_generation < campaign.max_mutations
                and (source_attempt.category, source_attempt.subcategory) in shortlist
            )
            category, subcategory = (
                (source_attempt.category, source_attempt.subcategory)
                if mutation_is_allowed and source_attempt is not None
                else shortlist[0]
            )
            fallback_action = (
                RequestedActionV1.MUTATION if mutation_is_allowed else RequestedActionV1.NEW_ATTACK
            )
            fallback_mutation_source_id = (
                str(source_attempt.id)
                if fallback_action == RequestedActionV1.MUTATION and source_attempt is not None
                else None
            )
            fallback_objective = build_objective(
                campaign_id=str(campaign.id),
                campaign_type=campaign.campaign_type,
                target_version=campaign.target_version,
                taxonomy=self.taxonomy,
                category_id=category,
                subcategory_id=subcategory,
                remaining_cost_usd=campaign.max_cost_usd - campaign.actual_cost_usd,
                remaining_attempts=campaign.max_attempts - campaign.actual_attempts,
                remaining_duration_seconds=max(0, int((deadline - utc_now()).total_seconds())),
                max_mutations=campaign.max_mutations,
                no_signal_limit=campaign.no_signal_limit,
                relevant_prior_attempts=prior_attempts,
                requested_action=fallback_action,
                mutation_source_attempt_id=fallback_mutation_source_id,
            )
            stop_reason = self._action_stop_reason(session, campaign, deadline)
            if stop_reason is not None:
                release_reservation(budget_state, reservation)
                return DiscoveryIterationResult(
                    terminal_result=CampaignProcessResult(
                        status=(
                            "cancelled" if stop_reason == "cancellation_requested" else "failed"
                        ),
                        actual_cost_usd=campaign.actual_cost_usd,
                        sanitized_error={
                            "code": stop_reason,
                            "message": "campaign stopped before Orchestrator invocation",
                        },
                    )
                )
            orchestrator_result = await self.orchestrator.invoke(
                {
                    "deterministic_shortlist": shortlist,
                    "coverage_counts": {
                        f"{item_category}/{item_subcategory}": count
                        for (item_category, item_subcategory), count in coverage.items()
                    },
                    "relevant_prior_attempts": [
                        item.model_dump(mode="json") for item in prior_attempts
                    ],
                    "remaining_limits": fallback_objective.remaining_budget_and_limits.model_dump(
                        mode="json"
                    ),
                    "authoritative_objective": fallback_objective.model_dump(mode="json"),
                },
                campaign_id=str(campaign.id),
                attempt_id=str(attempt_id),
                category=category,
                target_version=campaign.target_version,
            )
            agent_results.append(orchestrator_result)
            objective = fallback_objective
            objective_source = OBJECTIVE_DETERMINISTIC_FALLBACK
            allowed_mutation_ids = (
                {str(source_attempt.id)}
                if mutation_is_allowed and source_attempt is not None
                else set()
            )
            if orchestrator_result.output is not None and validate_objective_choice(
                orchestrator_result.output,
                campaign_id=str(campaign.id),
                target_version=campaign.target_version,
                shortlist=shortlist,
                allowed_mutation_source_ids=allowed_mutation_ids,
            ):
                selected = orchestrator_result.output
                selected_source = (
                    session.get(AttackAttempt, uuid.UUID(selected.mutation_source_attempt_id))
                    if selected.mutation_source_attempt_id is not None
                    else None
                )
                mutation_matches_lineage = bool(
                    selected.requested_action != RequestedActionV1.MUTATION
                    or (
                        selected_source is not None
                        and selected_source.category == selected.selected_category
                        and selected_source.subcategory == selected.selected_subcategory
                        and selected_source.mutation_generation < campaign.max_mutations
                    )
                )
                if mutation_matches_lineage:
                    objective = build_objective(
                        campaign_id=str(campaign.id),
                        campaign_type=campaign.campaign_type,
                        target_version=campaign.target_version,
                        taxonomy=self.taxonomy,
                        category_id=selected.selected_category,
                        subcategory_id=selected.selected_subcategory,
                        remaining_cost_usd=campaign.max_cost_usd - campaign.actual_cost_usd,
                        remaining_attempts=campaign.max_attempts - campaign.actual_attempts,
                        remaining_duration_seconds=max(
                            0, int((deadline - utc_now()).total_seconds())
                        ),
                        max_mutations=campaign.max_mutations,
                        no_signal_limit=campaign.no_signal_limit,
                        relevant_prior_attempts=prior_attempts,
                        requested_action=selected.requested_action,
                        mutation_source_attempt_id=selected.mutation_source_attempt_id,
                    )
                    objective_source = OBJECTIVE_ORCHESTRATOR_SELECTED

            seed = choose_seed_case(
                self.seeds,
                category=objective.selected_category,
                subcategory=objective.selected_subcategory,
                attempt_index=campaign.actual_attempts,
            )
            fallback_proposal = (
                proposal_from_seed(
                    seed,
                    campaign_id=str(campaign.id),
                    taxonomy=self.taxonomy,
                    profile=self.loaded_profile.profile,
                )
                if seed is not None
                else None
            )
            generator_result: AgentInvocationResult[Any] | None = None
            if not force_deterministic_fallback:
                stop_reason = self._action_stop_reason(session, campaign, deadline)
                if stop_reason is not None:
                    self._persist_agent_runs(
                        session,
                        campaign_id=campaign.id,
                        attempt_id=None,
                        finding_id=None,
                        results=agent_results,
                    )
                    self._reconcile_budget(
                        campaign=campaign,
                        budget_state=budget_state,
                        reservation=reservation,
                        results=agent_results,
                    )
                    session.commit()
                    return DiscoveryIterationResult(
                        terminal_result=CampaignProcessResult(
                            status=(
                                "cancelled" if stop_reason == "cancellation_requested" else "failed"
                            ),
                            actual_cost_usd=campaign.actual_cost_usd,
                            sanitized_error={
                                "code": stop_reason,
                                "message": "campaign stopped before Attack Generator invocation",
                            },
                        )
                    )
                generator_result = await self.attack_generator.invoke(
                    {
                        "objective": objective.model_dump(mode="json"),
                        "authoritative_fallback": (
                            fallback_proposal.model_dump(mode="json")
                            if fallback_proposal is not None
                            else None
                        ),
                    },
                    campaign_id=str(campaign.id),
                    attempt_id=str(attempt_id),
                    category=objective.selected_category,
                    target_version=campaign.target_version,
                )
                agent_results.append(generator_result)
            generated = generator_result.output if generator_result is not None else None
            fallback_reason: str | None = None
            proposal_source: str
            expected_parent = objective.mutation_source_attempt_id
            source_for_mutation = (
                session.get(AttackAttempt, uuid.UUID(expected_parent))
                if expected_parent is not None
                else None
            )
            generated_scope_matches = bool(
                generated is not None
                and generated.category == objective.selected_category
                and generated.subcategory == objective.selected_subcategory
            )
            generated_lineage_matches = bool(
                generated is not None
                and (
                    (
                        objective.requested_action == RequestedActionV1.NEW_ATTACK
                        and generated.parent_attempt_id is None
                    )
                    or (
                        objective.requested_action == RequestedActionV1.MUTATION
                        and source_for_mutation is not None
                        and generated.parent_attempt_id == expected_parent
                        and generated.lineage_id
                        == (source_for_mutation.lineage_id or source_for_mutation.attack_family_id)
                    )
                )
            )
            if force_deterministic_fallback and fallback_proposal is not None:
                proposal = fallback_proposal
                proposal_source = PROPOSAL_DETERMINISTIC_FALLBACK
                fallback_reason = "prior_iteration_agent_proposal_unusable"
            elif generated_scope_matches and generated_lineage_matches and generated is not None:
                proposal = generated
                proposal_source = (
                    PROPOSAL_AGENT_GENERATED_MUTATION
                    if objective.requested_action == RequestedActionV1.MUTATION
                    else PROPOSAL_AGENT_GENERATED
                )
            elif generated is not None:
                rejection_reason = (
                    "attack_generator_proposal_scope_mismatch"
                    if not generated_scope_matches
                    else "attack_generator_proposal_lineage_mismatch"
                )
                rejected = self._new_attempt(
                    attempt_id=attempt_id,
                    campaign=campaign,
                    objective=objective,
                    proposal=generated,
                    prompt_version=(
                        generator_result.prompt_version
                        if generator_result is not None
                        else _CONTROLLER_PROMPT_VERSION
                    ),
                    proposal_source=PROPOSAL_AGENT_GENERATED,
                    objective_source=objective_source,
                    fallback_reason=rejection_reason,
                    mutation_generation=0,
                    sequence_hash=proposal_sequence_hash(generated),
                )
                rejected.status = "rejected"
                rejected.completed_at = utc_now()
                rejected.evidence_summary = {
                    "controller_rejection": {
                        "code": rejection_reason,
                        "message": (
                            "Agent-generated proposal did not match the controller-assigned "
                            "objective or mutation lineage."
                        ),
                    }
                }
                session.add(rejected)
                session.flush()
                self._persist_agent_runs(
                    session,
                    campaign_id=campaign.id,
                    attempt_id=rejected.id,
                    finding_id=None,
                    results=agent_results,
                )
                self._update_attempt_usage(rejected, agent_results)
                campaign.actual_attempts += 1
                self._reconcile_budget(
                    campaign=campaign,
                    budget_state=budget_state,
                    reservation=reservation,
                    results=agent_results,
                )
                session.commit()
                return DiscoveryIterationResult(
                    prior_attempt=self._prior_attempt_summary(
                        rejected,
                        outcome=PriorAttemptOutcomeV1.ERROR,
                        summary=f"Controller rejected proposal: {rejection_reason}.",
                    ),
                    deterministic_fallback_candidate=fallback_proposal is not None,
                    no_signal=True,
                )
            elif (
                objective.requested_action == RequestedActionV1.NEW_ATTACK
                and fallback_proposal is not None
            ):
                proposal = fallback_proposal
                proposal_source = PROPOSAL_DETERMINISTIC_FALLBACK
                if generated is None:
                    fallback_reason = "attack_generator_returned_no_typed_proposal"
                elif not generated_scope_matches:
                    fallback_reason = "attack_generator_proposal_scope_mismatch"
                else:
                    fallback_reason = "attack_generator_proposal_lineage_mismatch"
            else:
                self._persist_agent_runs(
                    session,
                    campaign_id=campaign.id,
                    attempt_id=None,
                    finding_id=None,
                    results=agent_results,
                )
                self._reconcile_budget(
                    campaign=campaign,
                    budget_state=budget_state,
                    reservation=reservation,
                    results=agent_results,
                )
                session.commit()
                return DiscoveryIterationResult(
                    deterministic_fallback_candidate=fallback_proposal is not None,
                    no_signal=True,
                )

            mutation_generation = (
                source_for_mutation.mutation_generation + 1
                if proposal_source == PROPOSAL_AGENT_GENERATED_MUTATION
                and source_for_mutation is not None
                else 0
            )
            sequence_hash = proposal_sequence_hash(proposal)

            attempt = self._new_attempt(
                attempt_id=attempt_id,
                campaign=campaign,
                objective=objective,
                proposal=proposal,
                prompt_version=(
                    generator_result.prompt_version
                    if generator_result is not None
                    else _CONTROLLER_PROMPT_VERSION
                ),
                proposal_source=proposal_source,
                objective_source=objective_source,
                fallback_reason=fallback_reason,
                mutation_generation=mutation_generation,
                sequence_hash=sequence_hash,
            )
            session.add(attempt)
            session.flush()
            self._persist_agent_runs(
                session,
                campaign_id=campaign.id,
                attempt_id=attempt.id,
                finding_id=None,
                results=agent_results,
            )
            self._update_attempt_usage(attempt, agent_results)
            session.commit()

            gate_context = self._gate_context(
                campaign=campaign,
                objective=objective,
                budget_state=budget_state,
                reservation=reservation,
                deadline=deadline,
                sequence_counts=sequence_counts,
            )
            validated = validate_attack(
                proposal,
                self.loaded_profile.profile,
                gate_context,
                now=utc_now(),
            )
            if isinstance(validated, GateRejectionV1):
                attempt.status = "rejected"
                attempt.completed_at = utc_now()
                attempt.evidence_summary = {"gate_rejection": validated.model_dump(mode="json")}
                campaign.actual_attempts += 1
                self._reconcile_budget(
                    campaign=campaign,
                    budget_state=budget_state,
                    reservation=reservation,
                    results=agent_results,
                )
                session.commit()
                rejection_error = {
                    "code": "execution_gate_rejected",
                    "message": "the deterministic execution gate rejected the proposal",
                    "gate_code": validated.code.value,
                    "retryable": validated.retryable_after_revision,
                }
                prior = self._prior_attempt_summary(
                    attempt,
                    outcome=PriorAttemptOutcomeV1.ERROR,
                    summary=f"Execution gate rejected proposal: {validated.code.value}.",
                )
                if not validated.retryable_after_revision:
                    return DiscoveryIterationResult(
                        terminal_result=CampaignProcessResult(
                            status="failed",
                            actual_cost_usd=campaign.actual_cost_usd,
                            sanitized_error=rejection_error,
                        ),
                        prior_attempt=prior,
                        no_signal=True,
                        gate_rejected=True,
                    )
                return DiscoveryIterationResult(
                    prior_attempt=prior,
                    deterministic_fallback_candidate=(
                        proposal_source != PROPOSAL_DETERMINISTIC_FALLBACK
                        and fallback_proposal is not None
                    ),
                    no_signal=True,
                    gate_rejected=True,
                )

            attempt.status = "executing"
            session.commit()
            stop_reason = self._action_stop_reason(session, campaign, deadline)
            if stop_reason is not None:
                attempt.status = "cancelled" if stop_reason == "cancellation_requested" else "error"
                attempt.completed_at = utc_now()
                campaign.actual_attempts += 1
                self._reconcile_budget(
                    campaign=campaign,
                    budget_state=budget_state,
                    reservation=reservation,
                    results=agent_results,
                )
                session.commit()
                return DiscoveryIterationResult(
                    terminal_result=CampaignProcessResult(
                        status=(
                            "cancelled" if stop_reason == "cancellation_requested" else "failed"
                        ),
                        actual_cost_usd=campaign.actual_cost_usd,
                        sanitized_error={
                            "code": stop_reason,
                            "message": "campaign stopped before target execution",
                        },
                    ),
                    prior_attempt=self._prior_attempt_summary(
                        attempt,
                        outcome=PriorAttemptOutcomeV1.ERROR,
                        summary="Campaign stopped before target execution.",
                    ),
                    no_signal=True,
                )
            discovered = await self.version_discoverer(self.loaded_profile, target_alias)
            if discovered.version != campaign.target_version:
                attempt.status = "error"
                attempt.completed_at = utc_now()
                attempt.evidence_summary = {
                    "target_version_drift": {
                        "expected": campaign.target_version,
                        "observed": discovered.version,
                    }
                }
                campaign.actual_attempts += 1
                self._reconcile_budget(
                    campaign=campaign,
                    budget_state=budget_state,
                    reservation=reservation,
                    results=agent_results,
                )
                session.commit()
                return DiscoveryIterationResult(
                    terminal_result=CampaignProcessResult(
                        status="failed",
                        actual_cost_usd=campaign.actual_cost_usd,
                        sanitized_error={
                            "code": "target_version_drift",
                            "message": "target version changed before attack execution",
                        },
                    ),
                    prior_attempt=self._prior_attempt_summary(
                        attempt,
                        outcome=PriorAttemptOutcomeV1.ERROR,
                        summary="Target version changed before execution.",
                    ),
                    no_signal=True,
                )
            execution_context = self._execution_context(
                campaign=campaign,
                attempt_id=attempt.id,
                target_alias=target_alias,
                target_version=campaign.target_version,
                validated=validated,
            )
            evidence = await self.runner.execute(validated, execution_context)
            if (
                evidence.campaign_id != str(campaign.id)
                or evidence.attempt_id != str(attempt.id)
                or evidence.target_version != campaign.target_version
            ):
                raise ValueError("runner evidence identifiers do not match the claimed attempt")
            invariants = build_security_invariants(self.loaded_profile.profile)
            deterministic = evaluate_deterministically(evidence, invariants)
            evidence = _rehash_evidence(
                evidence,
                assertion_results=[
                    item.model_dump(mode="python") for item in deterministic.assertion_results
                ],
            )
            deterministic = evaluate_deterministically(evidence, invariants)
            attempt.executed_sequence = {
                "actions": [
                    item.model_dump(mode="json") for item in evidence.executed_action_sequence
                ]
            }
            attempt.evidence_payload = evidence.model_dump(mode="json")
            attempt.evidence_summary = deterministic.model_dump(mode="json")
            attempt.evidence_hash = evidence.evidence_hash
            attempt.latency_ms = round(evidence.total_latency_ms)
            attempt.langfuse_trace_id = evidence.langfuse_trace_id
            attempt.status = "evaluating"
            session.commit()

            stop_reason = self._action_stop_reason(session, campaign, deadline)
            if stop_reason is not None:
                attempt.status = (
                    "cancelled" if stop_reason == "cancellation_requested" else "inconclusive"
                )
                attempt.completed_at = utc_now()
                campaign.actual_attempts += 1
                self._reconcile_budget(
                    campaign=campaign,
                    budget_state=budget_state,
                    reservation=reservation,
                    results=agent_results,
                )
                session.commit()
                return DiscoveryIterationResult(
                    terminal_result=CampaignProcessResult(
                        status=(
                            "cancelled" if stop_reason == "cancellation_requested" else "failed"
                        ),
                        actual_cost_usd=campaign.actual_cost_usd,
                        sanitized_error={
                            "code": stop_reason,
                            "message": "campaign stopped before Judge invocation",
                        },
                    ),
                    prior_attempt=self._prior_attempt_summary(
                        attempt,
                        outcome=PriorAttemptOutcomeV1.INCONCLUSIVE,
                        summary="Evidence was collected but the Judge was not invoked.",
                    ),
                    no_signal=True,
                )
            verdict, judge_result = await self._judge_evidence(
                campaign=campaign,
                attempt_id=attempt.id,
                objective=objective,
                proposal=proposal,
                evidence=evidence,
                deterministic=deterministic,
                invariants=invariants,
            )
            agent_results.append(judge_result)
            self._persist_verdict(session, attempt_id=attempt.id, verdict=verdict)
            self._persist_agent_runs(
                session,
                campaign_id=campaign.id,
                attempt_id=attempt.id,
                finding_id=None,
                results=[judge_result],
            )
            self._update_attempt_usage(attempt, agent_results)
            attempt.completed_at = utc_now()
            campaign.actual_attempts += 1

            if not deterministic.proven_violation_ids:
                if (
                    verdict.verdict == JudgeVerdictKindV1.PARTIAL_SIGNAL
                    and deterministic.secure_pass_eligible
                ):
                    attempt.status = "partial_signal"
                    outcome = PriorAttemptOutcomeV1.PARTIAL_SIGNAL
                    mutation_candidate = True
                    no_signal = False
                elif (
                    verdict.verdict == JudgeVerdictKindV1.ATTACK_BLOCKED
                    and deterministic.secure_pass_eligible
                ):
                    attempt.status = "secure"
                    outcome = PriorAttemptOutcomeV1.ATTACK_BLOCKED
                    mutation_candidate = False
                    no_signal = True
                else:
                    attempt.status = "inconclusive"
                    outcome = PriorAttemptOutcomeV1.INCONCLUSIVE
                    mutation_candidate = False
                    no_signal = True
                self._reconcile_budget(
                    campaign=campaign,
                    budget_state=budget_state,
                    reservation=reservation,
                    results=agent_results,
                )
                session.commit()
                return DiscoveryIterationResult(
                    prior_attempt=self._prior_attempt_summary(
                        attempt,
                        outcome=outcome,
                        summary=verdict.observed_behavior,
                    ),
                    mutation_candidate=mutation_candidate,
                    no_signal=no_signal,
                )

            fingerprint = _finding_fingerprint(proposal, deterministic)
            finding, _ = FindingRepository(session).upsert_confirmed(
                fingerprint=fingerprint,
                source_attempt_id=attempt.id,
                vulnerability_id=f"AF-{fingerprint[:20].upper()}",
                title=f"Synthetic {proposal.category} invariant violation",
                category=proposal.category,
                subcategory=proposal.subcategory,
                severity=verdict.severity.value,
                description=verdict.observed_behavior,
                clinical_impact=(
                    "A confirmed synthetic security invariant violation may affect clinical "
                    "decision-support isolation if reproduced outside this fixture."
                ),
                expected_behavior=verdict.expected_behavior,
                observed_behavior=verdict.observed_behavior,
                target_version=campaign.target_version,
            )
            attempt.status = "documenting"
            session.commit()

            evidence_reference = self._evidence_reference(evidence)
            snapshot = ConfirmedFindingSnapshotV1(
                finding_id=str(finding.id),
                vulnerability_id=finding.vulnerability_id,
                source_attempt_id=str(attempt.id),
                deduplication_fingerprint=finding.fingerprint,
                title=finding.title,
                severity=verdict.severity,
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
            documentation_request = DocumentationRequestV1(
                schema_version="v1",
                confirmed_finding_snapshot=snapshot,
                minimal_evidence_package=MinimalEvidencePackageV1(
                    evidence_hash=evidence.evidence_hash,
                    target_version=evidence.target_version,
                    exact_action_sequence=[
                        item.action for item in evidence.executed_action_sequence
                    ],
                    transcript_excerpts=evidence.transcript[:30],
                    deterministic_assertion_results=evidence.deterministic_assertion_results,
                    evidence_references=[evidence_reference],
                ),
                reproduction_result_count=1,
                target_versions=[evidence.target_version],
                existing_validation_history=[],
                required_report_status=snapshot.status,
            )
            stop_reason = self._action_stop_reason(session, campaign, deadline)
            if stop_reason is not None:
                attempt.status = "documentation_failed"
                self._reconcile_budget(
                    campaign=campaign,
                    budget_state=budget_state,
                    reservation=reservation,
                    results=agent_results,
                )
                session.commit()
                return DiscoveryIterationResult(
                    terminal_result=CampaignProcessResult(
                        status=(
                            "cancelled" if stop_reason == "cancellation_requested" else "failed"
                        ),
                        actual_cost_usd=campaign.actual_cost_usd,
                        sanitized_error={
                            "code": stop_reason,
                            "message": "confirmed evidence could not be documented before stop",
                        },
                    ),
                    prior_attempt=self._prior_attempt_summary(
                        attempt,
                        outcome=PriorAttemptOutcomeV1.EXPLOIT_CONFIRMED,
                        summary=verdict.observed_behavior,
                    ),
                )
            try:
                documentation_result = await self.documentation.invoke(
                    documentation_request,
                    campaign_id=str(campaign.id),
                    attempt_id=str(attempt.id),
                    category=proposal.category,
                    target_version=campaign.target_version,
                )
            except Exception as exc:
                attempt.status = "documentation_failed"
                self._reconcile_budget(
                    campaign=campaign,
                    budget_state=budget_state,
                    reservation=reservation,
                    results=agent_results,
                )
                session.commit()
                return DiscoveryIterationResult(
                    terminal_result=CampaignProcessResult(
                        status="failed",
                        actual_cost_usd=campaign.actual_cost_usd,
                        sanitized_error=redact(
                            {
                                "code": "documentation_failed",
                                "type": type(exc).__name__,
                                "message": "documentation role failed before producing a report",
                                "retryable": True,
                            }
                        ),
                    ),
                    prior_attempt=self._prior_attempt_summary(
                        attempt,
                        outcome=PriorAttemptOutcomeV1.EXPLOIT_CONFIRMED,
                        summary=verdict.observed_behavior,
                    ),
                )
            agent_results.append(documentation_result)
            self._persist_agent_runs(
                session,
                campaign_id=campaign.id,
                attempt_id=attempt.id,
                finding_id=finding.id,
                results=[documentation_result],
            )
            self._update_attempt_usage(attempt, agent_results)
            if documentation_result.output is None:
                attempt.status = "documentation_failed"
                self._reconcile_budget(
                    campaign=campaign,
                    budget_state=budget_state,
                    reservation=reservation,
                    results=agent_results,
                )
                session.commit()
                return DiscoveryIterationResult(
                    terminal_result=CampaignProcessResult(
                        status="failed",
                        actual_cost_usd=campaign.actual_cost_usd,
                        sanitized_error={
                            "code": "documentation_failed",
                            "message": "documentation role returned a typed failure",
                            "retryable": True,
                        },
                    ),
                    prior_attempt=self._prior_attempt_summary(
                        attempt,
                        outcome=PriorAttemptOutcomeV1.EXPLOIT_CONFIRMED,
                        summary=verdict.observed_behavior,
                    ),
                )

            report_output = documentation_result.output
            if (
                report_output.vulnerability_id != finding.vulnerability_id
                or report_output.category != finding.category
                or report_output.subcategory != finding.subcategory
            ):
                session.rollback()
                raise ValueError("documentation report does not match the frozen finding")
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
                source_evidence=evidence,
                validated_attack=validated,
                invariants=invariants,
                case_version=next_case_version,
                created_at=utc_now(),
            )
            report_output = report_output.model_copy(
                update={"regression_case_id": regression_case.case_id}
            )
            markdown = render_vulnerability_report(
                report_output,
                _project_path(Path("config/report-template.md")),
            )
            stored_report = ReportRepository(session).create_versioned(
                finding_id=finding.id,
                structured_report=report_output.model_dump(mode="json"),
                markdown_body=markdown,
                validation_summary=deterministic.model_dump(mode="json"),
                prompt_version=documentation_result.prompt_version,
            )
            stored_case = RegressionCaseRepository(session).create_versioned(
                finding_id=finding.id,
                case_payload=regression_case.model_dump(mode="python"),
            )
            finding.current_regression_case_id = stored_case.id
            report_path = export_stored_report(
                stored_report,
                vulnerability_id=finding.vulnerability_id,
                reports_dir=self.settings.reports_dir,
            )
            stored_report.markdown_path = str(report_path)
            attempt.status = "confirmed"
            self._reconcile_budget(
                campaign=campaign,
                budget_state=budget_state,
                reservation=reservation,
                results=agent_results,
            )
            session.commit()
            return DiscoveryIterationResult(
                terminal_result=CampaignProcessResult(
                    status="completed",
                    actual_cost_usd=campaign.actual_cost_usd,
                ),
                prior_attempt=self._prior_attempt_summary(
                    attempt,
                    outcome=PriorAttemptOutcomeV1.EXPLOIT_CONFIRMED,
                    summary=verdict.observed_behavior,
                ),
            )

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
                    "expected_security_invariants": row.expected_security_invariants,
                    "deterministic_check_ids": row.deterministic_checks,
                    "judge_required": row.judge_required,
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
                    sanitized_error={"code": "campaign_not_found", "message": "campaign not found"},
                )
            try:
                run = RegressionRunRepository(session).for_campaign(campaign.id)
            except LookupError:
                return CampaignProcessResult(
                    status="failed",
                    sanitized_error={
                        "code": "regression_run_not_found",
                        "message": "regression campaign has no associated run",
                    },
                )
            rows = RegressionCaseRepository(session).active()
            run.status = "running"
            run.started_at = utc_now()
            run.total_cases = len(rows)
            session.commit()
            outcomes: Counter[str] = Counter()
            total_cost = Decimal("0")

            for row in rows:
                finding = session.get(Finding, row.finding_id)
                if finding is None:
                    outcomes["error"] += 1
                    continue
                try:
                    case = self._regression_case(row, finding)
                    if (
                        case.target_requirements.target_profile_version
                        != self.loaded_profile.profile.profile_version
                    ):
                        raise ValueError("saved case target profile version is no longer active")
                    attempt_id = uuid.uuid4()
                    proposal = ProposedAttackV1(
                        schema_version="v1",
                        proposal_id=f"replay-{case.case_id}",
                        category=case.category,
                        subcategory=case.subcategory,
                        attack_family_id=case.case_id,
                        lineage_id=case.case_id,
                        novelty_rationale="Exact replay of a saved versioned regression case.",
                        prerequisites=["Approved synthetic regression setup"],
                        ordered_actions=case.exact_ordered_sequence,
                        expected_exploit_signals=["Saved invariant violation is observed"],
                        expected_safe_behavior=["Every saved invariant remains satisfied"],
                        stop_conditions=["Stop after the exact bounded replay"],
                        risk_flags=[],
                        estimated_turns=sum(
                            action.action_type.value
                            in {
                                "send_chat_message",
                                "upload_approved_fixture",
                                "invoke_approved_api_request",
                            }
                            for action in case.exact_ordered_sequence
                        ),
                        estimated_cost_class=EstimatedCostClassV1.LOW,
                    )
                    objective = build_objective(
                        campaign_id=str(campaign.id),
                        campaign_type="regression",
                        target_version=campaign.target_version,
                        taxonomy=self.taxonomy,
                        category_id=case.category,
                        subcategory_id=case.subcategory,
                        remaining_cost_usd=campaign.max_cost_usd - total_cost,
                        remaining_attempts=max(0, len(rows) - sum(outcomes.values())),
                        remaining_duration_seconds=campaign.max_duration_seconds,
                        max_mutations=0,
                        no_signal_limit=campaign.no_signal_limit,
                    )
                    budget_state = self._initial_budget_state(session, campaign)
                    reservation_result = reserve_worst_case(
                        budget_state,
                        campaign_id=str(campaign.id),
                        reservation_id=f"regression-{attempt_id}",
                        worst_case_by_model=self._worst_case_usage(include_generation=False),
                        pricing=self.pricing,
                        reserved_at=utc_now(),
                    )
                    if not reservation_result.approved or reservation_result.reservation is None:
                        raise ValueError("regression budget reservation was rejected")
                    budget_state = reservation_result.state
                    reservation = reservation_result.reservation
                    deadline = campaign.started_at + timedelta(
                        seconds=campaign.max_duration_seconds
                    )
                    gate_context = self._gate_context(
                        campaign=campaign,
                        objective=objective,
                        budget_state=budget_state,
                        reservation=reservation,
                        deadline=deadline,
                        sequence_counts=Counter(),
                        patient_alias=case.setup.selected_patient_alias,
                        identity_alias=case.setup.test_identity_alias,
                        expected_role=case.setup.expected_role,
                    )
                    validated = validate_attack(
                        proposal,
                        self.loaded_profile.profile,
                        gate_context,
                        now=utc_now(),
                    )
                    if isinstance(validated, GateRejectionV1):
                        raise ValueError(f"regression gate rejected case: {validated.code.value}")
                    attempt = self._new_attempt(
                        attempt_id=attempt_id,
                        campaign=campaign,
                        objective=objective,
                        proposal=proposal,
                        prompt_version=_CONTROLLER_PROMPT_VERSION,
                        proposal_source=PROPOSAL_DETERMINISTIC_FALLBACK,
                        objective_source=OBJECTIVE_DETERMINISTIC_FALLBACK,
                        fallback_reason="saved_regression_replay",
                        mutation_generation=0,
                        sequence_hash=proposal_sequence_hash(proposal),
                    )
                    attempt.status = "executing"
                    session.add(attempt)
                    session.commit()
                    context = self._execution_context(
                        campaign=campaign,
                        attempt_id=attempt.id,
                        target_alias=target_alias,
                        target_version=campaign.target_version,
                        validated=validated,
                    )
                    evidence = await self.runner.execute(validated, context)
                    result = evaluate_regression(case, evidence)
                    judge_result: AgentInvocationResult[Any] | None = None
                    if case.judge_required and result.deterministic_evaluation is not None:
                        _, judge_result = await self._judge_evidence(
                            campaign=campaign,
                            attempt_id=attempt.id,
                            objective=objective,
                            proposal=proposal,
                            evidence=evidence,
                            deterministic=result.deterministic_evaluation,
                            invariants=case.expected_security_invariants,
                        )
                        result = evaluate_regression(
                            case,
                            evidence,
                            semantic_judge_verdict=judge_result.output,
                        )
                        self._persist_agent_runs(
                            session,
                            campaign_id=campaign.id,
                            attempt_id=attempt.id,
                            finding_id=finding.id,
                            results=[judge_result],
                        )
                    attempt.executed_sequence = {
                        "actions": [
                            item.model_dump(mode="json")
                            for item in evidence.executed_action_sequence
                        ]
                    }
                    attempt.evidence_payload = evidence.model_dump(mode="json")
                    attempt.evidence_summary = (
                        result.deterministic_evaluation.model_dump(mode="json")
                        if result.deterministic_evaluation is not None
                        else {"outcome": result.outcome.value, "summary": result.summary}
                    )
                    attempt.evidence_hash = evidence.evidence_hash
                    attempt.status = result.outcome.value
                    attempt.completed_at = utc_now()
                    role_results = [judge_result] if judge_result is not None else []
                    case_cost = (
                        self._reconcile_budget(
                            campaign=campaign,
                            budget_state=budget_state,
                            reservation=reservation,
                            results=role_results,
                        )
                        - total_cost
                    )
                    total_cost += case_cost
                    RegressionRunRepository(session).add_result(
                        run_id=run.id,
                        case_id=row.id,
                        case_version=row.case_version,
                        outcome=result.outcome.value,
                        deterministic_results=(
                            [
                                item.model_dump(mode="json")
                                for item in result.deterministic_evaluation.assertion_results
                            ]
                            if result.deterministic_evaluation is not None
                            else []
                        ),
                        judge_result=(
                            result.reconciled_judge_verdict.model_dump(mode="json")
                            if result.reconciled_judge_verdict is not None
                            else None
                        ),
                        evidence_references=[
                            reference.reference_id for reference in evidence.artifact_references
                        ],
                        estimated_cost_usd=max(Decimal("0"), case_cost),
                        latency_ms=round(evidence.total_latency_ms),
                        trace_id=evidence.langfuse_trace_id,
                    )
                    if result.reopen_finding:
                        FindingRepository(session).reopen(finding.id)
                    outcomes[result.outcome.value] += 1
                    campaign.actual_attempts += 1
                    session.commit()
                except Exception as exc:
                    session.rollback()
                    outcomes["error"] += 1
                    RegressionRunRepository(session).add_result(
                        run_id=run.id,
                        case_id=row.id,
                        case_version=row.case_version,
                        outcome="error",
                        deterministic_results=[],
                        judge_result={
                            "code": "regression_execution_error",
                            "type": type(exc).__name__,
                            "message": "saved regression case could not be completed",
                        },
                        evidence_references=[],
                        estimated_cost_usd=Decimal("0"),
                        latency_ms=None,
                        trace_id=None,
                    )
                    session.commit()

            run = session.get(RegressionRun, run.id)
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
    """Construct the production controller without performing any external call."""

    from agentforge.agents import (
        AttackGeneratorAgent,
        DocumentationAgent,
        JudgeAgent,
        OrchestratorAgent,
    )
    from agentforge.evaluation import load_judge_rubric, load_seed_cases, load_taxonomy
    from agentforge.target import load_target_profile

    return CampaignController(
        database=database,
        settings=settings,
        loaded_profile=load_target_profile(_project_path(settings.target_profile_path)),
        taxonomy=load_taxonomy(_project_path(settings.attack_taxonomy_path)),
        rubric=load_judge_rubric(_project_path(settings.judge_rubric_path)),
        seeds=load_seed_cases(PROJECT_ROOT / "evals" / "seed-cases"),
        pricing=load_pricing_config(_project_path(settings.pricing_path)),
        orchestrator=OrchestratorAgent(settings=settings, telemetry=telemetry),
        attack_generator=AttackGeneratorAgent(settings=settings, telemetry=telemetry),
        judge=JudgeAgent(settings=settings, telemetry=telemetry),
        documentation=DocumentationAgent(settings=settings, telemetry=telemetry),
        runner=CompositeAttackRunner(),
        telemetry=telemetry,
        metric_registry=metrics,
    )


__all__ = ["CampaignController", "VersionDiscoverer", "build_campaign_controller"]
