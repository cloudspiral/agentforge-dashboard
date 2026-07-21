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
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Protocol

import httpx
from sqlalchemy import func, select

from agentforge.agents import (
    AttackGeneratorAgent,
    DocumentationAgent,
    JudgeAgent,
    OrchestratorAgent,
)
from agentforge.agents.base import AgentInvocationResult
from agentforge.contracts.v1 import (
    AttackEvidenceV1,
    CampaignObjectiveV1,
    ConfirmedFindingSnapshotV1,
    DocumentationRequestV1,
    EvidenceReferenceKindV1,
    EvidenceReferenceV1,
    ExploitabilityV1,
    FindingStatusV1,
    JudgeRecommendedActionV1,
    JudgeVerdictKindV1,
    JudgeVerdictV1,
    MinimalEvidencePackageV1,
    ProposedAttackV1,
    SeverityV1,
    VulnerabilityReportV1,
    utc_now,
)
from agentforge.evaluation import (
    JudgeRubricV1,
    SeedCaseV1,
    TaxonomyV1,
    load_judge_rubric,
    load_seed_cases,
    load_taxonomy,
)
from agentforge.evaluation.deterministic import (
    DeterministicEvaluationV1,
    evaluate_deterministically,
)
from agentforge.evaluation.judge_service import reconcile_judge_verdict
from agentforge.observability import AgentForgeMetrics, LangfuseTelemetry, get_telemetry, metrics
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
from agentforge.orchestration.worker import CampaignProcessResult
from agentforge.persistence import Database
from agentforge.persistence.models import (
    AgentRun,
    AttackAttempt,
    Campaign,
    Finding,
    JudgeVerdict,
    RegressionCase,
    RegressionResult,
    RegressionRun,
    TargetVersion,
    VulnerabilityReport,
)
from agentforge.regression import RegressionCaseV1, build_regression_case, evaluate_regression
from agentforge.reports import export_stored_report, render_vulnerability_report
from agentforge.runners import CompositeAttackRunner, TargetExecutionContext
from agentforge.security.redaction import redact
from agentforge.settings import Settings
from agentforge.target import LoadedTargetProfile, load_target_profile
from agentforge.target.auth import TargetAuthenticationError, credentials_from_settings
from agentforge.target.profile import ResolvedTargetAlias
from agentforge.target.version import DiscoveredTargetVersion, discover_target_version

PROJECT_ROOT = Path(__file__).resolve().parents[3]
_HEX_SHA = re.compile(r"^[0-9a-fA-F]{7,64}$")
_CONTROLLER_PROMPT_VERSION = "controller-policy-v1-2026-07-21"
_MAX_INPUT_PER_CALL = 8_000


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
            if campaign.campaign_type == "regression":
                result = await self._process_regression(campaign_id, target_alias)
            else:
                result = await self._process_discovery(campaign_id, target_alias)
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
                    max_output_tokens=max(5_000, campaign.max_attempts * 6_000),
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

    def _new_attempt(
        self,
        *,
        attempt_id: uuid.UUID,
        campaign: Campaign,
        objective: CampaignObjectiveV1,
        proposal: ProposedAttackV1,
        prompt_version: str,
    ) -> AttackAttempt:
        return AttackAttempt(
            id=attempt_id,
            campaign_id=campaign.id,
            attack_family_id=proposal.attack_family_id,
            parent_attempt_id=(
                uuid.UUID(proposal.parent_attempt_id) if proposal.parent_attempt_id else None
            ),
            mutation_generation=0,
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
    ) -> CampaignExecutionContextV1:
        return CampaignExecutionContextV1(
            campaign_id=str(campaign.id),
            target_alias=campaign.target_alias,
            selected_category=objective.selected_category,
            selected_subcategory=objective.selected_subcategory,
            allowed_category_subcategories=self.allowed_categories,
            current_patient_alias="patient_a",
            test_identity_alias="physician_test",
            test_role="physician",
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
                max_sequence_repetitions=2,
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
            observed_behavior="Semantic judgment was unavailable; deterministic evidence remains authoritative.",
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
