"""Run one checked-in evaluation case through the local browser target."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal, Protocol

import httpx
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, SecretStr, model_validator
from sqlalchemy import select

from agentforge.agents.base import AgentInvocationResult
from agentforge.contracts.v1 import (
    AttackEvidenceV1,
    CampaignObjectiveV1,
    DeterministicAssertionResultV1,
    EvidenceReferenceKindV1,
    EvidenceReferenceV1,
    JudgeVerdictV1,
    TranscriptRoleV1,
)
from agentforge.contracts.v1.common import utc_now
from agentforge.evaluation.catalog import (
    JudgeRubricV1,
    SeedCaseV1,
    TaxonomyV1,
    load_judge_rubric,
    load_seed_case,
)
from agentforge.evaluation.deterministic import (
    DeterministicEvaluationV1,
    TransportStatusV1,
    evaluate_deterministically,
)
from agentforge.evaluation.judge_service import reconcile_judge_verdict
from agentforge.orchestration.budgets import (
    BudgetAccountV1,
    BudgetLimitsV1,
    BudgetStateV1,
    PricingConfigV1,
    TokenUsageV1,
    load_pricing_config,
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
    endpoint_bindings,
    proposal_from_seed,
)
from agentforge.persistence import Database
from agentforge.persistence.models import AttackAttempt, Campaign, JudgeVerdict, TargetVersion
from agentforge.regression.invariants import SecurityInvariantV1
from agentforge.runners.base import AttackRunner, TargetExecutionContext
from agentforge.runners.playwright_runner import (
    PlaywrightAttackRunner,
    resolve_ui_ignore_https_errors,
)
from agentforge.security.allowlist import require_allowed_url
from agentforge.security.redaction import redact
from agentforge.settings import Settings
from agentforge.target.auth import credentials_from_settings
from agentforge.target.profile import LoadedTargetProfile, ResolvedTargetAlias
from agentforge.target.version import DiscoveredTargetVersion, discover_target_version

PROJECT_ROOT = Path(__file__).resolve().parents[3]
RESULTS_DIRECTORY = Path("evals/results")
_SAFE_FILENAME = re.compile(r"[^a-z0-9._-]+")
_CASE_PROMPT_VERSION = "predefined-case-v1"
LiveTargetAlias = Literal["local", "deployed"]
LiveRunMode = Literal["live_local", "live_deployed"]


class JudgeInvoker(Protocol):
    async def invoke(
        self,
        payload: BaseModel | Mapping[str, Any],
        **kwargs: Any,
    ) -> AgentInvocationResult[JudgeVerdictV1]: ...


VersionDiscoverer = Callable[
    [LoadedTargetProfile, ResolvedTargetAlias], Awaitable[DiscoveredTargetVersion]
]


class CapturedMessageV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    content: str = Field(min_length=1, max_length=20_000)
    observed_at: AwareDatetime


class CapturedResponseV1(CapturedMessageV1):
    latency_ms: float = Field(ge=0)


class LiveLocalEvaluationResultV1(BaseModel):
    """Sanitized, reproducible export for one predefined local browser case."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    run_mode: LiveRunMode = "live_local"
    status: Literal["completed", "execution_failed", "judge_failed"]
    successful: bool
    case_id: str
    case_version: str
    case_source: str
    case_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_alias: LiveTargetAlias = "local"
    target_version: str
    target_profile_version: str
    target_profile_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    campaign_id: str
    attempt_id: str
    started_at: AwareDatetime
    completed_at: AwareDatetime
    total_latency_ms: float = Field(ge=0)
    step_latencies_ms: dict[str, float]
    sent_messages: list[CapturedMessageV1]
    visible_responses: list[CapturedResponseV1]
    deterministic_assertions: list[DeterministicAssertionResultV1]
    evidence: AttackEvidenceV1 | None
    judge_verdict: JudgeVerdictV1 | None
    warnings: list[str] = Field(default_factory=list, max_length=10)
    failed_step: Literal["execution", "judge"] | None = None
    error_code: str | None = None
    error_message: str | None = None
    result_path: str

    @model_validator(mode="after")
    def completion_shape_is_consistent(self) -> LiveLocalEvaluationResultV1:
        completed = self.status == "completed"
        if self.successful != completed:
            raise ValueError("successful must agree with completed status")
        if completed and (
            self.evidence is None
            or self.judge_verdict is None
            or self.failed_step is not None
            or self.error_code is not None
            or self.error_message is not None
        ):
            raise ValueError("completed results require evidence and a Judge verdict")
        if not completed and (
            self.judge_verdict is not None
            or self.failed_step is None
            or self.error_code is None
            or self.error_message is None
        ):
            raise ValueError("failed results cannot contain a Judge verdict")
        return self


async def _discover_version(
    loaded_profile: LoadedTargetProfile,
    target_alias: ResolvedTargetAlias,
) -> DiscoveredTargetVersion:
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(30.0),
        verify=target_alias.verify_tls,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        return await discover_target_version(
            client=client,
            profile=loaded_profile.profile,
            target_alias=target_alias,
        )


def _case_path(path: Path, repository_root: Path) -> tuple[Path, str]:
    repository = repository_root.resolve()
    allowed_root = (repository / "evals" / "seed-cases").resolve()
    resolved = (path if path.is_absolute() else repository / path).resolve()
    if resolved.suffix.lower() not in {".yaml", ".yml"} or allowed_root not in resolved.parents:
        raise ValueError("evaluation case must be a checked-in YAML file under evals/seed-cases")
    return resolved, resolved.relative_to(repository).as_posix()


def _secret_values(settings: Settings) -> list[str]:
    values: list[str] = []
    for name in (
        "target_test_username",
        "target_test_password",
        "openai_api_key",
        "platform_api_token",
        "deploy_webhook_secret",
        "langfuse_public_key",
        "langfuse_secret_key",
        "target_agent_shared_secret",
        "target_reset_token",
    ):
        value = getattr(settings, name, None)
        if isinstance(value, SecretStr):
            value = value.get_secret_value()
        if isinstance(value, str) and value:
            values.append(value)
    return list(dict.fromkeys(values))


def _replace_secret_values(value: Any, secrets: Sequence[str]) -> Any:
    if isinstance(value, dict):
        return {str(key): _replace_secret_values(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_secret_values(item, secrets) for item in value]
    if not isinstance(value, str):
        return value
    sanitized = value
    for secret in secrets:
        if sanitized == secret:
            sanitized = "[REDACTED]"
        elif len(secret) >= 8:
            sanitized = sanitized.replace(secret, "[REDACTED]")
        else:
            sanitized = re.sub(
                rf"(?<![A-Za-z0-9]){re.escape(secret)}(?![A-Za-z0-9])",
                "[REDACTED]",
                sanitized,
            )
    return sanitized


def _contains_secret(value: str, secret: str) -> bool:
    if len(secret) >= 8:
        return secret in value
    return bool(re.search(rf"(?<![A-Za-z0-9]){re.escape(secret)}(?![A-Za-z0-9])", value))


def _rehash_evidence(
    evidence: AttackEvidenceV1,
    *,
    secrets: Sequence[str],
    assertions: list[DeterministicAssertionResultV1] | None = None,
) -> AttackEvidenceV1:
    payload = evidence.model_dump(mode="json")
    if assertions is not None:
        payload["deterministic_assertion_results"] = [
            item.model_dump(mode="json") for item in assertions
        ]
    payload = redact(_replace_secret_values(payload, secrets))
    payload["evidence_hash"] = "0" * 64
    draft = AttackEvidenceV1.model_validate_json(json.dumps(payload))
    canonical = json.dumps(
        draft.model_dump(mode="json", exclude={"evidence_hash"}),
        sort_keys=True,
        separators=(",", ":"),
    )
    return AttackEvidenceV1.model_validate_json(
        json.dumps(
            {
                **draft.model_dump(mode="json"),
                "evidence_hash": hashlib.sha256(canonical.encode()).hexdigest(),
            }
        )
    )


def _budget_reservation(
    *,
    settings: Settings,
    pricing: PricingConfigV1,
    campaign_id: str,
    reserved_at: AwareDatetime,
):  # type: ignore[no-untyped-def]
    campaign_cost = Decimal(str(settings.default_campaign_max_cost_usd))
    global_cost = Decimal(str(settings.global_max_cost_usd))
    campaign_limits = BudgetLimitsV1(
        max_cost_usd=campaign_cost,
        max_calls=4,
        max_input_tokens=32_000,
        max_output_tokens=5_000,
    )
    state = BudgetStateV1(
        global_account=BudgetAccountV1(
            limits=campaign_limits.model_copy(update={"max_cost_usd": global_cost})
        ),
        campaign_account=BudgetAccountV1(limits=campaign_limits),
    )
    reserved = reserve_worst_case(
        state,
        campaign_id=campaign_id,
        reservation_id=f"live-local-{campaign_id}",
        worst_case_by_model=[
            TokenUsageV1(
                model=settings.openai_judge_model,
                calls=1,
                input_tokens=8_000,
                cached_input_tokens=0,
                cache_write_tokens=0,
                output_tokens=1_000,
            )
        ],
        pricing=pricing,
        reserved_at=reserved_at,
    )
    if not reserved.approved or reserved.reservation is None:
        raise ValueError("Judge budget reservation was rejected")
    return reserved.state, reserved.reservation


def _message_capture(
    evidence: AttackEvidenceV1,
) -> tuple[list[CapturedMessageV1], list[CapturedResponseV1]]:
    sent: list[CapturedMessageV1] = []
    responses: list[CapturedResponseV1] = []
    pending_at: AwareDatetime | None = None
    for turn in evidence.transcript:
        if turn.role == TranscriptRoleV1.USER:
            sent.append(CapturedMessageV1(content=turn.content, observed_at=turn.observed_at))
            pending_at = turn.observed_at
        elif turn.role == TranscriptRoleV1.ASSISTANT:
            latency_ms = (
                max(0.0, (turn.observed_at - pending_at).total_seconds() * 1_000)
                if pending_at is not None
                else 0.0
            )
            responses.append(
                CapturedResponseV1(
                    content=turn.content,
                    observed_at=turn.observed_at,
                    latency_ms=round(latency_ms, 3),
                )
            )
            pending_at = None
    return sent, responses


def _step_latencies(evidence: AttackEvidenceV1 | None) -> dict[str, float]:
    if evidence is None:
        return {}
    return {
        item.action.action_id: round(
            max(0.0, (item.completed_at - item.started_at).total_seconds() * 1_000), 3
        )
        for item in evidence.executed_action_sequence
    }


def _judge_payload(
    *,
    case: SeedCaseV1,
    objective: CampaignObjectiveV1,
    evidence: AttackEvidenceV1,
    deterministic: DeterministicEvaluationV1,
    invariants: list[SecurityInvariantV1],
    rubric: JudgeRubricV1,
    rubric_hash: str,
) -> tuple[dict[str, Any], str]:
    evidence_reference_id = f"evidence-{evidence.evidence_hash[:16]}"
    evidence_reference = EvidenceReferenceV1(
        reference_id=evidence_reference_id,
        kind=EvidenceReferenceKindV1.OTHER,
        artifact_path=None,
        description="Frozen sanitized evidence package persisted for this attempt.",
    )
    return (
        {
            "objective": objective.model_dump(mode="json"),
            "evaluation_case": {
                "case_id": case.id,
                "case_version": case.schema_version,
                "expected_safe_behavior": case.expected_safe_behavior,
                "configured_assertions": [
                    item.model_dump(mode="json") for item in case.deterministic_assertions
                ],
                "judge_criteria": case.judge.model_dump(mode="json"),
            },
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
                "version": rubric.rubric_version,
                "hash": rubric_hash,
                "global_rules": rubric.global_rules,
                "category": rubric.categories[case.category].model_dump(mode="json"),
            },
            "allowed_evidence_references": [evidence_reference.model_dump(mode="json")],
            "target_version": evidence.target_version,
        },
        evidence_reference_id,
    )


def _persist_initial(
    *,
    database: Database,
    settings: Settings,
    loaded_profile: LoadedTargetProfile,
    case: SeedCaseV1,
    taxonomy: TaxonomyV1,
    target_version: DiscoveredTargetVersion,
    campaign_id: uuid.UUID,
    attempt_id: uuid.UUID,
    started_at: AwareDatetime,
    proposal: Any,
    objective: Any,
    target_alias: LiveTargetAlias,
    run_mode: LiveRunMode,
) -> None:
    with database.session_factory() as session:
        version_label = f"{target_alias}:{target_version.version}"
        if (
            session.scalar(
                select(TargetVersion).where(TargetVersion.version_label == version_label)
            )
            is None
        ):
            session.add(
                TargetVersion(
                    environment=settings.environment,
                    version_label=version_label,
                    git_sha=None,
                    deployment_id=None,
                    base_url_alias=target_alias,
                    target_profile_hash=loaded_profile.profile_hash,
                    metadata_json={
                        "version_endpoint_id": target_version.endpoint_id,
                        "version_status_code": target_version.status_code,
                        "authorized_scope": "synthetic-only",
                        "run_mode": run_mode,
                    },
                )
            )
        campaign = Campaign(
            id=campaign_id,
            campaign_type="discovery",
            trigger_type=run_mode,
            status="running",
            target_alias=target_alias,
            target_version=target_version.version,
            category_scope=case.category,
            subcategory_scope=case.subcategory,
            max_cost_usd=Decimal(str(settings.default_campaign_max_cost_usd)),
            max_attempts=1,
            max_duration_seconds=settings.default_campaign_max_duration_seconds,
            max_mutations=0,
            no_signal_limit=1,
            actual_attempts=0,
            started_at=started_at,
        )
        campaign.attempts.append(
            AttackAttempt(
                id=attempt_id,
                attack_family_id=case.id,
                mutation_generation=0,
                category=case.category,
                subcategory=case.subcategory,
                owasp_mappings=objective.owasp_mappings.model_dump(mode="json"),
                objective=objective.objective,
                proposed_sequence=proposal.model_dump(mode="json"),
                taxonomy_version=taxonomy.taxonomy_version,
                profile_version=loaded_profile.profile.profile_version,
                prompt_version=_CASE_PROMPT_VERSION,
                status="executing",
                started_at=started_at,
            )
        )
        session.add(campaign)
        session.commit()


def _persist_evidence(
    database: Database,
    *,
    campaign_id: uuid.UUID,
    attempt_id: uuid.UUID,
    case: SeedCaseV1,
    evidence: AttackEvidenceV1,
    deterministic: DeterministicEvaluationV1,
    run_mode: LiveRunMode,
) -> None:
    with database.session_factory() as session:
        attempt = session.get(AttackAttempt, attempt_id)
        campaign = session.get(Campaign, campaign_id)
        if attempt is None or campaign is None:
            raise LookupError("live-local persistence records are missing")
        attempt.executed_sequence = {
            "actions": [item.model_dump(mode="json") for item in evidence.executed_action_sequence]
        }
        attempt.evidence_payload = evidence.model_dump(mode="json")
        attempt.evidence_summary = {
            "run_mode": run_mode,
            "case_id": case.id,
            "case_version": case.schema_version,
            "deterministic": deterministic.model_dump(mode="json"),
        }
        attempt.evidence_hash = evidence.evidence_hash
        attempt.latency_ms = round(evidence.total_latency_ms)
        attempt.langfuse_trace_id = evidence.langfuse_trace_id
        attempt.status = "evaluating"
        session.commit()


def _persist_failure(
    database: Database,
    *,
    campaign_id: uuid.UUID,
    attempt_id: uuid.UUID,
    code: str,
    message: str,
) -> None:
    completed_at = utc_now()
    with database.session_factory() as session:
        attempt = session.get(AttackAttempt, attempt_id)
        campaign = session.get(Campaign, campaign_id)
        if attempt is None or campaign is None:
            raise LookupError("live-local persistence records are missing")
        attempt.status = "error"
        attempt.completed_at = completed_at
        campaign.status = "failed"
        campaign.actual_attempts = 1
        campaign.completed_at = completed_at
        campaign.sanitized_error = {"code": code, "message": message}
        session.commit()


def _persist_verdict(
    database: Database,
    *,
    campaign_id: uuid.UUID,
    attempt_id: uuid.UUID,
    verdict: JudgeVerdictV1,
    judge_result: AgentInvocationResult[JudgeVerdictV1],
    rubric_hash: str,
    rubric_version: str,
) -> None:
    completed_at = utc_now()
    with database.session_factory() as session:
        attempt = session.get(AttackAttempt, attempt_id)
        campaign = session.get(Campaign, campaign_id)
        if attempt is None or campaign is None:
            raise LookupError("live-local persistence records are missing")
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
                rubric_hash=rubric_hash,
                rubric_version=rubric_version,
                deterministic_override_applied=verdict.deterministic_override_applied,
                deterministic_override_reason=(
                    "Deterministic invariant evidence controlled the final verdict."
                    if verdict.deterministic_override_applied
                    else None
                ),
            )
        )
        attempt.input_tokens = judge_result.usage.tokens.input_tokens
        attempt.output_tokens = judge_result.usage.tokens.output_tokens
        attempt.estimated_cost_usd = Decimal(str(judge_result.estimated_cost_usd))
        attempt.status = "completed"
        attempt.completed_at = completed_at
        campaign.actual_attempts = 1
        campaign.actual_cost_usd = Decimal(str(judge_result.estimated_cost_usd))
        campaign.status = "completed"
        campaign.completed_at = completed_at
        session.commit()


def _result_filename(case_id: str, attempt_id: uuid.UUID) -> str:
    safe_case = _SAFE_FILENAME.sub("-", case_id.casefold()).strip("-._") or "case"
    return f"{safe_case}-{attempt_id}.json"


def _export_result(
    result: LiveLocalEvaluationResultV1,
    *,
    destination: Path,
    secrets: Sequence[str],
) -> LiveLocalEvaluationResultV1:
    payload = redact(_replace_secret_values(result.model_dump(mode="json"), secrets))
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    for secret in secrets:
        if _contains_secret(serialized, secret):
            raise ValueError("result export still contains a configured secret")
    validated = LiveLocalEvaluationResultV1.model_validate_json(serialized)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(serialized, encoding="utf-8")
    return validated


def _build_result(
    *,
    status: Literal["completed", "execution_failed", "judge_failed"],
    case: SeedCaseV1,
    case_bytes: bytes,
    case_source: str,
    loaded_profile: LoadedTargetProfile,
    target_version: str,
    campaign_id: uuid.UUID,
    attempt_id: uuid.UUID,
    started_at: AwareDatetime,
    result_path: str,
    evidence: AttackEvidenceV1 | None,
    deterministic: DeterministicEvaluationV1 | None,
    verdict: JudgeVerdictV1 | None = None,
    warnings: Sequence[str] = (),
    error_code: str | None = None,
    error_message: str | None = None,
    target_alias: LiveTargetAlias = "local",
    run_mode: LiveRunMode = "live_local",
) -> LiveLocalEvaluationResultV1:
    completed_at = utc_now()
    sent, responses = _message_capture(evidence) if evidence is not None else ([], [])
    failed_step = (
        "execution"
        if status == "execution_failed"
        else "judge"
        if status == "judge_failed"
        else None
    )
    return LiveLocalEvaluationResultV1(
        run_mode=run_mode,
        status=status,
        successful=status == "completed",
        case_id=case.id,
        case_version=case.schema_version,
        case_source=case_source,
        case_sha256=hashlib.sha256(case_bytes).hexdigest(),
        target_alias=target_alias,
        target_version=target_version,
        target_profile_version=loaded_profile.profile.profile_version,
        target_profile_hash=loaded_profile.profile_hash,
        campaign_id=str(campaign_id),
        attempt_id=str(attempt_id),
        started_at=started_at,
        completed_at=completed_at,
        total_latency_ms=max(0.0, (completed_at - started_at).total_seconds() * 1_000),
        step_latencies_ms=_step_latencies(evidence),
        sent_messages=sent,
        visible_responses=responses,
        deterministic_assertions=(
            deterministic.assertion_results if deterministic is not None else []
        ),
        evidence=evidence,
        judge_verdict=verdict,
        warnings=list(dict.fromkeys(warnings)),
        failed_step=failed_step,
        error_code=error_code,
        error_message=error_message,
        result_path=result_path,
    )


async def run_live_local_case(
    *,
    case_path: Path,
    settings: Settings,
    database: Database,
    loaded_profile: LoadedTargetProfile,
    taxonomy: TaxonomyV1,
    target_alias: str = "local",
    headed: bool = False,
    repository_root: Path = PROJECT_ROOT,
    results_dir: Path | None = None,
    rubric: JudgeRubricV1 | None = None,
    pricing: PricingConfigV1 | None = None,
    runner: AttackRunner | None = None,
    judge: JudgeInvoker | None = None,
    version_discoverer: VersionDiscoverer = _discover_version,
) -> LiveLocalEvaluationResultV1:
    """Execute, judge, persist, and export one checked-in local or deployed case."""

    if target_alias not in {"local", "deployed"}:
        raise ValueError("single-case evaluation requires a configured live target alias")
    if target_alias == "deployed" and not settings.run_live_e2e:
        raise ValueError("deployed evaluation requires RUN_LIVE_E2E=1")
    if target_alias == "deployed" and headed:
        raise ValueError("deployed evaluation requires headless browser execution")
    live_target_alias: LiveTargetAlias = target_alias
    run_mode: LiveRunMode = "live_deployed" if target_alias == "deployed" else "live_local"
    repository = repository_root.resolve()
    resolved_case_path, relative_case_path = _case_path(case_path, repository)
    case_bytes = resolved_case_path.read_bytes()
    case = load_seed_case(resolved_case_path)
    selected_actions = [
        action.patient for action in case.actions if action.type == "select_patient"
    ]
    if selected_actions != [case.setup.selected_patient]:
        raise ValueError("case setup patient does not match its fixed selection action")

    configured_rubric = rubric or load_judge_rubric(
        settings.judge_rubric_path
        if settings.judge_rubric_path.is_absolute()
        else repository / settings.judge_rubric_path
    )
    configured_pricing = pricing or load_pricing_config(
        settings.pricing_path
        if settings.pricing_path.is_absolute()
        else repository / settings.pricing_path
    )
    resolved_alias = loaded_profile.resolve_alias(target_alias, settings)
    allow_http = target_alias == "local"
    for url in (resolved_alias.base_url, resolved_alias.status_url):
        require_allowed_url(url, resolved_alias.expected_hosts, allow_http=allow_http)
    if target_alias == "deployed" and not resolved_alias.verify_tls:
        raise ValueError("deployed evaluation requires normal TLS certificate verification")
    ignore_https_errors = resolve_ui_ignore_https_errors(
        enabled=settings.agentforge_ui_ignore_https_errors,
        base_url=resolved_alias.base_url,
    )
    credentials = credentials_from_settings(
        profile=loaded_profile.profile,
        settings=settings,
        identity_alias="physician_test",
        expected_role=case.setup.role,
    )
    discovered = await version_discoverer(loaded_profile, resolved_alias)

    started_at = utc_now()
    campaign_id = uuid.uuid4()
    attempt_id = uuid.uuid4()
    deadline = started_at + timedelta(seconds=settings.default_campaign_max_duration_seconds)
    budget_state, reservation = _budget_reservation(
        settings=settings,
        pricing=configured_pricing,
        campaign_id=str(campaign_id),
        reserved_at=started_at,
    )
    objective = build_objective(
        campaign_id=str(campaign_id),
        campaign_type="discovery",
        target_version=discovered.version,
        taxonomy=taxonomy,
        category_id=case.category,
        subcategory_id=case.subcategory,
        remaining_cost_usd=Decimal(str(settings.default_campaign_max_cost_usd)),
        remaining_attempts=1,
        remaining_duration_seconds=settings.default_campaign_max_duration_seconds,
        max_mutations=0,
        no_signal_limit=1,
    )
    proposal = proposal_from_seed(
        case,
        campaign_id=str(campaign_id),
        taxonomy=taxonomy,
        profile=loaded_profile.profile,
    )
    allowed_categories = {
        category.id: [subcategory.id for subcategory in category.subcategories]
        for category in taxonomy.categories
    }
    gate_context = CampaignExecutionContextV1(
        campaign_id=str(campaign_id),
        target_alias=target_alias,
        selected_category=case.category,
        selected_subcategory=case.subcategory,
        allowed_category_subcategories=allowed_categories,
        current_patient_alias=case.setup.selected_patient,
        test_identity_alias="physician_test",
        test_role=case.setup.role,
        endpoint_bindings=endpoint_bindings(loaded_profile.profile),
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
        campaign_started_at=started_at,
        campaign_deadline_at=deadline,
        budget_state=budget_state,
        budget_reservation=reservation,
        attempted_sequence_counts={},
        cancellation_requested=False,
        cleanup_succeeded=True,
    )
    validated = validate_attack(proposal, loaded_profile.profile, gate_context, now=started_at)
    if isinstance(validated, GateRejectionV1):
        raise ValueError(f"predefined case was rejected by the execution gate: {validated.code}")
    if not isinstance(validated, ValidatedAttackV1):  # pragma: no cover - closed union
        raise TypeError("execution gate returned an unsupported result")

    _persist_initial(
        database=database,
        settings=settings,
        loaded_profile=loaded_profile,
        case=case,
        taxonomy=taxonomy,
        target_version=discovered,
        campaign_id=campaign_id,
        attempt_id=attempt_id,
        started_at=started_at,
        proposal=proposal,
        objective=objective,
        target_alias=live_target_alias,
        run_mode=run_mode,
    )

    max_case_timeout = max(
        (action.timeout_seconds for action in case.actions if action.type == "wait_for_response"),
        default=settings.target_ui_smoke_timeout_seconds,
    )
    artifacts = (
        settings.artifacts_dir
        if settings.artifacts_dir.is_absolute()
        else repository / settings.artifacts_dir
    )
    execution_context = TargetExecutionContext(
        target_id=loaded_profile.profile.name,
        campaign_id=str(campaign_id),
        attempt_id=str(attempt_id),
        target_version=discovered.version,
        selected_patient_alias=case.setup.selected_patient,
        loaded_profile=loaded_profile,
        target_alias=resolved_alias,
        repository_root=repository,
        artifacts_dir=artifacts,
        credentials=credentials,
        request_timeout_seconds=max_case_timeout,
        max_upload_bytes=settings.max_upload_bytes,
    )
    configured_runner = runner or PlaywrightAttackRunner(
        headless=True if target_alias == "deployed" else not headed,
        browser_mode=(
            "chromium" if target_alias == "deployed" else settings.agentforge_browser_channel
        ),
        ignore_https_errors=ignore_https_errors,
    )
    configured_judge = judge
    if configured_judge is None:
        from agentforge.agents import JudgeAgent

        configured_judge = JudgeAgent(settings=settings)
    secrets = _secret_values(settings)
    result_directory = results_dir or repository / RESULTS_DIRECTORY
    destination = result_directory / _result_filename(case.id, attempt_id)
    result_path = (
        destination.resolve().relative_to(repository).as_posix()
        if repository in destination.resolve().parents
        else destination.name
    )
    warnings: list[str] = []

    evidence: AttackEvidenceV1 | None = None
    deterministic: DeterministicEvaluationV1 | None = None
    try:
        raw_evidence = await configured_runner.execute(validated, execution_context)
        warnings.extend(getattr(configured_runner, "cleanup_warnings", ()))
        if (
            raw_evidence.campaign_id != str(campaign_id)
            or raw_evidence.attempt_id != str(attempt_id)
            or raw_evidence.target_version != discovered.version
        ):
            raise ValueError("runner evidence identifiers do not match the persisted attempt")
        evidence = _rehash_evidence(raw_evidence, secrets=secrets)
        invariants = build_security_invariants(loaded_profile.profile)
        deterministic = evaluate_deterministically(evidence, invariants)
        evidence = _rehash_evidence(
            evidence,
            secrets=secrets,
            assertions=deterministic.assertion_results,
        )
        deterministic = evaluate_deterministically(evidence, invariants)
        _persist_evidence(
            database,
            campaign_id=campaign_id,
            attempt_id=attempt_id,
            case=case,
            evidence=evidence,
            deterministic=deterministic,
            run_mode=run_mode,
        )
    except Exception:
        warnings.extend(getattr(configured_runner, "cleanup_warnings", ()))
        warnings = list(dict.fromkeys(warnings))
        code = "browser_execution_failed"
        message = "the predefined browser evaluation did not complete"
        _persist_failure(
            database,
            campaign_id=campaign_id,
            attempt_id=attempt_id,
            code=code,
            message=message,
        )
        return _export_result(
            _build_result(
                status="execution_failed",
                case=case,
                case_bytes=case_bytes,
                case_source=relative_case_path,
                loaded_profile=loaded_profile,
                target_version=discovered.version,
                campaign_id=campaign_id,
                attempt_id=attempt_id,
                started_at=started_at,
                result_path=result_path,
                evidence=evidence,
                deterministic=deterministic,
                warnings=warnings,
                error_code=code,
                error_message=message,
                target_alias=live_target_alias,
                run_mode=run_mode,
            ),
            destination=destination,
            secrets=secrets,
        )

    assert evidence is not None and deterministic is not None
    sent, responses = _message_capture(evidence)
    expected_messages = [
        action.message for action in case.actions if action.type == "send_chat_message"
    ]
    if (
        deterministic.transport_status != TransportStatusV1.COMPLETE
        or [item.content for item in sent] != expected_messages
        or len(responses) != len(expected_messages)
        or any(not item.content.strip() for item in responses)
    ):
        code = "browser_execution_incomplete"
        message = "the predefined browser evaluation lacked a complete fixed transcript"
        _persist_failure(
            database,
            campaign_id=campaign_id,
            attempt_id=attempt_id,
            code=code,
            message=message,
        )
        return _export_result(
            _build_result(
                status="execution_failed",
                case=case,
                case_bytes=case_bytes,
                case_source=relative_case_path,
                loaded_profile=loaded_profile,
                target_version=discovered.version,
                campaign_id=campaign_id,
                attempt_id=attempt_id,
                started_at=started_at,
                result_path=result_path,
                evidence=evidence,
                deterministic=deterministic,
                warnings=warnings,
                error_code=code,
                error_message=message,
                target_alias=live_target_alias,
                run_mode=run_mode,
            ),
            destination=destination,
            secrets=secrets,
        )

    rubric_hash = canonical_hash(configured_rubric.model_dump(mode="json"))
    judge_payload, evidence_reference_id = _judge_payload(
        case=case,
        objective=objective,
        evidence=evidence,
        deterministic=deterministic,
        invariants=invariants,
        rubric=configured_rubric,
        rubric_hash=rubric_hash,
    )
    try:
        judge_result = await configured_judge.invoke(
            judge_payload,
            campaign_id=str(campaign_id),
            attempt_id=str(attempt_id),
            correlation_id=f"judge-{attempt_id}",
            category=case.category,
            target_version=evidence.target_version,
            escalate_to_sol=False,
        )
        if judge_result.output is None:
            raise ValueError("Judge returned no verdict")
        known_references = {
            evidence_reference_id,
            *(f"assertion-{item.invariant_id}" for item in deterministic.assertion_results),
        }
        if any(
            reference.reference_id not in known_references
            for reference in judge_result.output.supporting_evidence_references
        ):
            raise ValueError("Judge returned an unknown evidence reference")
        semantic = JudgeVerdictV1.model_validate(
            {
                **judge_result.output.model_dump(mode="python"),
                "rubric_version": configured_rubric.rubric_version,
                "rubric_hash": rubric_hash,
            }
        )
        verdict = reconcile_judge_verdict(semantic, deterministic, invariants)
    except Exception:
        code = "judge_failed"
        message = "the Judge did not return a valid evidence-backed verdict"
        _persist_failure(
            database,
            campaign_id=campaign_id,
            attempt_id=attempt_id,
            code=code,
            message=message,
        )
        return _export_result(
            _build_result(
                status="judge_failed",
                case=case,
                case_bytes=case_bytes,
                case_source=relative_case_path,
                loaded_profile=loaded_profile,
                target_version=discovered.version,
                campaign_id=campaign_id,
                attempt_id=attempt_id,
                started_at=started_at,
                result_path=result_path,
                evidence=evidence,
                deterministic=deterministic,
                warnings=warnings,
                error_code=code,
                error_message=message,
                target_alias=live_target_alias,
                run_mode=run_mode,
            ),
            destination=destination,
            secrets=secrets,
        )

    _persist_verdict(
        database,
        campaign_id=campaign_id,
        attempt_id=attempt_id,
        verdict=verdict,
        judge_result=judge_result,
        rubric_hash=rubric_hash,
        rubric_version=configured_rubric.rubric_version,
    )
    return _export_result(
        _build_result(
            status="completed",
            case=case,
            case_bytes=case_bytes,
            case_source=relative_case_path,
            loaded_profile=loaded_profile,
            target_version=discovered.version,
            campaign_id=campaign_id,
            attempt_id=attempt_id,
            started_at=started_at,
            result_path=result_path,
            evidence=evidence,
            deterministic=deterministic,
            verdict=verdict,
            warnings=warnings,
            target_alias=live_target_alias,
            run_mode=run_mode,
        ),
        destination=destination,
        secrets=secrets,
    )


__all__ = [
    "CapturedMessageV1",
    "CapturedResponseV1",
    "LiveLocalEvaluationResultV1",
    "run_live_local_case",
]
