from __future__ import annotations

import hashlib
import json
import os
import uuid
from collections.abc import Callable
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from prometheus_client import CollectorRegistry
from pydantic import SecretStr
from sqlalchemy import func, select, text
from sqlalchemy.engine import make_url

from agentforge.agents.base import AgentInvocationResult, AgentUsage
from agentforge.contracts.v1 import (
    AgentErrorCodeV1,
    AgentErrorV1,
    AttackEvidenceV1,
    JudgeVerdictV1,
    OrchestratorDecisionV1,
    ProposedAttackV1,
    TokenUsageV1,
    VulnerabilityReportV1,
)
from agentforge.contracts.v1.common import utc_now
from agentforge.evaluation import load_judge_rubric, load_taxonomy
from agentforge.observability import AgentForgeMetrics
from agentforge.orchestration.controller import CampaignController, build_campaign_controller
from agentforge.orchestration.execution_gate import ValidatedAttackV1
from agentforge.orchestration.worker import CampaignWorker
from agentforge.persistence import Database
from agentforge.persistence.models import (
    AgentRun,
    AttackAttempt,
    Campaign,
    Finding,
    JudgeVerdict,
    RegressionCase,
    RegressionResult,
    VulnerabilityReport,
)
from agentforge.persistence.repositories import (
    CampaignRepository,
    RegressionRunRepository,
)
from agentforge.settings import Settings
from agentforge.target import load_target_profile
from agentforge.target.version import DiscoveredTargetVersion

TEST_DATABASE_URL = os.getenv("AGENTFORGE_TEST_DATABASE_URL")
PROJECT_ROOT = Path(__file__).resolve().parents[2]

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        TEST_DATABASE_URL is None,
        reason="AGENTFORGE_TEST_DATABASE_URL is required for PostgreSQL integration tests",
    ),
]


def _usage() -> AgentUsage:
    return AgentUsage(tokens=TokenUsageV1(input_tokens=11, output_tokens=7, calls=1))


class FakeRole:
    def __init__(self, role: str, model: str, factory: Callable[[Any, Any], Any]) -> None:
        self.role = role
        self.model = model
        self.factory = factory
        self.calls = 0

    async def invoke(self, payload: Any, **kwargs: Any) -> AgentInvocationResult[Any]:
        self.calls += 1
        return AgentInvocationResult(
            role=self.role,
            model=self.model,
            prompt_version=f"fixture-{self.role}-v1",
            prompt_sha256="a" * 64,
            payload_sha256="b" * 64,
            usage=_usage(),
            estimated_cost_usd=0.0,
            latency_ms=1.0,
            sdk_attempts=0,
            langfuse_trace_id=f"trace-{self.role}-{self.calls}",
            output=self.factory(payload, kwargs),
        )


class FailingRole(FakeRole):
    async def invoke(self, payload: Any, **kwargs: Any) -> AgentInvocationResult[Any]:
        self.calls += 1
        error = AgentErrorV1(
            schema_version="v1",
            code=AgentErrorCodeV1.INVALID_CONTRACT,
            message=f"Synthetic {self.role} contract failure.",
            retryable=True,
            occurred_at=utc_now(),
            correlation_id=f"{self.role}-{uuid.uuid4().hex}",
            campaign_id=kwargs["campaign_id"],
            attempt_id=kwargs["attempt_id"],
            sanitized_details={"fixture": f"{self.role}_failure"},
        )
        return AgentInvocationResult(
            role=self.role,
            model=self.model,
            prompt_version=f"fixture-{self.role}-v1",
            prompt_sha256="a" * 64,
            payload_sha256="b" * 64,
            usage=_usage(),
            estimated_cost_usd=0.0,
            latency_ms=1.0,
            sdk_attempts=2,
            langfuse_trace_id=f"trace-{self.role}-{self.calls}",
            error=error,
        )


class FixtureRunner:
    def __init__(self, *, include_error: bool = False) -> None:
        self.include_error = include_error
        self.calls = 0

    async def execute(
        self,
        attack: ValidatedAttackV1,
        context: Any,
    ) -> AttackEvidenceV1:
        self.calls += 1
        started = utc_now()
        completed = started + timedelta(milliseconds=10)
        payload = {
            "schema_version": "v1",
            "target_id": context.target_id,
            "campaign_id": context.campaign_id,
            "attempt_id": context.attempt_id,
            "target_version": context.target_version,
            "executed_action_sequence": [
                {
                    "sequence_index": index,
                    "action": action.model_dump(mode="json"),
                    "status": "succeeded",
                    "started_at": started.isoformat(),
                    "completed_at": completed.isoformat(),
                    "sanitized_result_summary": "Synthetic action completed.",
                }
                for index, action in enumerate(attack.proposal.ordered_actions)
            ],
            "transcript": [
                {
                    "turn_index": 0,
                    "role": "assistant",
                    "content": "Synthetic patient A remained isolated.",
                    "observed_at": completed.isoformat(),
                }
            ],
            "sanitized_http_metadata": [
                {
                    "exchange_id": f"fixture-http-{self.calls}",
                    "method": "POST",
                    "endpoint_id": "copilot_chat_proxy",
                    "response_status": 200,
                    "response_content_type": "application/json",
                    "response_size_bytes": 64,
                    "response_truncated": False,
                    "elapsed_ms": 10.0,
                    "error_summary": None,
                }
            ],
            "target_visible_tool_calls": [
                {
                    "call_id": f"tool-{self.calls}",
                    "tool_name": "get_patient_summary",
                    "sanitized_arguments": {"patient_alias": "patient_a"},
                    "patient_context_alias": "patient_a",
                }
            ],
            "side_effects": [],
            "started_at": started.isoformat(),
            "completed_at": completed.isoformat(),
            "total_latency_ms": 10.0,
            "errors": (
                [
                    {
                        "schema_version": "v1",
                        "code": "target_timeout",
                        "message": "Synthetic partial evidence timeout.",
                        "retryable": True,
                        "occurred_at": completed.isoformat(),
                        "correlation_id": "runner-timeout",
                        "campaign_id": context.campaign_id,
                        "attempt_id": context.attempt_id,
                        "sanitized_details": {},
                    }
                ]
                if self.include_error
                else []
            ),
            "langfuse_trace_id": f"runner-trace-{self.calls}",
            "evidence_hash": "0" * 64,
        }
        draft = AttackEvidenceV1.model_validate_json(json.dumps(payload))
        canonical = json.dumps(
            draft.model_dump(mode="json", exclude={"evidence_hash"}),
            sort_keys=True,
            separators=(",", ":"),
        )
        payload["evidence_hash"] = hashlib.sha256(canonical.encode()).hexdigest()
        return AttackEvidenceV1.model_validate_json(json.dumps(payload))


@pytest.fixture(scope="module")
def database() -> Database:
    assert TEST_DATABASE_URL is not None
    if not (make_url(TEST_DATABASE_URL).database or "").endswith("_test"):
        pytest.fail("PostgreSQL integration database name must end with '_test'")
    configured = Database(TEST_DATABASE_URL)
    configured.ping()
    with configured.engine.begin() as connection:
        connection.execute(text("DROP SCHEMA public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))
    migration_config = Config(str(PROJECT_ROOT / "alembic.ini"))
    migration_config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    with configured.engine.begin() as connection:
        migration_config.attributes["connection"] = connection
        command.upgrade(migration_config, "head")
    yield configured
    configured.dispose()


@pytest.fixture(autouse=True)
def clean_database(database: Database) -> None:
    with database.engine.begin() as connection:
        connection.execute(text("TRUNCATE TABLE campaigns CASCADE"))
        connection.execute(text("TRUNCATE TABLE target_versions CASCADE"))


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    assert TEST_DATABASE_URL is not None
    return Settings(
        environment="test",
        database_url=TEST_DATABASE_URL,
        langfuse_enabled=False,
        worker_enabled=False,
        target_base_url="http://localhost:9300",
        target_api_base_url="http://localhost:8001",
        target_verify_tls=False,
        target_test_username="synthetic-fixture-user",
        target_test_password=SecretStr("synthetic-fixture-password"),  # noqa: S106
        target_test_role="physician",
        reports_dir=tmp_path / "reports",
        artifacts_dir=tmp_path / "artifacts",
    )


def _actions(message: str) -> list[dict[str, Any]]:
    return [
        {
            "action_id": "a0",
            "description": "Reset the synthetic conversation",
            "action_type": "reset_session",
            "reset_strategy_id": "fresh_ephemeral_browser_context",
            "require_clean_context": True,
        },
        {
            "action_id": "a1",
            "description": "Authenticate the synthetic physician",
            "action_type": "authenticate",
            "session_source": "environment_credentials",
            "test_identity_alias": "physician_test",
            "expected_role": "physician",
        },
        {
            "action_id": "a2",
            "description": "Select synthetic patient A",
            "action_type": "select_synthetic_patient",
            "patient_alias": "patient_a",
            "verify_selected_context": True,
        },
        {
            "action_id": "a3",
            "description": "Send the generated security probe",
            "action_type": "send_chat_message",
            "message": message,
            "conversation_alias": "fixture",
            "await_response": True,
        },
        {
            "action_id": "a4",
            "description": "Wait for the bounded response",
            "action_type": "wait_for_response",
            "timeout_seconds": 5.0,
            "expected_event": "copilot_response_complete",
        },
        {
            "action_id": "a5",
            "description": "Collect raw evidence",
            "action_type": "collect_evidence",
            "evidence_kinds": [
                "transcript",
                "http_metadata",
                "tool_calls",
                "side_effects",
            ],
            "capture_on": "always",
        },
    ]


def _proposal(payload: dict[str, Any], call: int) -> ProposedAttackV1:
    objective = payload["objective"]
    return ProposedAttackV1.model_validate_json(
        json.dumps(
            {
                "schema_version": "v1",
                "proposal_id": f"proposal-{call}",
                "category": objective["selected_category"],
                "subcategory": objective["selected_subcategory"],
                "attack_family_id": "semantic-boundary-family",
                "parent_attempt_id": objective["mutation_source_attempt_id"],
                "novelty_rationale": "Generated from the current objective and prior outcome.",
                "prerequisites": ["Synthetic physician identity"],
                "ordered_actions": _actions(f"Generated probe number {call}"),
                "expected_exploit_signals": ["A semantic security boundary is crossed"],
                "expected_safe_behavior": ["The request is safely refused"],
                "stop_conditions": ["Stop after one response"],
                "risk_flags": [],
                "estimated_turns": 1,
                "estimated_cost_class": "low",
            }
        )
    )


def _decision(payload: dict[str, Any], _kwargs: Any) -> OrchestratorDecisionV1:
    selected = payload["allowed_objectives"][0]
    eligible = payload["eligible_mutation_attempt_ids"]
    return OrchestratorDecisionV1.model_validate_json(
        json.dumps(
            {
                "schema_version": "v1",
                "requested_action": "mutation" if eligible else "new_attack",
                "selected_category": selected["category"],
                "selected_subcategory": selected["subcategory"],
                "objective": "Evaluate the semantic clinical-relevance boundary.",
                "mutation_source_attempt_id": eligible[0] if eligible else None,
            }
        )
    )


def _verdict(kind: str) -> JudgeVerdictV1:
    return JudgeVerdictV1.model_validate_json(
        json.dumps(
            {
                "schema_version": "v1",
                "verdict": kind,
                "severity": "none" if kind == "attack_blocked" else "medium",
                "exploitability": ("not_applicable" if kind == "attack_blocked" else "medium"),
                "confidence": 0.95,
                "violated_security_invariants": (
                    [] if kind == "attack_blocked" else ["clinical-relevance-boundary"]
                ),
                "observed_behavior": "The Judge evaluated the raw structured evidence.",
                "expected_behavior": "The target should preserve the clinical boundary.",
                "rubric_version": "fixture-rubric-v1",
                "rubric_hash": "c" * 64,
            }
        )
    )


def _report(request: Any, _kwargs: Any) -> VulnerabilityReportV1:
    snapshot = request.confirmed_finding_snapshot
    return VulnerabilityReportV1(
        report_schema_version="v1",
        vulnerability_id=snapshot.vulnerability_id,
        title="Judge-confirmed semantic security boundary failure",
        severity=snapshot.severity,
        status=snapshot.status,
        category=snapshot.category,
        subcategory=snapshot.subcategory,
        owasp_mappings=snapshot.owasp_mappings,
        affected_target_versions=[request.evidence.target_version],
        description="One generated attack crossed the semantic boundary.",
        clinical_impact="A clinically irrelevant tool action can undermine user trust.",
        prerequisites=["Synthetic physician identity"],
        minimal_reproducible_attack_sequence=request.exact_action_sequence,
        observed_behavior=request.judge_verdict.observed_behavior,
        expected_behavior=request.judge_verdict.expected_behavior,
        source_attempt_id=snapshot.source_attempt_id,
        evidence_hash=request.evidence.evidence_hash,
        recommended_remediation_approach="Enforce clinical relevance before tool execution.",
        current_fix_validation_results=[],
        confidence=request.judge_verdict.confidence,
        created_at=utc_now(),
        updated_at=utc_now(),
    )


async def _discover(*_args: Any) -> DiscoveredTargetVersion:
    return DiscoveredTargetVersion(
        version="synthetic-build-v1",
        endpoint_id="status_health",
        status_code=200,
    )


def _controller(
    database: Database,
    settings: Settings,
    tmp_path: Path,
    *,
    runner: FixtureRunner | None = None,
    orchestrator_factory: Callable[[Any, Any], Any] = _decision,
    attack_factory: Callable[[Any, Any], Any] | None = None,
    judge_factory: Callable[[Any, Any], Any] | None = None,
    fail_role: str | None = None,
) -> CampaignController:
    attack_calls = 0
    judge_calls = 0

    def generated(payload: Any, kwargs: Any) -> ProposedAttackV1:
        nonlocal attack_calls
        attack_calls += 1
        if attack_factory is not None:
            return attack_factory(payload, kwargs)
        return _proposal(payload, attack_calls)

    def judged(payload: Any, kwargs: Any) -> JudgeVerdictV1:
        nonlocal judge_calls
        judge_calls += 1
        if judge_factory is not None:
            return judge_factory(payload, {**kwargs, "call": judge_calls})
        return _verdict("attack_blocked")

    def role(name: str, factory: Callable[[Any, Any], Any]) -> FakeRole:
        setting_name = (
            "openai_attack_model" if name == "attack_generator" else f"openai_{name}_model"
        )
        model = getattr(settings, setting_name)
        if fail_role == name:
            return FailingRole(name, model, factory)
        return FakeRole(name, model, factory)

    return CampaignController(
        database=database,
        settings=settings,
        loaded_profile=load_target_profile(PROJECT_ROOT / "config/target-profile.yaml"),
        taxonomy=load_taxonomy(PROJECT_ROOT / "config/attack-taxonomy.yaml"),
        rubric=load_judge_rubric(PROJECT_ROOT / "config/judge-rubric.yaml"),
        orchestrator=role("orchestrator", orchestrator_factory),
        attack_generator=role("attack_generator", generated),
        judge=role("judge", judged),
        documentation=role("documentation", _report),
        runner=runner or FixtureRunner(),
        telemetry=None,
        metric_registry=AgentForgeMetrics(CollectorRegistry()),
        version_discoverer=_discover,
        repository_root=tmp_path,
    )


def _campaign(
    database: Database,
    *,
    campaign_type: str = "discovery",
    max_attempts: int = 1,
) -> Campaign:
    with database.session_factory() as session:
        return CampaignRepository(session).create(
            campaign_type=campaign_type,
            trigger_type="integration_fixture",
            target_alias="local",
            target_version="queued-version",
            category_scope=("data_exfiltration" if campaign_type == "discovery" else None),
            subcategory_scope=("cross_patient_exposure" if campaign_type == "discovery" else None),
            max_cost_usd=Decimal("1"),
            max_attempts=max_attempts,
            max_duration_seconds=60,
            idempotency_key=f"fixture-{campaign_type}-{uuid.uuid4()}",
        )


async def _run(
    database: Database,
    settings: Settings,
    controller: CampaignController,
) -> None:
    worker = CampaignWorker(
        database=database,
        settings=settings,
        processor=controller,
        metrics=AgentForgeMetrics(CollectorRegistry()),
        worker_name="fixture-worker",
    )
    assert await worker.run_once() is True


@pytest.mark.asyncio
async def test_secure_attempt_persists_raw_evidence_and_judge_only_outcome(
    database: Database,
    settings: Settings,
    tmp_path: Path,
) -> None:
    campaign = _campaign(database)
    await _run(database, settings, _controller(database, settings, tmp_path))

    with database.session_factory() as session:
        stored = session.get(Campaign, campaign.id)
        attempt = session.scalar(
            select(AttackAttempt).where(AttackAttempt.campaign_id == campaign.id)
        )
        assert stored.status == "completed"
        assert attempt.state == "completed"
        assert attempt.failure is None
        assert attempt.proposal_source == "agent_generated"
        assert attempt.objective_source == "orchestrator_selected"
        assert "deterministic_assertion_results" not in attempt.evidence_payload
        assert session.scalar(select(func.count()).select_from(JudgeVerdict)) == 1
        assert session.scalar(select(func.count()).select_from(Finding)) == 0
        assert session.scalar(select(func.count()).select_from(AgentRun)) == 3


@pytest.mark.asyncio
async def test_one_confirmed_attempt_immediately_creates_finding_report_and_regression(
    database: Database,
    settings: Settings,
    tmp_path: Path,
) -> None:
    campaign = _campaign(database)
    await _run(
        database,
        settings,
        _controller(
            database,
            settings,
            tmp_path,
            judge_factory=lambda *_args: _verdict("exploit_confirmed"),
        ),
    )
    with database.session_factory() as session:
        attempt = session.scalar(
            select(AttackAttempt).where(AttackAttempt.campaign_id == campaign.id)
        )
        assert session.get(Campaign, campaign.id).status == "completed"
        assert attempt.state == "completed"
        assert session.scalar(select(func.count()).select_from(Finding)) == 1
        assert session.scalar(select(func.count()).select_from(VulnerabilityReport)) == 1
        assert session.scalar(select(func.count()).select_from(RegressionCase)) == 1
        roles = list(
            session.scalars(select(AgentRun.role).where(AgentRun.campaign_id == campaign.id))
        )
        assert roles == ["orchestrator", "attack_generator", "judge", "documentation"]


@pytest.mark.asyncio
async def test_identical_semantic_exploits_create_separate_findings_and_continue(
    database: Database,
    settings: Settings,
    tmp_path: Path,
) -> None:
    campaign = _campaign(database, max_attempts=2)
    await _run(
        database,
        settings,
        _controller(
            database,
            settings,
            tmp_path,
            judge_factory=lambda *_args: _verdict("exploit_confirmed"),
        ),
    )
    with database.session_factory() as session:
        attempts = list(
            session.scalars(
                select(AttackAttempt)
                .where(AttackAttempt.campaign_id == campaign.id)
                .order_by(AttackAttempt.created_at)
            )
        )
        findings = list(session.scalars(select(Finding).order_by(Finding.created_at)))
        assert len(attempts) == 2
        assert all(attempt.state == "completed" for attempt in attempts)
        assert len(findings) == 2
        assert len({finding.fingerprint for finding in findings}) == 2
        assert session.scalar(select(func.count()).select_from(VulnerabilityReport)) == 2
        assert session.scalar(select(func.count()).select_from(RegressionCase)) == 2


@pytest.mark.asyncio
async def test_partial_signal_allows_agent_generated_mutation_with_parent(
    database: Database,
    settings: Settings,
    tmp_path: Path,
) -> None:
    campaign = _campaign(database, max_attempts=2)

    def partial_then_blocked(_payload: Any, kwargs: Any) -> JudgeVerdictV1:
        return _verdict("partial_signal" if kwargs["call"] == 1 else "attack_blocked")

    await _run(
        database,
        settings,
        _controller(
            database,
            settings,
            tmp_path,
            judge_factory=partial_then_blocked,
        ),
    )
    with database.session_factory() as session:
        attempts = list(
            session.scalars(
                select(AttackAttempt)
                .where(AttackAttempt.campaign_id == campaign.id)
                .order_by(AttackAttempt.created_at)
            )
        )
        assert len(attempts) == 2
        assert attempts[0].parent_attempt_id is None
        assert attempts[1].parent_attempt_id == attempts[0].id
        assert attempts[1].proposal_source == "agent_generated_mutation"


@pytest.mark.asyncio
async def test_invalid_orchestrator_decision_fails_without_target_attempt(
    database: Database,
    settings: Settings,
    tmp_path: Path,
) -> None:
    def invalid(_payload: Any, _kwargs: Any) -> OrchestratorDecisionV1:
        return OrchestratorDecisionV1.model_validate_json(
            json.dumps(
                {
                    "schema_version": "v1",
                    "requested_action": "new_attack",
                    "selected_category": "unknown",
                    "selected_subcategory": "unknown",
                    "objective": "Leave the supplied objective set.",
                }
            )
        )

    campaign = _campaign(database)
    runner = FixtureRunner()
    await _run(
        database,
        settings,
        _controller(
            database,
            settings,
            tmp_path,
            runner=runner,
            orchestrator_factory=invalid,
        ),
    )
    with database.session_factory() as session:
        stored = session.get(Campaign, campaign.id)
        run = session.scalar(select(AgentRun).where(AgentRun.campaign_id == campaign.id))
        assert stored.status == "failed"
        assert stored.sanitized_error["code"] == "invalid_objective_selection"
        assert run.status == "rejected"
        assert run.output_payload["selected_category"] == "unknown"
        assert session.scalar(select(func.count()).select_from(AttackAttempt)) == 0
    assert runner.calls == 0


@pytest.mark.asyncio
async def test_attack_generator_failure_has_no_seed_fallback_or_attempt(
    database: Database,
    settings: Settings,
    tmp_path: Path,
) -> None:
    campaign = _campaign(database)
    runner = FixtureRunner()
    await _run(
        database,
        settings,
        _controller(
            database,
            settings,
            tmp_path,
            runner=runner,
            fail_role="attack_generator",
        ),
    )
    with database.session_factory() as session:
        stored = session.get(Campaign, campaign.id)
        assert stored.status == "failed"
        assert stored.sanitized_error["code"] == "attack_generator_failed"
        assert session.scalar(select(func.count()).select_from(AttackAttempt)) == 0
        assert not session.scalar(
            select(func.count()).select_from(AgentRun).where(AgentRun.status == "fallback")
        )
    assert runner.calls == 0


@pytest.mark.asyncio
async def test_gate_rejection_records_rejected_agent_run_without_attempt(
    database: Database,
    settings: Settings,
    tmp_path: Path,
) -> None:
    def invalid_sequence(payload: Any, _kwargs: Any) -> ProposedAttackV1:
        objective = payload["objective"]
        return ProposedAttackV1.model_validate_json(
            json.dumps(
                {
                    "schema_version": "v1",
                    "proposal_id": "invalid-sequence",
                    "category": objective["selected_category"],
                    "subcategory": objective["selected_subcategory"],
                    "attack_family_id": "invalid-family",
                    "novelty_rationale": "Intentionally fails the structural gate.",
                    "ordered_actions": [
                        {
                            "action_id": "only-chat",
                            "description": "Missing required safety prefix",
                            "action_type": "send_chat_message",
                            "message": "Unsafe sequence shape",
                            "conversation_alias": "fixture",
                            "await_response": True,
                        }
                    ],
                    "expected_exploit_signals": ["No signal"],
                    "expected_safe_behavior": ["Gate rejection"],
                    "stop_conditions": ["Stop"],
                    "estimated_turns": 1,
                    "estimated_cost_class": "low",
                }
            )
        )

    campaign = _campaign(database)
    runner = FixtureRunner()
    await _run(
        database,
        settings,
        _controller(
            database,
            settings,
            tmp_path,
            runner=runner,
            attack_factory=invalid_sequence,
        ),
    )
    with database.session_factory() as session:
        attack_run = session.scalar(
            select(AgentRun)
            .where(AgentRun.campaign_id == campaign.id)
            .where(AgentRun.role == "attack_generator")
        )
        assert session.get(Campaign, campaign.id).status == "failed"
        assert attack_run.status == "rejected"
        assert attack_run.typed_error["stage"] == "authorization"
        assert attack_run.output_payload["proposal_id"] == "invalid-sequence"
        assert session.scalar(select(func.count()).select_from(AttackAttempt)) == 0
    assert runner.calls == 0


@pytest.mark.asyncio
async def test_judge_failure_preserves_raw_evidence_without_finding(
    database: Database,
    settings: Settings,
    tmp_path: Path,
) -> None:
    campaign = _campaign(database)
    await _run(
        database,
        settings,
        _controller(database, settings, tmp_path, fail_role="judge"),
    )
    with database.session_factory() as session:
        attempt = session.scalar(
            select(AttackAttempt).where(AttackAttempt.campaign_id == campaign.id)
        )
        assert session.get(Campaign, campaign.id).status == "failed"
        assert attempt.state == "failed"
        assert attempt.failure["stage"] == "judge"
        assert attempt.evidence_payload is not None
        assert session.scalar(select(func.count()).select_from(JudgeVerdict)) == 0
        assert session.scalar(select(func.count()).select_from(Finding)) == 0


@pytest.mark.asyncio
async def test_documentation_failure_preserves_confirmed_finding_and_stops_campaign(
    database: Database,
    settings: Settings,
    tmp_path: Path,
) -> None:
    campaign = _campaign(database)
    await _run(
        database,
        settings,
        _controller(
            database,
            settings,
            tmp_path,
            judge_factory=lambda *_args: _verdict("exploit_confirmed"),
            fail_role="documentation",
        ),
    )
    with database.session_factory() as session:
        attempt = session.scalar(
            select(AttackAttempt).where(AttackAttempt.campaign_id == campaign.id)
        )
        assert session.get(Campaign, campaign.id).status == "failed"
        assert attempt.failure["stage"] == "documentation"
        assert session.scalar(select(func.count()).select_from(Finding)) == 1
        assert session.scalar(select(func.count()).select_from(VulnerabilityReport)) == 0
        assert session.scalar(select(func.count()).select_from(RegressionCase)) == 0


@pytest.mark.asyncio
async def test_saved_regression_outcome_is_mapped_only_from_judge(
    database: Database,
    settings: Settings,
    tmp_path: Path,
) -> None:
    _campaign(database)
    await _run(
        database,
        settings,
        _controller(
            database,
            settings,
            tmp_path,
            judge_factory=lambda *_args: _verdict("exploit_confirmed"),
        ),
    )
    regression = _campaign(database, campaign_type="regression", max_attempts=10)
    with database.session_factory() as session:
        RegressionRunRepository(session).create(
            target_version="synthetic-build-v1",
            trigger="integration_fixture",
            campaign_id=regression.id,
        )
    await _run(database, settings, _controller(database, settings, tmp_path))
    with database.session_factory() as session:
        result = session.scalar(select(RegressionResult))
        attempt = session.scalar(
            select(AttackAttempt).where(AttackAttempt.campaign_id == regression.id)
        )
        assert result.outcome == "secure_pass", result.judge_result
        assert result.judge_result["verdict"] == "attack_blocked"
        assert result.evidence_hash
        assert attempt.proposal_source == "fixed_regression_case"
        assert attempt.state == "completed"


def test_default_controller_factory_constructs_without_external_calls(
    database: Database,
    settings: Settings,
) -> None:
    controller = build_campaign_controller(
        database=database,
        settings=settings,
        metrics=AgentForgeMetrics(CollectorRegistry()),
        telemetry=None,
    )
    assert isinstance(controller, CampaignController)
