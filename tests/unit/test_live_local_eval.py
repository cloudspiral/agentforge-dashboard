from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr
from sqlalchemy import func, select

from agentforge.agents.base import AgentInvocationResult, AgentUsage
from agentforge.contracts.v1 import (
    ActionExecutionStatusV1,
    AgentErrorCodeV1,
    AgentErrorV1,
    JudgeVerdictV1,
    TokenUsageV1,
    TranscriptRoleV1,
)
from agentforge.contracts.v1.common import utc_now
from agentforge.evaluation import live_local as live_local_module
from agentforge.evaluation import load_seed_case, load_taxonomy
from agentforge.evaluation.live_local import run_live_local_case
from agentforge.evidence import EvidenceArtifactExportFailed, EvidenceArtifactStore
from agentforge.orchestration.execution_gate import ValidatedAttackV1
from agentforge.persistence import Base, Database
from agentforge.persistence.models import (
    AgentRun,
    AttackAttempt,
    Campaign,
    JudgeVerdict,
    TargetVersion,
)
from agentforge.runners.base import (
    EvidenceRecorder,
    RunnerActionRejected,
    TargetExecutionContext,
)
from agentforge.settings import Settings
from agentforge.target import load_target_profile
from agentforge.target.version import DiscoveredTargetVersion

ROOT = Path(__file__).parents[2]
CASE_PATH = ROOT / "evals" / "seed-cases" / "pi-direct-instruction-override.yaml"
API_CASE_PATH = ROOT / "evals" / "seed-cases" / "tm-parameter-tampering.yaml"


def _database(tmp_path: Path) -> Database:
    database = Database(f"sqlite+pysqlite:///{tmp_path / 'live-local.db'}")
    campaign_table = Base.metadata.tables["campaigns"]
    duplicates = [
        index for index in campaign_table.indexes if index.name == "ix_campaigns_target_version"
    ]
    for duplicate in duplicates[1:]:
        campaign_table.indexes.remove(duplicate)
    Base.metadata.create_all(database.engine)
    return database


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "test",
        "database_url": f"sqlite+pysqlite:///{tmp_path / 'live-local.db'}",
        "target_profile_path": ROOT / "config" / "target-profile.yaml",
        "attack_taxonomy_path": ROOT / "config" / "attack-taxonomy.yaml",
        "judge_rubric_path": ROOT / "config" / "judge-rubric.yaml",
        "pricing_path": ROOT / "config" / "pricing.yaml",
        "target_base_url": "https://localhost:9300",
        "target_api_base_url": "http://localhost:8001",
        "target_verify_tls": True,
        "agentforge_ui_ignore_https_errors": True,
        "target_test_username": "admin",
        "target_test_password": SecretStr("pass"),
        "target_test_role": "physician",
        "openai_api_key": SecretStr("unit-openai-api-key"),
        "langfuse_enabled": False,
        "artifacts_dir": Path("artifacts"),
    }
    values.update(overrides)
    return Settings(**values)


async def _version(*_args: Any) -> DiscoveredTargetVersion:
    return DiscoveredTargetVersion("local-build-123", "status_health", 200)


class FakeBrowserRunner:
    def __init__(
        self,
        *,
        fail: bool = False,
        response: str = "The selected synthetic chart remained in scope.",
        cleanup_warnings: tuple[str, ...] = (),
    ) -> None:
        self.fail = fail
        self.response = response
        self.cleanup_warnings = cleanup_warnings
        self.sent_messages: list[str] = []
        self.context: TargetExecutionContext | None = None

    async def execute(
        self,
        attack: ValidatedAttackV1,
        context: TargetExecutionContext,
    ):
        self.context = context
        recorder = EvidenceRecorder(context)
        for index, action in enumerate(attack.proposal.ordered_actions):
            started_at = utc_now()
            if self.fail and index == 0:
                failure = RunnerActionRejected("fake browser execution failed")
                recorder.add_action(
                    sequence_index=index,
                    action=action,
                    started_at=started_at,
                    status=failure.status,
                    summary=failure.public_message,
                )
                recorder.add_error(failure)
                for skipped_index, skipped in enumerate(
                    attack.proposal.ordered_actions[index + 1 :], start=index + 1
                ):
                    recorder.add_skipped(skipped_index, skipped)
                break
            if action.action_type.value == "send_chat_message":
                self.sent_messages.append(action.message)
                recorder.add_transcript(TranscriptRoleV1.USER, action.message)
                recorder.add_transcript(TranscriptRoleV1.ASSISTANT, self.response)
            recorder.add_action(
                sequence_index=index,
                action=action,
                started_at=started_at,
                status=ActionExecutionStatusV1.SUCCEEDED,
                summary="fake browser action completed",
            )
        return recorder.finalize()


class FakeJudge:
    def __init__(self, *, contract_failures: int = 0) -> None:
        self.calls = 0
        self.contract_failures = contract_failures

    async def invoke(self, _payload: Any, **kwargs: Any) -> AgentInvocationResult[JudgeVerdictV1]:
        self.calls += 1
        trace_id = f"judge-trace-{self.calls}"
        if self.calls <= self.contract_failures:
            return AgentInvocationResult(
                role="judge",
                model="fake-judge",
                prompt_version="fake-judge-v1",
                prompt_sha256="a" * 64,
                payload_sha256="b" * 64,
                usage=AgentUsage.zero(),
                estimated_cost_usd=0.0,
                latency_ms=1.0,
                sdk_attempts=1,
                langfuse_trace_id=trace_id,
                error=AgentErrorV1(
                    schema_version="v1",
                    code=AgentErrorCodeV1.INVALID_CONTRACT,
                    message="The model response did not satisfy the declared output contract.",
                    retryable=False,
                    occurred_at=utc_now(),
                    correlation_id=f"judge-{self.calls}",
                    campaign_id=kwargs["campaign_id"],
                    attempt_id=kwargs["attempt_id"],
                    sanitized_details={"agent_role": "judge", "reason": "model_behavior"},
                ),
            )
        verdict = JudgeVerdictV1.model_validate_json(
            """{
                "schema_version":"v1",
                "verdict":"attack_blocked",
                "severity":"none",
                "exploitability":"not_applicable",
                "confidence":0.95,
                "violated_security_invariants":[],
                "observed_behavior":"The fixed synthetic case remained within scope.",
                "expected_behavior":"The selected chart remains authoritative.",
                "rubric_version":"fake-rubric",
                "rubric_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            }"""
        )
        return AgentInvocationResult(
            role="judge",
            model="fake-judge",
            prompt_version="fake-judge-v1",
            prompt_sha256="a" * 64,
            payload_sha256="b" * 64,
            usage=AgentUsage(tokens=TokenUsageV1(input_tokens=10, output_tokens=5, calls=1)),
            estimated_cost_usd=0.001,
            latency_ms=1.0,
            sdk_attempts=1,
            langfuse_trace_id=trace_id,
            output=verdict,
        )


async def _run(
    tmp_path: Path,
    *,
    runner: FakeBrowserRunner | None,
    judge: FakeJudge,
    case_path: Path = CASE_PATH,
    settings: Settings | None = None,
    target_alias: str = "local",
    headed: bool = False,
    evidence_store: EvidenceArtifactStore | None = None,
):
    database = _database(tmp_path)
    try:
        result = await run_live_local_case(
            case_path=case_path,
            settings=settings or _settings(tmp_path),
            database=database,
            loaded_profile=load_target_profile(ROOT / "config" / "target-profile.yaml"),
            taxonomy=load_taxonomy(ROOT / "config" / "attack-taxonomy.yaml"),
            repository_root=ROOT,
            results_dir=tmp_path / "results",
            runner=runner,
            judge=judge,
            version_discoverer=_version,
            target_alias=target_alias,
            headed=headed,
            evidence_store=evidence_store or EvidenceArtifactStore(tmp_path / "evidence"),
        )
        return database, result
    except Exception:
        database.dispose()
        raise


@pytest.mark.asyncio
async def test_seed_chat_case_uses_current_yaml_message(tmp_path: Path) -> None:
    browser = FakeBrowserRunner()
    judge = FakeJudge()
    database, result = await _run(
        tmp_path,
        runner=browser,
        judge=judge,
        case_path=API_CASE_PATH,
    )

    try:
        assert result.successful is True
        assert result.case_id == "AF-TM-002"
        current_case = load_seed_case(API_CASE_PATH)
        expected_messages = [
            action.message for action in current_case.actions if action.type == "send_chat_message"
        ]
        assert browser.sent_messages == expected_messages
        assert judge.calls == 1
    finally:
        database.dispose()


@pytest.mark.asyncio
async def test_deployed_case_requires_explicit_live_opt_in(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="RUN_LIVE_E2E=1"):
        await _run(
            tmp_path,
            runner=FakeBrowserRunner(),
            judge=FakeJudge(),
            settings=_settings(
                tmp_path,
                run_live_e2e=False,
                agentforge_ui_ignore_https_errors=False,
            ),
            target_alias="deployed",
        )


@pytest.mark.asyncio
async def test_deployed_case_pins_secure_headless_managed_chromium(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launch_options: dict[str, Any] = {}
    browser = FakeBrowserRunner()

    def runner_factory(**kwargs: Any) -> FakeBrowserRunner:
        launch_options.update(kwargs)
        return browser

    monkeypatch.setattr(live_local_module, "PlaywrightAttackRunner", runner_factory)
    database, result = await _run(
        tmp_path,
        runner=None,
        judge=FakeJudge(),
        settings=_settings(
            tmp_path,
            run_live_e2e=True,
            agentforge_ui_ignore_https_errors=False,
            agentforge_browser_channel="chrome",
        ),
        target_alias="deployed",
    )

    try:
        assert result.successful is True
        assert result.run_mode == "live_deployed"
        assert result.target_alias == "deployed"
        assert launch_options == {
            "headless": True,
            "browser_mode": "chromium",
            "ignore_https_errors": False,
        }
        assert browser.context is not None
        assert browser.context.target_alias.name == "deployed"
        assert browser.context.target_alias.verify_tls is True
        with database.session_factory() as session:
            campaign = session.scalar(select(Campaign))
            target_version = session.scalar(select(TargetVersion))
            assert campaign is not None
            assert campaign.target_alias == "deployed"
            assert campaign.trigger_type == "live_deployed"
            assert target_version is not None
            assert target_version.base_url_alias == "deployed"
            assert target_version.metadata_json["run_mode"] == "live_deployed"
    finally:
        database.dispose()


@pytest.mark.asyncio
async def test_fixed_case_persists_evidence_verdict_and_secret_free_export(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    response = (
        "Synthetic response accidentally echoed admin and pass, but the configured "
        "assertion outcome should remain passed. The long key was unit-openai-api-key."
    )
    browser = FakeBrowserRunner(response=response)
    judge = FakeJudge()
    database, result = await _run(tmp_path, runner=browser, judge=judge)

    try:
        assert result.successful is True
        assert result.status == "completed"
        assert result.run_mode == "live_local"
        assert result.case_id == "AF-PI-001"
        assert result.case_version == "1.0"
        assert result.target_version == "local-build-123"
        assert [item.content for item in result.sent_messages] == browser.sent_messages
        assert result.evidence is not None
        assert result.judge_verdict is not None
        assert judge.calls == 1

        with database.session_factory() as session:
            assert session.scalar(select(func.count()).select_from(Campaign)) == 1
            attempt = session.scalar(select(AttackAttempt))
            assert attempt is not None
            assert attempt.evidence_payload is not None
            assert attempt.evidence_hash == result.evidence.evidence_hash
            assert attempt.langfuse_trace_id == "judge-trace-1"
            assert session.scalar(select(JudgeVerdict)) is not None
            agent_run = session.scalar(select(AgentRun))
            assert agent_run is not None
            assert agent_run.status == "succeeded"
            assert agent_run.langfuse_trace_id == "judge-trace-1"
            assert agent_run.typed_error is None

        export_path = tmp_path / "results" / result.result_path
        exported = export_path.read_text(encoding="utf-8")
        for secret in (
            settings.target_test_username,
            settings.target_test_password.get_secret_value(),
            settings.openai_api_key.get_secret_value(),
        ):
            assert (
                re.search(rf"(?<![A-Za-z0-9]){re.escape(secret)}(?![A-Za-z0-9])", exported) is None
            )
        assert '"outcome": "passed"' in exported
        assert "[REDACTED]" in exported
    finally:
        database.dispose()


@pytest.mark.asyncio
async def test_evidence_export_failure_preserves_database_payload_and_skips_judge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EvidenceArtifactStore(tmp_path / "evidence")

    def fail_export(_prepared: object) -> Path:
        raise EvidenceArtifactExportFailed("injected evidence export failure")

    monkeypatch.setattr(store, "export", fail_export)
    judge = FakeJudge()
    database, result = await _run(
        tmp_path,
        runner=FakeBrowserRunner(),
        judge=judge,
        evidence_store=store,
    )

    try:
        assert result.successful is False
        assert result.error_code == "evidence_export_failed"
        assert judge.calls == 0
        with database.session_factory() as session:
            attempt = session.get(AttackAttempt, uuid.UUID(result.attempt_id))
            assert attempt is not None
            assert attempt.evidence_payload == result.evidence.model_dump(mode="json")
            assert attempt.evidence_hash == result.evidence.evidence_hash
            assert attempt.state == "failed"
            assert attempt.failure == {
                "stage": "evidence",
                "code": "evidence_export_failed",
                "retryable": True,
            }
    finally:
        database.dispose()


@pytest.mark.asyncio
async def test_invalid_judge_contract_is_retried_once_and_audited(tmp_path: Path) -> None:
    judge = FakeJudge(contract_failures=1)
    database, result = await _run(
        tmp_path,
        runner=FakeBrowserRunner(),
        judge=judge,
    )

    try:
        assert result.successful is True
        assert result.status == "completed"
        assert judge.calls == 2
        with database.session_factory() as session:
            attempt = session.scalar(select(AttackAttempt))
            assert attempt is not None
            assert attempt.state == "completed"
            assert attempt.langfuse_trace_id == "judge-trace-2"
            runs = list(session.scalars(select(AgentRun).order_by(AgentRun.created_at)))
            assert [run.status for run in runs] == ["failed", "succeeded"]
            assert [run.langfuse_trace_id for run in runs] == [
                "judge-trace-1",
                "judge-trace-2",
            ]
            assert runs[0].typed_error is not None
            assert runs[0].typed_error["code"] == "invalid_contract"
            assert runs[0].typed_error["sanitized_details"]["reason"] == "model_behavior"
            assert runs[1].typed_error is None
    finally:
        database.dispose()


@pytest.mark.asyncio
async def test_repeated_invalid_judge_contract_persists_specific_failure(
    tmp_path: Path,
) -> None:
    judge = FakeJudge(contract_failures=2)
    database, result = await _run(
        tmp_path,
        runner=FakeBrowserRunner(),
        judge=judge,
    )

    try:
        assert result.successful is False
        assert result.status == "judge_failed"
        assert result.error_code == "judge_failed"
        assert result.error_message == (
            "the Judge returned invalid structured output after one bounded retry"
        )
        assert judge.calls == 2
        with database.session_factory() as session:
            campaign = session.scalar(select(Campaign))
            attempt = session.scalar(select(AttackAttempt))
            assert campaign is not None
            assert campaign.status == "failed"
            assert campaign.sanitized_error == {
                "code": "judge_failed",
                "message": "the Judge returned invalid structured output after one bounded retry",
                "reason": "invalid_contract",
                "judge_invocations": 2,
                "judge_error_code": "invalid_contract",
                "judge_error_reason": "model_behavior",
                "trace_id": "judge-trace-2",
            }
            assert attempt is not None
            assert attempt.state == "failed"
            assert attempt.failure == {
                "stage": "judge",
                "code": "judge_failed",
                "retryable": False,
            }
            assert attempt.langfuse_trace_id == "judge-trace-2"
            assert session.scalar(select(JudgeVerdict)) is None
            runs = list(session.scalars(select(AgentRun).order_by(AgentRun.created_at)))
            assert len(runs) == 2
            assert all(run.status == "failed" for run in runs)
            assert all(run.typed_error is not None for run in runs)
    finally:
        database.dispose()


@pytest.mark.asyncio
async def test_execution_failure_persists_failure_without_fabricating_verdict(
    tmp_path: Path,
) -> None:
    judge = FakeJudge()
    database, result = await _run(
        tmp_path,
        runner=FakeBrowserRunner(fail=True),
        judge=judge,
    )

    try:
        assert result.successful is False
        assert result.status == "execution_failed"
        assert result.failed_step == "execution"
        assert result.judge_verdict is None
        assert judge.calls == 0
        with database.session_factory() as session:
            campaign = session.scalar(select(Campaign))
            attempt = session.scalar(select(AttackAttempt))
            assert campaign is not None and campaign.status == "failed"
            assert attempt is not None and attempt.state == "failed"
            assert attempt.evidence_payload is not None
            assert session.scalar(select(JudgeVerdict)) is None
    finally:
        database.dispose()


@pytest.mark.asyncio
async def test_cleanup_warning_does_not_overwrite_successful_interaction(
    tmp_path: Path,
) -> None:
    database, result = await _run(
        tmp_path,
        runner=FakeBrowserRunner(cleanup_warnings=("browser_cleanup_timeout",)),
        judge=FakeJudge(),
    )

    try:
        assert result.successful is True
        assert result.status == "completed"
        assert result.warnings == ["browser_cleanup_timeout"]
        assert result.judge_verdict is not None
    finally:
        database.dispose()
