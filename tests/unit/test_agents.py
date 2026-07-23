from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from agents import Agent, AgentOutputSchema, RunConfig
from agents.exceptions import ModelBehaviorError, ModelRefusalError
from agents.usage import Usage
from openai import APIStatusError
from openai.types.responses.response_usage import InputTokensDetails, OutputTokensDetails

from agentforge.agents import (
    AttackGeneratorAgent,
    DocumentationAgent,
    JudgeAgent,
    OrchestratorAgent,
    PricingCatalog,
    load_versioned_prompt,
)
from agentforge.contracts.v1 import (
    AgentErrorCodeV1,
    JudgeVerdictV1,
    OrchestratorDecisionV1,
    ProposedAttackV1,
    VulnerabilityReportV1,
)
from agentforge.settings import Settings

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REDACTED = "[REDACTED]"


@dataclass
class FakeResult:
    final_output: Any
    context_wrapper: Any


@dataclass
class RunnerCall:
    agent: Agent[Any]
    input: str
    max_turns: int | None
    run_config: RunConfig | None


class FakeRunner:
    def __init__(self, *events: Any) -> None:
        self.events = list(events)
        self.calls: list[RunnerCall] = []

    async def run(
        self,
        starting_agent: Agent[Any],
        input: str,
        *,
        max_turns: int | None = 10,
        run_config: RunConfig | None = None,
    ) -> Any:
        self.calls.append(
            RunnerCall(
                agent=starting_agent,
                input=input,
                max_turns=max_turns,
                run_config=run_config,
            )
        )
        if not self.events:
            raise AssertionError("fake Runner received an unexpected call")
        event = self.events.pop(0)
        if isinstance(event, BaseException):
            raise event
        return event


class FakeTelemetry:
    enabled = True

    def __init__(self) -> None:
        self.scopes: list[dict[str, Any]] = []

    @contextmanager
    def agent_scope(self, **kwargs: Any) -> Iterator[Any]:
        self.scopes.append(kwargs)
        yield SimpleNamespace(trace_id="langfuse-trace")


def _settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "test",
        "pricing_path": PROJECT_ROOT / "config/pricing.yaml",
        "openai_api_key": None,
        "langfuse_enabled": False,
    }
    values.update(overrides)
    return Settings(**values)


def _usage_result(output: Any, usage: Usage | None = None) -> FakeResult:
    return FakeResult(
        final_output=output,
        context_wrapper=SimpleNamespace(usage=usage or Usage()),
    )


def _output(output_type: type[Any]) -> Any:
    if output_type is VulnerabilityReportV1:
        return output_type.model_construct(report_schema_version="v1")
    return output_type.model_construct(schema_version="v1")


def _status_error(status_code: int) -> APIStatusError:
    request = httpx.Request("POST", "https://api.openai.invalid/v1/responses")
    response = httpx.Response(status_code, request=request)
    return APIStatusError("sanitized by adapter", response=response, body={})


def _agent_options(runner: FakeRunner, **overrides: Any) -> dict[str, Any]:
    options: dict[str, Any] = {
        "settings": _settings(),
        "runner": runner,
        "credentials_available": True,
        "telemetry": None,
        "trace_factory": lambda **_kwargs: nullcontext(),
    }
    options.update(overrides)
    return options


@pytest.mark.parametrize(
    (
        "agent_type",
        "output_type",
        "model",
        "max_tokens",
        "prompt_version",
        "strict_json_schema",
    ),
    [
        (
            OrchestratorAgent,
            OrchestratorDecisionV1,
            "gpt-5.6-terra",
            900,
            "orchestrator-v3-2026-07-23",
            False,
        ),
        (
            AttackGeneratorAgent,
            ProposedAttackV1,
            "gpt-5.6-terra",
            1200,
            "attack-generator-v3-2026-07-23",
            False,
        ),
        (
            JudgeAgent,
            JudgeVerdictV1,
            "gpt-5.6-terra",
            1000,
            "judge-v2-2026-07-23",
            True,
        ),
        (
            DocumentationAgent,
            VulnerabilityReportV1,
            "gpt-5.6-luna",
            1800,
            "documentation-v2-2026-07-23",
            False,
        ),
    ],
)
@pytest.mark.asyncio
async def test_roles_use_one_turn_typed_agents_without_tools_or_handoffs(
    agent_type: type[Any],
    output_type: type[Any],
    model: str,
    max_tokens: int,
    prompt_version: str,
    strict_json_schema: bool,
) -> None:
    expected = _output(output_type)
    runner = FakeRunner(_usage_result(expected))
    adapter = agent_type(**_agent_options(runner))

    outcome = await adapter.run(
        {"bounded": "input"},
        campaign_id="campaign-1",
        attempt_id="attempt-1",
    )

    assert outcome.succeeded is True
    assert outcome.output is expected
    assert outcome.model == model
    assert outcome.prompt_version == prompt_version
    assert len(outcome.prompt_sha256) == 64
    assert outcome.sdk_attempts == 1

    call = runner.calls[0]
    assert call.max_turns == 1
    assert call.agent.model == model
    assert isinstance(call.agent.output_type, AgentOutputSchema)
    assert call.agent.output_type.output_type is output_type
    assert call.agent.output_type.is_strict_json_schema() is strict_json_schema
    assert call.agent.tools == []
    assert call.agent.handoffs == []
    assert call.agent.mcp_servers == []
    assert call.agent.model_settings.max_tokens == max_tokens
    assert call.agent.model_settings.reasoning is not None
    assert call.agent.model_settings.reasoning.effort == "low"
    assert call.agent.model_settings.verbosity == "low"
    assert call.agent.model_settings.store is False
    assert call.agent.model_settings.parallel_tool_calls is False
    assert call.agent.model_settings.retry is not None
    assert call.agent.model_settings.retry.max_retries == 0
    assert call.run_config is not None
    assert call.run_config.trace_include_sensitive_data is False
    assert call.run_config.tracing_disabled is True
    assert set(call.run_config.trace_metadata or {}) == {
        "agent_role",
        "model",
        "prompt_version",
        "prompt_sha256",
        "payload_sha256",
        "campaign_id",
        "attempt_id",
    }


def test_prompt_loader_reads_version_body_and_source_hash(tmp_path: Path) -> None:
    raw = "---\nprompt_version: role-v1\n---\nReturn only a typed result.\n"
    prompt_path = tmp_path / "role.md"
    prompt_path.write_text(raw, encoding="utf-8")

    prompt = load_versioned_prompt(prompt_path)

    assert prompt.version == "role-v1"
    assert prompt.content == "Return only a typed result."
    assert prompt.sha256 == hashlib.sha256(raw.encode()).hexdigest()


@pytest.mark.parametrize(
    "raw",
    [
        "Return without metadata.",
        "---\nprompt_version: role-v1\nReturn without closing metadata.",
        "---\nprompt_version: bad version\n---\nBody.",
        "---\nprompt_version: role-v1\n---\n",
    ],
)
def test_prompt_loader_rejects_malformed_or_unversioned_prompts(
    tmp_path: Path,
    raw: str,
) -> None:
    prompt_path = tmp_path / "bad.md"
    prompt_path.write_text(raw, encoding="utf-8")

    with pytest.raises(ValueError):
        load_versioned_prompt(prompt_path)


@pytest.mark.asyncio
async def test_compact_input_is_redacted_and_usage_is_costed() -> None:
    usage = Usage(
        requests=1,
        input_tokens=100,
        output_tokens=50,
        input_tokens_details=InputTokensDetails(
            cached_tokens=20,
            cache_write_tokens=10,
        ),
        output_tokens_details=OutputTokensDetails(reasoning_tokens=5),
    )
    output = _output(ProposedAttackV1)
    runner = FakeRunner(_usage_result(output, usage))
    adapter = AttackGeneratorAgent(**_agent_options(runner))

    outcome = await adapter.run(
        {
            "password": "do-not-send",
            "remaining_input_tokens": 100,
            "message": "Authorization: Bearer private-value",
        },
        campaign_id="campaign-1",
        attempt_id="attempt-1",
    )

    sent = json.loads(runner.calls[0].input)
    assert sent["password"] == REDACTED
    assert sent["remaining_input_tokens"] == 100
    assert "private-value" not in runner.calls[0].input
    assert '": ' not in runner.calls[0].input
    assert ', "' not in runner.calls[0].input
    assert outcome.payload_sha256 == hashlib.sha256(runner.calls[0].input.encode()).hexdigest()
    assert outcome.usage.tokens.input_tokens == 100
    assert outcome.usage.tokens.output_tokens == 50
    assert outcome.usage.tokens.cached_input_tokens == 20
    assert outcome.usage.tokens.calls == 1
    assert outcome.usage.cache_write_input_tokens == 10
    assert outcome.usage.reasoning_output_tokens == 5
    assert outcome.estimated_cost_usd == pytest.approx(0.00096125)


@pytest.mark.asyncio
async def test_credentialless_run_returns_typed_failure_without_calling_runner() -> None:
    runner = FakeRunner()
    adapter = OrchestratorAgent(
        settings=_settings(),
        runner=runner,
        credentials_available=False,
        telemetry=None,
        trace_factory=lambda **_kwargs: nullcontext(),
    )

    outcome = await adapter.run(
        {"bounded": "input"},
        campaign_id="campaign-1",
        attempt_id="attempt-1",
    )

    assert outcome.succeeded is False
    assert outcome.error is not None
    assert outcome.error.code == AgentErrorCodeV1.AUTHENTICATION_FAILED
    assert outcome.error.retryable is False
    assert outcome.error.sanitized_details == {
        "provider": "openai",
        "reason": "missing_credentials",
    }
    assert outcome.sdk_attempts == 0
    assert runner.calls == []


@pytest.mark.asyncio
async def test_only_429_and_5xx_are_retried_with_bounded_backoff() -> None:
    output = _output(OrchestratorDecisionV1)
    runner = FakeRunner(
        _status_error(429),
        _status_error(503),
        _usage_result(output),
    )
    delays: list[float] = []

    async def record_delay(delay: float) -> None:
        delays.append(delay)

    adapter = OrchestratorAgent(
        **_agent_options(
            runner,
            sleeper=record_delay,
            jitter=lambda: 0.0,
            max_retries=2,
        )
    )

    outcome = await adapter.run(
        {"bounded": "input"},
        campaign_id="campaign-1",
        attempt_id="attempt-1",
    )

    assert outcome.succeeded is True
    assert outcome.sdk_attempts == 3
    assert len(runner.calls) == 3
    assert delays == [0.25, 0.5]


@pytest.mark.parametrize(
    ("failure", "expected_code"),
    [
        (_status_error(400), AgentErrorCodeV1.UNEXPECTED_INTERNAL_ERROR),
        (ModelBehaviorError("private invalid output"), AgentErrorCodeV1.INVALID_CONTRACT),
        (ModelRefusalError("private refusal"), AgentErrorCodeV1.AGENT_REFUSAL),
    ],
)
@pytest.mark.asyncio
async def test_contract_refusal_and_nonretryable_http_errors_are_not_retried(
    failure: Exception,
    expected_code: AgentErrorCodeV1,
) -> None:
    runner = FakeRunner(failure)
    adapter = AttackGeneratorAgent(**_agent_options(runner))

    outcome = await adapter.run(
        {"bounded": "input"},
        campaign_id="campaign-1",
        attempt_id="attempt-1",
    )

    assert outcome.error is not None
    assert outcome.error.code == expected_code
    assert outcome.error.retryable is False
    assert outcome.sdk_attempts == 1
    assert len(runner.calls) == 1
    assert "private" not in outcome.error.message


@pytest.mark.asyncio
async def test_invalid_fake_runner_output_is_a_nonretryable_contract_failure() -> None:
    runner = FakeRunner(_usage_result({"schema_version": "v1", "unexpected": True}))
    adapter = AttackGeneratorAgent(**_agent_options(runner))

    outcome = await adapter.run(
        {"bounded": "input"},
        campaign_id="campaign-1",
        attempt_id="attempt-1",
    )

    assert outcome.error is not None
    assert outcome.error.code == AgentErrorCodeV1.INVALID_CONTRACT
    assert outcome.error.retryable is False
    assert len(runner.calls) == 1


@pytest.mark.asyncio
async def test_unexpected_sdk_failure_records_only_the_safe_exception_type() -> None:
    runner = FakeRunner(RuntimeError("private provider payload must not cross the boundary"))
    adapter = AttackGeneratorAgent(**_agent_options(runner))

    outcome = await adapter.run(
        {"bounded": "input"},
        campaign_id="campaign-1",
        attempt_id="attempt-1",
    )

    assert outcome.error is not None
    assert outcome.error.code == AgentErrorCodeV1.UNEXPECTED_INTERNAL_ERROR
    assert outcome.error.sanitized_details["exception_type"] == "RuntimeError"
    assert "private provider payload" not in json.dumps(outcome.error.model_dump(mode="json"))


@pytest.mark.asyncio
async def test_judge_uses_terra_unless_controller_explicitly_selects_sol() -> None:
    output = _output(JudgeVerdictV1)
    runner = FakeRunner(_usage_result(output), _usage_result(output))
    judge = JudgeAgent(**_agent_options(runner))

    routine = await judge.run(
        {"frozen_evidence": "hash-only"},
        campaign_id="campaign-1",
        attempt_id="attempt-1",
    )
    escalated = await judge.run(
        {"frozen_evidence": "hash-only"},
        campaign_id="campaign-1",
        attempt_id="attempt-1",
        escalate_to_sol=True,
    )

    assert routine.model == "gpt-5.6-terra"
    assert escalated.model == "gpt-5.6-sol"
    assert [call.agent.model for call in runner.calls] == [
        "gpt-5.6-terra",
        "gpt-5.6-sol",
    ]


@pytest.mark.asyncio
async def test_langfuse_and_sdk_trace_scopes_receive_hashes_not_payloads() -> None:
    output = _output(OrchestratorDecisionV1)
    runner = FakeRunner(_usage_result(output))
    telemetry = FakeTelemetry()
    traces: list[dict[str, Any]] = []

    def trace_factory(**kwargs: Any) -> Any:
        traces.append(kwargs)
        return nullcontext()

    adapter = OrchestratorAgent(
        **_agent_options(
            runner,
            telemetry=telemetry,
            trace_factory=trace_factory,
            sdk_tracing_enabled=True,
        )
    )

    outcome = await adapter.run(
        {"password": "never-traced", "bounded": "input"},
        campaign_id="campaign-1",
        attempt_id="attempt-1",
        category="prompt-injection",
        target_version="target-v1",
    )

    assert outcome.langfuse_trace_id == "langfuse-trace"
    assert telemetry.scopes[0]["agent_role"] == "orchestrator"
    assert telemetry.scopes[0]["prompt_version"] == outcome.prompt_version
    assert traces[0]["disabled"] is False
    rendered_metadata = json.dumps(traces[0]["metadata"], sort_keys=True)
    assert "never-traced" not in rendered_metadata
    assert outcome.payload_sha256 in rendered_metadata
    assert runner.calls[0].run_config is not None
    assert runner.calls[0].run_config.trace_include_sensitive_data is False


def test_pricing_catalog_rejects_unknown_models() -> None:
    catalog = PricingCatalog.from_yaml(PROJECT_ROOT / "config/pricing.yaml")

    with pytest.raises(ValueError, match="no verified pricing"):
        catalog.price_for("unpriced-model")


@pytest.mark.asyncio
async def test_unpriced_model_is_rejected_before_any_live_call() -> None:
    runner = FakeRunner()
    adapter = OrchestratorAgent(
        **_agent_options(
            runner,
            settings=_settings(openai_orchestrator_model="unpriced-model"),
        )
    )

    outcome = await adapter.run(
        {"bounded": "input"},
        campaign_id="campaign-1",
        attempt_id="attempt-1",
    )

    assert outcome.error is not None
    assert outcome.error.code == AgentErrorCodeV1.INVALID_CONTRACT
    assert outcome.error.sanitized_details["reason"] == "unknown_model_pricing"
    assert outcome.sdk_attempts == 0
    assert runner.calls == []
