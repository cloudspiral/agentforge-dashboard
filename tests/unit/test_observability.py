from __future__ import annotations

from collections.abc import Iterator
from contextlib import nullcontext
from typing import Any

import pytest
from prometheus_client import CollectorRegistry

import agentforge.observability.langfuse as langfuse_module
from agentforge.observability.langfuse import LangfuseTelemetry
from agentforge.observability.metrics import AgentForgeMetrics
from agentforge.observability.tracing import redact_for_telemetry
from agentforge.settings import Settings

REDACTED = "[REDACTED]"


def _credential(prefix: str) -> str:
    return "-".join((prefix, "unit", "only", "value"))


def _settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "test",
        "langfuse_enabled": True,
        "langfuse_public_key": _credential("pk"),
        "langfuse_secret_key": _credential("sk"),
    }
    values.update(overrides)
    return Settings(**values)


class FakeInstrumentor:
    def __init__(self, *, already_instrumented: bool = False, error: Exception | None = None):
        self.is_instrumented_by_opentelemetry = already_instrumented
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def instrument(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        self.is_instrumented_by_opentelemetry = True


class FakeObservation:
    def __init__(self, trace_id: str) -> None:
        self.trace_id = trace_id
        self.updates: list[dict[str, Any]] = []

    def update(self, **kwargs: Any) -> FakeObservation:
        self.updates.append(kwargs)
        return self


class FakeObservationContext:
    def __init__(self, client: FakeClient, observation: FakeObservation) -> None:
        self.client = client
        self.observation = observation

    def __enter__(self) -> FakeObservation:
        self.client.active_depth += 1
        return self.observation

    def __exit__(self, *_args: Any) -> None:
        self.client.active_depth -= 1


class FakeClient:
    def __init__(
        self,
        *,
        trace_id: str = "a" * 32,
        flush_error: Exception | None = None,
        shutdown_error: Exception | None = None,
        start_error: Exception | None = None,
    ) -> None:
        self.trace_id = trace_id
        self.flush_error = flush_error
        self.shutdown_error = shutdown_error
        self.start_error = start_error
        self.active_depth = 0
        self.starts: list[dict[str, Any]] = []
        self.observations: list[FakeObservation] = []
        self.flush_calls = 0
        self.shutdown_calls = 0

    def start_as_current_observation(self, **kwargs: Any) -> FakeObservationContext:
        if self.start_error is not None:
            raise self.start_error
        self.starts.append(kwargs)
        observation = FakeObservation(self.trace_id)
        self.observations.append(observation)
        return FakeObservationContext(self, observation)

    def get_current_trace_id(self) -> str | None:
        return self.trace_id if self.active_depth else None

    def flush(self) -> None:
        self.flush_calls += 1
        if self.flush_error is not None:
            raise self.flush_error

    def shutdown(self) -> None:
        self.shutdown_calls += 1
        if self.shutdown_error is not None:
            raise self.shutdown_error


@pytest.fixture(autouse=True)
def reset_process_instrumentation(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(langfuse_module, "_AGENTS_INSTRUMENTED", False)
    monkeypatch.setattr(langfuse_module, "_AGENTS_INSTRUMENTOR", None)
    langfuse_module.get_telemetry.cache_clear()
    yield
    langfuse_module.get_telemetry.cache_clear()


def test_missing_credentials_is_a_noop_without_initializing_exporters() -> None:
    client_calls = 0
    instrumentor_calls = 0

    def client_factory(**_kwargs: Any) -> FakeClient:
        nonlocal client_calls
        client_calls += 1
        return FakeClient()

    def instrumentor_factory() -> FakeInstrumentor:
        nonlocal instrumentor_calls
        instrumentor_calls += 1
        return FakeInstrumentor()

    telemetry = LangfuseTelemetry.from_settings(
        _settings(langfuse_public_key=None, langfuse_secret_key=None),
        client_factory=client_factory,
        instrumentor_factory=instrumentor_factory,
    )

    assert telemetry.enabled is False
    assert telemetry.disabled_reason == "missing_credentials"
    with telemetry.campaign(campaign_id="campaign-1", input={"password": "not-exported"}) as span:
        assert span.trace_id is None
        assert span.update(output={"ok": True}) is False
    assert telemetry.current_trace_id is None
    assert telemetry.flush() is False
    assert telemetry.shutdown() is False
    assert client_calls == 0
    assert instrumentor_calls == 0


def test_agents_sdk_instrumentation_is_installed_exactly_once() -> None:
    clients: list[FakeClient] = []
    instrumentor = FakeInstrumentor()

    def client_factory(**kwargs: Any) -> FakeClient:
        assert kwargs["mask"] is redact_for_telemetry
        assert kwargs["tracing_enabled"] is True
        client = FakeClient()
        clients.append(client)
        return client

    first = LangfuseTelemetry.from_settings(
        _settings(),
        client_factory=client_factory,
        instrumentor_factory=lambda: instrumentor,
    )
    second = LangfuseTelemetry.from_settings(
        _settings(),
        client_factory=client_factory,
        instrumentor_factory=lambda: instrumentor,
    )

    assert first.enabled is True
    assert second.enabled is True
    assert len(clients) == 2
    assert len(instrumentor.calls) == 1
    call = instrumentor.calls[0]
    assert call["exclusive_processor"] is True
    assert call["config"].hide_inputs is True
    assert call["config"].hide_outputs is True


def test_initialization_failure_degrades_and_closes_partial_client() -> None:
    client = FakeClient()
    instrumentor = FakeInstrumentor(error=RuntimeError("instrumentation failed"))

    telemetry = LangfuseTelemetry.from_settings(
        _settings(),
        client_factory=lambda **_kwargs: client,
        instrumentor_factory=lambda: instrumentor,
    )

    assert telemetry.enabled is False
    assert telemetry.disabled_reason == "initialization_failed"
    assert client.shutdown_calls == 1


def test_campaign_attempt_and_runner_contexts_share_trace_and_redact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attributes: list[dict[str, Any]] = []

    def fake_propagate_attributes(**kwargs: Any) -> Any:
        attributes.append(kwargs)
        return nullcontext()

    monkeypatch.setattr(langfuse_module, "propagate_attributes", fake_propagate_attributes)
    client = FakeClient()
    telemetry = LangfuseTelemetry.from_settings(
        _settings(),
        client_factory=lambda **_kwargs: client,
        instrumentor_factory=FakeInstrumentor,
    )
    raw_key = _credential("sk")

    with telemetry.campaign(
        campaign_id="campaign-1",
        campaign_type="manual",
        category="prompt_injection",
        target_version="target-sha",
        prompt_version="attack-v1",
        model="gpt-5.6-terra",
        input={
            "password": "plain-value",
            "headers": {"Authorization": "Bearer visible-token"},
            "url": "https://admin:pass@example.test/path?api_key=visible",
        },
        metadata={"api_key": raw_key, "suite": "seed"},
    ) as campaign:
        assert campaign.trace_id == client.trace_id
        assert telemetry.current_trace_id == client.trace_id
        assert campaign.update(output={"cookie": "session=value", "status": "running"}) is True

        with telemetry.attempt(
            campaign_id="campaign-1",
            attempt_id="attempt-1",
            agent_role="attack",
            category="prompt_injection",
            input={"csrf_token": "do-not-export", "payload": "safe-summary"},
        ) as attempt:
            assert attempt.trace_id == client.trace_id
            with telemetry.runner(
                campaign_id="campaign-1",
                attempt_id="attempt-1",
                transport="http",
                input={"cookie": "private"},
            ) as runner:
                assert runner.trace_id == client.trace_id

    assert telemetry.current_trace_id is None
    assert [start["as_type"] for start in client.starts] == ["agent", "chain", "tool"]

    campaign_input = client.starts[0]["input"]
    assert campaign_input["password"] == REDACTED
    assert campaign_input["headers"]["Authorization"] == REDACTED
    assert "admin:pass" not in campaign_input["url"]
    assert "api_key=visible" not in campaign_input["url"]
    assert client.starts[0]["metadata"]["api_key"] == REDACTED
    assert client.starts[1]["input"]["csrf_token"] == REDACTED
    assert client.starts[2]["input"]["cookie"] == REDACTED

    update = client.observations[0].updates[0]
    assert update["output"]["cookie"] == REDACTED
    assert update["output"]["status"] == "running"

    assert attributes[0]["trace_name"] == "AgentForge campaign"
    assert attributes[0]["session_id"] == "campaign-1"
    assert attributes[0]["metadata"]["campaignId"] == "campaign-1"
    assert attributes[0]["metadata"]["apikey"] == REDACTED
    assert attributes[1]["metadata"]["attemptId"] == "attempt-1"


def test_context_start_and_export_failures_never_break_execution() -> None:
    client = FakeClient(
        start_error=RuntimeError("start failed"),
        flush_error=RuntimeError("flush failed"),
        shutdown_error=RuntimeError("shutdown failed"),
    )
    telemetry = LangfuseTelemetry.from_settings(
        _settings(),
        client_factory=lambda **_kwargs: client,
        instrumentor_factory=FakeInstrumentor,
    )

    body_executed = False
    with telemetry.campaign(campaign_id="campaign-1") as span:
        body_executed = True
        assert span.trace_id is None

    assert body_executed is True
    assert telemetry.flush() is False
    assert telemetry.shutdown() is False
    assert telemetry.shutdown() is False
    assert client.flush_calls == 1
    assert client.shutdown_calls == 1


def test_redactor_handles_headers_keys_urls_keys_and_cycles() -> None:
    cyclic: list[Any] = []
    cyclic.append(cyclic)
    payload = {
        "authorization": "Bearer visible",
        "nested": {
            "password": "visible",
            "message": f"Authorization: Bearer visible\nkey={_credential('sk')}",
        },
        "url": "https://user:password@example.test/?token=visible",
        "cycle": cyclic,
    }

    safe = redact_for_telemetry(payload)

    assert safe["authorization"] == REDACTED
    assert safe["nested"]["password"] == REDACTED
    assert "Bearer visible" not in safe["nested"]["message"]
    assert "user:password" not in safe["url"]
    assert "token=visible" not in safe["url"]
    assert safe["cycle"][0] == "[CYCLE]"


def test_required_prometheus_metrics_render_from_an_isolated_registry() -> None:
    registry = CollectorRegistry()
    observed = AgentForgeMetrics(registry)

    observed.queue_depth.labels(queue="campaigns").set(2)
    observed.queue_oldest_age_seconds.labels(queue="campaigns").set(12)
    observed.queue_wait_seconds.labels(queue="campaigns").observe(4)
    observed.campaigns_current.labels(status="running", campaign_type="manual").set(1)
    observed.campaigns_total.labels(status="completed", campaign_type="manual").inc()
    observed.attempts_total.labels(category="prompt_injection", verdict="blocked").inc()
    observed.worker_active.labels(worker="primary").set(1)
    observed.worker_heartbeat_timestamp_seconds.labels(worker="primary").set(123)
    observed.agent_latency_seconds.labels(role="judge", model="gpt-5.6-terra", status="ok").observe(
        0.5
    )
    observed.agent_tokens_total.labels(
        role="judge",
        model="gpt-5.6-terra",
        token_type="input",  # noqa: S106
    ).inc(20)
    observed.agent_estimated_cost_usd_total.labels(role="judge", model="gpt-5.6-terra").inc(0.01)
    observed.target_latency_seconds.labels(
        transport="http", operation="chat", status="200"
    ).observe(0.2)
    observed.target_errors_total.labels(transport="http", error_type="timeout").inc()
    observed.regression_outcomes_total.labels(category="authorization", outcome="passed").inc()
    observed.report_generation_failures_total.labels(error_type="render").inc()

    rendered = observed.render().decode()
    required_names = {
        "agentforge_queue_depth",
        "agentforge_queue_oldest_age_seconds",
        "agentforge_campaigns_current",
        "agentforge_campaigns_total",
        "agentforge_attempts_total",
        "agentforge_worker_heartbeat_timestamp_seconds",
        "agentforge_agent_latency_seconds",
        "agentforge_target_latency_seconds",
        "agentforge_target_errors_total",
        "agentforge_agent_tokens_total",
        "agentforge_agent_estimated_cost_usd_total",
        "agentforge_regression_outcomes_total",
        "agentforge_report_generation_failures_total",
    }
    for metric_name in required_names:
        assert metric_name in rendered
    assert observed.content_type.startswith("text/plain")
