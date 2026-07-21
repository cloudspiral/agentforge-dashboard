from __future__ import annotations

import importlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from agentforge.settings import Settings
from agentforge.target import TargetProbeResult, load_target_profile, probe_target

ROOT = Path(__file__).parents[2]
cli_module = importlib.import_module("agentforge.cli.app")


def _settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "test",
        "target_base_url": "http://localhost:9300",
        "target_api_base_url": "http://localhost:8001",
        "target_verify_tls": False,
        "langfuse_enabled": False,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.mark.asyncio
async def test_probe_resolves_valid_local_target_and_extracts_version() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"build_sha": "local-release-123"}, request=request)

    result = await probe_target(
        loaded_profile=load_target_profile(ROOT / "config/target-profile.yaml"),
        settings=_settings(),
        target_alias="local",
        timeout_seconds=1,
        transport=httpx.MockTransport(handler),
    )

    assert result.reachable is True
    assert result.sanitized_base_url == "http://localhost:8001"
    assert result.http_status == 200
    assert result.target_version == "local-release-123"
    assert result.error_code is None
    assert result.timestamp.tzinfo is not None
    assert [(request.method, str(request.url)) for request in requests] == [
        ("GET", "http://localhost:8001/health")
    ]
    assert requests[0].headers.get("authorization") is None
    assert requests[0].headers.get("cookie") is None


@pytest.mark.asyncio
async def test_probe_reports_missing_base_url_without_requesting() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, request=request)

    result = await probe_target(
        loaded_profile=load_target_profile(ROOT / "config/target-profile.yaml"),
        settings=_settings(target_base_url=""),
        target_alias="local",
        timeout_seconds=1,
        transport=httpx.MockTransport(handler),
    )

    assert result.reachable is False
    assert result.error_code == "target_configuration_error"
    assert requests == []


@pytest.mark.asyncio
async def test_probe_reports_unknown_alias_without_requesting() -> None:
    requests: list[httpx.Request] = []

    result = await probe_target(
        loaded_profile=load_target_profile(ROOT / "config/target-profile.yaml"),
        settings=_settings(),
        target_alias="missing-target",
        timeout_seconds=1,
        transport=httpx.MockTransport(
            lambda request: requests.append(request) or httpx.Response(200, request=request)
        ),
    )

    assert result.reachable is False
    assert result.error_code == "target_alias_not_found"
    assert requests == []


@pytest.mark.asyncio
async def test_probe_rejects_non_allowlisted_base_url_without_requesting() -> None:
    requests: list[httpx.Request] = []

    result = await probe_target(
        loaded_profile=load_target_profile(ROOT / "config/target-profile.yaml"),
        settings=_settings(target_base_url="http://outside.invalid:9300"),
        target_alias="local",
        timeout_seconds=1,
        transport=httpx.MockTransport(
            lambda request: requests.append(request) or httpx.Response(200, request=request)
        ),
    )

    assert result.reachable is False
    assert result.error_code == "target_url_rejected"
    assert result.sanitized_base_url == "http://outside.invalid:9300"
    assert requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exception_type", "expected_code"),
    [
        (httpx.ReadTimeout, "timeout"),
        (httpx.ConnectError, "connection_failed"),
    ],
)
async def test_probe_sanitizes_transport_failures(
    exception_type: type[httpx.RequestError],
    expected_code: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exception_type("access_token=transport-secret", request=request)

    result = await probe_target(
        loaded_profile=load_target_profile(ROOT / "config/target-profile.yaml"),
        settings=_settings(),
        target_alias="local",
        timeout_seconds=1,
        transport=httpx.MockTransport(handler),
    )

    assert result.reachable is False
    assert result.error_code == expected_code
    assert "transport-secret" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_probe_rejects_cross_host_redirect() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"location": "https://outside.invalid/health?token=redirect-secret"},
            request=request,
        )

    result = await probe_target(
        loaded_profile=load_target_profile(ROOT / "config/target-profile.yaml"),
        settings=_settings(),
        target_alias="local",
        timeout_seconds=1,
        transport=httpx.MockTransport(handler),
    )

    assert result.reachable is False
    assert result.http_status == 302
    assert result.error_code == "cross_host_redirect"
    assert "outside.invalid" not in result.model_dump_json()
    assert "redirect-secret" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_probe_redacts_url_credentials_and_sensitive_query_parameters() -> None:
    profile = load_target_profile(ROOT / "config/target-profile.yaml")
    credential_result = await probe_target(
        loaded_profile=profile,
        settings=_settings(
            target_base_url=(
                "http://probe-user:credential-secret@localhost:9300/?api_key=query-secret"
            )
        ),
        target_alias="local",
        timeout_seconds=1,
        transport=httpx.MockTransport(lambda request: httpx.Response(200, request=request)),
    )

    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, content=b"healthy", request=request)

    query_result = await probe_target(
        loaded_profile=profile,
        settings=_settings(
            target_base_url="http://localhost:9300/root?api_key=base-query-secret",
            target_api_base_url="http://localhost:8001/status?token=status-query-secret",
        ),
        target_alias="local",
        timeout_seconds=1,
        transport=httpx.MockTransport(handler),
    )

    serialized = credential_result.model_dump_json() + query_result.model_dump_json()
    assert credential_result.error_code == "target_url_rejected"
    assert credential_result.sanitized_base_url == "http://localhost:9300"
    assert query_result.reachable is True
    assert query_result.target_version is None
    assert str(requests[0].url) == "http://localhost:8001/health"
    for secret in (
        "probe-user",
        "credential-secret",
        "query-secret",
        "base-query-secret",
        "status-query-secret",
    ):
        assert secret not in serialized


def test_target_probe_cli_success_and_failure_exit_codes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timestamp = datetime(2026, 7, 21, tzinfo=UTC)
    success = TargetProbeResult(
        target_alias="local",
        reachable=True,
        sanitized_base_url="http://localhost:9300",
        http_status=200,
        target_version="local-release-123",
        latency_ms=4.25,
        timestamp=timestamp,
        error_code=None,
        error_message=None,
    )
    failure = TargetProbeResult(
        target_alias="local",
        reachable=False,
        sanitized_base_url="http://localhost:9300",
        http_status=None,
        target_version=None,
        latency_ms=1000,
        timestamp=timestamp,
        error_code="timeout",
        error_message="target probe timed out",
    )
    results = iter([success, failure])

    async def fake_probe_target(**_kwargs: Any) -> TargetProbeResult:
        return next(results)

    monkeypatch.setattr(cli_module, "get_settings", lambda: _settings())
    monkeypatch.setattr(cli_module, "probe_target", fake_probe_target)
    runner = CliRunner()

    succeeded = runner.invoke(cli_module.app, ["target", "probe", "--target", "local"])
    failed = runner.invoke(
        cli_module.app,
        ["target", "probe", "--target", "local", "--json"],
    )

    assert succeeded.exit_code == 0, succeeded.output
    assert "Target local is reachable" in succeeded.stdout
    assert failed.exit_code == 1
    payload = json.loads(failed.stdout)
    assert payload["reachable"] is False
    assert payload["error_code"] == "timeout"
    assert "secret" not in failed.output
