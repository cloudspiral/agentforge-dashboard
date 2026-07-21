from __future__ import annotations

import importlib
import json
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from pydantic import SecretStr
from typer.testing import CliRunner

from agentforge.runners.base import RunnerActionRejected
from agentforge.runners.playwright_runner import (
    SelectedPatient,
    UISmokeResult,
    UISmokeStep,
    run_ui_smoke,
)
from agentforge.settings import Settings
from agentforge.target.profile import load_target_profile

ROOT = Path(__file__).parents[2]
cli_module = importlib.import_module("agentforge.cli.app")


def _settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "test",
        "target_base_url": "http://localhost:9300",
        "target_api_base_url": "http://localhost:8001",
        "target_verify_tls": False,
        "target_test_username": "synthetic-clinician",
        "target_test_password": SecretStr("browser-only-secret"),
        "target_test_role": "physician",
        "target_version": "local-test-version",
        "langfuse_enabled": False,
    }
    values.update(overrides)
    return Settings(**values)


class FakePlaywrightSession(AbstractAsyncContextManager["FakePlaywrightSession"]):
    """Deterministic fake for the browser, context, and current page state."""

    def __init__(self, *, fail_step: UISmokeStep | None = None) -> None:
        self.fail_step = fail_step
        self.events: list[str] = []
        self.context_closed = False

    def _fail(self, step: UISmokeStep) -> None:
        if self.fail_step != step:
            return
        if step in {
            UISmokeStep.NAVIGATE_LOGIN,
            UISmokeStep.VERIFY_LOGIN_FORM,
            UISmokeStep.LOGIN,
            UISmokeStep.OPEN_COPILOT,
        }:
            raise PlaywrightTimeoutError(
                "synthetic-clinician browser-only-secret access_token=fake-secret"
            )
        raise RunnerActionRejected(
            "synthetic-clinician browser-only-secret access_token=fake-secret"
        )

    async def __aenter__(self) -> FakePlaywrightSession:
        self.events.append("browser:open")
        self._fail(UISmokeStep.LAUNCH_BROWSER)
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:  # type: ignore[no-untyped-def]
        self.context_closed = True
        self.events.append("context:closed")

    async def navigate_to_login(self) -> None:
        self.events.append("page:navigate-login")
        self._fail(UISmokeStep.NAVIGATE_LOGIN)

    async def verify_login_form(self) -> None:
        self.events.append("page:login-form")
        self._fail(UISmokeStep.VERIFY_LOGIN_FORM)

    async def login(self) -> None:
        self.events.append("page:login")
        self._fail(UISmokeStep.LOGIN)

    async def select_patient(self, patient_alias: str) -> SelectedPatient:
        self.events.append(f"page:patient:{patient_alias}")
        self._fail(UISmokeStep.SELECT_PATIENT)
        return SelectedPatient(
            patient_alias=patient_alias,
            external_id="configured-synthetic-id",
            display_name="Configured Synthetic Patient",
            numeric_pid="7",
        )

    async def verify_copilot_ready(self) -> None:
        self.events.append("page:copilot-ready")
        self._fail(UISmokeStep.OPEN_COPILOT)

    async def capture_screenshot(self, path: Path) -> None:
        self.events.append(f"page:screenshot:{path.name}")

    async def clear_sensitive_fields(self) -> None:
        self.events.append("page:clear-sensitive")


async def _run(
    tmp_path: Path,
    fake: FakePlaywrightSession,
    *,
    settings: Settings | None = None,
    target_alias: str = "local",
    screenshot_on_failure: bool = False,
) -> UISmokeResult:
    return await run_ui_smoke(
        loaded_profile=load_target_profile(ROOT / "config/target-profile.yaml"),
        settings=settings or _settings(),
        target_alias=target_alias,
        repository_root=tmp_path,
        artifacts_dir=tmp_path / "artifacts",
        timeout_seconds=5,
        screenshot_on_failure=screenshot_on_failure,
        session_factory=lambda _context, _headless: fake,
    )


@pytest.mark.asyncio
async def test_ui_smoke_success_uses_configured_patient_and_closes_context(
    tmp_path: Path,
) -> None:
    fake = FakePlaywrightSession()

    result = await _run(tmp_path, fake)

    assert result.failed_step is None
    assert result.current_step == UISmokeStep.COMPLETE
    assert result.navigation_succeeded is True
    assert result.login_succeeded is True
    assert result.patient_selected is True
    assert result.copilot_opened is True
    assert result.sanitized_route == "clinical_copilot_panel"
    assert "page:patient:patient_a" in fake.events
    assert fake.context_closed is True
    assert all("chat" not in event and "upload" not in event for event in fake.events)


@pytest.mark.asyncio
async def test_ui_smoke_missing_credentials_does_not_launch_browser(tmp_path: Path) -> None:
    fake = FakePlaywrightSession()

    result = await _run(
        tmp_path,
        fake,
        settings=_settings(target_test_username=None, target_test_password=None),
    )

    assert result.failed_step == UISmokeStep.LOAD_CREDENTIALS
    assert result.error_code == "missing_credentials"
    assert fake.events == []


@pytest.mark.asyncio
async def test_ui_smoke_rejects_target_url_before_browser_launch(tmp_path: Path) -> None:
    fake = FakePlaywrightSession()

    result = await _run(
        tmp_path,
        fake,
        settings=_settings(target_base_url="http://outside.invalid:9300"),
    )

    assert result.failed_step == UISmokeStep.VALIDATE_TARGET
    assert result.error_code == "target_url_rejected"
    assert fake.events == []


@pytest.mark.asyncio
async def test_ui_smoke_rejects_deployed_alias_before_browser_launch(tmp_path: Path) -> None:
    fake = FakePlaywrightSession()

    result = await _run(tmp_path, fake, target_alias="deployed")

    assert result.failed_step == UISmokeStep.VALIDATE_TARGET
    assert result.error_code == "target_alias_rejected"
    assert fake.events == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("step", "expected_code"),
    [
        (UISmokeStep.VERIFY_LOGIN_FORM, "login_form_not_found"),
        (UISmokeStep.LOGIN, "login_failed"),
        (UISmokeStep.SELECT_PATIENT, "synthetic_patient_not_found"),
        (UISmokeStep.OPEN_COPILOT, "copilot_ui_not_found"),
        (UISmokeStep.NAVIGATE_LOGIN, "navigation_timeout"),
    ],
)
async def test_ui_smoke_reports_exact_failed_step_and_closes_context(
    tmp_path: Path,
    step: UISmokeStep,
    expected_code: str,
) -> None:
    fake = FakePlaywrightSession(fail_step=step)

    result = await _run(tmp_path, fake)

    assert result.failed_step == step
    assert result.error_code == expected_code
    assert fake.context_closed is True


@pytest.mark.asyncio
async def test_ui_smoke_rejects_cross_host_redirect_and_closes_context(tmp_path: Path) -> None:
    class CrossHostFake(FakePlaywrightSession):
        async def navigate_to_login(self) -> None:
            self.events.append("page:cross-host-redirect")
            raise RunnerActionRejected("browser navigation left approved origin")

    fake = CrossHostFake()

    result = await _run(tmp_path, fake)

    assert result.failed_step == UISmokeStep.NAVIGATE_LOGIN
    assert result.error_code == "cross_host_navigation_rejected"
    assert result.sanitized_route is None
    assert fake.context_closed is True


@pytest.mark.asyncio
async def test_ui_smoke_never_returns_credentials_or_logs_exception_secrets(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = FakePlaywrightSession(fail_step=UISmokeStep.LOGIN)

    result = await _run(tmp_path, fake)

    serialized = result.model_dump_json() + caplog.text
    for secret in (
        "synthetic-clinician",
        "browser-only-secret",
        "fake-secret",
        "access_token",
    ):
        assert secret not in serialized


@pytest.mark.asyncio
async def test_ui_smoke_failure_screenshot_is_explicit_and_follows_field_clear(
    tmp_path: Path,
) -> None:
    fake = FakePlaywrightSession(fail_step=UISmokeStep.LOGIN)

    result = await _run(tmp_path, fake, screenshot_on_failure=True)

    screenshot_event = "page:screenshot:ui-smoke-failure.png"
    assert result.failure_screenshot is not None
    assert result.failure_screenshot.endswith("/ui-smoke-failure.png")
    assert fake.events.index("page:clear-sensitive") < fake.events.index(screenshot_event)


def _cli_result(*, succeeded: bool) -> UISmokeResult:
    failed_step = None if succeeded else UISmokeStep.LOGIN
    return UISmokeResult(
        target_alias="local",
        navigation_succeeded=True,
        login_succeeded=succeeded,
        patient_selected=succeeded,
        copilot_opened=succeeded,
        current_step=UISmokeStep.COMPLETE if succeeded else UISmokeStep.LOGIN,
        failed_step=failed_step,
        sanitized_route="clinical_copilot_panel" if succeeded else "login",
        total_latency_ms=12.5,
        step_latencies_ms={"navigate_login": 2.5},
        timestamp=datetime(2026, 7, 21, tzinfo=UTC),
        error_code=None if succeeded else "login_failed",
        error_message=None if succeeded else "approved OpenEMR test login did not complete",
    )


def test_ui_smoke_cli_success_and_failure_exit_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = iter(
        [
            _cli_result(succeeded=True),
            _cli_result(succeeded=False),
            _cli_result(succeeded=True),
        ]
    )
    calls: list[dict[str, Any]] = []

    async def fake_run_ui_smoke(**kwargs: Any) -> UISmokeResult:
        calls.append(kwargs)
        return next(results)

    settings = _settings(
        target_profile_path=ROOT / "config/target-profile.yaml",
        artifacts_dir=tmp_path / "artifacts",
    )
    monkeypatch.setattr(cli_module, "get_settings", lambda: settings)
    monkeypatch.setattr(cli_module, "run_ui_smoke", fake_run_ui_smoke)
    runner = CliRunner()

    succeeded = runner.invoke(cli_module.app, ["target", "ui-smoke", "--target", "local"])
    failed = runner.invoke(
        cli_module.app,
        ["target", "ui-smoke", "--target", "local", "--json"],
    )
    headed = runner.invoke(
        cli_module.app,
        ["target", "ui-smoke", "--target", "local", "--headed"],
    )

    assert succeeded.exit_code == 0, succeeded.output
    assert "Clinical Co-Pilot is ready" in succeeded.stdout
    assert failed.exit_code == 1
    assert json.loads(failed.stdout)["failed_step"] == "login"
    assert headed.exit_code == 0, headed.output
    assert calls[0]["headless"] is True
    assert calls[2]["headless"] is False
    assert "database" not in calls[0]
