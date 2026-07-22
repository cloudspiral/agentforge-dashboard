from __future__ import annotations

import importlib
import json
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from pydantic import SecretStr, ValidationError
from typer.testing import CliRunner

from agentforge.runners import playwright_runner as playwright_module
from agentforge.runners.base import RunnerActionRejected, TargetExecutionContext
from agentforge.runners.playwright_runner import (
    BrowserChatResult,
    SelectedPatient,
    UISmokeResult,
    UISmokeStep,
    run_ui_smoke,
)
from agentforge.settings import Settings
from agentforge.target.auth import credentials_from_settings
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

    def __init__(
        self,
        *,
        fail_step: UISmokeStep | None = None,
        chat_response_text: str = "Synthetic chart summary.",
        cleanup_error: Exception | None = None,
    ) -> None:
        self.fail_step = fail_step
        self.chat_response_text = chat_response_text
        self.cleanup_error = cleanup_error
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
            UISmokeStep.RECEIVE_CHAT_RESPONSE,
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
        if self.cleanup_error is not None:
            raise self.cleanup_error

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

    async def submit_ui_smoke_chat(self, message: str, _timeout_seconds: float) -> int:
        self.events.append(f"page:chat-submit:{message}")
        self._fail(UISmokeStep.SUBMIT_CHAT)
        return 0

    async def wait_for_ui_smoke_response(
        self,
        _before_count: int,
        _timeout_seconds: float,
    ) -> BrowserChatResult:
        self.events.append("page:chat-response")
        self._fail(UISmokeStep.RECEIVE_CHAT_RESPONSE)
        if not self.chat_response_text.strip():
            raise playwright_module._CopilotEmptyResponse(
                "Clinical Co-Pilot returned an empty response"
            )
        return BrowserChatResult(self.chat_response_text)

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
        session_factory=lambda _context, _headless, _browser_mode, _ignore_https_errors: fake,
    )


class FakeLocatorCollection:
    def __init__(self, items: list[Any]) -> None:
        self.items = items

    async def count(self) -> int:
        return len(self.items)

    def nth(self, index: int) -> Any:
        return self.items[index]

    @property
    def first(self) -> Any:
        return self.items[0]


class FakeTextCell:
    def __init__(self, text: str) -> None:
        self.text = text

    async def inner_text(self) -> str:
        return self.text


class FakePatientLink:
    def __init__(self) -> None:
        self.clicked = False

    async def click(self) -> None:
        self.clicked = True


class FakePatientRow:
    def __init__(self, cells: list[str]) -> None:
        self.cells = FakeLocatorCollection([FakeTextCell(cell) for cell in cells])
        self.link = FakePatientLink()

    def locator(self, selector: str) -> FakeLocatorCollection:
        if selector == "td":
            return self.cells
        if selector == "a:visible":
            return FakeLocatorCollection([self.link])
        raise AssertionError(f"unexpected row selector: {selector}")


class FakePatientTable:
    def __init__(
        self,
        rows: list[FakePatientRow],
        *,
        initial_empty_reads: int = 0,
    ) -> None:
        self.rows = FakeLocatorCollection(rows)
        self.initial_empty_reads = initial_empty_reads

    def locator(self, selector: str) -> FakeLocatorCollection:
        if selector == "tbody tr":
            if self.initial_empty_reads > 0:
                self.initial_empty_reads -= 1
                return FakeLocatorCollection([])
            return self.rows
        raise AssertionError(f"unexpected table selector: {selector}")


class FakeChatMessageInput:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.enabled_results = iter([False, True])

    async def scroll_into_view_if_needed(self, *, timeout: float) -> None:
        self.events.append(f"input:scroll:{timeout}")

    async def wait_for(self, *, state: str, timeout: float) -> None:
        self.events.append(f"input:wait:{state}:{timeout}")

    async def is_enabled(self) -> bool:
        enabled = next(self.enabled_results)
        self.events.append(f"input:enabled:{str(enabled).lower()}")
        return enabled

    async def click(self, *, timeout: float) -> None:
        self.events.append(f"input:click:{timeout}")

    async def fill(self, message: str, *, timeout: float) -> None:
        self.events.append(f"input:fill:{timeout}:{message}")


class FakeChatSubmitButton:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def click(self, *, timeout: float) -> None:
        self.events.append(f"submit:click:{timeout}")


def _configured_patient_a_external_id() -> str:
    return load_target_profile(
        ROOT / "config/target-profile.yaml"
    ).profile.patients.patient_a.external_id


def _configured_patient_a_display_name() -> str:
    return load_target_profile(
        ROOT / "config/target-profile.yaml"
    ).profile.patients.patient_a.display_name


def _configured_external_ids() -> frozenset[str]:
    patients = load_target_profile(ROOT / "config/target-profile.yaml").profile.patients
    return frozenset({patients.patient_a.external_id, patients.patient_b.external_id})


@pytest.mark.asyncio
async def test_ui_smoke_scrolls_focuses_and_fills_fixed_message_before_submit() -> None:
    events: list[str] = []
    message = "Briefly summarize the selected synthetic patient's chart."

    await playwright_module._scroll_focus_fill_and_submit(
        message_input=FakeChatMessageInput(events),  # type: ignore[arg-type]
        submit_button=FakeChatSubmitButton(events),  # type: ignore[arg-type]
        message=message,
        timeout_ms=500,
    )

    assert events == [
        "input:scroll:500",
        "input:wait:visible:500",
        "input:enabled:false",
        "input:enabled:true",
        "input:click:500",
        f"input:fill:500:{message}",
        "submit:click:500",
    ]


@pytest.mark.asyncio
async def test_patient_finder_selects_only_exact_configured_external_id() -> None:
    configured_external_id = _configured_patient_a_external_id()
    partial_row = FakePatientRow(["Other, Patient", f"{configured_external_id}-ARCHIVE"])
    exact_row = FakePatientRow(["Unrelated Display Name", f"  {configured_external_id}  "])
    table = FakePatientTable([partial_row, exact_row], initial_empty_reads=1)

    await playwright_module._click_patient_link_by_external_id(
        table=table,  # type: ignore[arg-type]
        external_id=configured_external_id,
        finder_iframe_found=True,
        configured_external_ids=_configured_external_ids(),
        timeout_ms=500,
    )

    assert exact_row.link.clicked is True
    assert partial_row.link.clicked is False


@pytest.mark.asyncio
async def test_patient_finder_does_not_depend_on_display_name_order() -> None:
    configured_external_id = _configured_patient_a_external_id()
    configured_display_name = _configured_patient_a_display_name()
    first_name, last_name = configured_display_name.split(maxsplit=1)
    reversed_name_row = FakePatientRow([f"{last_name}, {first_name}", configured_external_id])
    table = FakePatientTable([reversed_name_row])

    await playwright_module._click_patient_link_by_external_id(
        table=table,  # type: ignore[arg-type]
        external_id=configured_external_id,
        finder_iframe_found=True,
        configured_external_ids=_configured_external_ids(),
        timeout_ms=0,
    )

    assert reversed_name_row.link.clicked is True


@pytest.mark.asyncio
async def test_patient_finder_missing_external_id_returns_synthetic_patient_not_found(
    tmp_path: Path,
) -> None:
    configured_ids = _configured_external_ids()
    patient_b_external_id = next(
        external_id
        for external_id in configured_ids
        if external_id != _configured_patient_a_external_id()
    )
    table = FakePatientTable(
        [FakePatientRow(["Private Patient Name", patient_b_external_id, "OTHER-PATIENT-ID"])]
    )

    class MissingExternalIdSession(FakePlaywrightSession):
        async def select_patient(self, _patient_alias: str) -> SelectedPatient:
            await playwright_module._click_patient_link_by_external_id(
                table=table,  # type: ignore[arg-type]
                external_id=_configured_patient_a_external_id(),
                finder_iframe_found=True,
                configured_external_ids=configured_ids,
                timeout_ms=0,
            )
            raise AssertionError("missing external ID unexpectedly matched")

    result = await _run(tmp_path, MissingExternalIdSession())

    assert result.failed_step == UISmokeStep.SELECT_PATIENT
    assert result.error_code == "synthetic_patient_not_found"
    assert result.error_message is not None
    assert "finder_iframe_found=true" in result.error_message
    assert "table_rows=1" in result.error_message
    assert f"sanitized_external_id_cells={patient_b_external_id}" in result.error_message
    assert "Private Patient Name" not in result.error_message
    assert "OTHER-PATIENT-ID" not in result.error_message


def _execution_context(tmp_path: Path) -> TargetExecutionContext:
    settings = _settings()
    loaded = load_target_profile(ROOT / "config/target-profile.yaml")
    credentials = credentials_from_settings(
        profile=loaded.profile,
        settings=settings,
        identity_alias="physician_test",
        expected_role="physician",
    )
    return TargetExecutionContext(
        target_id="ui-smoke-launch-test",
        campaign_id="ui-smoke-launch-test",
        attempt_id="ui-smoke-launch-test",
        target_version="local-test-version",
        selected_patient_alias="patient_a",
        loaded_profile=loaded,
        target_alias=loaded.resolve_alias("local", settings),
        repository_root=tmp_path,
        artifacts_dir=tmp_path / "artifacts",
        credentials=credentials,
        request_timeout_seconds=5,
    )


class FakeBrowserContext:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def route(self, _pattern: str, _handler: Any) -> None:
        self.events.append("context:route")

    async def new_page(self) -> object:
        self.events.append("context:new-page")
        return object()

    async def close(self) -> None:
        self.events.append("context:close")


class FakeBrowser:
    def __init__(
        self,
        events: list[str],
        *,
        context_error: Exception | None = None,
    ) -> None:
        self.events = events
        self.context_error = context_error
        self.context = FakeBrowserContext(events)
        self.new_context_calls: list[dict[str, Any]] = []

    async def new_context(self, **kwargs: Any) -> FakeBrowserContext:
        self.events.append("browser:new-context")
        self.new_context_calls.append(kwargs)
        if self.context_error is not None:
            raise self.context_error
        return self.context

    async def close(self) -> None:
        self.events.append("browser:close")


class FakeBrowserType:
    def __init__(
        self,
        *,
        executable_path: Path,
        outcomes: list[FakeBrowser | Exception],
    ) -> None:
        self.executable_path = str(executable_path)
        self.outcomes = outcomes
        self.launch_calls: list[dict[str, Any]] = []

    async def launch(self, **kwargs: Any) -> FakeBrowser:
        self.launch_calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakePlaywrightManager:
    def __init__(self, browser_type: FakeBrowserType, events: list[str]) -> None:
        self.playwright = SimpleNamespace(chromium=browser_type)
        self.events = events

    async def start(self) -> Any:
        self.events.append("manager:start")
        return self.playwright

    async def stop(self) -> None:
        self.events.append("manager:stop")


def _install_fake_playwright(
    monkeypatch: pytest.MonkeyPatch,
    browser_type: FakeBrowserType,
    events: list[str],
) -> FakePlaywrightManager:
    manager = FakePlaywrightManager(browser_type, events)
    monkeypatch.setattr(playwright_module, "async_playwright", lambda: manager)
    return manager


def test_ui_ignore_https_errors_is_false_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AGENTFORGE_UI_IGNORE_HTTPS_ERRORS", raising=False)
    assert Settings().agentforge_ui_ignore_https_errors is False


@pytest.mark.asyncio
async def test_ui_ignore_https_errors_is_passed_for_explicit_local_https_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    browser = FakeBrowser(events)
    browser_type = FakeBrowserType(
        executable_path=tmp_path / "managed-chromium",
        outcomes=[browser],
    )
    _install_fake_playwright(monkeypatch, browser_type, events)

    result = await run_ui_smoke(
        loaded_profile=load_target_profile(ROOT / "config/target-profile.yaml"),
        settings=_settings(
            target_base_url="https://localhost:9300",
            target_verify_tls=True,
            agentforge_ui_ignore_https_errors=True,
        ),
        target_alias="local",
        repository_root=tmp_path,
        artifacts_dir=tmp_path / "artifacts",
        timeout_seconds=5,
    )

    assert browser.new_context_calls == [{"accept_downloads": False, "ignore_https_errors": True}]
    assert result.failed_step == UISmokeStep.NAVIGATE_LOGIN


@pytest.mark.asyncio
async def test_ui_ignore_https_errors_is_rejected_for_non_local_target(
    tmp_path: Path,
) -> None:
    fake = FakePlaywrightSession()

    result = await _run(
        tmp_path,
        fake,
        settings=_settings(
            target_base_url="https://host.docker.internal:9300",
            target_verify_tls=True,
            agentforge_ui_ignore_https_errors=True,
        ),
    )

    assert result.failed_step == UISmokeStep.VALIDATE_TARGET
    assert result.error_code == "https_errors_override_rejected"
    assert fake.events == []


@pytest.mark.asyncio
async def test_browser_auto_uses_playwright_chromium_when_available(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    browser = FakeBrowser(events)
    browser_type = FakeBrowserType(
        executable_path=tmp_path / "managed-chromium",
        outcomes=[browser],
    )
    _install_fake_playwright(monkeypatch, browser_type, events)
    session = playwright_module._LivePlaywrightSession(
        _execution_context(tmp_path),
        trace_enabled=False,
        headless=True,
        browser_mode="auto",
    )

    async with session:
        pass

    assert browser_type.launch_calls == [{"headless": True}]
    assert events[-3:] == ["context:close", "browser:close", "manager:stop"]


@pytest.mark.asyncio
async def test_browser_auto_falls_back_only_for_missing_managed_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    missing_path = tmp_path / "missing-managed-chromium"
    missing = PlaywrightError(f"Executable doesn't exist at {missing_path}")
    browser_type = FakeBrowserType(
        executable_path=missing_path,
        outcomes=[missing, FakeBrowser(events)],
    )
    _install_fake_playwright(monkeypatch, browser_type, events)
    session = playwright_module._LivePlaywrightSession(
        _execution_context(tmp_path),
        trace_enabled=False,
        headless=False,
        browser_mode="auto",
    )

    async with session:
        pass

    assert browser_type.launch_calls == [
        {"headless": False},
        {"headless": False, "channel": "chrome"},
    ]
    assert events[-3:] == ["context:close", "browser:close", "manager:stop"]


@pytest.mark.asyncio
async def test_browser_auto_does_not_fallback_for_unrelated_launch_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    browser_type = FakeBrowserType(
        executable_path=tmp_path / "missing-managed-chromium",
        outcomes=[PlaywrightError("browser process crashed access_token=launch-secret")],
    )
    _install_fake_playwright(monkeypatch, browser_type, events)
    result = await run_ui_smoke(
        loaded_profile=load_target_profile(ROOT / "config/target-profile.yaml"),
        settings=_settings(agentforge_browser_channel="auto"),
        target_alias="local",
        repository_root=tmp_path,
        artifacts_dir=tmp_path / "artifacts",
        timeout_seconds=5,
    )

    assert browser_type.launch_calls == [{"headless": True}]
    assert result.error_code == "browser_launch_failed"
    assert "launch-secret" not in result.model_dump_json()
    assert events[-1] == "manager:stop"


@pytest.mark.asyncio
async def test_browser_chromium_mode_never_falls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    missing_path = tmp_path / "missing-managed-chromium"
    browser_type = FakeBrowserType(
        executable_path=missing_path,
        outcomes=[PlaywrightError(f"Executable doesn't exist at {missing_path}")],
    )
    _install_fake_playwright(monkeypatch, browser_type, events)
    session = playwright_module._LivePlaywrightSession(
        _execution_context(tmp_path),
        trace_enabled=False,
        browser_mode="chromium",
    )

    with pytest.raises(playwright_module._ManagedChromiumUnavailable):
        await session.__aenter__()

    assert browser_type.launch_calls == [{"headless": True}]
    assert events[-1] == "manager:stop"


@pytest.mark.asyncio
async def test_browser_chrome_mode_uses_playwright_channel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    browser_type = FakeBrowserType(
        executable_path=tmp_path / "unused-managed-chromium",
        outcomes=[FakeBrowser(events)],
    )
    _install_fake_playwright(monkeypatch, browser_type, events)
    session = playwright_module._LivePlaywrightSession(
        _execution_context(tmp_path),
        trace_enabled=False,
        headless=False,
        browser_mode="chrome",
    )

    async with session:
        pass

    assert browser_type.launch_calls == [{"headless": False, "channel": "chrome"}]


@pytest.mark.asyncio
async def test_browser_chrome_mode_reports_missing_system_chrome_without_raw_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    secret_path = tmp_path / "browser-only-secret" / "Google Chrome"
    browser_type = FakeBrowserType(
        executable_path=tmp_path / "unused-managed-chromium",
        outcomes=[PlaywrightError(f"Chromium distribution 'chrome' is not found at {secret_path}")],
    )
    _install_fake_playwright(monkeypatch, browser_type, events)
    settings = _settings(agentforge_browser_channel="chrome")

    result = await run_ui_smoke(
        loaded_profile=load_target_profile(ROOT / "config/target-profile.yaml"),
        settings=settings,
        target_alias="local",
        repository_root=tmp_path,
        artifacts_dir=tmp_path / "artifacts",
        timeout_seconds=5,
    )

    assert browser_type.launch_calls == [{"headless": True, "channel": "chrome"}]
    assert result.error_code == "chrome_not_installed"
    assert result.error_message == "Google Chrome is unavailable for Playwright channel `chrome`"
    assert "browser-only-secret" not in result.model_dump_json()
    assert events[-1] == "manager:stop"


@pytest.mark.asyncio
async def test_browser_cleanup_runs_when_context_creation_fails_after_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    browser = FakeBrowser(events, context_error=RuntimeError("context setup failed"))
    browser_type = FakeBrowserType(
        executable_path=tmp_path / "managed-chromium",
        outcomes=[browser],
    )
    _install_fake_playwright(monkeypatch, browser_type, events)
    session = playwright_module._LivePlaywrightSession(
        _execution_context(tmp_path),
        trace_enabled=False,
        browser_mode="auto",
    )

    with pytest.raises(RuntimeError, match="context setup failed"):
        await session.__aenter__()

    assert browser_type.launch_calls == [{"headless": True}]
    assert events[-2:] == ["browser:close", "manager:stop"]


def test_browser_channel_setting_is_validated_and_defaults_for_local_development(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AGENTFORGE_BROWSER_CHANNEL", raising=False)
    assert Settings().agentforge_browser_channel == "auto"
    assert Settings(agentforge_browser_channel="chromium").agentforge_browser_channel == "chromium"
    with pytest.raises(ValidationError):
        Settings(agentforge_browser_channel="firefox")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_missing_browser_error_is_sanitized_and_suggests_install_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    secret_path = tmp_path / "browser-only-secret" / "managed-chromium"
    browser_type = FakeBrowserType(
        executable_path=secret_path,
        outcomes=[
            PlaywrightError(
                f"Executable doesn't exist at {secret_path}; synthetic-clinician access_token=x"
            )
        ],
    )
    _install_fake_playwright(monkeypatch, browser_type, events)
    settings = _settings(agentforge_browser_channel="chromium")

    result = await run_ui_smoke(
        loaded_profile=load_target_profile(ROOT / "config/target-profile.yaml"),
        settings=settings,
        target_alias="local",
        repository_root=tmp_path,
        artifacts_dir=tmp_path / "artifacts",
        timeout_seconds=5,
    )

    assert result.failed_step == UISmokeStep.LAUNCH_BROWSER
    assert result.error_code == "chromium_not_installed"
    assert "uv run playwright install chromium" in (result.error_message or "")
    serialized = result.model_dump_json()
    for secret in ("browser-only-secret", "synthetic-clinician", "access_token"):
        assert secret not in serialized
    assert events[-1] == "manager:stop"


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
    assert result.chat_submitted is True
    assert result.response_received is True
    assert result.response_length == len(fake.chat_response_text)
    assert result.sanitized_route == "clinical_copilot_panel"
    assert "page:patient:patient_a" in fake.events
    assert (
        "page:chat-submit:Briefly summarize the selected synthetic patient's chart." in fake.events
    )
    assert "page:chat-response" in fake.events
    assert fake.context_closed is True
    assert all("upload" not in event for event in fake.events)
    assert UISmokeStep.SUBMIT_CHAT.value in result.step_latencies_ms
    assert UISmokeStep.RECEIVE_CHAT_RESPONSE.value in result.step_latencies_ms


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure_mode", "expected_code"),
    [
        ("timeout", "copilot_response_timeout"),
        ("empty", "copilot_empty_response"),
    ],
)
async def test_ui_smoke_reports_response_timeout_or_empty_response(
    tmp_path: Path,
    failure_mode: str,
    expected_code: str,
) -> None:
    fake = (
        FakePlaywrightSession(fail_step=UISmokeStep.RECEIVE_CHAT_RESPONSE)
        if failure_mode == "timeout"
        else FakePlaywrightSession(chat_response_text="  ")
    )

    result = await _run(tmp_path, fake)

    assert result.failed_step == UISmokeStep.RECEIVE_CHAT_RESPONSE
    assert result.error_code == expected_code
    assert result.chat_submitted is True
    assert result.response_received is False
    assert result.response_length == 0
    assert fake.context_closed is True


@pytest.mark.asyncio
async def test_ui_smoke_success_survives_browser_cleanup_timeout(tmp_path: Path) -> None:
    fake = FakePlaywrightSession(
        cleanup_error=PlaywrightTimeoutError("browser-only-secret access_token=cleanup-secret")
    )

    result = await _run(tmp_path, fake)

    assert result.failed_step is None
    assert result.current_step == UISmokeStep.COMPLETE
    assert result.chat_submitted is True
    assert result.response_received is True
    assert result.warnings == ["browser_cleanup_timeout"]
    assert result.error_code is None
    assert result.error_message is None
    assert UISmokeStep.CLOSE_BROWSER.value in result.step_latencies_ms
    serialized = result.model_dump_json()
    assert "browser-only-secret" not in serialized
    assert "cleanup-secret" not in serialized


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
        chat_submitted=succeeded,
        response_received=succeeded,
        response_length=24 if succeeded else 0,
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
