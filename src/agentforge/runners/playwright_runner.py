"""Ephemeral Playwright runner for the approved OpenEMR UI workflow."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager, suppress
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from time import monotonic
from typing import Protocol
from urllib.parse import unquote, urljoin, urlparse
from uuid import uuid4

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
    PlaywrightContextManager,
    async_playwright,
)
from playwright.async_api import (
    TimeoutError as PlaywrightTimeoutError,
)
from pydantic import BaseModel, ConfigDict, Field

from agentforge.contracts.v1.actions import (
    AuthenticateActionV1,
    AuthenticationSessionSourceV1,
    CollectEvidenceActionV1,
    EvidenceKindV1,
    InvokeApprovedApiRequestActionV1,
    ResetSessionActionV1,
    SelectSyntheticPatientActionV1,
    SendChatMessageActionV1,
    UploadApprovedFixtureActionV1,
    WaitForResponseActionV1,
)
from agentforge.contracts.v1.campaign import ProposedAttackV1
from agentforge.contracts.v1.common import EvidenceReferenceKindV1, utc_now
from agentforge.contracts.v1.errors import AgentErrorCodeV1
from agentforge.contracts.v1.evidence import (
    ActionExecutionStatusV1,
    AttackEvidenceV1,
    TranscriptRoleV1,
)
from agentforge.orchestration.execution_gate import ValidatedAttackV1
from agentforge.security.allowlist import TargetRejected, require_allowed_url
from agentforge.settings import Settings
from agentforge.target.auth import TargetAuthenticationError, credentials_from_settings
from agentforge.target.fixtures import ApprovedFixture, resolve_approved_fixture
from agentforge.target.profile import LoadedTargetProfile
from agentforge.target.version import (
    approved_browser_url,
    join_profile_path,
    resolve_endpoint,
    same_origin,
)

from .base import (
    EvidenceRecorder,
    RunnerActionRejected,
    RunnerFailure,
    TargetExecutionContext,
    require_validated_attack,
)


@dataclass(frozen=True, slots=True)
class SelectedPatient:
    patient_alias: str
    external_id: str
    display_name: str
    numeric_pid: str


@dataclass(frozen=True, slots=True)
class BrowserChatResult:
    response_text: str


@dataclass(frozen=True, slots=True)
class BrowserUploadResult:
    review_text: str


class UISmokeStep(StrEnum):
    VALIDATE_TARGET = "validate_target"
    LOAD_CREDENTIALS = "load_credentials"
    LAUNCH_BROWSER = "launch_browser"
    NAVIGATE_LOGIN = "navigate_login"
    VERIFY_LOGIN_FORM = "verify_login_form"
    LOGIN = "login"
    SELECT_PATIENT = "select_patient"
    OPEN_COPILOT = "open_copilot"
    CLOSE_BROWSER = "close_browser"
    COMPLETE = "complete"


class UISmokeResult(BaseModel):
    """Typed outcome containing no browser state, credentials, or raw URLs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_alias: str
    navigation_succeeded: bool
    login_succeeded: bool
    patient_selected: bool
    copilot_opened: bool
    current_step: UISmokeStep
    failed_step: UISmokeStep | None
    sanitized_route: str | None
    total_latency_ms: float = Field(ge=0)
    step_latencies_ms: dict[str, float]
    timestamp: datetime
    error_code: str | None
    error_message: str | None
    failure_screenshot: str | None = None


class _CrossHostNavigationRejected(RunnerActionRejected):
    """Raised without retaining the rejected destination URL."""


class BrowserSession(Protocol):
    async def __aenter__(self) -> BrowserSession: ...

    async def __aexit__(self, exc_type, exc, traceback) -> None: ...  # type: ignore[no-untyped-def]

    async def reset(self, strategy_id: str) -> None: ...

    async def authenticate(self, action: AuthenticateActionV1) -> None: ...

    async def select_patient(self, patient_alias: str) -> SelectedPatient: ...

    async def send_chat(
        self,
        message: str,
        timeout_seconds: float,
    ) -> BrowserChatResult: ...

    async def stage_and_reject(
        self,
        fixture: ApprovedFixture,
        timeout_seconds: float,
    ) -> BrowserUploadResult: ...

    async def capture_screenshot(self, path: Path) -> None: ...

    async def stop_trace(self, path: Path) -> None: ...

    async def clear_sensitive_fields(self) -> None: ...


class UISmokeBrowserSession(Protocol):
    async def __aenter__(self) -> UISmokeBrowserSession: ...

    async def __aexit__(self, exc_type, exc, traceback) -> None: ...  # type: ignore[no-untyped-def]

    async def navigate_to_login(self) -> None: ...

    async def verify_login_form(self) -> None: ...

    async def login(self) -> None: ...

    async def select_patient(self, patient_alias: str) -> SelectedPatient: ...

    async def verify_copilot_ready(self) -> None: ...

    async def capture_screenshot(self, path: Path) -> None: ...

    async def clear_sensitive_fields(self) -> None: ...


BrowserSessionFactory = Callable[
    [TargetExecutionContext, bool], AbstractAsyncContextManager[BrowserSession]
]
UISmokeSessionFactory = Callable[
    [TargetExecutionContext, bool], AbstractAsyncContextManager[UISmokeBrowserSession]
]


class _LivePlaywrightSession(AbstractAsyncContextManager["_LivePlaywrightSession"]):
    """Low-level, selector-driven browser session; never persists storage state."""

    def __init__(
        self,
        context: TargetExecutionContext,
        trace_enabled: bool,
        *,
        headless: bool = True,
    ) -> None:
        self.execution = context
        self.trace_enabled = trace_enabled
        self.headless = headless
        self._manager: PlaywrightContextManager | None = None
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None
        self._page: Page | None = None
        self._trace_active = False
        self._used = False
        self._selected: SelectedPatient | None = None
        self._bound_csrf: str | None = None
        self._cross_host_navigation_blocked = False

    async def __aenter__(self) -> _LivePlaywrightSession:
        self._manager = async_playwright()
        self._playwright = await self._manager.start()
        self._browser = await self._playwright.chromium.launch(headless=self.headless)
        self._context = await self._browser.new_context(
            accept_downloads=False,
            ignore_https_errors=not self.execution.target_alias.verify_tls,
        )
        await self._context.route("**/*", self._route_request)
        self._page = await self._context.new_page()
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:  # type: ignore[no-untyped-def]
        try:
            if self._context is not None:
                await self._context.close()
        finally:
            try:
                if self._browser is not None:
                    await self._browser.close()
            finally:
                if self._manager is not None:
                    await self._manager.stop()
                self._page = None
                self._context = None
                self._browser = None
                self._playwright = None
                self._manager = None

    @property
    def page(self) -> Page:
        if self._page is None:
            raise RuntimeError("browser page is not initialized")
        return self._page

    @property
    def browser_context(self) -> BrowserContext:
        if self._context is None:
            raise RuntimeError("browser context is not initialized")
        return self._context

    async def _route_request(self, route) -> None:  # type: ignore[no-untyped-def]
        request_url = route.request.url
        path = unquote(urlparse(request_url).path).rstrip("/") or "/"
        prohibited = {
            unquote(item).rstrip("/") or "/" for item in self.execution.profile.prohibited_endpoints
        }
        if path in prohibited:
            await route.abort("blockedbyclient")
            return
        if not approved_browser_url(request_url, target_alias=self.execution.target_alias):
            if route.request.is_navigation_request():
                self._cross_host_navigation_blocked = True
            await route.abort("blockedbyclient")
            return
        await route.continue_()

    async def reset(self, strategy_id: str) -> None:
        if strategy_id != self.execution.profile.reset.conversation:
            raise RunnerActionRejected("browser reset strategy is not approved")
        if self._used:
            raise RunnerActionRejected("ephemeral browser reset must be the first UI action")

    async def authenticate(self, action: AuthenticateActionV1) -> None:
        credentials = self.execution.credentials
        if credentials is None:
            raise RunnerFailure(
                AgentErrorCodeV1.AUTHENTICATION_FAILED,
                "target test credentials are unavailable",
            )
        if action.session_source != AuthenticationSessionSourceV1.ENVIRONMENT_CREDENTIALS:
            raise RunnerActionRejected("persisted browser sessions are prohibited")
        if action.test_identity_alias != credentials.identity_alias:
            raise RunnerActionRejected("authentication identity alias is not approved")
        if action.expected_role != credentials.role:
            raise RunnerActionRejected("authentication role does not match the test identity")

        try:
            await self.navigate_to_login()
            await self.verify_login_form()
            await self.login()
        except (KeyError, PlaywrightTimeoutError) as exc:
            await self.clear_sensitive_fields()
            raise RunnerFailure(
                AgentErrorCodeV1.AUTHENTICATION_FAILED,
                "approved OpenEMR test login did not complete",
            ) from exc
        self._used = True
        if self.trace_enabled and not self._trace_active:
            await self.browser_context.tracing.start(
                screenshots=True,
                snapshots=True,
                sources=False,
            )
            self._trace_active = True

    async def navigate_to_login(self) -> None:
        auth = self.execution.profile.authentication
        login_url = join_profile_path(self.execution.target_alias.base_url, auth.login_path)
        timeout_ms = self.execution.request_timeout_seconds * 1_000
        try:
            await self.page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
        except Exception as exc:
            if self._cross_host_navigation_blocked:
                raise _CrossHostNavigationRejected(
                    "browser navigation left the approved target origin"
                ) from exc
            raise
        self._require_page_origin()

    async def verify_login_form(self) -> None:
        auth = self.execution.profile.authentication
        timeout_ms = self.execution.request_timeout_seconds * 1_000
        await self.page.locator(auth.selectors["form"]).wait_for(
            state="visible", timeout=timeout_ms
        )

    async def login(self) -> None:
        credentials = self.execution.credentials
        if credentials is None:
            raise RunnerFailure(
                AgentErrorCodeV1.AUTHENTICATION_FAILED,
                "target test credentials are unavailable",
            )
        auth = self.execution.profile.authentication
        timeout_ms = self.execution.request_timeout_seconds * 1_000
        await self.page.locator(auth.selectors["username"]).fill(credentials.username)
        await self.page.locator(auth.selectors["password"]).fill(
            credentials.password.get_secret_value()
        )
        try:
            await self.page.locator(auth.selectors["submit"]).click()
            await self.page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
        except Exception as exc:
            if self._cross_host_navigation_blocked:
                raise _CrossHostNavigationRejected(
                    "browser navigation left the approved target origin"
                ) from exc
            raise
        self._require_page_origin()
        search_selector = self.execution.profile.patient_selection.search_selector
        await self.page.locator(search_selector).wait_for(state="visible", timeout=timeout_ms)
        self._used = True

    def _require_page_origin(self) -> None:
        if not same_origin(self.page.url, self.execution.target_alias.base_url):
            raise _CrossHostNavigationRejected("browser navigation left the approved target origin")

    async def select_patient(self, patient_alias: str) -> SelectedPatient:
        if patient_alias not in {"patient_a", "patient_b"}:
            raise RunnerActionRejected("unknown synthetic patient alias")
        patient = getattr(self.execution.profile.patients, patient_alias)
        selection = self.execution.profile.patient_selection
        timeout_ms = self.execution.request_timeout_seconds * 1_000

        search = self.page.locator(selection.search_selector)
        await search.fill(patient.external_id)
        try:
            await search.press("Enter")
            finder = self.page.frame_locator(selection.finder_frame)
            await finder.locator(selection.result_table).wait_for(
                state="visible", timeout=timeout_ms
            )
        except PlaywrightTimeoutError:
            await self.page.locator(selection.submit_selector).click()
            finder = self.page.frame_locator(selection.finder_frame)
            await finder.locator(selection.result_table).wait_for(
                state="visible", timeout=timeout_ms
            )

        rows = finder.locator(f'tr[id^="{selection.result_row_prefix}"]').filter(
            has_text=patient.external_id
        )
        if await rows.count() != 1:
            raise RunnerActionRejected("synthetic patient lookup was not uniquely identified")
        row = rows.first
        row_text = (await row.inner_text()).casefold()
        expected_tokens = patient.display_name.casefold().split()
        if patient.external_id.casefold() not in row_text or not all(
            token in row_text for token in expected_tokens
        ):
            raise RunnerActionRejected("synthetic patient result did not match exact ID and name")
        row_id = await row.get_attribute("id")
        prefix = selection.result_row_prefix
        numeric_pid = row_id[len(prefix) :] if row_id and row_id.startswith(prefix) else ""
        if not numeric_pid.isdigit() or int(numeric_pid) <= 0:
            raise RunnerActionRejected("synthetic patient row did not expose a valid numeric PID")
        await row.click()

        patient_frame = self.page.frame_locator(selection.patient_frame)
        await patient_frame.locator(self.execution.profile.chat.card_selector).wait_for(
            state="visible", timeout=timeout_ms
        )
        selected = SelectedPatient(
            patient_alias=patient_alias,
            external_id=patient.external_id,
            display_name=patient.display_name,
            numeric_pid=numeric_pid,
        )
        self._selected = selected
        await self._bind_and_validate_card(first_binding=True)
        return selected

    async def _bind_and_validate_card(self, *, first_binding: bool) -> None:
        if self._selected is None:
            raise RunnerActionRejected("no synthetic patient is selected")
        profile = self.execution.profile
        frame = self.page.frame_locator(profile.patient_selection.patient_frame)
        card = frame.locator(profile.chat.card_selector)
        pid = await card.get_attribute(profile.chat.patient_id_attribute)
        csrf = await card.get_attribute(profile.chat.csrf_attribute)
        endpoint_value = await card.get_attribute(profile.chat.endpoint_attribute)
        if pid != self._selected.numeric_pid:
            raise RunnerActionRejected("Clinical Co-Pilot card PID does not match selected patient")
        if not csrf or len(csrf) > 4_096:
            raise RunnerActionRejected("Clinical Co-Pilot card lacks a bounded CSRF binding")
        if not endpoint_value:
            raise RunnerActionRejected("Clinical Co-Pilot card lacks its endpoint binding")
        expected = resolve_endpoint(
            profile=profile,
            target_alias=self.execution.target_alias,
            endpoint_id="copilot_chat_proxy",
            requested_method="POST",
        )
        rendered_endpoint = urljoin(self.page.url, endpoint_value)
        if rendered_endpoint != expected.url:
            raise RunnerActionRejected("Clinical Co-Pilot card endpoint is not the approved proxy")
        if first_binding:
            self._bound_csrf = csrf
        elif csrf != self._bound_csrf:
            raise RunnerActionRejected("Clinical Co-Pilot card CSRF binding changed unexpectedly")

    async def verify_copilot_ready(self) -> None:
        """Verify the rendered UI without clicking submit or touching upload controls."""

        if self._selected is None:
            raise RunnerActionRejected("no synthetic patient is selected")
        profile = self.execution.profile
        timeout_ms = self.execution.request_timeout_seconds * 1_000
        frame = self.page.frame_locator(profile.patient_selection.patient_frame)
        for selector in (
            profile.chat.card_selector,
            profile.chat.message_selector,
            profile.chat.submit_selector,
            profile.chat.completed_selector,
        ):
            await frame.locator(selector).wait_for(state="visible", timeout=timeout_ms)
        await self._bind_and_validate_card(first_binding=False)

    async def send_chat(self, message: str, timeout_seconds: float) -> BrowserChatResult:
        if len(message.encode("utf-8")) > self.execution.profile.chat.message_max_bytes:
            raise RunnerActionRejected("chat message exceeds the target profile byte limit")
        await self._bind_and_validate_card(first_binding=False)
        profile = self.execution.profile
        frame = self.page.frame_locator(profile.patient_selection.patient_frame)
        answers = frame.locator(f"{profile.chat.output_selector} {profile.chat.answer_selector}")
        before_count = await answers.count()
        await frame.locator(profile.chat.message_selector).fill(message)
        await frame.locator(profile.chat.submit_selector).click()

        timeout = min(timeout_seconds, self.execution.request_timeout_seconds)
        deadline = asyncio.get_running_loop().time() + timeout
        response_text = ""
        while asyncio.get_running_loop().time() < deadline:
            answer_count = await answers.count()
            if answer_count > before_count:
                response_text = await answers.nth(answer_count - 1).inner_text()
                break
            errors = frame.locator(profile.chat.error_selector)
            if await errors.count():
                response_text = await errors.last.inner_text()
                break
            await asyncio.sleep(0.05)
        if not response_text.strip():
            raise RunnerFailure(
                AgentErrorCodeV1.AGENT_TIMEOUT,
                "Clinical Co-Pilot response did not complete before the timeout",
                retryable=True,
                status=ActionExecutionStatusV1.TIMED_OUT,
            )
        await frame.locator(profile.chat.completed_selector).wait_for(
            state="visible", timeout=timeout * 1_000
        )
        await self._bind_and_validate_card(first_binding=False)
        return BrowserChatResult(response_text.strip()[:20_000])

    async def stage_and_reject(
        self,
        fixture: ApprovedFixture,
        timeout_seconds: float,
    ) -> BrowserUploadResult:
        profile = self.execution.profile
        if not profile.upload.enabled or profile.upload.persist_confirmation_enabled:
            raise RunnerActionRejected("safe stage-and-reject upload mode is unavailable")
        await self._bind_and_validate_card(first_binding=False)
        frame = self.page.frame_locator(profile.patient_selection.patient_frame)
        await frame.locator(profile.upload.open_selector).click()
        await frame.locator(profile.upload.type_selector).select_option(fixture.document_type)
        await frame.locator(profile.upload.file_selector).set_input_files(str(fixture.path))
        await frame.locator(profile.upload.submit_selector).click()
        review = frame.locator(profile.upload.review_selector)
        review_text = ""
        timeout_ms = min(timeout_seconds, self.execution.request_timeout_seconds) * 1_000
        try:
            await review.wait_for(state="visible", timeout=timeout_ms)
            review_text = (await review.inner_text()).strip()[:20_000]
        finally:
            await frame.locator(profile.upload.reject_selector).click()
            await review.wait_for(state="hidden", timeout=timeout_ms)
        await self._bind_and_validate_card(first_binding=False)
        return BrowserUploadResult(review_text or "Upload staged and rejected without persistence.")

    async def capture_screenshot(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        await self.page.screenshot(path=str(path), full_page=True)

    async def stop_trace(self, path: Path) -> None:
        if not self._trace_active:
            raise RunnerActionRejected("browser trace was not enabled for this attempt")
        path.parent.mkdir(parents=True, exist_ok=True)
        await self.browser_context.tracing.stop(path=str(path))
        self._trace_active = False

    async def clear_sensitive_fields(self) -> None:
        selector = self.execution.profile.authentication.selectors.get("password")
        if selector and self._page is not None:
            with suppress(Exception):
                await self.page.locator(selector).fill("")


_SAFE_TARGET_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _sanitized_target_alias(value: str) -> str:
    return value if _SAFE_TARGET_ALIAS.fullmatch(value) else "invalid"


def _ui_smoke_result(
    *,
    target_alias: str,
    timestamp: datetime,
    started: float,
    step_latencies_ms: dict[str, float],
    current_step: UISmokeStep,
    failed_step: UISmokeStep | None,
    navigation_succeeded: bool = False,
    login_succeeded: bool = False,
    patient_selected: bool = False,
    copilot_opened: bool = False,
    sanitized_route: str | None = None,
    error_code: str | None = None,
    error_message: str | None = None,
    failure_screenshot: str | None = None,
) -> UISmokeResult:
    return UISmokeResult(
        target_alias=_sanitized_target_alias(target_alias),
        navigation_succeeded=navigation_succeeded,
        login_succeeded=login_succeeded,
        patient_selected=patient_selected,
        copilot_opened=copilot_opened,
        current_step=current_step,
        failed_step=failed_step,
        sanitized_route=sanitized_route,
        total_latency_ms=round((monotonic() - started) * 1_000, 3),
        step_latencies_ms=step_latencies_ms,
        timestamp=timestamp,
        error_code=error_code,
        error_message=error_message,
        failure_screenshot=failure_screenshot,
    )


def _smoke_error(
    step: UISmokeStep,
    exc: Exception,
) -> tuple[str, str]:
    if isinstance(exc, _CrossHostNavigationRejected) or (
        isinstance(exc, RunnerActionRejected)
        and step in {UISmokeStep.NAVIGATE_LOGIN, UISmokeStep.LOGIN}
    ):
        return (
            "cross_host_navigation_rejected",
            "browser navigation left the approved target origin",
        )
    if step == UISmokeStep.LAUNCH_BROWSER:
        return "browser_launch_failed", "Chromium could not be launched"
    if step == UISmokeStep.NAVIGATE_LOGIN:
        if isinstance(exc, PlaywrightTimeoutError):
            return "navigation_timeout", "local target navigation timed out"
        return "navigation_failed", "local target navigation failed"
    if step == UISmokeStep.VERIFY_LOGIN_FORM:
        return "login_form_not_found", "approved OpenEMR login form was not found"
    if step == UISmokeStep.LOGIN:
        return "login_failed", "approved OpenEMR test login did not complete"
    if step == UISmokeStep.SELECT_PATIENT:
        return (
            "synthetic_patient_not_found",
            "configured synthetic patient could not be selected",
        )
    if step == UISmokeStep.OPEN_COPILOT:
        return "copilot_ui_not_found", "Clinical Co-Pilot UI was not ready"
    if step == UISmokeStep.CLOSE_BROWSER:
        return "browser_cleanup_failed", "ephemeral browser cleanup did not complete"
    return "ui_smoke_failed", "local UI smoke flow failed"


def _default_ui_smoke_session_factory(
    context: TargetExecutionContext,
    headless: bool,
) -> AbstractAsyncContextManager[UISmokeBrowserSession]:
    return _LivePlaywrightSession(context, trace_enabled=False, headless=headless)


async def run_ui_smoke(
    *,
    loaded_profile: LoadedTargetProfile,
    settings: Settings,
    target_alias: str,
    repository_root: Path,
    artifacts_dir: Path,
    timeout_seconds: float,
    headless: bool = True,
    screenshot_on_failure: bool = False,
    session_factory: UISmokeSessionFactory | None = None,
) -> UISmokeResult:
    """Run a local-only, no-submit UI readiness flow in an ephemeral context."""

    timestamp = utc_now()
    started = monotonic()
    timings: dict[str, float] = {}
    validation_started = monotonic()
    if target_alias != "local":
        timings[UISmokeStep.VALIDATE_TARGET.value] = round(
            (monotonic() - validation_started) * 1_000, 3
        )
        return _ui_smoke_result(
            target_alias=target_alias,
            timestamp=timestamp,
            started=started,
            step_latencies_ms=timings,
            current_step=UISmokeStep.VALIDATE_TARGET,
            failed_step=UISmokeStep.VALIDATE_TARGET,
            error_code="target_alias_rejected",
            error_message="UI smoke is restricted to the configured local target alias",
        )
    if not 0.1 <= timeout_seconds <= 120:
        timings[UISmokeStep.VALIDATE_TARGET.value] = round(
            (monotonic() - validation_started) * 1_000, 3
        )
        return _ui_smoke_result(
            target_alias=target_alias,
            timestamp=timestamp,
            started=started,
            step_latencies_ms=timings,
            current_step=UISmokeStep.VALIDATE_TARGET,
            failed_step=UISmokeStep.VALIDATE_TARGET,
            error_code="target_configuration_error",
            error_message="browser timeout is outside the approved range",
        )

    try:
        resolved_alias = loaded_profile.resolve_alias(target_alias, settings)
        for url in (resolved_alias.base_url, resolved_alias.status_url):
            require_allowed_url(url, resolved_alias.expected_hosts, allow_http=True)
    except (AttributeError, TargetRejected, ValueError):
        timings[UISmokeStep.VALIDATE_TARGET.value] = round(
            (monotonic() - validation_started) * 1_000, 3
        )
        return _ui_smoke_result(
            target_alias=target_alias,
            timestamp=timestamp,
            started=started,
            step_latencies_ms=timings,
            current_step=UISmokeStep.VALIDATE_TARGET,
            failed_step=UISmokeStep.VALIDATE_TARGET,
            error_code="target_url_rejected",
            error_message="configured local target URL failed approved-host validation",
        )
    timings[UISmokeStep.VALIDATE_TARGET.value] = round(
        (monotonic() - validation_started) * 1_000, 3
    )

    credential_started = monotonic()
    try:
        credentials = credentials_from_settings(
            profile=loaded_profile.profile,
            settings=settings,
            identity_alias="physician_test",
            expected_role="physician",
        )
    except TargetAuthenticationError:
        timings[UISmokeStep.LOAD_CREDENTIALS.value] = round(
            (monotonic() - credential_started) * 1_000, 3
        )
        return _ui_smoke_result(
            target_alias=target_alias,
            timestamp=timestamp,
            started=started,
            step_latencies_ms=timings,
            current_step=UISmokeStep.LOAD_CREDENTIALS,
            failed_step=UISmokeStep.LOAD_CREDENTIALS,
            error_code="missing_credentials",
            error_message="approved local test credentials are not configured",
        )
    timings[UISmokeStep.LOAD_CREDENTIALS.value] = round(
        (monotonic() - credential_started) * 1_000, 3
    )

    repository = repository_root.resolve()
    artifacts = artifacts_dir if artifacts_dir.is_absolute() else repository / artifacts_dir
    screenshot_artifacts = artifacts / "screenshots"
    try:
        context = TargetExecutionContext(
            target_id="openemr-ui-smoke",
            campaign_id="ui-smoke",
            attempt_id=f"ui-smoke-{uuid4().hex}",
            target_version=settings.target_version or "local-unknown",
            selected_patient_alias="patient_a",
            loaded_profile=loaded_profile,
            target_alias=resolved_alias,
            repository_root=repository,
            artifacts_dir=screenshot_artifacts,
            credentials=credentials,
            request_timeout_seconds=timeout_seconds,
        )
    except ValueError:
        return _ui_smoke_result(
            target_alias=target_alias,
            timestamp=timestamp,
            started=started,
            step_latencies_ms=timings,
            current_step=UISmokeStep.VALIDATE_TARGET,
            failed_step=UISmokeStep.VALIDATE_TARGET,
            error_code="target_configuration_error",
            error_message="local UI smoke configuration is invalid",
        )

    factory = session_factory or _default_ui_smoke_session_factory
    current_step = UISmokeStep.LAUNCH_BROWSER
    navigation_succeeded = False
    login_succeeded = False
    patient_selected = False
    copilot_opened = False
    sanitized_route: str | None = None
    failure_screenshot: str | None = None
    cleanup_started = monotonic()

    async def perform(
        step: UISmokeStep,
        operation: Callable[[], Awaitable[object]],
    ) -> object:
        nonlocal current_step
        current_step = step
        step_started = monotonic()
        try:
            return await operation()
        finally:
            timings[step.value] = round((monotonic() - step_started) * 1_000, 3)

    try:
        launch_started = monotonic()
        async with factory(context, headless) as session:
            timings[UISmokeStep.LAUNCH_BROWSER.value] = round(
                (monotonic() - launch_started) * 1_000, 3
            )
            try:
                await perform(UISmokeStep.NAVIGATE_LOGIN, session.navigate_to_login)
                navigation_succeeded = True
                sanitized_route = "login"
                await perform(UISmokeStep.VERIFY_LOGIN_FORM, session.verify_login_form)
                await perform(UISmokeStep.LOGIN, session.login)
                login_succeeded = True
                sanitized_route = "authenticated_home"
                await perform(
                    UISmokeStep.SELECT_PATIENT,
                    lambda: session.select_patient(context.selected_patient_alias),
                )
                patient_selected = True
                sanitized_route = "synthetic_patient_chart"
                await perform(UISmokeStep.OPEN_COPILOT, session.verify_copilot_ready)
                copilot_opened = True
                sanitized_route = "clinical_copilot_panel"
            except Exception:
                await session.clear_sensitive_fields()
                if screenshot_on_failure:
                    screenshot_path, screenshot_reference = context.artifact_path(
                        "ui-smoke-failure.png"
                    )
                    with suppress(Exception):
                        await session.capture_screenshot(screenshot_path)
                        failure_screenshot = screenshot_reference
                raise
            finally:
                with suppress(Exception):
                    await session.clear_sensitive_fields()
            current_step = UISmokeStep.CLOSE_BROWSER
            cleanup_started = monotonic()
        timings[UISmokeStep.CLOSE_BROWSER.value] = round((monotonic() - cleanup_started) * 1_000, 3)
    except Exception as exc:
        if current_step == UISmokeStep.LAUNCH_BROWSER:
            timings[UISmokeStep.LAUNCH_BROWSER.value] = round(
                (monotonic() - launch_started) * 1_000, 3
            )
        elif current_step == UISmokeStep.CLOSE_BROWSER:
            timings[UISmokeStep.CLOSE_BROWSER.value] = round(
                (monotonic() - cleanup_started) * 1_000, 3
            )
        error_code, error_message = _smoke_error(current_step, exc)
        return _ui_smoke_result(
            target_alias=target_alias,
            timestamp=timestamp,
            started=started,
            step_latencies_ms=timings,
            current_step=current_step,
            failed_step=current_step,
            navigation_succeeded=navigation_succeeded,
            login_succeeded=login_succeeded,
            patient_selected=patient_selected,
            copilot_opened=copilot_opened,
            sanitized_route=sanitized_route,
            error_code=error_code,
            error_message=error_message,
            failure_screenshot=failure_screenshot,
        )

    return _ui_smoke_result(
        target_alias=target_alias,
        timestamp=timestamp,
        started=started,
        step_latencies_ms=timings,
        current_step=UISmokeStep.COMPLETE,
        failed_step=None,
        navigation_succeeded=True,
        login_succeeded=True,
        patient_selected=True,
        copilot_opened=True,
        sanitized_route=sanitized_route,
    )


def _default_session_factory(
    context: TargetExecutionContext,
    trace_enabled: bool,
) -> AbstractAsyncContextManager[BrowserSession]:
    return _LivePlaywrightSession(context, trace_enabled)


class PlaywrightAttackRunner:
    """Run allowlisted UI actions inside one disposable browser context."""

    def __init__(self, session_factory: BrowserSessionFactory | None = None) -> None:
        self._session_factory = session_factory or _default_session_factory

    async def execute(
        self,
        attack: ValidatedAttackV1,
        context: TargetExecutionContext,
    ) -> AttackEvidenceV1:
        proposal = require_validated_attack(attack, context)
        recorder = EvidenceRecorder(context)
        trace_requested = any(
            isinstance(action, CollectEvidenceActionV1)
            and EvidenceKindV1.BROWSER_TRACE in action.evidence_kinds
            for action in proposal.ordered_actions
        )
        trace_stopped = False
        try:
            async with self._session_factory(context, trace_requested) as session:
                for index, action in enumerate(proposal.ordered_actions):
                    started_at = utc_now()
                    response_timeout_seconds = context.request_timeout_seconds
                    if index + 1 < len(proposal.ordered_actions):
                        next_action = proposal.ordered_actions[index + 1]
                        if isinstance(next_action, WaitForResponseActionV1):
                            response_timeout_seconds = min(
                                response_timeout_seconds,
                                next_action.timeout_seconds,
                            )
                    try:
                        summary, trace_stopped = await self._execute_action(
                            action=action,
                            sequence_index=index,
                            context=context,
                            recorder=recorder,
                            session=session,
                            trace_stopped=trace_stopped,
                            response_timeout_seconds=response_timeout_seconds,
                        )
                    except RunnerFailure as failure:
                        recorder.add_action(
                            sequence_index=index,
                            action=action,
                            started_at=started_at,
                            status=failure.status,
                            summary=failure.public_message,
                        )
                        recorder.add_error(failure)
                        trace_stopped = await self._capture_failure_artifacts(
                            attack=proposal,
                            context=context,
                            recorder=recorder,
                            session=session,
                            trace_requested=trace_requested,
                            trace_stopped=trace_stopped,
                            authentication_failure=isinstance(action, AuthenticateActionV1),
                        )
                        for skipped_index, skipped in enumerate(
                            proposal.ordered_actions[index + 1 :], start=index + 1
                        ):
                            recorder.add_skipped(skipped_index, skipped)
                        break
                    except Exception:
                        failure = RunnerFailure(
                            AgentErrorCodeV1.UNEXPECTED_INTERNAL_ERROR,
                            "browser runner encountered an unexpected internal error",
                        )
                        recorder.add_action(
                            sequence_index=index,
                            action=action,
                            started_at=started_at,
                            status=failure.status,
                            summary=failure.public_message,
                        )
                        recorder.add_error(failure)
                        for skipped_index, skipped in enumerate(
                            proposal.ordered_actions[index + 1 :], start=index + 1
                        ):
                            recorder.add_skipped(skipped_index, skipped)
                        break
                    else:
                        recorder.add_action(
                            sequence_index=index,
                            action=action,
                            started_at=started_at,
                            status=ActionExecutionStatusV1.SUCCEEDED,
                            summary=summary,
                        )
        except Exception:
            if not recorder.executed_actions:
                failure = RunnerFailure(
                    AgentErrorCodeV1.TARGET_UNREACHABLE,
                    "ephemeral browser session could not be initialized",
                    retryable=True,
                )
                first = proposal.ordered_actions[0]
                timestamp = utc_now()
                recorder.add_action(
                    sequence_index=0,
                    action=first,
                    started_at=timestamp,
                    status=failure.status,
                    summary=failure.public_message,
                )
                recorder.add_error(failure)
                for index, action in enumerate(proposal.ordered_actions[1:], start=1):
                    recorder.add_skipped(index, action)
        return recorder.finalize()

    async def _execute_action(
        self,
        *,
        action,
        sequence_index: int,
        context: TargetExecutionContext,
        recorder: EvidenceRecorder,
        session: BrowserSession,
        trace_stopped: bool,
        response_timeout_seconds: float,
    ) -> tuple[str, bool]:
        if isinstance(action, ResetSessionActionV1):
            await session.reset(action.reset_strategy_id)
            return "fresh ephemeral browser context verified", trace_stopped
        if isinstance(action, AuthenticateActionV1):
            await session.authenticate(action)
            return "approved synthetic-test identity authenticated", trace_stopped
        if isinstance(action, SelectSyntheticPatientActionV1):
            selected = await session.select_patient(action.patient_alias)
            return (
                f"selected {selected.patient_alias} by exact synthetic ID/name and bound PID",
                trace_stopped,
            )
        if isinstance(action, SendChatMessageActionV1):
            if not action.await_response:
                raise RunnerActionRejected("UI chat actions must await their bounded response")
            recorder.add_transcript(TranscriptRoleV1.USER, action.message)
            result = await session.send_chat(action.message, response_timeout_seconds)
            recorder.add_transcript(TranscriptRoleV1.ASSISTANT, result.response_text)
            return (
                "captured bounded Clinical Co-Pilot response from the patient card",
                trace_stopped,
            )
        if isinstance(action, UploadApprovedFixtureActionV1):
            if action.upload_surface_id != context.upload_surface_id:
                raise RunnerActionRejected("upload surface alias is not approved")
            authorization = context.approved_fixtures.get(action.fixture_id)
            if authorization is None:
                raise RunnerActionRejected("fixture alias lacks controller authorization")
            fixture = resolve_approved_fixture(
                profile=context.profile,
                repository_root=context.repository_root,
                fixture_id=action.fixture_id,
                declared_media_type=action.declared_media_type,
                authorization=authorization,
                configured_max_bytes=context.max_upload_bytes,
            )
            result = await session.stage_and_reject(fixture, response_timeout_seconds)
            recorder.add_transcript(
                TranscriptRoleV1.SYSTEM,
                f"Fixture {fixture.fixture_id} was staged, reviewed, and rejected. "
                f"Review: {result.review_text}",
            )
            return "approved fixture staged then rejected without persistence", trace_stopped
        if isinstance(action, InvokeApprovedApiRequestActionV1):
            raise RunnerActionRejected(
                "browser runner does not accept direct API actions; use the status HTTP runner"
            )
        if isinstance(action, WaitForResponseActionV1):
            return "preceding UI action had already awaited its bounded response", trace_stopped
        if isinstance(action, CollectEvidenceActionV1):
            return await self._collect_artifacts(
                action=action,
                sequence_index=sequence_index,
                context=context,
                recorder=recorder,
                session=session,
                trace_stopped=trace_stopped,
            )
        raise RunnerActionRejected("action type is unsupported by the browser runner")

    async def _collect_artifacts(
        self,
        *,
        action: CollectEvidenceActionV1,
        sequence_index: int,
        context: TargetExecutionContext,
        recorder: EvidenceRecorder,
        session: BrowserSession,
        trace_stopped: bool,
    ) -> tuple[str, bool]:
        if action.capture_on != "always":
            return "deferred artifact capture condition was not met during execution", trace_stopped
        captured: list[str] = []
        if EvidenceKindV1.SCREENSHOT in action.evidence_kinds:
            path, relative = context.artifact_path(f"action-{sequence_index}-screenshot.png")
            await session.capture_screenshot(path)
            recorder.add_artifact(
                reference_id=f"screenshot-{sequence_index}",
                kind=EvidenceReferenceKindV1.SCREENSHOT,
                relative_path=relative,
                description="Synthetic target UI screenshot captured after approved actions",
            )
            captured.append("screenshot")
        if EvidenceKindV1.BROWSER_TRACE in action.evidence_kinds and not trace_stopped:
            path, relative = context.artifact_path(f"action-{sequence_index}-trace.zip")
            await session.stop_trace(path)
            recorder.add_artifact(
                reference_id=f"trace-{sequence_index}",
                kind=EvidenceReferenceKindV1.BROWSER_TRACE,
                relative_path=relative,
                description="Ephemeral same-origin browser trace for the synthetic attempt",
            )
            trace_stopped = True
            captured.append("browser trace")
        label = ", ".join(captured) if captured else "in-memory evidence"
        return f"captured {label}", trace_stopped

    async def _capture_failure_artifacts(
        self,
        *,
        attack: ProposedAttackV1,
        context: TargetExecutionContext,
        recorder: EvidenceRecorder,
        session: BrowserSession,
        trace_requested: bool,
        trace_stopped: bool,
        authentication_failure: bool,
    ) -> bool:
        failure_collectors = [
            action
            for action in attack.ordered_actions
            if isinstance(action, CollectEvidenceActionV1)
            and action.capture_on in {"failure", "always"}
        ]
        if not failure_collectors:
            return trace_stopped
        if authentication_failure:
            await session.clear_sensitive_fields()
        wants_screenshot = any(
            EvidenceKindV1.SCREENSHOT in action.evidence_kinds for action in failure_collectors
        )
        if wants_screenshot and not authentication_failure:
            with suppress(Exception):
                path, relative = context.artifact_path("failure-screenshot.png")
                await session.capture_screenshot(path)
                recorder.add_artifact(
                    reference_id="failure-screenshot",
                    kind=EvidenceReferenceKindV1.SCREENSHOT,
                    relative_path=relative,
                    description="Synthetic target UI state captured after runner failure",
                )
        if trace_requested and not trace_stopped:
            with suppress(Exception):
                path, relative = context.artifact_path("failure-trace.zip")
                await session.stop_trace(path)
                recorder.add_artifact(
                    reference_id="failure-trace",
                    kind=EvidenceReferenceKindV1.BROWSER_TRACE,
                    relative_path=relative,
                    description="Ephemeral same-origin browser trace captured on failure",
                )
                trace_stopped = True
        return trace_stopped


__all__ = [
    "BrowserChatResult",
    "BrowserSession",
    "BrowserSessionFactory",
    "BrowserUploadResult",
    "PlaywrightAttackRunner",
    "SelectedPatient",
    "UISmokeBrowserSession",
    "UISmokeResult",
    "UISmokeSessionFactory",
    "UISmokeStep",
    "run_ui_smoke",
]
