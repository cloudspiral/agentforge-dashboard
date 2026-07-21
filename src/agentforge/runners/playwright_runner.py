"""Ephemeral Playwright runner for the approved OpenEMR UI workflow."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import unquote, urljoin, urlparse

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
from agentforge.target.fixtures import ApprovedFixture, resolve_approved_fixture
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


BrowserSessionFactory = Callable[
    [TargetExecutionContext, bool], AbstractAsyncContextManager[BrowserSession]
]


class _LivePlaywrightSession(AbstractAsyncContextManager["_LivePlaywrightSession"]):
    """Low-level, selector-driven browser session; never persists storage state."""

    def __init__(self, context: TargetExecutionContext, trace_enabled: bool) -> None:
        self.execution = context
        self.trace_enabled = trace_enabled
        self._manager: PlaywrightContextManager | None = None
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None
        self._page: Page | None = None
        self._trace_active = False
        self._used = False
        self._selected: SelectedPatient | None = None
        self._bound_csrf: str | None = None

    async def __aenter__(self) -> _LivePlaywrightSession:
        self._manager = async_playwright()
        self._playwright = await self._manager.start()
        self._browser = await self._playwright.chromium.launch(headless=True)
        self._context = await self._browser.new_context(
            accept_downloads=False,
            ignore_https_errors=not self.execution.target_alias.verify_tls,
        )
        await self._context.route("**/*", self._route_request)
        self._page = await self._context.new_page()
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:  # type: ignore[no-untyped-def]
        if self._context is not None:
            await self._context.close()
        if self._browser is not None:
            await self._browser.close()
        if self._manager is not None:
            await self._manager.stop()

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
        if path in prohibited or not approved_browser_url(
            request_url, target_alias=self.execution.target_alias
        ):
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

        auth = self.execution.profile.authentication
        login_url = join_profile_path(self.execution.target_alias.base_url, auth.login_path)
        timeout_ms = self.execution.request_timeout_seconds * 1_000
        try:
            await self.page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
            self._require_page_origin()
            await self.page.locator(auth.selectors["form"]).wait_for(
                state="visible", timeout=timeout_ms
            )
            await self.page.locator(auth.selectors["username"]).fill(credentials.username)
            await self.page.locator(auth.selectors["password"]).fill(
                credentials.password.get_secret_value()
            )
            await self.page.locator(auth.selectors["submit"]).click()
            await self.page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
            self._require_page_origin()
            search_selector = self.execution.profile.patient_selection.search_selector
            await self.page.locator(search_selector).wait_for(state="visible", timeout=timeout_ms)
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

    def _require_page_origin(self) -> None:
        if not same_origin(self.page.url, self.execution.target_alias.base_url):
            raise RunnerActionRejected("browser navigation left the approved target origin")

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
]
