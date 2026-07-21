from __future__ import annotations

import hashlib
import json
from contextlib import AbstractAsyncContextManager
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from agentforge.contracts.v1.campaign import ProposedAttackV1
from agentforge.contracts.v1.errors import AgentErrorCodeV1
from agentforge.contracts.v1.evidence import ActionExecutionStatusV1
from agentforge.runners.base import RunnerActionRejected, TargetExecutionContext
from agentforge.runners.composite import CompositeAttackRunner
from agentforge.runners.http_runner import HttpAttackRunner
from agentforge.runners.playwright_runner import (
    BrowserChatResult,
    BrowserUploadResult,
    PlaywrightAttackRunner,
    SelectedPatient,
)
from agentforge.security.allowlist import TargetRejected
from agentforge.settings import Settings
from agentforge.target.auth import TargetCredentials, credentials_from_settings
from agentforge.target.fixtures import ApprovedFixtureAuthorization, resolve_approved_fixture
from agentforge.target.profile import load_target_profile
from agentforge.target.version import (
    approved_browser_url,
    discover_target_version,
    resolve_endpoint,
)

ROOT = Path(__file__).parents[2]


def _attack(actions: list[dict[str, object]]) -> ProposedAttackV1:
    return ProposedAttackV1.model_validate_json(
        json.dumps(
            {
                "schema_version": "v1",
                "proposal_id": "proposal-1",
                "category": "prompt_injection",
                "subcategory": "direct",
                "attack_family_id": "family-1",
                "lineage_id": "lineage-1",
                "novelty_rationale": "Focused adapter unit test.",
                "prerequisites": [],
                "ordered_actions": actions,
                "expected_exploit_signals": ["bounded test signal"],
                "expected_safe_behavior": ["request remains allowlisted"],
                "stop_conditions": ["adapter rejects the action"],
                "risk_flags": [],
                "estimated_turns": 1,
                "estimated_cost_class": "low",
            }
        )
    )


def _context(
    tmp_path: Path,
    *,
    credentials: bool = False,
    approved_fixtures: dict[str, ApprovedFixtureAuthorization] | None = None,
) -> TargetExecutionContext:
    loaded = load_target_profile(ROOT / "config/target-profile.yaml")
    alias = loaded.resolve_alias(
        "local",
        Settings(
            target_base_url="http://localhost:9300",
            target_api_base_url="http://localhost:8001",
            target_verify_tls=False,
        ),
    )
    resolved_credentials = (
        TargetCredentials(
            identity_alias="physician_test",
            username="synthetic-admin",
            password=SecretStr("not-logged"),
            role="physician",
        )
        if credentials
        else None
    )
    return TargetExecutionContext(
        target_id="openemr-test",
        campaign_id="campaign-1",
        attempt_id="attempt-1",
        target_version="test-sha",
        loaded_profile=loaded,
        target_alias=alias,
        repository_root=tmp_path,
        artifacts_dir=tmp_path / "artifacts",
        credentials=resolved_credentials,
        approved_fixtures=approved_fixtures or {},
    )


def _status_action(endpoint_id: str = "status_health") -> dict[str, object]:
    return {
        "action_type": "invoke_approved_api_request",
        "action_id": "status-1",
        "description": "Read approved target status.",
        "endpoint_id": endpoint_id,
        "method": "GET",
        "query": {},
        "body": {},
    }


def _chat_action() -> dict[str, object]:
    return {
        "action_type": "send_chat_message",
        "action_id": "chat-1",
        "description": "Send a bounded test message.",
        "message": "Summarize the synthetic chart.",
        "await_response": True,
    }


@pytest.mark.asyncio
async def test_http_runner_calls_only_symbolic_status_endpoint(tmp_path: Path) -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"build_sha": "abc123"}, request=request)

    transport = httpx.MockTransport(handler)
    runner = HttpAttackRunner(
        lambda context: httpx.AsyncClient(
            transport=transport,
            timeout=context.request_timeout_seconds,
            follow_redirects=False,
        )
    )
    attack = _attack(
        [
            _status_action(),
            {
                "action_type": "collect_evidence",
                "action_id": "collect-1",
                "description": "Keep HTTP metadata.",
                "evidence_kinds": ["http_metadata"],
                "capture_on": "always",
            },
        ]
    )

    evidence = await runner.execute(attack, _context(tmp_path))

    assert [request.url.path for request in requests] == ["/health"]
    assert all(
        item.status == ActionExecutionStatusV1.SUCCEEDED
        for item in evidence.executed_action_sequence
    )
    assert evidence.sanitized_http_metadata[0].endpoint_id == "status_health"
    assert evidence.sanitized_http_metadata[0].response_status == 200
    assert len(evidence.evidence_hash) == 64


@pytest.mark.asyncio
async def test_http_runner_rejects_chat_without_sending_request(tmp_path: Path) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(500, request=request)

    transport = httpx.MockTransport(handler)
    runner = HttpAttackRunner(
        lambda context: httpx.AsyncClient(
            transport=transport,
            timeout=context.request_timeout_seconds,
        )
    )

    evidence = await runner.execute(_attack([_chat_action()]), _context(tmp_path))

    assert requests == []
    assert evidence.executed_action_sequence[0].status == ActionExecutionStatusV1.REJECTED
    assert evidence.errors[0].code == AgentErrorCodeV1.ACTION_REJECTED
    assert "/agent/chat" not in evidence.model_dump_json()


@pytest.mark.asyncio
async def test_http_runner_records_and_rejects_redirect(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"location": "https://outside.invalid/health"},
            request=request,
        )

    runner = HttpAttackRunner(
        lambda context: httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            timeout=context.request_timeout_seconds,
        )
    )

    evidence = await runner.execute(_attack([_status_action()]), _context(tmp_path))

    assert evidence.executed_action_sequence[0].status == ActionExecutionStatusV1.REJECTED
    assert evidence.sanitized_http_metadata[0].response_status == 302


@pytest.mark.asyncio
async def test_version_discovery_reads_bounded_approved_health_field(tmp_path: Path) -> None:
    context = _context(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"build_sha": "release-123"}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        discovered = await discover_target_version(
            client=client,
            profile=context.profile,
            target_alias=context.target_alias,
        )

    assert discovered.version == "release-123"
    assert discovered.endpoint_id == "status_health"


def test_endpoint_and_fixture_resolvers_accept_aliases_not_paths(tmp_path: Path) -> None:
    context = _context(tmp_path)
    with pytest.raises(TargetRejected, match="unknown target endpoint alias"):
        resolve_endpoint(
            profile=context.profile,
            target_alias=context.target_alias,
            endpoint_id="http://outside.invalid/agent/chat",
        )

    fixture_root = tmp_path / context.profile.upload.fixture_root
    fixture_root.mkdir(parents=True)
    fixture_path = fixture_root / "boundary_fixture.pdf"
    fixture_bytes = b"%PDF-1.4\n1 0 obj<</Type /Page>>endobj\n%%EOF\n"
    fixture_path.write_bytes(fixture_bytes)
    authorization = ApprovedFixtureAuthorization(
        fixture_id="boundary_fixture",
        repository_relative_path=fixture_path.relative_to(tmp_path).as_posix(),
        document_type="lab_pdf",
        media_type="application/pdf",
        size_bytes=len(fixture_bytes),
        pages=1,
        sha256=hashlib.sha256(fixture_bytes).hexdigest(),
    )
    fixture = resolve_approved_fixture(
        profile=context.profile,
        repository_root=tmp_path,
        fixture_id="boundary_fixture",
        declared_media_type="application/pdf",
        authorization=authorization,
        configured_max_bytes=1_048_576,
    )

    assert fixture.path == fixture_path.resolve()
    assert fixture.pages == 1
    assert len(fixture.sha256) == 64
    assert approved_browser_url(
        "http://localhost:9300/interface/main/tabs/main.php",
        target_alias=context.target_alias,
    )
    assert not approved_browser_url(
        "http://localhost:8001/agent/chat",
        target_alias=context.target_alias,
    )
    with pytest.raises(TargetRejected, match="fixture alias"):
        resolve_approved_fixture(
            profile=context.profile,
            repository_root=tmp_path,
            fixture_id="../outside",
            declared_media_type="application/pdf",
            authorization=authorization,
            configured_max_bytes=1_048_576,
        )


def test_test_credentials_are_alias_bounded_and_secret_safe() -> None:
    profile = load_target_profile(ROOT / "config/target-profile.yaml").profile
    credentials = credentials_from_settings(
        profile=profile,
        settings=Settings(
            target_test_username="admin",
            target_test_password=SecretStr("ultra-sensitive-value"),
            target_test_role="physician",
        ),
        identity_alias="physician_test",
        expected_role="physician",
    )

    assert credentials.username == "admin"
    assert "ultra-sensitive-value" not in repr(credentials)


class FakeBrowserSession(AbstractAsyncContextManager["FakeBrowserSession"]):
    def __init__(self, *, fail_chat: bool = False) -> None:
        self.events: list[str] = []
        self.fail_chat = fail_chat

    async def __aenter__(self) -> FakeBrowserSession:
        self.events.append("enter")
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:  # type: ignore[no-untyped-def]
        self.events.append("exit")

    async def reset(self, strategy_id: str) -> None:
        self.events.append(f"reset:{strategy_id}")

    async def authenticate(self, action) -> None:  # type: ignore[no-untyped-def]
        self.events.append(f"authenticate:{action.test_identity_alias}")

    async def select_patient(self, patient_alias: str) -> SelectedPatient:
        self.events.append(f"select:{patient_alias}")
        return SelectedPatient(patient_alias, "GOLDEN-LONGITUDINAL", "Avery GoldenFixture", "7")

    async def send_chat(self, message: str, timeout_seconds: float) -> BrowserChatResult:
        self.events.append(f"chat:{message}")
        assert timeout_seconds == 7
        if self.fail_chat:
            raise RunnerActionRejected("fake bounded chat failure")
        return BrowserChatResult("Synthetic chart response with bounded evidence.")

    async def stage_and_reject(
        self,
        fixture,  # type: ignore[no-untyped-def]
        timeout_seconds: float,
    ) -> BrowserUploadResult:
        self.events.append(f"stage-reject:{fixture.fixture_id}")
        assert timeout_seconds == 7
        return BrowserUploadResult("No persistent change was made.")

    async def capture_screenshot(self, path: Path) -> None:
        self.events.append(f"screenshot:{path.name}")

    async def stop_trace(self, path: Path) -> None:
        self.events.append(f"trace:{path.name}")

    async def clear_sensitive_fields(self) -> None:
        self.events.append("clear-sensitive")


def _browser_actions(*, failure_capture: bool = False) -> list[dict[str, object]]:
    return [
        {
            "action_type": "reset_session",
            "action_id": "reset-1",
            "description": "Require a clean browser.",
            "reset_strategy_id": "fresh_ephemeral_browser_context",
            "require_clean_context": True,
        },
        {
            "action_type": "authenticate",
            "action_id": "auth-1",
            "description": "Use approved test identity.",
            "session_source": "environment_credentials",
            "test_identity_alias": "physician_test",
            "expected_role": "physician",
        },
        {
            "action_type": "select_synthetic_patient",
            "action_id": "patient-1",
            "description": "Select exact synthetic patient.",
            "patient_alias": "patient_a",
            "verify_selected_context": True,
        },
        _chat_action(),
        {
            "action_type": "wait_for_response",
            "action_id": "wait-1",
            "description": "Wait within the approved bound.",
            "timeout_seconds": 7,
            "expected_event": "assistant_response",
        },
        {
            "action_type": "collect_evidence",
            "action_id": "collect-1",
            "description": "Collect bounded browser evidence.",
            "evidence_kinds": (
                ["screenshot", "browser_trace"] if failure_capture else ["transcript"]
            ),
            "capture_on": "failure" if failure_capture else "always",
        },
    ]


@pytest.mark.asyncio
async def test_playwright_runner_uses_fake_ephemeral_session_and_captures_transcript(
    tmp_path: Path,
) -> None:
    fake = FakeBrowserSession()
    runner = PlaywrightAttackRunner(lambda context, trace: fake)

    evidence = await runner.execute(
        _attack(_browser_actions()),
        _context(tmp_path, credentials=True),
    )

    assert fake.events[:4] == [
        "enter",
        "reset:fresh_ephemeral_browser_context",
        "authenticate:physician_test",
        "select:patient_a",
    ]
    assert [turn.role.value for turn in evidence.transcript] == ["user", "assistant"]
    assert all(
        item.status == ActionExecutionStatusV1.SUCCEEDED
        for item in evidence.executed_action_sequence
    )
    assert fake.events[-1] == "exit"


@pytest.mark.asyncio
async def test_playwright_failure_capture_skips_later_actions_without_state_persistence(
    tmp_path: Path,
) -> None:
    fake = FakeBrowserSession(fail_chat=True)
    runner = PlaywrightAttackRunner(lambda context, trace: fake)

    evidence = await runner.execute(
        _attack(_browser_actions(failure_capture=True)),
        _context(tmp_path, credentials=True),
    )

    assert evidence.executed_action_sequence[3].status == ActionExecutionStatusV1.REJECTED
    assert evidence.executed_action_sequence[4].status == ActionExecutionStatusV1.SKIPPED
    assert evidence.executed_action_sequence[5].status == ActionExecutionStatusV1.SKIPPED
    assert "screenshot:failure-screenshot.png" in fake.events
    assert "trace:failure-trace.zip" in fake.events
    assert {artifact.kind.value for artifact in evidence.artifact_references} == {
        "screenshot",
        "browser_trace",
    }


@pytest.mark.asyncio
async def test_playwright_upload_uses_authorized_fixture_and_only_stage_rejects(
    tmp_path: Path,
) -> None:
    fixture_root = tmp_path / "evals/fixtures/uploads"
    fixture_root.mkdir(parents=True)
    fixture_bytes = b"%PDF-1.4\n1 0 obj<</Type /Page>>endobj\n%%EOF\n"
    fixture_path = fixture_root / "bounded-upload.pdf"
    fixture_path.write_bytes(fixture_bytes)
    authorization = ApprovedFixtureAuthorization(
        fixture_id="bounded-upload",
        repository_relative_path="evals/fixtures/uploads/bounded-upload.pdf",
        document_type="lab_pdf",
        media_type="application/pdf",
        size_bytes=len(fixture_bytes),
        pages=1,
        sha256=hashlib.sha256(fixture_bytes).hexdigest(),
    )
    actions = _browser_actions()
    actions[3] = {
        "action_type": "upload_approved_fixture",
        "action_id": "upload-1",
        "description": "Stage an approved synthetic fixture.",
        "fixture_id": "bounded-upload",
        "upload_surface_id": "clinical_document_upload",
        "declared_media_type": "application/pdf",
    }
    fake = FakeBrowserSession()
    runner = PlaywrightAttackRunner(lambda context, trace: fake)

    evidence = await runner.execute(
        _attack(actions),
        _context(
            tmp_path,
            credentials=True,
            approved_fixtures={"bounded-upload": authorization},
        ),
    )

    assert "stage-reject:bounded-upload" in fake.events
    assert all("confirm" not in event for event in fake.events)
    assert evidence.errors == []


@pytest.mark.asyncio
async def test_composite_rejects_mixed_api_and_ui_before_running_either(tmp_path: Path) -> None:
    attack = _attack([_status_action(), _chat_action()])
    runner = CompositeAttackRunner()

    evidence = await runner.execute(attack, _context(tmp_path))

    assert evidence.executed_action_sequence[0].status == ActionExecutionStatusV1.REJECTED
    assert evidence.executed_action_sequence[1].status == ActionExecutionStatusV1.SKIPPED
    assert evidence.errors[0].code == AgentErrorCodeV1.ACTION_REJECTED
