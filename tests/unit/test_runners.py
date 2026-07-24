from __future__ import annotations

import hashlib
import json
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from pydantic import SecretStr

from agentforge.contracts.v1 import ApprovedHttpMethodV1
from agentforge.contracts.v1.campaign import ProposedAttackV1
from agentforge.contracts.v1.errors import AgentErrorCodeV1
from agentforge.contracts.v1.evidence import (
    ActionExecutionStatusV1,
    TargetVisibleToolCallV1,
)
from agentforge.orchestration.execution_gate import (
    ApprovedFixtureV1,
    EndpointAuthenticationV1,
    EndpointBindingV1,
    EndpointPersistenceV1,
    EndpointPurposeV1,
    ValidatedAttackV1,
    proposal_sequence_hash,
)
from agentforge.runners.base import RunnerActionRejected, TargetExecutionContext
from agentforge.runners.composite import CompositeAttackRunner
from agentforge.runners.http_runner import HttpAttackRunner
from agentforge.runners.playwright_runner import (
    BrowserApiResult,
    BrowserChatResult,
    BrowserUploadResult,
    PlaywrightAttackRunner,
    SelectedPatient,
    _extract_target_visible_tool_calls,
    _LivePlaywrightSession,
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
    direct_context: bool = False,
    agent_shared_secret: SecretStr | None = None,
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
        selected_patient_alias="patient_a",
        loaded_profile=loaded,
        target_alias=alias,
        repository_root=tmp_path,
        artifacts_dir=tmp_path / "artifacts",
        credentials=resolved_credentials,
        approved_fixtures=approved_fixtures or {},
        agent_shared_secret=agent_shared_secret,
        test_user_id="42" if direct_context else None,
        test_auth_username="synthetic-admin" if direct_context else None,
        synthetic_patient_ids=({"patient_a": "7", "patient_b": "8"} if direct_context else {}),
    )


def _validated(
    attack: ProposedAttackV1,
    context: TargetExecutionContext,
    *,
    expires_at: datetime | None = None,
) -> ValidatedAttackV1:
    bindings: dict[str, EndpointBindingV1] = {}
    fixtures: list[ApprovedFixtureV1] = []
    action_types = {action.action_type.value for action in attack.ordered_actions}
    if "invoke_approved_api_request" in action_types:
        for action in attack.ordered_actions:
            if action.action_type.value != "invoke_approved_api_request":
                continue
            if action.endpoint_id == "agent_chat":
                bindings[action.endpoint_id] = EndpointBindingV1(
                    endpoint_id="agent_chat",
                    method=ApprovedHttpMethodV1.POST,
                    surface="agent_service",
                    path="/agent/chat",
                    purpose=EndpointPurposeV1.CHAT,
                    authentication=EndpointAuthenticationV1.SHARED_SECRET,
                    persistence=EndpointPersistenceV1.EPHEMERAL,
                    request_encoding="json",
                )
            elif action.endpoint_id == "copilot_chat_proxy":
                bindings[action.endpoint_id] = EndpointBindingV1(
                    endpoint_id="copilot_chat_proxy",
                    method=ApprovedHttpMethodV1.POST,
                    surface="ui",
                    path="/interface/patient_file/clinical_copilot/proxy.php",
                    purpose=EndpointPurposeV1.CHAT,
                    authentication=EndpointAuthenticationV1.BROWSER_SESSION_CSRF,
                    persistence=EndpointPersistenceV1.EPHEMERAL,
                    request_encoding="json",
                )
            elif action.endpoint_id == "document_confirm":
                bindings[action.endpoint_id] = EndpointBindingV1(
                    endpoint_id="document_confirm",
                    method=ApprovedHttpMethodV1.POST,
                    surface="ui",
                    path="/interface/patient_file/clinical_copilot/ingestion_confirm.php",
                    purpose=EndpointPurposeV1.UPLOAD_CONFIRM,
                    authentication=EndpointAuthenticationV1.BROWSER_SESSION_CSRF,
                    persistence=EndpointPersistenceV1.PERSISTENT_SYNTHETIC,
                    request_encoding="json",
                )
            else:
                bindings[action.endpoint_id] = EndpointBindingV1(
                    endpoint_id=action.endpoint_id,
                    method=ApprovedHttpMethodV1.GET,
                    surface="status",
                    path="/health",
                    purpose=EndpointPurposeV1.STATUS,
                )
    if "send_chat_message" in action_types:
        bindings["copilot_chat_proxy"] = EndpointBindingV1(
            endpoint_id="copilot_chat_proxy",
            method=ApprovedHttpMethodV1.POST,
            surface="ui",
            path="/interface/patient_file/clinical_copilot/proxy.php",
            purpose=EndpointPurposeV1.CHAT,
        )
    if "upload_approved_fixture" in action_types:
        for endpoint_id, path, purpose in (
            (
                "document_stage",
                "/interface/patient_file/clinical_copilot/ingestion_stage.php",
                EndpointPurposeV1.UPLOAD_STAGE,
            ),
            (
                "document_reject",
                "/interface/patient_file/clinical_copilot/ingestion_reject.php",
                EndpointPurposeV1.UPLOAD_REJECT,
            ),
        ):
            bindings[endpoint_id] = EndpointBindingV1(
                endpoint_id=endpoint_id,
                method=ApprovedHttpMethodV1.POST,
                surface="ui",
                path=path,
                purpose=purpose,
            )
        for authorization in context.approved_fixtures.values():
            fixtures.append(
                ApprovedFixtureV1(
                    fixture_id=authorization.fixture_id,
                    repository_relative_path=authorization.repository_relative_path,
                    document_type=authorization.document_type,
                    extension=Path(authorization.repository_relative_path).suffix,
                    media_type=authorization.media_type,
                    size_bytes=authorization.size_bytes,
                    pages=authorization.pages,
                    sha256=authorization.sha256,
                )
            )
    now = datetime.now(UTC)
    return ValidatedAttackV1(
        campaign_id=context.campaign_id,
        proposal=attack,
        target_alias=context.target_alias.name,
        target_profile_version=context.profile.profile_version,
        selected_patient_alias=context.selected_patient_alias,
        authorized_endpoint_bindings=list(bindings.values()),
        authorized_fixtures=fixtures,
        sequence_hash=proposal_sequence_hash(attack),
        authorized_at=now - timedelta(seconds=1),
        expires_at=expires_at or now + timedelta(minutes=5),
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


def _api_action(
    *,
    endpoint_id: str,
    credential_mode: str = "endpoint_default",
    correlation_mode: str = "valid",
    body: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "action_type": "invoke_approved_api_request",
        "action_id": f"api-{endpoint_id}",
        "description": "Invoke one controller-catalogued API.",
        "endpoint_id": endpoint_id,
        "method": "POST",
        "credential_mode": credential_mode,
        "correlation_mode": correlation_mode,
        "query": {},
        "body": body or {},
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

    context = _context(tmp_path)
    evidence = await runner.execute(_validated(attack, context), context)

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

    context = _context(tmp_path)
    attack = _attack([_chat_action()])
    evidence = await runner.execute(_validated(attack, context), context)

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

    context = _context(tmp_path)
    attack = _attack([_status_action()])
    evidence = await runner.execute(_validated(attack, context), context)

    assert evidence.executed_action_sequence[0].status == ActionExecutionStatusV1.REJECTED
    assert evidence.sanitized_http_metadata[0].response_status == 302


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("credential_mode", "expected_status", "expected_header"),
    [
        ("missing", 401, None),
        ("invalid", 403, "agentforge-invalid-shared-secret"),
        ("valid", 200, "controller-owned-secret"),
    ],
)
async def test_direct_agent_chat_auth_and_context_are_controller_owned(
    tmp_path: Path,
    credential_mode: str,
    expected_status: int,
    expected_header: str | None,
) -> None:
    captured: list[tuple[httpx.Request, dict[str, object]]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        captured.append((request, payload))
        header = request.headers.get("X-Agent-Shared-Secret")
        status_code = 401 if header is None else 403 if header != "controller-owned-secret" else 200
        response_payload = (
            {"detail": "authentication rejected"}
            if status_code >= 400
            else {"blocks": [{"text": "Synthetic response."}], "evidence_packet": {}}
        )
        return httpx.Response(status_code, json=response_payload, request=request)

    runner = HttpAttackRunner(
        lambda context: httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            timeout=context.request_timeout_seconds,
        )
    )
    context = _context(
        tmp_path,
        direct_context=True,
        agent_shared_secret=SecretStr("controller-owned-secret"),
    )
    attack = _attack(
        [
            _api_action(
                endpoint_id="agent_chat",
                credential_mode=credential_mode,
                correlation_mode="mismatch",
                body={
                    "message": "Bounded direct-agent request.",
                    "conversation_id": "agentforge-unit",
                    "context": {
                        "patient_alias": "patient_b",
                        "allowed_tool_names": ["get_vitals"],
                        "auth_username_claim": "synthetic-admin",
                        "user_id_claim": "42",
                    },
                },
            ),
            {
                "action_type": "collect_evidence",
                "action_id": "collect-direct",
                "description": "Collect direct API evidence.",
                "evidence_kinds": ["transcript", "http_metadata", "tool_calls"],
                "capture_on": "always",
            },
        ]
    )

    evidence = await runner.execute(_validated(attack, context), context)

    assert len(captured) == 1
    request, payload = captured[0]
    assert request.headers.get("X-Agent-Shared-Secret") == expected_header
    assert payload["context"]["patient_id"] == "8"
    assert payload["context"]["user_id"] == "42"
    assert payload["context"]["allowed_tool_names"] == ["get_vitals"]
    assert evidence.sanitized_http_metadata[0].response_status == expected_status
    assert evidence.executed_action_sequence[0].status == ActionExecutionStatusV1.SUCCEEDED
    assert "controller-owned-secret" not in evidence.model_dump_json()


@pytest.mark.asyncio
async def test_live_same_origin_api_injects_bound_patient_and_csrf(
    tmp_path: Path,
) -> None:
    captured: dict[str, object] = {}

    class FakeResponse:
        status = 200
        headers = {"content-type": "application/json"}

        async def body(self) -> bytes:
            return b'{"blocks":[{"text":"Bound response"}],"evidence_packet":{"retrievals":[]}}'

    class FakeRequestContext:
        async def fetch(self, url: str, **kwargs: object) -> FakeResponse:
            captured.update({"url": url, **kwargs})
            return FakeResponse()

    context = _context(tmp_path, credentials=True)
    session = _LivePlaywrightSession(context, False)
    session._context = SimpleNamespace(request=FakeRequestContext())
    session._selected = SelectedPatient(
        "patient_a",
        "GOLDEN-LONGITUDINAL",
        "Avery GoldenFixture",
        "7",
    )
    session._bound_csrf = "controller-bound-csrf"

    async def validate_card(*, first_binding: bool) -> None:
        assert first_binding is False

    session._bind_and_validate_card = validate_card  # type: ignore[method-assign]
    action = next(
        item
        for item in _attack(
            [
                _api_action(
                    endpoint_id="copilot_chat_proxy",
                    body={"message": "Bound same-origin request."},
                )
            ]
        ).ordered_actions
        if item.action_type.value == "invoke_approved_api_request"
    )
    binding = _validated(
        _attack(
            [
                _api_action(
                    endpoint_id="copilot_chat_proxy",
                    body={"message": "Bound same-origin request."},
                )
            ]
        ),
        context,
    ).authorized_endpoint_bindings[0]

    result = await session.invoke_same_origin_api(action, binding, 7)
    sent = json.loads(str(captured["data"]))

    assert sent["message"] == "Bound same-origin request."
    assert sent["expected_patient_id"] == "7"
    assert sent["csrf_token"] == "controller-bound-csrf"  # noqa: S105
    assert captured["headers"]["X-Correlation-ID"]
    assert result.status_code == 200
    assert result.response_text == "Bound response"


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
    def __init__(
        self,
        *,
        fail_chat: bool = False,
        target_visible_tool_calls: tuple[TargetVisibleToolCallV1, ...] = (),
        api_result: BrowserApiResult | None = None,
    ) -> None:
        self.events: list[str] = []
        self.fail_chat = fail_chat
        self.target_visible_tool_calls = target_visible_tool_calls
        self.api_result = api_result

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
        return BrowserChatResult(
            "Synthetic chart response with bounded evidence.",
            target_visible_tool_calls=self.target_visible_tool_calls,
        )

    async def stage_and_reject(
        self,
        fixture,  # type: ignore[no-untyped-def]
        timeout_seconds: float,
    ) -> BrowserUploadResult:
        self.events.append(f"stage-reject:{fixture.fixture_id}")
        assert timeout_seconds == 7
        return BrowserUploadResult("No persistent change was made.")

    async def invoke_same_origin_api(
        self,
        action,  # type: ignore[no-untyped-def]
        binding,  # type: ignore[no-untyped-def]
        timeout_seconds: float,
    ) -> BrowserApiResult:
        self.events.append(f"same-origin:{action.endpoint_id}:{binding.authentication.value}")
        assert timeout_seconds == 7
        return self.api_result or BrowserApiResult(
            status_code=200,
            content_type="application/json",
            response_size_bytes=2,
            response_truncated=False,
            elapsed_ms=1,
            response_text=None,
        )

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
    tool_call = TargetVisibleToolCallV1(
        call_id="turn-1:retrieval-1",
        tool_name="get_vitals",
        sanitized_arguments={"metrics": ["blood_pressure"], "limit": 25},
        patient_context_alias="patient_a",
    )
    fake = FakeBrowserSession(target_visible_tool_calls=(tool_call,))
    runner = PlaywrightAttackRunner(lambda context, trace: fake)

    context = _context(tmp_path, credentials=True)
    attack = _attack(_browser_actions())
    evidence = await runner.execute(_validated(attack, context), context)

    assert fake.events[:4] == [
        "enter",
        "reset:fresh_ephemeral_browser_context",
        "authenticate:physician_test",
        "select:patient_a",
    ]
    assert [turn.role.value for turn in evidence.transcript] == ["user", "assistant"]
    assert evidence.target_visible_tool_calls == [tool_call]
    assert all(
        item.status == ActionExecutionStatusV1.SUCCEEDED
        for item in evidence.executed_action_sequence
    )
    assert fake.events[-1] == "exit"


def test_extract_target_visible_tool_calls_uses_validated_proxy_metadata() -> None:
    calls = _extract_target_visible_tool_calls(
        {
            "evidence_packet": {
                "retrievals": [
                    {
                        "retrieval_id": "retrieval-1",
                        "tool_name": "get_vitals",
                        "effective_filters": [
                            {"name": "metrics", "value": ["blood_pressure"]},
                            {"name": "limit", "value": 25},
                        ],
                    }
                ]
            }
        },
        patient_alias="patient_a",
        turn_number=3,
    )

    assert len(calls) == 1
    assert calls[0].call_id == "turn-3:retrieval-1"
    assert calls[0].tool_name == "get_vitals"
    assert calls[0].sanitized_arguments == {
        "metrics": ["blood_pressure"],
        "limit": 25,
    }
    assert calls[0].patient_context_alias == "patient_a"


def test_extract_target_visible_tool_calls_rejects_unreadable_or_invalid_evidence() -> None:
    assert (
        _extract_target_visible_tool_calls(
            {"evidence_packet": None},
            patient_alias="patient_a",
            turn_number=1,
        )
        == ()
    )

    with pytest.raises(ValueError, match="evidence envelope"):
        _extract_target_visible_tool_calls(
            {"answer": "No validated target evidence."},
            patient_alias="patient_a",
            turn_number=1,
        )
    with pytest.raises(ValueError, match="filter entry"):
        _extract_target_visible_tool_calls(
            {
                "evidence_packet": {
                    "retrievals": [
                        {
                            "retrieval_id": "retrieval-1",
                            "tool_name": "get_vitals",
                            "effective_filters": [{"name": "limit"}],
                        }
                    ]
                }
            },
            patient_alias="patient_a",
            turn_number=1,
        )


@pytest.mark.asyncio
async def test_playwright_failure_capture_skips_later_actions_without_state_persistence(
    tmp_path: Path,
) -> None:
    fake = FakeBrowserSession(fail_chat=True)
    runner = PlaywrightAttackRunner(lambda context, trace: fake)

    context = _context(tmp_path, credentials=True)
    attack = _attack(_browser_actions(failure_capture=True))
    evidence = await runner.execute(_validated(attack, context), context)

    assert evidence.executed_action_sequence[3].status == ActionExecutionStatusV1.REJECTED
    assert evidence.executed_action_sequence[4].status == ActionExecutionStatusV1.SKIPPED
    assert evidence.executed_action_sequence[5].status == ActionExecutionStatusV1.SKIPPED
    assert "screenshot:failure-screenshot.png" in fake.events
    assert "trace:failure-trace.zip" in fake.events
    assert not hasattr(evidence, "artifact_references")


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

    context = _context(
        tmp_path,
        credentials=True,
        approved_fixtures={"bounded-upload": authorization},
    )
    attack = _attack(actions)
    evidence = await runner.execute(_validated(attack, context), context)

    assert "stage-reject:bounded-upload" in fake.events
    assert all("confirm" not in event for event in fake.events)
    assert evidence.errors == []


@pytest.mark.asyncio
async def test_persistent_same_origin_result_is_labeled_with_returned_synthetic_id(
    tmp_path: Path,
) -> None:
    actions = _browser_actions()
    actions[3] = _api_action(
        endpoint_id="document_confirm",
        body={"staging_token": "approved-synthetic-token"},
    )
    fake = FakeBrowserSession(
        api_result=BrowserApiResult(
            status_code=200,
            content_type="application/json",
            response_size_bytes=32,
            response_truncated=False,
            elapsed_ms=2,
            response_text="Synthetic confirmation accepted.",
            synthetic_artifact_reference="document_id=AF-SYNTHETIC-1",
        )
    )
    runner = PlaywrightAttackRunner(lambda context, trace: fake)
    context = _context(tmp_path, credentials=True)
    attack = _attack(actions)

    evidence = await runner.execute(_validated(attack, context), context)

    assert evidence.errors == []
    assert len(evidence.side_effects) == 1
    assert evidence.side_effects[0].effect_type == "retained_synthetic_artifact"
    assert "document_id=AF-SYNTHETIC-1" in evidence.side_effects[0].description
    assert "same-origin:document_confirm:browser_session_csrf" in fake.events


@pytest.mark.asyncio
async def test_composite_rejects_mixed_api_and_ui_before_running_either(tmp_path: Path) -> None:
    attack = _attack([_status_action(), _chat_action()])
    runner = CompositeAttackRunner()

    context = _context(tmp_path)
    evidence = await runner.execute(_validated(attack, context), context)

    assert evidence.executed_action_sequence[0].status == ActionExecutionStatusV1.REJECTED
    assert evidence.executed_action_sequence[1].status == ActionExecutionStatusV1.SKIPPED
    assert evidence.errors[0].code == AgentErrorCodeV1.ACTION_REJECTED


@pytest.mark.asyncio
async def test_runner_rejects_raw_expired_and_mismatched_envelopes_before_adapter(
    tmp_path: Path,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, request=request)

    runner = HttpAttackRunner(
        lambda context: httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    context = _context(tmp_path)
    attack = _attack([_status_action()])

    with pytest.raises(RunnerActionRejected, match="gate-approved"):
        await runner.execute(attack, context)  # type: ignore[arg-type]

    expired = _validated(
        attack,
        context,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    with pytest.raises(RunnerActionRejected, match="not active"):
        await runner.execute(expired, context)

    mismatch = _validated(attack, context).model_copy(update={"campaign_id": "other-campaign"})
    with pytest.raises(RunnerActionRejected, match="campaign"):
        await runner.execute(mismatch, context)
    assert requests == []
