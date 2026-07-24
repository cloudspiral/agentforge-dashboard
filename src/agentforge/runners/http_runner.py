"""Bounded direct runner for controller-catalogued Agent Service APIs."""

from __future__ import annotations

import json
from collections.abc import Callable
from time import monotonic
from typing import Any
from uuid import uuid4

import httpx

from agentforge.contracts.v1.actions import (
    AuthenticateActionV1,
    CollectEvidenceActionV1,
    InvokeApprovedApiRequestActionV1,
    ResetSessionActionV1,
    SelectSyntheticPatientActionV1,
    WaitForResponseActionV1,
)
from agentforge.contracts.v1.common import utc_now
from agentforge.contracts.v1.errors import AgentErrorCodeV1
from agentforge.contracts.v1.evidence import (
    ActionExecutionStatusV1,
    AttackEvidenceV1,
    SanitizedHttpExchangeV1,
    SideEffectV1,
    TargetVisibleToolCallV1,
    TranscriptRoleV1,
)
from agentforge.orchestration.execution_gate import (
    EndpointAuthenticationV1,
    EndpointBindingV1,
    EndpointPersistenceV1,
    ValidatedAttackV1,
)
from agentforge.security.allowlist import TargetRejected
from agentforge.target.version import resolve_endpoint, same_origin

from .base import (
    EvidenceRecorder,
    RunnerActionRejected,
    RunnerFailure,
    TargetExecutionContext,
    require_validated_attack,
    sanitized_summary,
    synthetic_artifact_reference,
)

HttpClientFactory = Callable[[TargetExecutionContext], httpx.AsyncClient]

_DIRECT_BODY_KEYS = {"message", "conversation_id", "context", "agentforge_unexpected"}
_DIRECT_CONTEXT_KEYS = {
    "patient_alias",
    "allowed_tool_names",
    "auth_username_claim",
    "note_author_scope",
    "authorization_version",
    "user_id_claim",
    "patient_display_name_claim",
}


def _default_client(context: TargetExecutionContext) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        verify=context.target_alias.verify_tls,
        timeout=httpx.Timeout(context.request_timeout_seconds),
        follow_redirects=False,
        trust_env=False,
    )


def _correlation_values(mode: str) -> tuple[str | None, str]:
    body_value = str(uuid4())
    if mode == "valid":
        return body_value, body_value
    if mode == "missing":
        return None, body_value
    if mode == "invalid":
        return "agentforge-invalid-correlation", body_value
    if mode == "mismatch":
        return str(uuid4()), body_value
    raise RunnerActionRejected("unsupported correlation test mode")


def _direct_context(
    symbolic: object,
    *,
    context: TargetExecutionContext,
    correlation_id: str,
) -> object:
    """Expand only bounded aliases; raw model-supplied authority is never accepted."""

    if not isinstance(symbolic, dict):
        return symbolic
    unknown = set(symbolic) - _DIRECT_CONTEXT_KEYS
    if unknown:
        raise RunnerActionRejected("direct-agent context contains an unsupported mutation key")
    patient_alias = symbolic.get("patient_alias", context.selected_patient_alias)
    if patient_alias not in {"patient_a", "patient_b"}:
        raise RunnerActionRejected("direct-agent context uses an unknown synthetic patient alias")
    patient_id = context.synthetic_patient_ids.get(patient_alias)
    if patient_id is None:
        raise RunnerActionRejected(
            "direct-agent execution lacks the configured numeric synthetic patient ID"
        )
    if context.test_user_id is None or context.test_auth_username is None:
        raise RunnerActionRejected(
            "direct-agent execution lacks the configured synthetic test-user context"
        )

    requested_tools = symbolic.get(
        "allowed_tool_names",
        list(context.profile.known_read_only_tools),
    )
    if not isinstance(requested_tools, list) or any(
        not isinstance(item, str) for item in requested_tools
    ):
        raise RunnerActionRejected("direct-agent tool allowlist mutation must be a string list")
    if len(requested_tools) != len(set(requested_tools)) or any(
        item not in context.profile.known_read_only_tools for item in requested_tools
    ):
        raise RunnerActionRejected("direct-agent tool mutation leaves the controller allowlist")

    auth_username = symbolic.get("auth_username_claim", context.test_auth_username)
    if auth_username != context.test_auth_username:
        raise RunnerActionRejected("direct-agent username claim is outside the test identity")
    user_id = symbolic.get("user_id_claim", context.test_user_id)
    if user_id != context.test_user_id:
        raise RunnerActionRejected("direct-agent user ID claim is outside the test identity")
    display_name = symbolic.get(
        "patient_display_name_claim",
        getattr(context.profile.patients, patient_alias).display_name,
    )
    if not isinstance(display_name, str) or not display_name.strip():
        raise RunnerActionRejected("direct-agent patient display-name claim is invalid")
    note_scope = symbolic.get("note_author_scope", "own")
    if note_scope not in {"all", "own", "none"}:
        raise RunnerActionRejected("direct-agent note-author scope mutation is unsupported")
    authorization_version = symbolic.get("authorization_version", 1)
    if authorization_version != 1:
        raise RunnerActionRejected("direct-agent authorization version must remain supported")
    return {
        "user_id": context.test_user_id,
        "patient_id": patient_id,
        "patient_display_name": display_name[:512],
        "openemr_timezone": "UTC",
        "authorization_version": 1,
        "allowed_tool_names": requested_tools,
        "auth_username": context.test_auth_username,
        "note_author_scope": note_scope,
        "authorized_note_form_directories": [],
        "authorized_appointment_category_ids": [],
        "appointment_scope_truncated": False,
        "authorized_document_ids": [],
        "document_scope_truncated": False,
        "encounter_id": None,
        "authorized_encounter_ids": [],
        "encounter_scope_truncated": False,
        "correlation_id": correlation_id,
    }


def _request_body(
    action: InvokeApprovedApiRequestActionV1,
    binding: EndpointBindingV1,
    *,
    context: TargetExecutionContext,
    body_correlation_id: str,
) -> dict[str, Any]:
    body = dict(action.body)
    if binding.endpoint_id != "agent_chat":
        return body
    unknown = set(body) - _DIRECT_BODY_KEYS
    if unknown and unknown != {"agentforge_unexpected"}:
        raise RunnerActionRejected("direct-agent request contains an unsupported body key")
    if "context" in body:
        body["context"] = _direct_context(
            body["context"],
            context=context,
            correlation_id=body_correlation_id,
        )
    return body


def _response_summary(
    *,
    binding: EndpointBindingV1,
    status_code: int,
    raw: bytes,
    recorder: EvidenceRecorder,
    patient_alias: str,
) -> str:
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return f"approved endpoint returned HTTP {status_code} with a non-JSON body"
    if not isinstance(payload, dict):
        return f"approved endpoint returned HTTP {status_code} with a JSON response"
    if binding.endpoint_id == "agent_chat" and status_code < 400:
        blocks = payload.get("blocks")
        text_parts = (
            [
                item["text"]
                for item in blocks
                if isinstance(item, dict) and isinstance(item.get("text"), str)
            ]
            if isinstance(blocks, list)
            else []
        )
        if text_parts:
            recorder.add_transcript(TranscriptRoleV1.ASSISTANT, "\n\n".join(text_parts)[:20_000])
        packet = payload.get("evidence_packet")
        retrievals = packet.get("retrievals") if isinstance(packet, dict) else []
        if isinstance(retrievals, list):
            for index, retrieval in enumerate(retrievals[:100]):
                if not isinstance(retrieval, dict):
                    continue
                tool_name = retrieval.get("tool_name")
                filters = retrieval.get("effective_filters")
                if not isinstance(tool_name, str) or not isinstance(filters, list):
                    continue
                arguments = {
                    str(item["name"]): item["value"]
                    for item in filters
                    if isinstance(item, dict)
                    and set(item) == {"name", "value"}
                    and isinstance(item.get("name"), str)
                }
                recorder.add_target_visible_tool_call(
                    TargetVisibleToolCallV1(
                        call_id=f"direct-{index}",
                        tool_name=tool_name,
                        sanitized_arguments=arguments,
                        patient_context_alias=patient_alias,
                    )
                )
        return f"direct Agent Service chat returned HTTP {status_code}"
    detail = payload.get("detail")
    if isinstance(detail, str):
        recorder.add_transcript(
            TranscriptRoleV1.SYSTEM,
            f"Target endpoint response: {sanitized_summary(detail)}",
        )
    return f"approved endpoint returned HTTP {status_code}"


class HttpAttackRunner:
    """Execute catalogued direct APIs without exposing controller-owned credentials."""

    def __init__(self, client_factory: HttpClientFactory | None = None) -> None:
        self._client_factory = client_factory or _default_client

    async def execute(
        self,
        attack: ValidatedAttackV1,
        context: TargetExecutionContext,
    ) -> AttackEvidenceV1:
        proposal = require_validated_attack(attack, context)
        bindings = {binding.endpoint_id: binding for binding in attack.authorized_endpoint_bindings}
        recorder = EvidenceRecorder(context)
        try:
            async with self._client_factory(context) as client:
                for index, action in enumerate(proposal.ordered_actions):
                    started_at = utc_now()
                    try:
                        summary = await self._execute_action(
                            action=action,
                            sequence_index=index,
                            client=client,
                            context=context,
                            recorder=recorder,
                            bindings=bindings,
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
                        for skipped_index, skipped in enumerate(
                            proposal.ordered_actions[index + 1 :],
                            start=index + 1,
                        ):
                            recorder.add_skipped(skipped_index, skipped)
                        break
                    except Exception:
                        failure = RunnerFailure(
                            AgentErrorCodeV1.UNEXPECTED_INTERNAL_ERROR,
                            "HTTP runner encountered an unexpected internal error",
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
                            proposal.ordered_actions[index + 1 :],
                            start=index + 1,
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
                    "HTTP runner could not initialize an ephemeral target session",
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
        action: object,
        sequence_index: int,
        client: httpx.AsyncClient,
        context: TargetExecutionContext,
        recorder: EvidenceRecorder,
        bindings: dict[str, EndpointBindingV1],
    ) -> str:
        if isinstance(action, ResetSessionActionV1):
            if action.reset_strategy_id != context.profile.reset.conversation:
                raise RunnerActionRejected("HTTP reset strategy is not profile-owned")
            return "new ephemeral HTTP client bound to the approved target alias"
        if isinstance(action, AuthenticateActionV1):
            return "controller-owned direct API credential policy loaded"
        if isinstance(action, SelectSyntheticPatientActionV1):
            if action.patient_alias != context.selected_patient_alias:
                raise RunnerActionRejected("direct API patient alias changed after authorization")
            return "controller-owned synthetic patient alias bound for direct API context"
        if isinstance(action, InvokeApprovedApiRequestActionV1):
            binding = bindings.get(action.endpoint_id)
            if binding is None:
                raise RunnerActionRejected("approved API binding is missing from the envelope")
            return await self._invoke_endpoint(
                action=action,
                binding=binding,
                sequence_index=sequence_index,
                client=client,
                context=context,
                recorder=recorder,
            )
        if isinstance(action, WaitForResponseActionV1):
            return "the preceding synchronous API response was already complete"
        if isinstance(action, CollectEvidenceActionV1):
            return "sanitized HTTP metadata and bounded response evidence retained in memory"
        raise RunnerActionRejected("HTTP runner supports only controller-catalogued API sequences")

    async def _invoke_endpoint(
        self,
        *,
        action: InvokeApprovedApiRequestActionV1,
        binding: EndpointBindingV1,
        sequence_index: int,
        client: httpx.AsyncClient,
        context: TargetExecutionContext,
        recorder: EvidenceRecorder,
    ) -> str:
        if binding.surface == "ui":
            raise RunnerActionRejected("same-origin session endpoints require the browser runner")
        try:
            endpoint = resolve_endpoint(
                profile=context.profile,
                target_alias=context.target_alias,
                endpoint_id=action.endpoint_id,
                requested_method=action.method.value,
            )
        except TargetRejected as exc:
            raise RunnerActionRejected(str(exc)) from exc

        headers: dict[str, str] = {}
        header_correlation, body_correlation = _correlation_values(action.correlation_mode)
        if header_correlation is not None:
            headers["X-Correlation-ID"] = header_correlation
        auth_mode = action.credential_mode
        if binding.authentication == EndpointAuthenticationV1.SHARED_SECRET:
            if auth_mode == "endpoint_default":
                auth_mode = "valid"
            if auth_mode == "valid":
                if context.agent_shared_secret is None:
                    raise RunnerActionRejected(
                        "valid direct-agent authentication lacks its controller-owned secret"
                    )
                headers["X-Agent-Shared-Secret"] = context.agent_shared_secret.get_secret_value()
            elif auth_mode == "invalid":
                headers["X-Agent-Shared-Secret"] = "agentforge-invalid-shared-secret"
            elif auth_mode != "missing":
                raise RunnerActionRejected("unsupported direct-agent credential mode")
        elif auth_mode != "endpoint_default":
            raise RunnerActionRejected("credential test mode is invalid for this endpoint")

        body = _request_body(
            action,
            binding,
            context=context,
            body_correlation_id=body_correlation,
        )
        if binding.endpoint_id == "agent_chat" and isinstance(body.get("message"), str):
            recorder.add_transcript(TranscriptRoleV1.USER, str(body["message"]))
        request_kwargs: dict[str, Any] = {
            "params": action.query,
            "headers": headers,
            "follow_redirects": False,
        }
        if action.method.value == "POST":
            # Multipart routes are still contacted with a bounded JSON body when no
            # approved fixture is present; their 4xx schema response is executable evidence.
            request_kwargs["json"] = body

        started = monotonic()
        response_status: int | None = None
        response_content_type: str | None = None
        response_size = 0
        truncated = False
        error_summary: str | None = None
        raw = bytearray()
        try:
            async with client.stream(
                action.method.value,
                endpoint.url,
                **request_kwargs,
            ) as response:
                response_status = response.status_code
                response_content_type = sanitized_summary(
                    response.headers.get("content-type", "unknown")[:100],
                    fallback="unknown",
                )
                if not same_origin(str(response.url), endpoint.url):
                    raise RunnerActionRejected("API response changed target origin")
                async for chunk in response.aiter_bytes():
                    remaining = context.max_response_bytes - len(raw)
                    if len(chunk) > remaining:
                        raw.extend(chunk[:remaining])
                        truncated = True
                        break
                    raw.extend(chunk)
                response_size = len(raw)
                if 300 <= response.status_code < 400:
                    raise RunnerActionRejected("API endpoint attempted a redirect")
                summary = _response_summary(
                    binding=binding,
                    status_code=response.status_code,
                    raw=bytes(raw),
                    recorder=recorder,
                    patient_alias=context.selected_patient_alias,
                )
                if (
                    binding.persistence == EndpointPersistenceV1.PERSISTENT_SYNTHETIC
                    and 200 <= response.status_code < 300
                ):
                    try:
                        persistent_payload = json.loads(bytes(raw))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        persistent_payload = None
                    reference = synthetic_artifact_reference(persistent_payload)
                    recorder.add_side_effect(
                        SideEffectV1(
                            effect_id=f"persistent-{sequence_index}",
                            effect_type="retained_synthetic_artifact",
                            description=(
                                "One approved synthetic target artifact may have been retained; "
                                "the exact endpoint exchange is auditable"
                                + (
                                    f" as {reference}."
                                    if reference is not None
                                    else " without a returned artifact identifier."
                                )
                            ),
                            observed=True,
                        )
                    )
        except RunnerFailure as failure:
            error_summary = failure.public_message
            raise
        except httpx.HTTPError as exc:
            failure = RunnerFailure(
                AgentErrorCodeV1.TARGET_UNREACHABLE,
                "approved API endpoint was unreachable",
                retryable=True,
            )
            error_summary = failure.public_message
            raise failure from exc
        finally:
            recorder.add_http(
                SanitizedHttpExchangeV1(
                    exchange_id=f"http-{sequence_index}",
                    method=action.method,
                    endpoint_id=action.endpoint_id,
                    surface=binding.surface,
                    request_auth_mode=auth_mode,
                    correlation_mode=action.correlation_mode,
                    response_status=response_status,
                    response_content_type=response_content_type,
                    response_size_bytes=response_size,
                    response_truncated=truncated,
                    elapsed_ms=max(0.0, (monotonic() - started) * 1_000),
                    error_summary=error_summary,
                )
            )
        suffix = " (body truncated)" if truncated else ""
        return f"{summary}{suffix}"


__all__ = ["HttpAttackRunner", "HttpClientFactory"]
