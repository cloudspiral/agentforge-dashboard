"""Status-only HTTP runner with symbolic endpoint resolution."""

from __future__ import annotations

from collections.abc import Callable
from time import monotonic

import httpx

from agentforge.contracts.v1.actions import (
    CollectEvidenceActionV1,
    InvokeApprovedApiRequestActionV1,
    ResetSessionActionV1,
    WaitForResponseActionV1,
)
from agentforge.contracts.v1.campaign import ProposedAttackV1
from agentforge.contracts.v1.common import utc_now
from agentforge.contracts.v1.errors import AgentErrorCodeV1
from agentforge.contracts.v1.evidence import (
    ActionExecutionStatusV1,
    AttackEvidenceV1,
    SanitizedHttpExchangeV1,
)
from agentforge.security.allowlist import TargetRejected
from agentforge.target.version import resolve_endpoint, same_origin

from .base import (
    EvidenceRecorder,
    RunnerActionRejected,
    RunnerFailure,
    TargetExecutionContext,
    sanitized_summary,
)

HttpClientFactory = Callable[[TargetExecutionContext], httpx.AsyncClient]


def _default_client(context: TargetExecutionContext) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        verify=context.target_alias.verify_tls,
        timeout=httpx.Timeout(context.request_timeout_seconds),
        follow_redirects=False,
    )


class HttpAttackRunner:
    """Execute only approved health/readiness requests.

    Chat, authentication, patient selection, uploads, and UI proxy calls are
    deliberately unsupported here. They belong to the ephemeral browser runner.
    """

    def __init__(self, client_factory: HttpClientFactory | None = None) -> None:
        self._client_factory = client_factory or _default_client

    async def execute(
        self,
        attack: ProposedAttackV1,
        context: TargetExecutionContext,
    ) -> AttackEvidenceV1:
        recorder = EvidenceRecorder(context)
        try:
            async with self._client_factory(context) as client:
                for index, action in enumerate(attack.ordered_actions):
                    started_at = utc_now()
                    try:
                        summary = await self._execute_action(
                            action=action,
                            sequence_index=index,
                            client=client,
                            context=context,
                            recorder=recorder,
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
                            attack.ordered_actions[index + 1 :], start=index + 1
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
                            attack.ordered_actions[index + 1 :], start=index + 1
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
                first = attack.ordered_actions[0]
                timestamp = utc_now()
                recorder.add_action(
                    sequence_index=0,
                    action=first,
                    started_at=timestamp,
                    status=failure.status,
                    summary=failure.public_message,
                )
                recorder.add_error(failure)
                for index, action in enumerate(attack.ordered_actions[1:], start=1):
                    recorder.add_skipped(index, action)
        return recorder.finalize()

    async def _execute_action(
        self,
        *,
        action,
        sequence_index: int,
        client: httpx.AsyncClient,
        context: TargetExecutionContext,
        recorder: EvidenceRecorder,
    ) -> str:
        if isinstance(action, ResetSessionActionV1):
            if action.reset_strategy_id not in {"fresh_http_session", "fresh_ephemeral_session"}:
                raise RunnerActionRejected("HTTP reset strategy is not approved")
            return "using a newly created ephemeral HTTP client"
        if isinstance(action, InvokeApprovedApiRequestActionV1):
            return await self._invoke_status_endpoint(
                action=action,
                sequence_index=sequence_index,
                client=client,
                context=context,
                recorder=recorder,
            )
        if isinstance(action, WaitForResponseActionV1):
            return "the preceding synchronous status response was already complete"
        if isinstance(action, CollectEvidenceActionV1):
            return "sanitized HTTP metadata retained in memory"
        raise RunnerActionRejected(
            "HTTP runner supports status endpoints only; browser interaction is required"
        )

    async def _invoke_status_endpoint(
        self,
        *,
        action: InvokeApprovedApiRequestActionV1,
        sequence_index: int,
        client: httpx.AsyncClient,
        context: TargetExecutionContext,
        recorder: EvidenceRecorder,
    ) -> str:
        if action.endpoint_id not in {"status_health", "status_ready"}:
            raise RunnerActionRejected("HTTP runner endpoint alias is not status-only")
        if action.query or action.body:
            raise RunnerActionRejected("status endpoint actions cannot include query or body data")
        try:
            endpoint = resolve_endpoint(
                profile=context.profile,
                target_alias=context.target_alias,
                endpoint_id=action.endpoint_id,
                requested_method=action.method.value,
            )
        except TargetRejected as exc:
            raise RunnerActionRejected(str(exc)) from exc

        started = monotonic()
        response_status: int | None = None
        response_content_type: str | None = None
        response_size = 0
        truncated = False
        error_summary: str | None = None
        try:
            async with client.stream(
                action.method.value,
                endpoint.url,
                follow_redirects=False,
            ) as response:
                response_status = response.status_code
                response_content_type = sanitized_summary(
                    response.headers.get("content-type", "unknown")[:100],
                    fallback="unknown",
                )
                if not same_origin(str(response.url), endpoint.url):
                    raise RunnerActionRejected("status response changed target origin")
                async for chunk in response.aiter_bytes():
                    remaining = context.max_response_bytes - response_size
                    if len(chunk) > remaining:
                        response_size = context.max_response_bytes
                        truncated = True
                        break
                    response_size += len(chunk)
                if 300 <= response.status_code < 400:
                    raise RunnerActionRejected("status endpoint attempted a redirect")
        except RunnerFailure as failure:
            error_summary = failure.public_message
            raise
        except httpx.HTTPError as exc:
            failure = RunnerFailure(
                AgentErrorCodeV1.TARGET_UNREACHABLE,
                "approved status endpoint was unreachable",
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
                    response_status=response_status,
                    response_content_type=response_content_type,
                    response_size_bytes=response_size,
                    response_truncated=truncated,
                    elapsed_ms=max(0.0, (monotonic() - started) * 1_000),
                    error_summary=error_summary,
                )
            )
        suffix = " (body truncated)" if truncated else ""
        return f"approved status endpoint returned HTTP {response_status}{suffix}"


__all__ = ["HttpAttackRunner", "HttpClientFactory"]
