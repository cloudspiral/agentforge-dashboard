from __future__ import annotations

import logging
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager, suppress
from functools import lru_cache
from threading import Lock
from typing import Any, Literal

from langfuse import Langfuse, propagate_attributes
from openinference.instrumentation import TraceConfig
from openinference.instrumentation.openai_agents import OpenAIAgentsInstrumentor

from agentforge.settings import Settings, get_settings

from .tracing import (
    ObservationHandle,
    _reset_current_trace_id,
    _set_current_trace_id,
    current_trace_id,
    iter_required_metadata,
    normalize_metadata,
    normalize_tags,
    redact_for_telemetry,
)

LOGGER = logging.getLogger(__name__)

_INSTRUMENTATION_LOCK = Lock()
_AGENTS_INSTRUMENTED = False
_AGENTS_INSTRUMENTOR: Any = None

ObservationType = Literal[
    "span",
    "agent",
    "tool",
    "chain",
    "retriever",
    "evaluator",
    "guardrail",
]


def _instrument_agents_once(instrumentor_factory: Callable[[], Any]) -> bool:
    """Install the process-global OpenAI Agents trace processor at most once."""

    global _AGENTS_INSTRUMENTED, _AGENTS_INSTRUMENTOR

    with _INSTRUMENTATION_LOCK:
        if _AGENTS_INSTRUMENTED:
            return False

        instrumentor = instrumentor_factory()
        already_instrumented = bool(
            getattr(instrumentor, "is_instrumented_by_opentelemetry", False)
        )
        if not already_instrumented:
            instrumentor.instrument(
                exclusive_processor=True,
                config=TraceConfig(
                    hide_llm_invocation_parameters=True,
                    hide_llm_tools=True,
                    hide_inputs=True,
                    hide_outputs=True,
                ),
            )

        _AGENTS_INSTRUMENTOR = instrumentor
        _AGENTS_INSTRUMENTED = True
        return not already_instrumented


class LangfuseTelemetry:
    """Failure-isolated Langfuse/OpenAI Agents observability adapter."""

    def __init__(
        self,
        *,
        client: Any | None,
        enabled: bool,
        disabled_reason: str | None,
        environment: str,
    ) -> None:
        self._client = client
        self._enabled = enabled
        self._disabled_reason = disabled_reason
        self._environment = environment
        self._closed = False
        self._lifecycle_lock = Lock()

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        client_factory: Callable[..., Any] = Langfuse,
        instrumentor_factory: Callable[[], Any] = OpenAIAgentsInstrumentor,
    ) -> LangfuseTelemetry:
        if not settings.langfuse_enabled:
            return cls(
                client=None,
                enabled=False,
                disabled_reason="disabled_by_config",
                environment=settings.environment,
            )
        if not settings.has_langfuse_credentials:
            return cls(
                client=None,
                enabled=False,
                disabled_reason="missing_credentials",
                environment=settings.environment,
            )

        public_key = settings.langfuse_public_key
        secret_key = settings.langfuse_secret_key
        if public_key is None or secret_key is None:  # narrowed above; defensive for type checking
            return cls(
                client=None,
                enabled=False,
                disabled_reason="missing_credentials",
                environment=settings.environment,
            )

        client: Any | None = None
        try:
            client = client_factory(
                public_key=public_key.get_secret_value(),
                secret_key=secret_key.get_secret_value(),
                base_url=settings.langfuse_base_url,
                environment=settings.environment,
                mask=redact_for_telemetry,
                tracing_enabled=True,
            )
            _instrument_agents_once(instrumentor_factory)
        except Exception as exc:
            LOGGER.warning("Langfuse initialization failed (%s)", type(exc).__name__)
            if client is not None:
                with suppress(Exception):
                    client.shutdown()
            return cls(
                client=None,
                enabled=False,
                disabled_reason="initialization_failed",
                environment=settings.environment,
            )

        return cls(
            client=client,
            enabled=True,
            disabled_reason=None,
            environment=settings.environment,
        )

    @property
    def enabled(self) -> bool:
        return self._enabled and not self._closed and self._client is not None

    @property
    def disabled_reason(self) -> str | None:
        if self._closed:
            return "shutdown"
        return self._disabled_reason

    @property
    def current_trace_id(self) -> str | None:
        contextual = current_trace_id()
        if contextual is not None:
            return contextual
        if not self.enabled:
            return None
        try:
            trace_id = self._client.get_current_trace_id()
        except Exception as exc:
            LOGGER.warning("Langfuse trace ID lookup failed (%s)", type(exc).__name__)
            return None
        return str(trace_id) if trace_id else None

    @contextmanager
    def campaign(
        self,
        *,
        campaign_id: str,
        campaign_type: str | None = None,
        category: str | None = None,
        target_version: str | None = None,
        prompt_version: str | None = None,
        model: str | None = None,
        input: Any = None,
        metadata: Mapping[str, Any] | None = None,
        tags: Sequence[str] | None = None,
    ) -> Iterator[ObservationHandle]:
        required = dict(
            iter_required_metadata(
                campaign_id=str(campaign_id),
                category=category,
                target_version=target_version,
                prompt_version=prompt_version,
                model=model,
            )
        )
        if campaign_type is not None:
            required["campaignType"] = campaign_type
        combined_metadata = {**dict(metadata or {}), **required}
        campaign_tags = normalize_tags(
            ["agentforge", self._environment, *(tags or ()), *([category] if category else [])]
        )
        with self._observation(
            name="agentforge.campaign",
            as_type="agent",
            input=input,
            metadata=combined_metadata,
            propagated_metadata=combined_metadata,
            tags=campaign_tags,
            version=prompt_version,
            trace_name="AgentForge campaign",
            session_id=str(campaign_id),
        ) as handle:
            yield handle

    @contextmanager
    def attempt(
        self,
        *,
        campaign_id: str,
        attempt_id: str,
        agent_role: str | None = None,
        category: str | None = None,
        target_version: str | None = None,
        prompt_version: str | None = None,
        model: str | None = None,
        input: Any = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Iterator[ObservationHandle]:
        required = dict(
            iter_required_metadata(
                campaign_id=str(campaign_id),
                attempt_id=str(attempt_id),
                agent_role=agent_role,
                category=category,
                target_version=target_version,
                prompt_version=prompt_version,
                model=model,
            )
        )
        combined_metadata = {**dict(metadata or {}), **required}
        with self._observation(
            name="agentforge.attempt",
            as_type="chain",
            input=input,
            metadata=combined_metadata,
            propagated_metadata=combined_metadata,
            tags=normalize_tags([category] if category else []),
            version=prompt_version,
        ) as handle:
            yield handle

    @contextmanager
    def agent_scope(
        self,
        *,
        campaign_id: str,
        attempt_id: str,
        agent_role: str,
        category: str | None = None,
        target_version: str | None = None,
        prompt_version: str | None = None,
        model: str | None = None,
    ) -> Iterator[ObservationHandle]:
        """Create a role root span before automatic Agents SDK observations begin."""

        metadata = dict(
            iter_required_metadata(
                campaign_id=str(campaign_id),
                attempt_id=str(attempt_id),
                agent_role=agent_role,
                category=category,
                target_version=target_version,
                prompt_version=prompt_version,
                model=model,
            )
        )
        with self._observation(
            name=f"agentforge.{agent_role}",
            as_type="agent",
            metadata=metadata,
            propagated_metadata=metadata,
            tags=normalize_tags([agent_role]),
            version=prompt_version,
            trace_name=f"AgentForge {agent_role}",
        ) as handle:
            yield handle

    @contextmanager
    def runner(
        self,
        *,
        campaign_id: str,
        attempt_id: str,
        transport: str,
        input: Any = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Iterator[ObservationHandle]:
        combined_metadata = {
            **dict(metadata or {}),
            "campaignId": str(campaign_id),
            "attemptId": str(attempt_id),
            "transport": transport,
        }
        with self._observation(
            name="agentforge.runner",
            as_type="tool",
            input=input,
            metadata=combined_metadata,
            propagated_metadata=combined_metadata,
            tags=normalize_tags([transport]),
        ) as handle:
            yield handle

    @contextmanager
    def _observation(
        self,
        *,
        name: str,
        as_type: ObservationType,
        input: Any = None,
        metadata: Mapping[str, Any] | None = None,
        propagated_metadata: Mapping[str, Any] | None = None,
        tags: Sequence[str] | None = None,
        version: str | None = None,
        trace_name: str | None = None,
        session_id: str | None = None,
    ) -> Iterator[ObservationHandle]:
        if not self.enabled:
            yield ObservationHandle(trace_id=None)
            return

        stack = ExitStack()
        try:
            observation = stack.enter_context(
                self._client.start_as_current_observation(
                    name=name,
                    as_type=as_type,
                    input=redact_for_telemetry(input),
                    metadata=redact_for_telemetry(metadata or {}),
                    version=version,
                )
            )
            stack.enter_context(
                propagate_attributes(
                    session_id=session_id,
                    metadata=normalize_metadata(propagated_metadata),
                    version=version,
                    tags=normalize_tags(tags),
                    trace_name=trace_name,
                )
            )
        except Exception as exc:
            LOGGER.warning("Langfuse observation start failed (%s)", type(exc).__name__)
            with suppress(Exception):
                stack.close()
            yield ObservationHandle(trace_id=None)
            return

        trace_id = self.current_trace_id
        if trace_id is None:
            observation_trace_id = getattr(observation, "trace_id", None)
            trace_id = str(observation_trace_id) if observation_trace_id else None
        token = _set_current_trace_id(trace_id)
        handle = ObservationHandle(trace_id=trace_id, _observation=observation)
        try:
            yield handle
        except BaseException as exc:
            handle.record_exception(exc)
            raise
        finally:
            _reset_current_trace_id(token)
            try:
                stack.close()
            except Exception as exc:
                LOGGER.warning("Langfuse observation cleanup failed (%s)", type(exc).__name__)

    def flush(self) -> bool:
        if not self.enabled:
            return False
        try:
            self._client.flush()
        except Exception as exc:
            LOGGER.warning("Langfuse flush failed (%s)", type(exc).__name__)
            return False
        return True

    def shutdown(self) -> bool:
        with self._lifecycle_lock:
            if self._closed:
                return False
            self._closed = True

        if self._client is None:
            return False
        try:
            self._client.shutdown()
        except Exception as exc:
            LOGGER.warning("Langfuse shutdown failed (%s)", type(exc).__name__)
            return False
        return True


@lru_cache(maxsize=1)
def get_telemetry() -> LangfuseTelemetry:
    return LangfuseTelemetry.from_settings(get_settings())
