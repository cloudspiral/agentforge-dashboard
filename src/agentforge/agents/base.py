"""Bounded OpenAI Agents SDK adapter shared by AgentForge's four model roles.

This module intentionally exposes proposal/evaluation capability only.  Agents
receive one compact JSON value and return one declared Pydantic contract; they
have no tools, handoffs, MCP servers, target credentials, or execution authority.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import AbstractContextManager, ExitStack
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from time import perf_counter
from typing import Any, Protocol
from uuid import UUID, uuid4

import yaml
from agents import (
    Agent,
    ModelRetrySettings,
    ModelSettings,
    RunConfig,
    Runner,
    gen_trace_id,
)
from agents import (
    trace as sdk_trace,
)
from agents.exceptions import MaxTurnsExceeded, ModelBehaviorError, ModelRefusalError
from agents.models.openai_provider import OpenAIProvider
from openai import APIConnectionError, APIStatusError, APITimeoutError, AsyncOpenAI
from openai.types.shared_params import Reasoning
from pydantic import BaseModel, SecretStr, ValidationError

from agentforge.contracts.v1 import AgentErrorCodeV1, AgentErrorV1, TokenUsageV1
from agentforge.contracts.v1.common import SCHEMA_VERSION_V1, utc_now
from agentforge.observability import get_telemetry, redact_for_telemetry
from agentforge.settings import Settings, get_settings

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MAX_INPUT_CHARACTERS = 32_000
DEFAULT_MAX_RETRIES = 2
DEFAULT_BASE_BACKOFF_SECONDS = 0.25
DEFAULT_MAX_BACKOFF_SECONDS = 2.0

_FRONT_MATTER_BOUNDARY = "---"
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SENSITIVE_INPUT_KEY = re.compile(
    r"(?:authorization|cookie|password|passwd|secret|api[_-]?key|credential|"
    r"(?:access|auth|bearer|csrf|refresh|session)[_-]?token)",
    re.IGNORECASE,
)
_DEFAULT_TELEMETRY = object()


class RunnerLike(Protocol):
    """Narrow Runner seam used by unit tests and alternate SDK transports."""

    async def run(
        self,
        starting_agent: Agent[Any],
        input: str,
        *,
        max_turns: int | None = 10,
        run_config: RunConfig | None = None,
    ) -> Any: ...


class TelemetryLike(Protocol):
    """Subset of the Langfuse adapter needed for nested agent observations."""

    @property
    def enabled(self) -> bool: ...

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
    ) -> AbstractContextManager[Any]: ...


TraceFactory = Callable[..., AbstractContextManager[Any]]
SleepCallable = Callable[[float], Awaitable[None]]
JitterCallable = Callable[[], float]


@dataclass(frozen=True, slots=True)
class VersionedPrompt:
    """Prompt body plus immutable source identity used in run records."""

    path: Path
    version: str
    content: str
    sha256: str


@dataclass(frozen=True, slots=True)
class ModelPrice:
    """USD prices for one million tokens in each billed token class."""

    input: float
    cached_input: float
    cache_write: float
    output: float


@dataclass(frozen=True, slots=True)
class PricingCatalog:
    """Validated model prices loaded from the repository's versioned YAML file."""

    models: Mapping[str, ModelPrice]
    source: str
    verified_at: str

    @classmethod
    def from_yaml(cls, path: Path | str) -> PricingCatalog:
        resolved = resolve_project_path(path)
        try:
            document = yaml.safe_load(resolved.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ValueError(f"unable to load pricing catalog: {resolved}") from exc

        if not isinstance(document, Mapping):
            raise ValueError("pricing catalog must be a YAML mapping")
        if document.get("unit") != "per_1m_tokens" or document.get("currency") != "USD":
            raise ValueError("pricing catalog must use USD per_1m_tokens")

        raw_models = document.get("models")
        if not isinstance(raw_models, Mapping) or not raw_models:
            raise ValueError("pricing catalog must define at least one model")

        models: dict[str, ModelPrice] = {}
        for raw_name, raw_price in raw_models.items():
            if not isinstance(raw_name, str) or not raw_name:
                raise ValueError("pricing model names must be non-empty strings")
            if not isinstance(raw_price, Mapping):
                raise ValueError(f"pricing for {raw_name} must be a mapping")
            models[raw_name] = ModelPrice(
                input=_non_negative_price(raw_price.get("input"), raw_name, "input"),
                cached_input=_non_negative_price(
                    raw_price.get("cached_input"), raw_name, "cached_input"
                ),
                cache_write=_non_negative_price(
                    raw_price.get("cache_write"), raw_name, "cache_write"
                ),
                output=_non_negative_price(raw_price.get("output"), raw_name, "output"),
            )

        return cls(
            models=models,
            source=str(document.get("source", "unknown")),
            verified_at=str(document.get("verified_at", "unknown")),
        )

    def price_for(self, model: str) -> ModelPrice:
        try:
            return self.models[model]
        except KeyError as exc:
            # The repository policy says unknown prices reject a live call.  A
            # guessed dollar value would undermine the controller's budget gate.
            raise ValueError(f"model has no verified pricing entry: {model}") from exc

    def estimate_cost(self, model: str, usage: AgentUsage) -> float:
        price = self.price_for(model)
        uncached_input = max(
            0,
            usage.tokens.input_tokens
            - usage.tokens.cached_input_tokens
            - usage.cache_write_input_tokens,
        )
        million = 1_000_000
        total = (
            uncached_input * price.input
            + usage.tokens.cached_input_tokens * price.cached_input
            + usage.cache_write_input_tokens * price.cache_write
            + usage.tokens.output_tokens * price.output
        ) / million
        return round(total, 12)


@dataclass(frozen=True, slots=True)
class AgentUsage:
    """Normalized SDK usage, including details not present in TokenUsageV1."""

    tokens: TokenUsageV1
    cache_write_input_tokens: int = 0
    reasoning_output_tokens: int = 0

    @classmethod
    def zero(cls) -> AgentUsage:
        return cls(tokens=TokenUsageV1(input_tokens=0, output_tokens=0))


@dataclass(frozen=True, slots=True)
class AgentInvocationResult[OutputT: BaseModel]:
    """Success or typed failure plus the audit data needed by the controller."""

    role: str
    model: str
    prompt_version: str
    prompt_sha256: str
    payload_sha256: str | None
    usage: AgentUsage
    estimated_cost_usd: float
    latency_ms: float
    sdk_attempts: int
    langfuse_trace_id: str | None
    output: OutputT | None = None
    error: AgentErrorV1 | None = None

    def __post_init__(self) -> None:
        if (self.output is None) == (self.error is None):
            raise ValueError("exactly one of output or error must be present")

    @property
    def succeeded(self) -> bool:
        return self.output is not None


@dataclass(frozen=True, slots=True)
class _PreparedPayload:
    compact_json: str
    sha256: str


def resolve_project_path(path: Path | str) -> Path:
    """Resolve repository-relative configuration paths independently of cwd."""

    candidate = Path(path)
    return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate


def load_versioned_prompt(path: Path | str) -> VersionedPrompt:
    """Load YAML-front-matter prompt text and compute its source hash."""

    resolved = resolve_project_path(path)
    try:
        raw = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"unable to load prompt: {resolved}") from exc

    lines = raw.splitlines()
    if not lines or lines[0].strip() != _FRONT_MATTER_BOUNDARY:
        raise ValueError(f"prompt is missing YAML front matter: {resolved}")
    try:
        closing_index = next(
            index
            for index, line in enumerate(lines[1:], start=1)
            if line.strip() == _FRONT_MATTER_BOUNDARY
        )
    except StopIteration as exc:
        raise ValueError(f"prompt front matter is not closed: {resolved}") from exc

    try:
        metadata = yaml.safe_load("\n".join(lines[1:closing_index]))
    except yaml.YAMLError as exc:
        raise ValueError(f"prompt front matter is invalid YAML: {resolved}") from exc
    if not isinstance(metadata, Mapping):
        raise ValueError(f"prompt front matter must be a mapping: {resolved}")

    version = metadata.get("prompt_version")
    if not isinstance(version, str) or not _SAFE_IDENTIFIER.fullmatch(version):
        raise ValueError(f"prompt_version must be a safe identifier: {resolved}")
    content = "\n".join(lines[closing_index + 1 :]).strip()
    if not content:
        raise ValueError(f"prompt body must not be empty: {resolved}")

    return VersionedPrompt(
        path=resolved,
        version=version,
        content=content,
        sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
    )


class BaseAgentAdapter[OutputT: BaseModel]:
    """One-turn, structured-output boundary around ``openai-agents`` 0.18.3."""

    def __init__(
        self,
        *,
        role: str,
        agent_name: str,
        output_type: type[OutputT],
        model: str,
        prompt_path: Path | str,
        max_output_tokens: int,
        max_turns: int,
        settings: Settings | None = None,
        pricing: PricingCatalog | None = None,
        runner: RunnerLike = Runner,
        credentials_available: bool | None = None,
        telemetry: TelemetryLike | None | object = _DEFAULT_TELEMETRY,
        trace_factory: TraceFactory = sdk_trace,
        sdk_tracing_enabled: bool | None = None,
        sleeper: SleepCallable = asyncio.sleep,
        jitter: JitterCallable = random.random,
        max_retries: int = DEFAULT_MAX_RETRIES,
        base_backoff_seconds: float = DEFAULT_BASE_BACKOFF_SECONDS,
        max_backoff_seconds: float = DEFAULT_MAX_BACKOFF_SECONDS,
        max_input_characters: int = DEFAULT_MAX_INPUT_CHARACTERS,
    ) -> None:
        if not _SAFE_IDENTIFIER.fullmatch(role):
            raise ValueError("agent role must be a safe identifier")
        if max_output_tokens < 1 or max_turns < 1:
            raise ValueError("agent token and turn limits must be positive")
        if not 0 <= max_retries <= 5:
            raise ValueError("max_retries must be between zero and five")
        if base_backoff_seconds < 0 or max_backoff_seconds < base_backoff_seconds:
            raise ValueError("retry backoff bounds are invalid")
        if max_input_characters < 1:
            raise ValueError("max_input_characters must be positive")

        self.role = role
        self.agent_name = agent_name
        self.output_type = output_type
        self.model = model
        self.max_output_tokens = max_output_tokens
        self.max_turns = max_turns
        self.prompt = load_versioned_prompt(prompt_path)
        self.settings = settings or get_settings()
        self.pricing = pricing or PricingCatalog.from_yaml(self.settings.pricing_path)

        self._runner = runner
        self._credentials_available = (
            self.settings.has_openai_credentials
            if credentials_available is None
            else credentials_available
        )
        if telemetry is _DEFAULT_TELEMETRY:
            self._telemetry: TelemetryLike | None = get_telemetry()
        else:
            self._telemetry = telemetry  # type: ignore[assignment]
        self._trace_factory = trace_factory
        self._sdk_tracing_enabled = (
            bool(self._telemetry and self._telemetry.enabled)
            if sdk_tracing_enabled is None
            else sdk_tracing_enabled
        )
        self._sleeper = sleeper
        self._jitter = jitter
        self._max_retries = max_retries
        self._base_backoff_seconds = base_backoff_seconds
        self._max_backoff_seconds = max_backoff_seconds
        self._max_input_characters = max_input_characters
        self._model_provider = self._create_model_provider()

    async def run(
        self,
        payload: BaseModel | Mapping[str, Any],
        *,
        campaign_id: str,
        attempt_id: str,
        correlation_id: str | None = None,
        category: str | None = None,
        target_version: str | None = None,
    ) -> AgentInvocationResult[OutputT]:
        """Run the role's configured routine model once within fixed limits."""

        return await self._invoke_with_model(
            payload,
            model=self.model,
            campaign_id=campaign_id,
            attempt_id=attempt_id,
            correlation_id=correlation_id,
            category=category,
            target_version=target_version,
        )

    async def invoke(
        self,
        payload: BaseModel | Mapping[str, Any],
        *,
        campaign_id: str,
        attempt_id: str,
        correlation_id: str | None = None,
        category: str | None = None,
        target_version: str | None = None,
    ) -> AgentInvocationResult[OutputT]:
        """Readable alias for controller code that treats roles as invocations."""

        return await self.run(
            payload,
            campaign_id=campaign_id,
            attempt_id=attempt_id,
            correlation_id=correlation_id,
            category=category,
            target_version=target_version,
        )

    async def _invoke_with_model(
        self,
        payload: BaseModel | Mapping[str, Any],
        *,
        model: str,
        campaign_id: str,
        attempt_id: str,
        correlation_id: str | None,
        category: str | None,
        target_version: str | None,
    ) -> AgentInvocationResult[OutputT]:
        started_at = perf_counter()
        pricing_available = True
        try:
            self.pricing.price_for(model)
        except ValueError:
            pricing_available = False

        if not pricing_available:
            return self._failure(
                code=AgentErrorCodeV1.INVALID_CONTRACT,
                message="The selected model has no verified pricing entry.",
                retryable=False,
                campaign_id=campaign_id,
                attempt_id=attempt_id,
                correlation_id=correlation_id,
                model=model,
                started_at=started_at,
                payload_sha256=None,
                sdk_attempts=0,
                details={"agent_role": self.role, "reason": "unknown_model_pricing"},
            )

        try:
            prepared = self._prepare_payload(payload)
        except (TypeError, ValueError) as exc:
            reason = "input_too_large" if isinstance(exc, _InputTooLargeError) else "invalid_input"
            return self._failure(
                code=AgentErrorCodeV1.INVALID_CONTRACT,
                message="The agent input could not be converted to bounded sanitized JSON.",
                retryable=False,
                campaign_id=campaign_id,
                attempt_id=attempt_id,
                correlation_id=correlation_id,
                model=model,
                started_at=started_at,
                payload_sha256=None,
                sdk_attempts=0,
                details={"agent_role": self.role, "reason": reason},
            )

        if not self._credentials_available:
            return self._failure(
                code=AgentErrorCodeV1.AUTHENTICATION_FAILED,
                message="OpenAI credentials are not configured; the agent role was not run.",
                retryable=False,
                campaign_id=campaign_id,
                attempt_id=attempt_id,
                correlation_id=correlation_id,
                model=model,
                started_at=started_at,
                payload_sha256=prepared.sha256,
                sdk_attempts=0,
                details={"provider": "openai", "reason": "missing_credentials"},
            )

        agent = self._build_agent(model)
        sdk_trace_id = gen_trace_id()
        metadata = {
            "agent_role": self.role,
            "model": model,
            "prompt_version": self.prompt.version,
            "prompt_sha256": self.prompt.sha256,
            "payload_sha256": prepared.sha256,
            "campaign_id": campaign_id,
            "attempt_id": attempt_id,
        }
        run_config_values: dict[str, Any] = {
            "tracing_disabled": not self._sdk_tracing_enabled,
            "trace_include_sensitive_data": False,
            "workflow_name": f"AgentForge {self.role}",
            "trace_id": sdk_trace_id,
            "group_id": campaign_id,
            "trace_metadata": metadata,
        }
        if self._model_provider is not None:
            run_config_values["model_provider"] = self._model_provider
        run_config = RunConfig(**run_config_values)

        result: Any | None = None
        sdk_attempts = 0
        langfuse_trace_id: str | None = None
        try:
            with ExitStack() as stack:
                if self._telemetry is not None:
                    observation = stack.enter_context(
                        self._telemetry.agent_scope(
                            campaign_id=campaign_id,
                            attempt_id=attempt_id,
                            agent_role=self.role,
                            category=category,
                            target_version=target_version,
                            prompt_version=self.prompt.version,
                            model=model,
                        )
                    )
                    langfuse_trace_id = getattr(observation, "trace_id", None)
                stack.enter_context(
                    self._trace_factory(
                        workflow_name=f"AgentForge {self.role}",
                        trace_id=sdk_trace_id,
                        group_id=campaign_id,
                        metadata=metadata,
                        disabled=not self._sdk_tracing_enabled,
                    )
                )

                while True:
                    sdk_attempts += 1
                    try:
                        result = await self._runner.run(
                            agent,
                            prepared.compact_json,
                            max_turns=self.max_turns,
                            run_config=run_config,
                        )
                        break
                    except APIStatusError as exc:
                        if (
                            not _is_retryable_status(exc.status_code)
                            or sdk_attempts > self._max_retries
                        ):
                            raise
                        await self._sleeper(self._retry_delay(sdk_attempts))
        except ModelRefusalError:
            return self._failure(
                code=AgentErrorCodeV1.AGENT_REFUSAL,
                message="The provider declined the authorized structured-output request.",
                retryable=False,
                campaign_id=campaign_id,
                attempt_id=attempt_id,
                correlation_id=correlation_id,
                model=model,
                started_at=started_at,
                payload_sha256=prepared.sha256,
                sdk_attempts=sdk_attempts,
                langfuse_trace_id=langfuse_trace_id,
                details={"agent_role": self.role, "provider": "openai"},
            )
        except ModelBehaviorError:
            return self._failure(
                code=AgentErrorCodeV1.INVALID_CONTRACT,
                message="The model response did not satisfy the declared output contract.",
                retryable=False,
                campaign_id=campaign_id,
                attempt_id=attempt_id,
                correlation_id=correlation_id,
                model=model,
                started_at=started_at,
                payload_sha256=prepared.sha256,
                sdk_attempts=sdk_attempts,
                langfuse_trace_id=langfuse_trace_id,
                details={"agent_role": self.role, "reason": "model_behavior"},
            )
        except MaxTurnsExceeded:
            return self._failure(
                code=self._timeout_code(),
                message="The agent reached its configured turn limit.",
                retryable=False,
                campaign_id=campaign_id,
                attempt_id=attempt_id,
                correlation_id=correlation_id,
                model=model,
                started_at=started_at,
                payload_sha256=prepared.sha256,
                sdk_attempts=sdk_attempts,
                langfuse_trace_id=langfuse_trace_id,
                details={"agent_role": self.role, "reason": "max_turns"},
            )
        except APITimeoutError:
            return self._failure(
                code=self._timeout_code(),
                message="The OpenAI request exceeded its provider timeout.",
                retryable=False,
                campaign_id=campaign_id,
                attempt_id=attempt_id,
                correlation_id=correlation_id,
                model=model,
                started_at=started_at,
                payload_sha256=prepared.sha256,
                sdk_attempts=sdk_attempts,
                langfuse_trace_id=langfuse_trace_id,
                details={"agent_role": self.role, "provider": "openai"},
            )
        except APIStatusError as exc:
            code, message, retryable = _status_error(exc.status_code)
            return self._failure(
                code=code,
                message=message,
                retryable=retryable,
                campaign_id=campaign_id,
                attempt_id=attempt_id,
                correlation_id=correlation_id,
                model=model,
                started_at=started_at,
                payload_sha256=prepared.sha256,
                sdk_attempts=sdk_attempts,
                langfuse_trace_id=langfuse_trace_id,
                details={"agent_role": self.role, "provider": "openai"},
            )
        except APIConnectionError:
            return self._failure(
                code=AgentErrorCodeV1.UNEXPECTED_INTERNAL_ERROR,
                message="The OpenAI provider could not be reached.",
                retryable=False,
                campaign_id=campaign_id,
                attempt_id=attempt_id,
                correlation_id=correlation_id,
                model=model,
                started_at=started_at,
                payload_sha256=prepared.sha256,
                sdk_attempts=sdk_attempts,
                langfuse_trace_id=langfuse_trace_id,
                details={"agent_role": self.role, "provider": "openai"},
            )
        except Exception:
            # No exception text crosses the boundary: provider/HTTP messages can
            # contain request excerpts, headers, or schema content.
            return self._failure(
                code=AgentErrorCodeV1.UNEXPECTED_INTERNAL_ERROR,
                message="The agent role failed before producing a validated result.",
                retryable=False,
                campaign_id=campaign_id,
                attempt_id=attempt_id,
                correlation_id=correlation_id,
                model=model,
                started_at=started_at,
                payload_sha256=prepared.sha256,
                sdk_attempts=sdk_attempts,
                langfuse_trace_id=langfuse_trace_id,
                details={"agent_role": self.role, "provider": "openai"},
            )

        try:
            output = self._validate_output(result)
        except (TypeError, ValueError, ValidationError):
            return self._failure(
                code=AgentErrorCodeV1.INVALID_CONTRACT,
                message="The model response did not satisfy the declared output contract.",
                retryable=False,
                campaign_id=campaign_id,
                attempt_id=attempt_id,
                correlation_id=correlation_id,
                model=model,
                started_at=started_at,
                payload_sha256=prepared.sha256,
                sdk_attempts=sdk_attempts,
                langfuse_trace_id=langfuse_trace_id,
                details={"agent_role": self.role, "reason": "output_validation"},
            )

        usage = _extract_usage(result)
        return AgentInvocationResult(
            role=self.role,
            model=model,
            prompt_version=self.prompt.version,
            prompt_sha256=self.prompt.sha256,
            payload_sha256=prepared.sha256,
            usage=usage,
            estimated_cost_usd=self.pricing.estimate_cost(model, usage),
            latency_ms=_elapsed_ms(started_at),
            sdk_attempts=sdk_attempts,
            langfuse_trace_id=langfuse_trace_id,
            output=output,
        )

    def _create_model_provider(self) -> OpenAIProvider | None:
        # Every credentialed SDK invocation gets an explicit zero-retry client so
        # the bounded retry loop above is the only retry authority. Constructing
        # the async client does not make a network request.
        if not self.settings.has_openai_credentials:
            return None
        api_key = self.settings.openai_api_key
        if api_key is None:  # narrowed by has_openai_credentials; defensive only
            return None
        client = AsyncOpenAI(api_key=api_key.get_secret_value(), max_retries=0)
        return OpenAIProvider(
            openai_client=client,
            use_responses=True,
            strict_feature_validation=True,
        )

    def _build_agent(self, model: str) -> Agent[Any]:
        settings = ModelSettings(
            reasoning=Reasoning(effort="low"),
            verbosity="low",
            max_tokens=self.max_output_tokens,
            store=False,
            parallel_tool_calls=False,
            retry=ModelRetrySettings(max_retries=0),
        )
        return Agent(
            name=self.agent_name,
            instructions=self.prompt.content,
            model=model,
            model_settings=settings,
            output_type=self.output_type,
            tools=[],
            handoffs=[],
            mcp_servers=[],
        )

    def _prepare_payload(self, payload: BaseModel | Mapping[str, Any]) -> _PreparedPayload:
        if not isinstance(payload, (BaseModel, Mapping)):
            raise TypeError("agent input must be a Pydantic model or mapping")
        normalized: Any = (
            payload.model_dump(mode="json") if isinstance(payload, BaseModel) else payload
        )
        sanitized = _sanitize_model_input(normalized)
        compact = json.dumps(
            sanitized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        if len(compact) > self._max_input_characters:
            raise _InputTooLargeError
        return _PreparedPayload(
            compact_json=compact,
            sha256=hashlib.sha256(compact.encode("utf-8")).hexdigest(),
        )

    def _validate_output(self, result: Any) -> OutputT:
        if result is None or not hasattr(result, "final_output"):
            raise TypeError("SDK result is missing final_output")
        final_output = result.final_output
        if isinstance(final_output, self.output_type):
            return final_output
        return self.output_type.model_validate(final_output)

    def _retry_delay(self, sdk_attempts: int) -> float:
        base = min(
            self._max_backoff_seconds,
            self._base_backoff_seconds * (2 ** max(0, sdk_attempts - 1)),
        )
        jitter = min(1.0, max(0.0, float(self._jitter()))) * min(base, 1.0)
        return min(self._max_backoff_seconds, base + jitter)

    def _timeout_code(self) -> AgentErrorCodeV1:
        return (
            AgentErrorCodeV1.JUDGE_TIMEOUT
            if self.role == "judge"
            else AgentErrorCodeV1.AGENT_TIMEOUT
        )

    def _failure(
        self,
        *,
        code: AgentErrorCodeV1,
        message: str,
        retryable: bool,
        campaign_id: str,
        attempt_id: str,
        correlation_id: str | None,
        model: str,
        started_at: float,
        payload_sha256: str | None,
        sdk_attempts: int,
        details: dict[str, Any],
        langfuse_trace_id: str | None = None,
    ) -> AgentInvocationResult[OutputT]:
        safe_campaign_id = campaign_id if _SAFE_IDENTIFIER.fullmatch(campaign_id) else None
        safe_attempt_id = attempt_id if _SAFE_IDENTIFIER.fullmatch(attempt_id) else None
        candidate_correlation_id = correlation_id or safe_attempt_id or str(uuid4())
        safe_correlation_id = (
            candidate_correlation_id
            if _SAFE_IDENTIFIER.fullmatch(candidate_correlation_id)
            else str(uuid4())
        )
        error = AgentErrorV1(
            schema_version=SCHEMA_VERSION_V1,
            code=code,
            message=message,
            retryable=retryable,
            occurred_at=utc_now(),
            correlation_id=safe_correlation_id,
            campaign_id=safe_campaign_id,
            attempt_id=safe_attempt_id,
            sanitized_details=details,
        )
        return AgentInvocationResult(
            role=self.role,
            model=model,
            prompt_version=self.prompt.version,
            prompt_sha256=self.prompt.sha256,
            payload_sha256=payload_sha256,
            usage=AgentUsage.zero(),
            estimated_cost_usd=0.0,
            latency_ms=_elapsed_ms(started_at),
            sdk_attempts=sdk_attempts,
            langfuse_trace_id=langfuse_trace_id,
            error=error,
        )


class _InputTooLargeError(ValueError):
    pass


def _non_negative_price(value: Any, model: str, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ValueError(f"pricing {model}.{field} must be a non-negative number")
    return float(value)


def _sanitize_model_input(value: Any, *, depth: int = 0) -> Any:
    """Normalize JSON input while retaining non-secret token budget counters."""

    if depth > 16:
        return "[TRUNCATED]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, SecretStr):
        return "[REDACTED]"
    if isinstance(value, str):
        return redact_for_telemetry(value)
    if isinstance(value, (date, datetime, UUID, Path, Enum)):
        return _sanitize_model_input(
            value.value if isinstance(value, Enum) else str(value),
            depth=depth + 1,
        )
    if isinstance(value, Mapping):
        return {
            str(key): (
                "[REDACTED]"
                if _SENSITIVE_INPUT_KEY.search(str(key))
                else _sanitize_model_input(item, depth=depth + 1)
            )
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_sanitize_model_input(item, depth=depth + 1) for item in value]
    if isinstance(value, (set, frozenset)):
        normalized = [_sanitize_model_input(item, depth=depth + 1) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True, default=str))
    return redact_for_telemetry(value)


def _extract_usage(result: Any) -> AgentUsage:
    context = getattr(result, "context_wrapper", None)
    usage = getattr(context, "usage", None)
    if usage is None:
        return AgentUsage.zero()

    input_details = getattr(usage, "input_tokens_details", None)
    output_details = getattr(usage, "output_tokens_details", None)
    cached_tokens = _non_negative_int(getattr(input_details, "cached_tokens", 0))
    cache_write_tokens = _non_negative_int(getattr(input_details, "cache_write_tokens", 0))
    reasoning_tokens = _non_negative_int(getattr(output_details, "reasoning_tokens", 0))
    return AgentUsage(
        tokens=TokenUsageV1(
            input_tokens=_non_negative_int(getattr(usage, "input_tokens", 0)),
            output_tokens=_non_negative_int(getattr(usage, "output_tokens", 0)),
            cached_input_tokens=cached_tokens,
            calls=_non_negative_int(getattr(usage, "requests", 0)),
        ),
        cache_write_input_tokens=cache_write_tokens,
        reasoning_output_tokens=reasoning_tokens,
    )


def _non_negative_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, value)


def _is_retryable_status(status_code: int) -> bool:
    return status_code == 429 or 500 <= status_code <= 599


def _status_error(status_code: int) -> tuple[AgentErrorCodeV1, str, bool]:
    if status_code in {401, 403}:
        return (
            AgentErrorCodeV1.AUTHENTICATION_FAILED,
            "The OpenAI provider rejected the configured credentials.",
            False,
        )
    if status_code == 429:
        return (
            AgentErrorCodeV1.RATE_LIMITED,
            "The OpenAI provider remained rate limited after bounded retries.",
            True,
        )
    if 500 <= status_code <= 599:
        return (
            AgentErrorCodeV1.UNEXPECTED_INTERNAL_ERROR,
            "The OpenAI provider remained unavailable after bounded retries.",
            True,
        )
    return (
        AgentErrorCodeV1.UNEXPECTED_INTERNAL_ERROR,
        "The OpenAI provider rejected the request without a retryable status.",
        False,
    )


def _elapsed_ms(started_at: float) -> float:
    return max(0.0, (perf_counter() - started_at) * 1000)


__all__ = [
    "AgentInvocationResult",
    "AgentUsage",
    "BaseAgentAdapter",
    "ModelPrice",
    "PricingCatalog",
    "VersionedPrompt",
    "load_versioned_prompt",
    "resolve_project_path",
]
