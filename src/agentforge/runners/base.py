"""Shared target-runner interface and sanitized evidence construction."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, Protocol
from uuid import uuid4

from pydantic import JsonValue

from agentforge.contracts.v1.actions import AttackActionV1
from agentforge.contracts.v1.campaign import ProposedAttackV1
from agentforge.contracts.v1.common import utc_now
from agentforge.contracts.v1.errors import AgentErrorCodeV1, AgentErrorV1
from agentforge.contracts.v1.evidence import (
    ActionExecutionStatusV1,
    AttackEvidenceV1,
    ExecutedActionV1,
    SanitizedHttpExchangeV1,
    TargetVisibleToolCallV1,
    TranscriptRoleV1,
    TranscriptTurnV1,
)
from agentforge.evidence import with_computed_evidence_hash
from agentforge.orchestration.execution_gate import (
    EndpointPurposeV1,
    ValidatedAttackV1,
    proposal_sequence_hash,
)
from agentforge.security.allowlist import require_allowed_url
from agentforge.target.fixtures import ApprovedFixtureAuthorization
from agentforge.target.profile import LoadedTargetProfile, ResolvedTargetAlias, TargetProfileV1

if TYPE_CHECKING:
    from agentforge.target.auth import TargetCredentials


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def sanitized_summary(value: str, *, fallback: str = "runner event") -> str:
    """Produce bounded, single-line evidence text without reflecting secrets."""

    normalized = " ".join(value.replace("\x00", " ").split())
    return (normalized or fallback)[:512]


@dataclass(frozen=True, slots=True)
class TargetExecutionContext:
    """Resolved, profile-owned execution inputs; actions never supply a target URL."""

    target_id: str
    campaign_id: str
    attempt_id: str
    target_version: str
    selected_patient_alias: Literal["patient_a", "patient_b"]
    loaded_profile: LoadedTargetProfile
    target_alias: ResolvedTargetAlias
    repository_root: Path
    artifacts_dir: Path
    credentials: TargetCredentials | None = None
    request_timeout_seconds: float = 30.0
    max_response_bytes: int = 1_000_000
    max_upload_bytes: int = 1_048_576
    upload_surface_id: str = "clinical_document_upload"
    approved_fixtures: Mapping[str, ApprovedFixtureAuthorization] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for value, label in (
            (self.target_id, "target_id"),
            (self.campaign_id, "campaign_id"),
            (self.attempt_id, "attempt_id"),
        ):
            if not _IDENTIFIER.fullmatch(value):
                raise ValueError(f"{label} is not a valid identifier")
        if not self.target_version.strip() or len(self.target_version) > 512:
            raise ValueError("target_version must be non-empty and bounded")
        if self.target_alias.name not in self.loaded_profile.profile.aliases:
            raise ValueError("resolved target alias is absent from the loaded profile")
        configured_alias = self.loaded_profile.profile.aliases[self.target_alias.name]
        configured_hosts = {host.casefold() for host in configured_alias.expected_hosts}
        resolved_hosts = {host.casefold() for host in self.target_alias.expected_hosts}
        if resolved_hosts != configured_hosts:
            raise ValueError("resolved target hosts do not match the loaded profile")
        require_allowed_url(
            self.target_alias.base_url,
            configured_alias.expected_hosts,
            allow_http=True,
        )
        require_allowed_url(
            self.target_alias.status_url,
            configured_alias.expected_hosts,
            allow_http=True,
        )
        if configured_alias.base_url and self.target_alias.base_url != configured_alias.base_url:
            raise ValueError("resolved base URL does not match the profile literal")
        if (
            configured_alias.status_url
            and self.target_alias.status_url != configured_alias.status_url
        ):
            raise ValueError("resolved status URL does not match the profile literal")
        if not 0 < self.request_timeout_seconds <= 120:
            raise ValueError("request timeout must be between zero and 120 seconds")
        if not 0 < self.max_response_bytes <= 10_000_000:
            raise ValueError("response byte limit is out of range")
        if not 0 < self.max_upload_bytes <= 10_485_760:
            raise ValueError("upload byte limit is out of range")
        if not _IDENTIFIER.fullmatch(self.upload_surface_id):
            raise ValueError("upload_surface_id is not a valid identifier")
        fixture_registry = dict(self.approved_fixtures)
        for fixture_id, authorization in fixture_registry.items():
            if fixture_id != authorization.fixture_id or not _IDENTIFIER.fullmatch(fixture_id):
                raise ValueError("approved fixture registry key is invalid")
            allowed_document_types = self.loaded_profile.profile.upload.allowed_document_types
            if authorization.document_type not in allowed_document_types:
                raise ValueError("approved fixture document type is outside the target profile")
            if (
                authorization.size_bytes <= 0
                or authorization.pages <= 0
                or re.fullmatch(r"[0-9a-f]{64}", authorization.sha256) is None
            ):
                raise ValueError("approved fixture authorization metadata is invalid")
        object.__setattr__(self, "approved_fixtures", MappingProxyType(fixture_registry))

        repository = self.repository_root.resolve()
        artifacts = self.artifacts_dir.resolve()
        if artifacts != repository and repository not in artifacts.parents:
            raise ValueError("artifacts_dir must remain beneath repository_root")
        object.__setattr__(self, "repository_root", repository)
        object.__setattr__(self, "artifacts_dir", artifacts)

    @property
    def profile(self) -> TargetProfileV1:
        return self.loaded_profile.profile

    def artifact_path(self, filename: str) -> tuple[Path, str]:
        """Return a bounded per-attempt path and repository-relative reference."""

        if not filename or "/" in filename or "\\" in filename or filename in {".", ".."}:
            raise ValueError("artifact filename must be a single safe path component")
        path = (self.artifacts_dir / self.attempt_id / filename).resolve()
        if self.artifacts_dir not in path.parents:
            raise ValueError("artifact path escaped its configured root")
        relative = path.relative_to(self.repository_root).as_posix()
        return path, relative


class AttackRunner(Protocol):
    async def execute(
        self,
        attack: ValidatedAttackV1,
        context: TargetExecutionContext,
    ) -> AttackEvidenceV1: ...


class RunnerFailure(RuntimeError):
    """A typed execution failure whose public fields are safe for evidence."""

    def __init__(
        self,
        code: AgentErrorCodeV1,
        message: str,
        *,
        retryable: bool = False,
        status: ActionExecutionStatusV1 = ActionExecutionStatusV1.FAILED,
        details: dict[str, JsonValue] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.public_message = sanitized_summary(message)
        self.retryable = retryable
        self.status = status
        self.details = details or {}


class RunnerActionRejected(RunnerFailure):
    def __init__(self, message: str, *, details: dict[str, JsonValue] | None = None) -> None:
        super().__init__(
            AgentErrorCodeV1.ACTION_REJECTED,
            message,
            status=ActionExecutionStatusV1.REJECTED,
            details=details,
        )


def require_validated_attack(
    attack: object,
    context: TargetExecutionContext,
    *,
    now: datetime | None = None,
) -> ProposedAttackV1:
    """Fail closed unless the immutable gate envelope exactly matches execution context."""

    if not isinstance(attack, ValidatedAttackV1):
        raise RunnerActionRejected("runner requires a gate-approved attack envelope")
    checked_at = now or datetime.now(UTC)
    if checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise ValueError("runner authorization time must be timezone-aware")
    if checked_at < attack.authorized_at or checked_at >= attack.expires_at:
        raise RunnerActionRejected("gate-approved attack authorization is not active")
    if attack.campaign_id != context.campaign_id:
        raise RunnerActionRejected("approved campaign does not match execution context")
    if attack.target_alias != context.target_alias.name:
        raise RunnerActionRejected("approved target alias does not match execution context")
    if attack.target_profile_version != context.profile.profile_version:
        raise RunnerActionRejected(
            "approved target profile version does not match execution context"
        )
    if attack.selected_patient_alias != context.selected_patient_alias:
        raise RunnerActionRejected("approved synthetic patient does not match execution context")

    proposal = attack.proposal
    if proposal_sequence_hash(proposal) != attack.sequence_hash:
        raise RunnerActionRejected("approved attack sequence hash does not match its proposal")

    selected_actions = [
        action
        for action in proposal.ordered_actions
        if action.action_type.value == "select_synthetic_patient"
    ]
    if len(selected_actions) > 1 or (
        selected_actions
        and getattr(selected_actions[0], "patient_alias", None) != attack.selected_patient_alias
    ):
        raise RunnerActionRejected("approved synthetic patient does not match the action sequence")

    bindings = {binding.endpoint_id: binding for binding in attack.authorized_endpoint_bindings}
    if len(bindings) != len(attack.authorized_endpoint_bindings):
        raise RunnerActionRejected("approved endpoint bindings contain duplicate identifiers")
    profile_endpoints = {
        (rule.method, rule.surface, rule.path) for rule in context.profile.allowed_endpoints
    }
    if any(
        (binding.method.value, binding.surface, binding.path) not in profile_endpoints
        for binding in bindings.values()
    ):
        raise RunnerActionRejected(
            "approved endpoint metadata no longer matches the target profile"
        )

    required_endpoint_ids: set[str] = set()
    required_purposes: set[EndpointPurposeV1] = set()
    required_fixture_ids: set[str] = set()
    for action in proposal.ordered_actions:
        action_type = action.action_type.value
        if action_type == "invoke_approved_api_request":
            required_endpoint_ids.add(action.endpoint_id)
        elif action_type == "send_chat_message":
            required_purposes.add(EndpointPurposeV1.CHAT)
        elif action_type == "upload_approved_fixture":
            required_purposes.update(
                {EndpointPurposeV1.UPLOAD_STAGE, EndpointPurposeV1.UPLOAD_REJECT}
            )
            required_fixture_ids.add(action.fixture_id)
    if not required_endpoint_ids.issubset(bindings):
        raise RunnerActionRejected("approved endpoint envelope omits an action endpoint")
    if not required_purposes.issubset({binding.purpose for binding in bindings.values()}):
        raise RunnerActionRejected("approved endpoint envelope omits a required execution surface")

    fixtures = {fixture.fixture_id: fixture for fixture in attack.authorized_fixtures}
    if len(fixtures) != len(attack.authorized_fixtures):
        raise RunnerActionRejected("approved fixture metadata contains duplicate identifiers")
    if set(fixtures) != required_fixture_ids:
        raise RunnerActionRejected("approved fixture envelope does not match the action sequence")
    for fixture_id, fixture in fixtures.items():
        context_fixture = context.approved_fixtures.get(fixture_id)
        if context_fixture is None or (
            fixture.repository_relative_path != context_fixture.repository_relative_path
            or fixture.document_type != context_fixture.document_type
            or fixture.media_type != context_fixture.media_type
            or fixture.size_bytes != context_fixture.size_bytes
            or fixture.pages != context_fixture.pages
            or fixture.sha256 != context_fixture.sha256
        ):
            raise RunnerActionRejected("approved fixture metadata does not match execution context")
    return proposal


class EvidenceRecorder:
    """Mutable execution-local builder producing an immutable v1 evidence object."""

    def __init__(self, context: TargetExecutionContext) -> None:
        self.context = context
        self.started_at = utc_now()
        self.executed_actions: list[ExecutedActionV1] = []
        self.transcript: list[TranscriptTurnV1] = []
        self.http_metadata: list[SanitizedHttpExchangeV1] = []
        self.target_visible_tool_calls: list[TargetVisibleToolCallV1] = []
        self.errors: list[AgentErrorV1] = []

    def add_action(
        self,
        *,
        sequence_index: int,
        action: AttackActionV1,
        started_at,  # type: ignore[no-untyped-def]
        status: ActionExecutionStatusV1,
        summary: str,
    ) -> None:
        self.executed_actions.append(
            ExecutedActionV1(
                sequence_index=sequence_index,
                action=action,
                status=status,
                started_at=started_at,
                completed_at=utc_now(),
                sanitized_result_summary=sanitized_summary(summary),
            )
        )

    def add_skipped(self, sequence_index: int, action: AttackActionV1) -> None:
        timestamp = utc_now()
        self.executed_actions.append(
            ExecutedActionV1(
                sequence_index=sequence_index,
                action=action,
                status=ActionExecutionStatusV1.SKIPPED,
                started_at=timestamp,
                completed_at=timestamp,
                sanitized_result_summary="skipped after an earlier action failure",
            )
        )

    def add_error(self, failure: RunnerFailure) -> None:
        self.errors.append(
            AgentErrorV1(
                schema_version="v1",
                code=failure.code,
                message=failure.public_message,
                retryable=failure.retryable,
                occurred_at=utc_now(),
                correlation_id=f"runner-{uuid4().hex}",
                campaign_id=self.context.campaign_id,
                attempt_id=self.context.attempt_id,
                sanitized_details=failure.details,
            )
        )

    def add_transcript(self, role: TranscriptRoleV1, content: str) -> None:
        bounded = content.replace("\x00", " ").strip()[:20_000]
        if not bounded:
            bounded = "No response content was rendered."
        self.transcript.append(
            TranscriptTurnV1(
                turn_index=len(self.transcript),
                role=role,
                content=bounded,
                observed_at=utc_now(),
            )
        )

    def add_http(self, exchange: SanitizedHttpExchangeV1) -> None:
        self.http_metadata.append(exchange)

    def add_target_visible_tool_call(self, call: TargetVisibleToolCallV1) -> None:
        self.target_visible_tool_calls.append(call)

    def finalize(self) -> AttackEvidenceV1:
        completed_at = utc_now()
        draft = AttackEvidenceV1(
            schema_version="v1",
            target_id=self.context.target_id,
            campaign_id=self.context.campaign_id,
            attempt_id=self.context.attempt_id,
            target_version=self.context.target_version,
            executed_action_sequence=self.executed_actions,
            transcript=self.transcript,
            sanitized_http_metadata=self.http_metadata,
            target_visible_tool_calls=self.target_visible_tool_calls,
            side_effects=[],
            started_at=self.started_at,
            completed_at=completed_at,
            total_latency_ms=max(0.0, (completed_at - self.started_at).total_seconds() * 1_000),
            errors=self.errors,
            langfuse_trace_id=None,
            evidence_hash="0" * 64,
        )
        return with_computed_evidence_hash(draft)


__all__ = [
    "AttackRunner",
    "EvidenceRecorder",
    "RunnerActionRejected",
    "RunnerFailure",
    "TargetExecutionContext",
    "sanitized_summary",
]
