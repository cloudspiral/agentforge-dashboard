"""Pure authorization gate between model proposals and target execution."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from agentforge.contracts.v1 import (
    ActionTypeV1,
    ApprovedHttpMethodV1,
    AuthenticateActionV1,
    CollectEvidenceActionV1,
    InvokeApprovedApiRequestActionV1,
    ProposedAttackV1,
    ResetSessionActionV1,
    SelectSyntheticPatientActionV1,
    SendChatMessageActionV1,
    UploadApprovedFixtureActionV1,
    WaitForResponseActionV1,
)
from agentforge.target.profile import TargetProfileV1

_PATIENT_PARAMETER_KEYS = {
    "external_id",
    "patient",
    "patient_alias",
    "patient_id",
    "pid",
    "pubpid",
}
_AUTHORITY_PARAMETER_KEYS = {
    "command",
    "file_path",
    "filepath",
    "host",
    "hostname",
    "path",
    "raw_sql",
    "shell",
    "sql",
    "uri",
    "url",
}
_EXTERNAL_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


class GateModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class EndpointPurposeV1(StrEnum):
    CHAT = "chat"
    STATUS = "status"
    GENERAL_API = "general_api"
    UPLOAD_STAGE = "upload_stage"
    UPLOAD_REJECT = "upload_reject"


class EndpointBindingV1(GateModel):
    endpoint_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    method: ApprovedHttpMethodV1
    surface: Literal["status", "ui"]
    path: str = Field(min_length=1, max_length=512)
    purpose: EndpointPurposeV1

    @field_validator("path")
    @classmethod
    def path_is_origin_relative(cls, value: str) -> str:
        if not value.startswith("/") or _EXTERNAL_URL.match(value) or "\\" in value:
            raise ValueError("endpoint path must be an origin-relative POSIX path")
        if ".." in PurePosixPath(value).parts or "\x00" in value:
            raise ValueError("endpoint path cannot traverse directories")
        return value


class ApprovedFixtureV1(GateModel):
    fixture_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    repository_relative_path: str = Field(min_length=1, max_length=512)
    document_type: str = Field(min_length=1, max_length=100)
    extension: str = Field(min_length=2, max_length=20, pattern=r"^\.[A-Za-z0-9]+$")
    media_type: str = Field(min_length=3, max_length=100)
    size_bytes: int = Field(gt=0, le=10_485_760)
    pages: int = Field(gt=0, le=100)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("repository_relative_path")
    @classmethod
    def fixture_path_is_bounded(cls, value: str) -> str:
        if _EXTERNAL_URL.match(value) or "\\" in value or "\x00" in value:
            raise ValueError("fixture path must be a repository-relative POSIX path")
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("fixture path cannot be absolute or traverse directories")
        return value


class GateLimitsV1(GateModel):
    max_actions: int = Field(ge=5, le=30)
    max_turns: int = Field(ge=1, le=20)
    max_total_wait_seconds: float = Field(gt=0, le=1_200, allow_inf_nan=False)
    max_total_message_bytes: int = Field(gt=0, le=100_000)
    max_upload_count: int = Field(ge=0, le=20)
    max_total_upload_bytes: int = Field(ge=0, le=50_000_000)
    max_sequence_repetitions: int = Field(ge=1, le=10)


class CampaignExecutionContextV1(GateModel):
    campaign_id: str = Field(min_length=1, max_length=128)
    target_alias: str = Field(min_length=1, max_length=128)
    selected_category: str = Field(min_length=1, max_length=128)
    selected_subcategory: str = Field(min_length=1, max_length=128)
    allowed_category_subcategories: dict[str, list[str]] = Field(min_length=1)
    current_patient_alias: Literal["patient_a", "patient_b"]
    test_identity_alias: str = Field(min_length=1, max_length=128)
    test_role: str = Field(min_length=1, max_length=128)
    endpoint_bindings: dict[str, EndpointBindingV1] = Field(min_length=1)
    chat_endpoint_id: str = Field(min_length=1, max_length=128)
    upload_surface_id: str = Field(min_length=1, max_length=128)
    upload_stage_endpoint_id: str = Field(min_length=1, max_length=128)
    upload_reject_endpoint_id: str = Field(min_length=1, max_length=128)
    approved_fixtures: dict[str, ApprovedFixtureV1] = Field(default_factory=dict)
    limits: GateLimitsV1
    campaign_started_at: AwareDatetime
    campaign_deadline_at: AwareDatetime
    attempted_sequence_counts: dict[str, int] = Field(default_factory=dict, max_length=1_000)
    cancellation_requested: bool = False
    cleanup_succeeded: bool = True

    @field_validator("allowed_category_subcategories")
    @classmethod
    def category_entries_are_unique(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        if any(not subcategories for subcategories in value.values()):
            raise ValueError("each allowed category requires at least one subcategory")
        if any(len(items) != len(set(items)) for items in value.values()):
            raise ValueError("allowed subcategories must be unique")
        return value

    @model_validator(mode="after")
    def context_references_are_consistent(self) -> CampaignExecutionContextV1:
        for endpoint_id, binding in self.endpoint_bindings.items():
            if endpoint_id != binding.endpoint_id:
                raise ValueError("endpoint binding keys must match endpoint_id")
        for fixture_id, fixture in self.approved_fixtures.items():
            if fixture_id != fixture.fixture_id:
                raise ValueError("approved fixture keys must match fixture_id")
        if self.campaign_deadline_at <= self.campaign_started_at:
            raise ValueError("campaign deadline must follow campaign start")
        return self


class GateRejectionCodeV1(StrEnum):
    CAMPAIGN_STOPPED = "campaign_stopped"
    UNKNOWN_CATEGORY = "unknown_category"
    UNKNOWN_SUBCATEGORY = "unknown_subcategory"
    CATEGORY_SCOPE_MISMATCH = "category_scope_mismatch"
    INVALID_SEQUENCE = "invalid_sequence"
    RESET_SCOPE_MISMATCH = "reset_scope_mismatch"
    AUTHENTICATION_SCOPE_MISMATCH = "authentication_scope_mismatch"
    PATIENT_SCOPE_MISMATCH = "patient_scope_mismatch"
    UNKNOWN_ENDPOINT = "unknown_endpoint"
    ENDPOINT_NOT_ALLOWLISTED = "endpoint_not_allowlisted"
    METHOD_NOT_ALLOWLISTED = "method_not_allowlisted"
    PROHIBITED_PERSISTENT_ROUTE = "prohibited_persistent_route"
    UNKNOWN_FIXTURE = "unknown_fixture"
    FIXTURE_NOT_ALLOWLISTED = "fixture_not_allowlisted"
    ARBITRARY_AUTHORITY = "arbitrary_authority"
    ACTION_LIMIT = "action_limit"
    TURN_LIMIT = "turn_limit"
    MESSAGE_SIZE_LIMIT = "message_size_limit"
    UPLOAD_SIZE_LIMIT = "upload_size_limit"
    TIME_LIMIT = "time_limit"
    DUPLICATE_SEQUENCE = "duplicate_sequence"


class GateRejectionV1(GateModel):
    approved: Literal[False] = False
    campaign_id: str
    proposal_id: str
    code: GateRejectionCodeV1
    reason: str = Field(min_length=1, max_length=512)
    action_id: str | None = None
    retryable_after_revision: bool


class ValidatedAttackV1(GateModel):
    approved: Literal[True] = True
    campaign_id: str
    proposal: ProposedAttackV1
    target_alias: str
    target_profile_version: str
    selected_patient_alias: Literal["patient_a", "patient_b"]
    authorized_endpoint_bindings: list[EndpointBindingV1]
    authorized_fixtures: list[ApprovedFixtureV1]
    sequence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorized_at: AwareDatetime
    expires_at: AwareDatetime


ExecutionGateResultV1 = ValidatedAttackV1 | GateRejectionV1


def _reject(
    context: CampaignExecutionContextV1,
    proposal: ProposedAttackV1,
    code: GateRejectionCodeV1,
    reason: str,
    *,
    action_id: str | None = None,
    retryable: bool = True,
) -> GateRejectionV1:
    return GateRejectionV1(
        campaign_id=context.campaign_id,
        proposal_id=proposal.proposal_id,
        code=code,
        reason=reason,
        action_id=action_id,
        retryable_after_revision=retryable,
    )


def proposal_sequence_hash(proposal: ProposedAttackV1) -> str:
    """Hash executable semantics, excluding model-controlled cosmetic identifiers."""

    actions = []
    for action in proposal.ordered_actions:
        payload = action.model_dump(mode="json")
        payload.pop("action_id", None)
        payload.pop("description", None)
        payload.pop("conversation_alias", None)
        actions.append(payload)
    canonical = json.dumps(
        {
            "category": proposal.category,
            "subcategory": proposal.subcategory,
            "ordered_actions": actions,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _profile_patient(profile: TargetProfileV1, alias: str):
    return getattr(profile.patients, alias)


def _is_persistent_confirm_route(path: str) -> bool:
    normalized = path.lower().rstrip("/")
    return normalized.endswith("/confirm") or normalized.endswith("ingestion_confirm.php")


def _parameter_authority_violation(
    value: object,
    *,
    allowed_patient_values: set[str],
    parent_key: str = "",
) -> str | None:
    if isinstance(value, dict):
        for raw_key, child in value.items():
            key = str(raw_key).lower()
            if key in _AUTHORITY_PARAMETER_KEYS:
                return (
                    f"request parameter {raw_key!r} grants arbitrary URL/path/shell/SQL authority"
                )
            if key in _PATIENT_PARAMETER_KEYS and str(child) not in allowed_patient_values:
                return f"request parameter {raw_key!r} leaves the selected synthetic patient scope"
            violation = _parameter_authority_violation(
                child,
                allowed_patient_values=allowed_patient_values,
                parent_key=key,
            )
            if violation:
                return violation
    elif isinstance(value, list):
        for child in value:
            violation = _parameter_authority_violation(
                child,
                allowed_patient_values=allowed_patient_values,
                parent_key=parent_key,
            )
            if violation:
                return violation
    elif isinstance(value, str):
        if _EXTERNAL_URL.match(value) or value.startswith(("/", "\\")):
            return f"request parameter {parent_key!r} contains an arbitrary URL or absolute path"
        if ".." in PurePosixPath(value).parts:
            return f"request parameter {parent_key!r} contains path traversal"
    return None


def validate_attack(
    proposal: ProposedAttackV1,
    target_profile: TargetProfileV1,
    context: CampaignExecutionContextV1,
    *,
    now: datetime | None = None,
) -> ExecutionGateResultV1:
    """Authorize a bounded proposal or return a typed rejection; never execute it."""

    checked_at = now or datetime.now(UTC)
    if checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise ValueError("execution-gate time must be timezone-aware")
    if context.cancellation_requested or not context.cleanup_succeeded:
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.CAMPAIGN_STOPPED,
            "campaign cancellation or cleanup failure prevents further execution",
            retryable=False,
        )
    if checked_at < context.campaign_started_at or checked_at >= context.campaign_deadline_at:
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.TIME_LIMIT,
            "campaign execution window is not active",
            retryable=False,
        )
    if context.target_alias not in target_profile.aliases:
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.ARBITRARY_AUTHORITY,
            "target alias is not declared in the loaded target profile",
            retryable=False,
        )
    if target_profile.authorized_scope != "synthetic-only":
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.ARBITRARY_AUTHORITY,
            "target profile is not restricted to synthetic-only scope",
            retryable=False,
        )

    allowed_subcategories = context.allowed_category_subcategories.get(proposal.category)
    if allowed_subcategories is None:
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.UNKNOWN_CATEGORY,
            "proposal category is absent from the loaded campaign taxonomy",
        )
    if proposal.subcategory not in allowed_subcategories:
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.UNKNOWN_SUBCATEGORY,
            "proposal subcategory is absent from the selected taxonomy category",
        )
    if (
        proposal.category != context.selected_category
        or proposal.subcategory != context.selected_subcategory
    ):
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.CATEGORY_SCOPE_MISMATCH,
            "proposal category does not match the controller-selected objective",
        )

    actions = proposal.ordered_actions
    if len(actions) > context.limits.max_actions:
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.ACTION_LIMIT,
            "proposal exceeds the campaign action limit",
        )
    required_prefix = [
        ActionTypeV1.RESET_SESSION,
        ActionTypeV1.AUTHENTICATE,
        ActionTypeV1.SELECT_SYNTHETIC_PATIENT,
    ]
    if len(actions) < 5 or [action.action_type for action in actions[:3]] != required_prefix:
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.INVALID_SEQUENCE,
            "sequence must begin with reset, authentication, and synthetic-patient selection",
        )
    reset = actions[0]
    authenticate = actions[1]
    select = actions[2]
    if (
        not isinstance(reset, ResetSessionActionV1)
        or reset.reset_strategy_id != target_profile.reset.conversation
        or not reset.require_clean_context
    ):
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.RESET_SCOPE_MISMATCH,
            "reset strategy is not the profile-owned ephemeral conversation reset",
            action_id=reset.action_id,
        )
    if not isinstance(authenticate, AuthenticateActionV1) or (
        authenticate.test_identity_alias != context.test_identity_alias
        or authenticate.expected_role != context.test_role
        or authenticate.expected_role not in target_profile.authentication.supported_roles
    ):
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.AUTHENTICATION_SCOPE_MISMATCH,
            "authentication action does not match the approved synthetic test identity and role",
            action_id=authenticate.action_id,
        )
    if (
        not isinstance(select, SelectSyntheticPatientActionV1)
        or select.patient_alias != context.current_patient_alias
        or not select.verify_selected_context
    ):
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.PATIENT_SCOPE_MISMATCH,
            "patient selection does not match the controller-owned synthetic patient context",
            action_id=select.action_id,
        )

    identity_types = {
        ActionTypeV1.RESET_SESSION,
        ActionTypeV1.AUTHENTICATE,
        ActionTypeV1.SELECT_SYNTHETIC_PATIENT,
    }
    if any(action.action_type in identity_types for action in actions[3:]):
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.INVALID_SEQUENCE,
            "reset/authentication/patient-selection actions may appear only in the required prefix",
        )
    if not isinstance(actions[-1], CollectEvidenceActionV1) or any(
        isinstance(action, CollectEvidenceActionV1) for action in actions[:-1]
    ):
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.INVALID_SEQUENCE,
            "sequence must end with exactly one evidence-collection action",
        )

    pending_response = False
    operation_count = 0
    for action in actions[3:-1]:
        if isinstance(
            action,
            (
                SendChatMessageActionV1,
                UploadApprovedFixtureActionV1,
                InvokeApprovedApiRequestActionV1,
            ),
        ):
            if pending_response:
                return _reject(
                    context,
                    proposal,
                    GateRejectionCodeV1.INVALID_SEQUENCE,
                    "each target operation must be followed by one bounded wait",
                    action_id=action.action_id,
                )
            pending_response = True
            operation_count += 1
        elif isinstance(action, WaitForResponseActionV1):
            if not pending_response:
                return _reject(
                    context,
                    proposal,
                    GateRejectionCodeV1.INVALID_SEQUENCE,
                    "wait actions must immediately follow a target operation",
                    action_id=action.action_id,
                )
            pending_response = False
        else:
            return _reject(
                context,
                proposal,
                GateRejectionCodeV1.INVALID_SEQUENCE,
                "sequence contains an action outside the deterministic state machine",
                action_id=action.action_id,
            )
    if pending_response or operation_count == 0:
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.INVALID_SEQUENCE,
            (
                "sequence requires at least one operation and a bounded wait "
                "before evidence collection"
            ),
        )
    if (
        operation_count > context.limits.max_turns
        or proposal.estimated_turns > context.limits.max_turns
    ):
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.TURN_LIMIT,
            "proposal exceeds the bounded turn limit",
        )
    if proposal.estimated_turns < operation_count:
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.TURN_LIMIT,
            "proposal underestimates the number of target-operation turns",
        )

    login_path = target_profile.authentication.login_path
    if (
        not login_path.startswith("/")
        or _EXTERNAL_URL.match(login_path)
        or ".." in PurePosixPath(login_path).parts
    ):
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.ARBITRARY_AUTHORITY,
            "profile authentication path is not origin-relative",
            retryable=False,
        )

    profile_allowed = {
        (rule.method, rule.surface, rule.path) for rule in target_profile.allowed_endpoints
    }
    prohibited_paths = set(target_profile.prohibited_endpoints)
    authorized_bindings: dict[str, EndpointBindingV1] = {}

    def authorize_endpoint(
        endpoint_id: str,
        *,
        action_id: str,
        required_method: ApprovedHttpMethodV1,
        required_purpose: set[EndpointPurposeV1],
    ) -> GateRejectionV1 | None:
        binding = context.endpoint_bindings.get(endpoint_id)
        if binding is None:
            return _reject(
                context,
                proposal,
                GateRejectionCodeV1.UNKNOWN_ENDPOINT,
                "endpoint alias is absent from the controller-owned binding table",
                action_id=action_id,
            )
        if binding.method != required_method or binding.method not in {
            ApprovedHttpMethodV1.GET,
            ApprovedHttpMethodV1.POST,
        }:
            return _reject(
                context,
                proposal,
                GateRejectionCodeV1.METHOD_NOT_ALLOWLISTED,
                "endpoint method is not the exact approved GET/POST method",
                action_id=action_id,
            )
        if binding.purpose not in required_purpose:
            return _reject(
                context,
                proposal,
                GateRejectionCodeV1.ENDPOINT_NOT_ALLOWLISTED,
                "endpoint purpose does not match the proposed action",
                action_id=action_id,
            )
        if binding.path in prohibited_paths or _is_persistent_confirm_route(binding.path):
            return _reject(
                context,
                proposal,
                GateRejectionCodeV1.PROHIBITED_PERSISTENT_ROUTE,
                "persistent confirmation and other prohibited target routes cannot be executed",
                action_id=action_id,
                retryable=False,
            )
        if (binding.method.value, binding.surface, binding.path) not in profile_allowed:
            return _reject(
                context,
                proposal,
                GateRejectionCodeV1.ENDPOINT_NOT_ALLOWLISTED,
                "endpoint method, surface, and path are not in the loaded target profile",
                action_id=action_id,
            )
        authorized_bindings[binding.endpoint_id] = binding
        return None

    current_patient = _profile_patient(target_profile, context.current_patient_alias)
    allowed_patient_values = {context.current_patient_alias, current_patient.external_id}
    approved_fixtures: dict[str, ApprovedFixtureV1] = {}
    total_message_bytes = 0
    total_wait_seconds = 0.0
    total_upload_bytes = 0
    upload_count = 0
    for action in actions[3:-1]:
        if isinstance(action, SendChatMessageActionV1):
            size = len(action.message.encode("utf-8"))
            if size > target_profile.chat.message_max_bytes:
                return _reject(
                    context,
                    proposal,
                    GateRejectionCodeV1.MESSAGE_SIZE_LIMIT,
                    "chat message exceeds the target-profile byte limit",
                    action_id=action.action_id,
                )
            total_message_bytes += size
            rejection = authorize_endpoint(
                context.chat_endpoint_id,
                action_id=action.action_id,
                required_method=ApprovedHttpMethodV1.POST,
                required_purpose={EndpointPurposeV1.CHAT},
            )
            if rejection:
                return rejection
        elif isinstance(action, InvokeApprovedApiRequestActionV1):
            binding = context.endpoint_bindings.get(action.endpoint_id)
            if binding is None:
                return _reject(
                    context,
                    proposal,
                    GateRejectionCodeV1.UNKNOWN_ENDPOINT,
                    "API endpoint alias is absent from the binding table",
                    action_id=action.action_id,
                )
            if action.method == ApprovedHttpMethodV1.GET and action.body:
                return _reject(
                    context,
                    proposal,
                    GateRejectionCodeV1.ARBITRARY_AUTHORITY,
                    "GET actions cannot carry a request body",
                    action_id=action.action_id,
                )
            violation = _parameter_authority_violation(
                {"query_parameters": action.query, "body_parameters": action.body},
                allowed_patient_values=allowed_patient_values,
            )
            if violation:
                code = (
                    GateRejectionCodeV1.PATIENT_SCOPE_MISMATCH
                    if "patient scope" in violation
                    else GateRejectionCodeV1.ARBITRARY_AUTHORITY
                )
                return _reject(
                    context,
                    proposal,
                    code,
                    violation,
                    action_id=action.action_id,
                    retryable=False,
                )
            rejection = authorize_endpoint(
                action.endpoint_id,
                action_id=action.action_id,
                required_method=action.method,
                required_purpose={EndpointPurposeV1.GENERAL_API, EndpointPurposeV1.STATUS},
            )
            if rejection:
                return rejection
        elif isinstance(action, UploadApprovedFixtureActionV1):
            if (
                not target_profile.upload.enabled
                or target_profile.upload.persist_confirmation_enabled
                or target_profile.reset.staged_upload != "authenticated_reject"
            ):
                return _reject(
                    context,
                    proposal,
                    GateRejectionCodeV1.PROHIBITED_PERSISTENT_ROUTE,
                    (
                        "uploads require staging plus rejection cleanup; "
                        "persistent confirmation is forbidden"
                    ),
                    action_id=action.action_id,
                    retryable=False,
                )
            if action.upload_surface_id != context.upload_surface_id:
                return _reject(
                    context,
                    proposal,
                    GateRejectionCodeV1.FIXTURE_NOT_ALLOWLISTED,
                    "upload surface is not the controller-owned staged fixture surface",
                    action_id=action.action_id,
                )
            fixture = context.approved_fixtures.get(action.fixture_id)
            if fixture is None:
                return _reject(
                    context,
                    proposal,
                    GateRejectionCodeV1.UNKNOWN_FIXTURE,
                    "fixture ID is absent from the approved fixture registry",
                    action_id=action.action_id,
                )
            fixture_path = PurePosixPath(fixture.repository_relative_path)
            fixture_root = PurePosixPath(target_profile.upload.fixture_root)
            if (
                not fixture_path.is_relative_to(fixture_root)
                or fixture.document_type not in target_profile.upload.allowed_document_types
                or fixture.extension.lower()
                not in {extension.lower() for extension in target_profile.upload.allowed_extensions}
                or fixture.media_type != action.declared_media_type
                or fixture.size_bytes > target_profile.upload.max_bytes
                or fixture.pages > target_profile.upload.max_pages
            ):
                return _reject(
                    context,
                    proposal,
                    GateRejectionCodeV1.FIXTURE_NOT_ALLOWLISTED,
                    "fixture path/type/size/pages do not match the loaded upload profile",
                    action_id=action.action_id,
                    retryable=False,
                )
            for endpoint_id, purpose in (
                (context.upload_stage_endpoint_id, EndpointPurposeV1.UPLOAD_STAGE),
                (context.upload_reject_endpoint_id, EndpointPurposeV1.UPLOAD_REJECT),
            ):
                rejection = authorize_endpoint(
                    endpoint_id,
                    action_id=action.action_id,
                    required_method=ApprovedHttpMethodV1.POST,
                    required_purpose={purpose},
                )
                if rejection:
                    return rejection
            upload_count += 1
            total_upload_bytes += fixture.size_bytes
            approved_fixtures[fixture.fixture_id] = fixture
        elif isinstance(action, WaitForResponseActionV1):
            total_wait_seconds += action.timeout_seconds

    if total_message_bytes > context.limits.max_total_message_bytes:
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.MESSAGE_SIZE_LIMIT,
            "sequence exceeds the total chat-message byte limit",
        )
    if (
        upload_count > context.limits.max_upload_count
        or total_upload_bytes > context.limits.max_total_upload_bytes
    ):
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.UPLOAD_SIZE_LIMIT,
            "sequence exceeds the upload count or aggregate byte limit",
        )
    remaining_seconds = (context.campaign_deadline_at - checked_at).total_seconds()
    if (
        total_wait_seconds > context.limits.max_total_wait_seconds
        or total_wait_seconds > remaining_seconds
    ):
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.TIME_LIMIT,
            "bounded response waits exceed the campaign's remaining time",
        )

    sequence_hash = proposal_sequence_hash(proposal)
    if (
        context.attempted_sequence_counts.get(sequence_hash, 0)
        >= context.limits.max_sequence_repetitions
    ):
        return _reject(
            context,
            proposal,
            GateRejectionCodeV1.DUPLICATE_SEQUENCE,
            "exact sequence has reached its bounded repetition limit",
        )

    return ValidatedAttackV1(
        campaign_id=context.campaign_id,
        proposal=proposal,
        target_alias=context.target_alias,
        target_profile_version=target_profile.profile_version,
        selected_patient_alias=context.current_patient_alias,
        authorized_endpoint_bindings=list(authorized_bindings.values()),
        authorized_fixtures=list(approved_fixtures.values()),
        sequence_hash=sequence_hash,
        authorized_at=checked_at,
        expires_at=context.campaign_deadline_at,
    )


__all__ = [
    "ApprovedFixtureV1",
    "CampaignExecutionContextV1",
    "EndpointBindingV1",
    "EndpointPurposeV1",
    "ExecutionGateResultV1",
    "GateLimitsV1",
    "GateRejectionCodeV1",
    "GateRejectionV1",
    "ValidatedAttackV1",
    "proposal_sequence_hash",
    "validate_attack",
]
