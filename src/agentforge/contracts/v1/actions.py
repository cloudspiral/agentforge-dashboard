"""Allowlisted action vocabulary for proposed and executed attacks."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, JsonValue, StringConstraints, field_validator

from .common import ContractModel, Identifier, ShortText, validate_sanitized_mapping


class ActionTypeV1(StrEnum):
    RESET_SESSION = "reset_session"
    AUTHENTICATE = "authenticate"
    SELECT_SYNTHETIC_PATIENT = "select_synthetic_patient"
    SEND_CHAT_MESSAGE = "send_chat_message"
    UPLOAD_APPROVED_FIXTURE = "upload_approved_fixture"
    INVOKE_APPROVED_API_REQUEST = "invoke_approved_api_request"
    WAIT_FOR_RESPONSE = "wait_for_response"
    COLLECT_EVIDENCE = "collect_evidence"


class ActionBaseV1(ContractModel):
    action_id: Identifier
    description: ShortText


class ResetSessionActionV1(ActionBaseV1):
    action_type: Literal[ActionTypeV1.RESET_SESSION]
    reset_strategy_id: Identifier
    require_clean_context: bool = True


class AuthenticationSessionSourceV1(StrEnum):
    ENVIRONMENT_CREDENTIALS = "environment_credentials"
    EPHEMERAL_SAVED_TEST_SESSION = "ephemeral_saved_test_session"


class AuthenticateActionV1(ActionBaseV1):
    action_type: Literal[ActionTypeV1.AUTHENTICATE]
    session_source: AuthenticationSessionSourceV1
    test_identity_alias: Identifier
    expected_role: Identifier


class SelectSyntheticPatientActionV1(ActionBaseV1):
    action_type: Literal[ActionTypeV1.SELECT_SYNTHETIC_PATIENT]
    patient_alias: Identifier
    verify_selected_context: bool = True


ChatMessage = Annotated[str, StringConstraints(min_length=1, max_length=4_000)]


class SendChatMessageActionV1(ActionBaseV1):
    action_type: Literal[ActionTypeV1.SEND_CHAT_MESSAGE]
    message: ChatMessage
    conversation_alias: Identifier | None = None
    await_response: bool = True

    @field_validator("message")
    @classmethod
    def message_has_no_nul(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("chat messages cannot contain NUL bytes")
        return value


class UploadApprovedFixtureActionV1(ActionBaseV1):
    action_type: Literal[ActionTypeV1.UPLOAD_APPROVED_FIXTURE]
    fixture_id: Identifier
    upload_surface_id: Identifier
    declared_media_type: Annotated[
        str,
        StringConstraints(
            min_length=3,
            max_length=100,
            pattern=r"^[A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+$",
        ),
    ]


class ApprovedHttpMethodV1(StrEnum):
    GET = "GET"
    POST = "POST"


class InvokeApprovedApiRequestActionV1(ActionBaseV1):
    action_type: Literal[ActionTypeV1.INVOKE_APPROVED_API_REQUEST]
    endpoint_id: Identifier
    method: ApprovedHttpMethodV1
    query: dict[str, JsonValue] = Field(default_factory=dict, max_length=25)
    body: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("query", "body")
    @classmethod
    def request_metadata_is_sanitized(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        return validate_sanitized_mapping(value)


class WaitForResponseActionV1(ActionBaseV1):
    action_type: Literal[ActionTypeV1.WAIT_FOR_RESPONSE]
    timeout_seconds: float = Field(gt=0.0, le=120.0, allow_inf_nan=False)
    expected_event: Identifier | None = None


class EvidenceKindV1(StrEnum):
    TRANSCRIPT = "transcript"
    HTTP_METADATA = "http_metadata"
    TOOL_CALLS = "tool_calls"
    SIDE_EFFECTS = "side_effects"
    SCREENSHOT = "screenshot"
    BROWSER_TRACE = "browser_trace"


class CollectEvidenceActionV1(ActionBaseV1):
    action_type: Literal[ActionTypeV1.COLLECT_EVIDENCE]
    evidence_kinds: list[EvidenceKindV1] = Field(min_length=1, max_length=6)
    capture_on: Literal["always", "failure", "confirmed_signal"] = "always"

    @field_validator("evidence_kinds")
    @classmethod
    def evidence_kinds_are_unique(cls, value: list[EvidenceKindV1]) -> list[EvidenceKindV1]:
        if len(value) != len(set(value)):
            raise ValueError("evidence_kinds must not contain duplicates")
        return value


AttackActionV1 = Annotated[
    ResetSessionActionV1
    | AuthenticateActionV1
    | SelectSyntheticPatientActionV1
    | SendChatMessageActionV1
    | UploadApprovedFixtureActionV1
    | InvokeApprovedApiRequestActionV1
    | WaitForResponseActionV1
    | CollectEvidenceActionV1,
    Field(discriminator="action_type"),
]


__all__ = [
    "ActionTypeV1",
    "ApprovedHttpMethodV1",
    "AttackActionV1",
    "AuthenticateActionV1",
    "AuthenticationSessionSourceV1",
    "CollectEvidenceActionV1",
    "EvidenceKindV1",
    "InvokeApprovedApiRequestActionV1",
    "ResetSessionActionV1",
    "SelectSyntheticPatientActionV1",
    "SendChatMessageActionV1",
    "UploadApprovedFixtureActionV1",
    "WaitForResponseActionV1",
]
