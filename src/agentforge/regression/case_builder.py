"""Build immutable, versioned regression cases from confirmed report snapshots."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from agentforge.contracts.v1 import (
    ActionExecutionStatusV1,
    AttackActionV1,
    AttackEvidenceV1,
    AuthenticateActionV1,
    CollectEvidenceActionV1,
    InvokeApprovedApiRequestActionV1,
    OwaspMappingsV1,
    ResetSessionActionV1,
    SelectSyntheticPatientActionV1,
    SendChatMessageActionV1,
    UploadApprovedFixtureActionV1,
    VulnerabilityReportV1,
    WaitForResponseActionV1,
)
from agentforge.orchestration.execution_gate import ValidatedAttackV1

from .invariants import SecurityInvariantV1


class RegressionModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RegressionSetupV1(RegressionModel):
    reset_strategy_id: str = Field(min_length=1, max_length=128)
    test_identity_alias: str = Field(min_length=1, max_length=128)
    expected_role: str = Field(min_length=1, max_length=128)
    selected_patient_alias: Literal["patient_a", "patient_b"]
    requires_approved_upload_fixture: bool


class RegressionTargetRequirementsV1(RegressionModel):
    target_profile_version: str = Field(min_length=1, max_length=255)
    source_target_version: str = Field(min_length=1, max_length=512)
    synthetic_only: Literal[True] = True


class RegressionCaseV1(RegressionModel):
    schema_version: Literal["v1"] = "v1"
    case_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    finding_id: str = Field(min_length=1, max_length=128)
    vulnerability_id: str = Field(min_length=1, max_length=128)
    case_version: int = Field(ge=1)
    active: bool = True
    category: str = Field(min_length=1, max_length=128)
    subcategory: str = Field(min_length=1, max_length=128)
    owasp_mappings: OwaspMappingsV1
    setup: RegressionSetupV1
    exact_ordered_sequence: list[AttackActionV1] = Field(min_length=6, max_length=30)
    expected_security_invariants: list[SecurityInvariantV1] = Field(min_length=1, max_length=50)
    deterministic_check_ids: list[str] = Field(min_length=1, max_length=50)
    judge_required: bool
    target_requirements: RegressionTargetRequirementsV1
    created_from_evidence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    sequence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: AwareDatetime

    @field_validator("expected_security_invariants")
    @classmethod
    def invariant_ids_are_unique(
        cls,
        value: list[SecurityInvariantV1],
    ) -> list[SecurityInvariantV1]:
        ids = [invariant.invariant_id for invariant in value]
        if len(ids) != len(set(ids)):
            raise ValueError("regression invariant IDs must be unique")
        return value

    @model_validator(mode="after")
    def deterministic_checks_match_invariants(self) -> RegressionCaseV1:
        ids = [invariant.invariant_id for invariant in self.expected_security_invariants]
        if self.deterministic_check_ids != ids:
            raise ValueError("deterministic_check_ids must preserve exact invariant order")
        return self


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _normalized_action(action: AttackActionV1) -> dict[str, object]:
    value = action.model_dump(mode="json")
    value.pop("action_id", None)
    value.pop("description", None)
    return value


def _validate_minimal_sequence(actions: list[AttackActionV1]) -> None:
    if len(actions) < 6:
        raise ValueError(
            "minimal regression sequence requires safety prefix, operation, wait, collect"
        )
    if not (
        isinstance(actions[0], ResetSessionActionV1)
        and isinstance(actions[1], AuthenticateActionV1)
        and isinstance(actions[2], SelectSyntheticPatientActionV1)
        and isinstance(actions[-1], CollectEvidenceActionV1)
    ):
        raise ValueError(
            "minimal sequence must preserve reset/auth/select and final evidence collection"
        )
    if any(
        isinstance(
            action,
            (
                ResetSessionActionV1,
                AuthenticateActionV1,
                SelectSyntheticPatientActionV1,
                CollectEvidenceActionV1,
            ),
        )
        for action in actions[3:-1]
    ):
        raise ValueError("identity setup and evidence collection cannot be duplicated")

    pending_wait = False
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
            if pending_wait:
                raise ValueError("every regression operation requires its own bounded wait")
            pending_wait = True
            operation_count += 1
        elif isinstance(action, WaitForResponseActionV1):
            if not pending_wait:
                raise ValueError("regression waits must immediately follow target operations")
            pending_wait = False
        else:
            raise ValueError("regression sequence contains an unsupported action ordering")
    if pending_wait or operation_count == 0:
        raise ValueError("minimal sequence needs an operation followed by a bounded wait")


def _is_ordered_action_subsequence(
    selected: list[AttackActionV1],
    candidates: list[AttackActionV1],
) -> bool:
    remaining = iter(candidates)
    for selected_action in selected:
        selected_json = selected_action.model_dump(mode="json")
        if not any(candidate.model_dump(mode="json") == selected_json for candidate in remaining):
            return False
    return True


def build_regression_case(
    *,
    finding_id: str,
    report: VulnerabilityReportV1,
    source_evidence: AttackEvidenceV1,
    validated_attack: ValidatedAttackV1,
    invariants: list[SecurityInvariantV1],
    case_version: int,
    created_at: AwareDatetime,
    judge_required: bool = False,
) -> RegressionCaseV1:
    """Freeze the confirmed minimal sequence and stable invariant fingerprint."""

    actions = report.minimal_reproducible_attack_sequence
    _validate_minimal_sequence(actions)
    validated_actions = validated_attack.proposal.ordered_actions
    if (
        validated_attack.campaign_id != source_evidence.campaign_id
        or validated_attack.proposal.category != report.category
        or validated_attack.proposal.subcategory != report.subcategory
        or not _is_ordered_action_subsequence(actions, validated_actions)
    ):
        raise ValueError(
            "report sequence and scope must match the deterministic gate authorization"
        )
    if source_evidence.target_version not in report.affected_target_versions:
        raise ValueError("source evidence target version is absent from the report")
    executed = source_evidence.executed_action_sequence
    successful_executed_actions = [
        execution.action
        for execution in executed
        if execution.status == ActionExecutionStatusV1.SUCCEEDED
    ]
    if not _is_ordered_action_subsequence(actions, successful_executed_actions):
        raise ValueError("report sequence must be an ordered subset of successful source evidence")
    if not invariants:
        raise ValueError("a regression case requires at least one security invariant")

    reset = actions[0]
    authenticate = actions[1]
    select = actions[2]
    if not (
        isinstance(reset, ResetSessionActionV1)
        and isinstance(authenticate, AuthenticateActionV1)
        and isinstance(select, SelectSyntheticPatientActionV1)
    ):
        raise ValueError("regression setup actions are malformed")
    if select.patient_alias not in {"patient_a", "patient_b"}:
        raise ValueError("regression cases may select only a named synthetic patient")
    if select.patient_alias != validated_attack.selected_patient_alias:
        raise ValueError("regression patient must match the deterministic gate authorization")

    sequence_json = [action.model_dump(mode="json") for action in actions]
    normalized = {
        "category": report.category,
        "subcategory": report.subcategory,
        "sequence": [_normalized_action(action) for action in actions],
        "invariants": [
            {
                key: value
                for key, value in invariant.model_dump(mode="json").items()
                if key not in {"description", "severity_on_failure"}
            }
            for invariant in invariants
        ],
    }
    fingerprint = _hash(normalized)
    case_id = f"REG-{report.vulnerability_id}-v{case_version}"
    if len(case_id) > 128:
        case_id = f"REG-{report.vulnerability_id[:80]}-{fingerprint[:12]}-v{case_version}"
    return RegressionCaseV1(
        case_id=case_id,
        finding_id=finding_id,
        vulnerability_id=report.vulnerability_id,
        case_version=case_version,
        category=report.category,
        subcategory=report.subcategory,
        owasp_mappings=report.owasp_mappings,
        setup=RegressionSetupV1(
            reset_strategy_id=reset.reset_strategy_id,
            test_identity_alias=authenticate.test_identity_alias,
            expected_role=authenticate.expected_role,
            selected_patient_alias=select.patient_alias,
            requires_approved_upload_fixture=any(
                isinstance(action, UploadApprovedFixtureActionV1) for action in actions
            ),
        ),
        exact_ordered_sequence=actions,
        expected_security_invariants=invariants,
        deterministic_check_ids=[invariant.invariant_id for invariant in invariants],
        judge_required=judge_required,
        target_requirements=RegressionTargetRequirementsV1(
            target_profile_version=validated_attack.target_profile_version,
            source_target_version=source_evidence.target_version,
        ),
        created_from_evidence_hash=source_evidence.evidence_hash,
        sequence_hash=_hash(sequence_json),
        fingerprint=fingerprint,
        created_at=created_at,
    )


__all__ = [
    "RegressionCaseV1",
    "RegressionSetupV1",
    "RegressionTargetRequirementsV1",
    "build_regression_case",
]
