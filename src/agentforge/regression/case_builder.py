"""Build immutable, versioned Judge-driven regression cases."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from agentforge.contracts.v1 import (
    ActionExecutionStatusV1,
    AttackActionV1,
    AttackEvidenceV1,
    AuthenticateActionV1,
    CollectEvidenceActionV1,
    InvokeApprovedApiRequestActionV1,
    JudgeVerdictV1,
    OwaspMappingsV1,
    ResetSessionActionV1,
    SelectSyntheticPatientActionV1,
    SendChatMessageActionV1,
    UploadApprovedFixtureActionV1,
    VulnerabilityReportV1,
    WaitForResponseActionV1,
)
from agentforge.orchestration.execution_gate import ValidatedAttackV1


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
    judge_context: dict[str, Any]
    expected_behavior: str = Field(min_length=1, max_length=20_000)
    target_requirements: RegressionTargetRequirementsV1
    created_from_evidence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    sequence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: AwareDatetime


class RegressionCaseV2(RegressionModel):
    schema_version: Literal["v2"] = "v2"
    case_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    finding_id: str = Field(min_length=1, max_length=128)
    vulnerability_id: str = Field(min_length=1, max_length=128)
    finding_key: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    source_provenance: str = Field(min_length=1, max_length=40)
    required_replays: Literal[2] = 2
    case_version: int = Field(ge=1)
    active: bool = True
    category: str = Field(min_length=1, max_length=128)
    subcategory: str = Field(min_length=1, max_length=128)
    owasp_mappings: OwaspMappingsV1
    setup: RegressionSetupV1
    exact_ordered_sequence: list[AttackActionV1] = Field(min_length=6, max_length=30)
    judge_context: dict[str, Any]
    expected_behavior: str = Field(min_length=1, max_length=20_000)
    target_requirements: RegressionTargetRequirementsV1
    created_from_evidence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    sequence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: AwareDatetime


AnyRegressionCase = RegressionCaseV1 | RegressionCaseV2


def _hash(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


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
            raise ValueError("regression sequence contains unsupported action ordering")
    if pending_wait or operation_count == 0:
        raise ValueError("minimal sequence needs an operation followed by a bounded wait")


def _is_ordered_action_subsequence(
    selected: list[AttackActionV1],
    candidates: list[AttackActionV1],
) -> bool:
    remaining = iter(candidates)
    return all(
        any(
            candidate.model_dump(mode="json") == selected_action.model_dump(mode="json")
            for candidate in remaining
        )
        for selected_action in selected
    )


def build_regression_case(
    *,
    finding_id: str,
    report: VulnerabilityReportV1,
    judge_verdict: JudgeVerdictV1,
    source_evidence: AttackEvidenceV1,
    validated_attack: ValidatedAttackV1,
    case_version: int,
    created_at: AwareDatetime,
    source_provenance: str,
) -> RegressionCaseV2:
    """Freeze the exact successful attack and the Judge context that confirmed it."""

    if not judge_verdict.finding_key:
        raise ValueError("confirmed exploits require a semantic finding key")
    actions = report.minimal_reproducible_attack_sequence
    _validate_minimal_sequence(actions)
    if (
        validated_attack.campaign_id != source_evidence.campaign_id
        or validated_attack.proposal.category != report.category
        or validated_attack.proposal.subcategory != report.subcategory
        or not _is_ordered_action_subsequence(actions, validated_attack.proposal.ordered_actions)
    ):
        raise ValueError("report sequence and scope must match gate authorization")
    if source_evidence.target_version not in report.affected_target_versions:
        raise ValueError("source evidence target version is absent from the report")
    successful_actions = [
        execution.action
        for execution in source_evidence.executed_action_sequence
        if execution.status == ActionExecutionStatusV1.SUCCEEDED
    ]
    if not _is_ordered_action_subsequence(actions, successful_actions):
        raise ValueError("report sequence must be an ordered subset of successful evidence")

    reset, authenticate, select = actions[:3]
    if not (
        isinstance(reset, ResetSessionActionV1)
        and isinstance(authenticate, AuthenticateActionV1)
        and isinstance(select, SelectSyntheticPatientActionV1)
    ):
        raise ValueError("regression setup actions are malformed")
    if select.patient_alias != validated_attack.selected_patient_alias:
        raise ValueError("regression patient must match gate authorization")

    sequence_json = [action.model_dump(mode="json") for action in actions]
    fingerprint = _hash(
        {
            "finding_id": finding_id,
            "evidence_hash": source_evidence.evidence_hash,
            "sequence": sequence_json,
        }
    )
    case_id = f"REG-{report.vulnerability_id}-v{case_version}"
    if len(case_id) > 128:
        case_id = f"REG-{report.vulnerability_id[:80]}-{fingerprint[:12]}-v{case_version}"
    return RegressionCaseV2(
        case_id=case_id,
        finding_id=finding_id,
        vulnerability_id=report.vulnerability_id,
        finding_key=judge_verdict.finding_key,
        source_provenance=source_provenance,
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
        judge_context={
            "finding_key": judge_verdict.finding_key,
            "violated_security_invariants": judge_verdict.violated_security_invariants,
            "original_judge_verdict": judge_verdict.model_dump(mode="json"),
            "original_execution_evidence": source_evidence.model_dump(mode="json"),
        },
        expected_behavior=judge_verdict.expected_behavior,
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
    "AnyRegressionCase",
    "RegressionCaseV1",
    "RegressionCaseV2",
    "RegressionSetupV1",
    "RegressionTargetRequirementsV1",
    "build_regression_case",
]
