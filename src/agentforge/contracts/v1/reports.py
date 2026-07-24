"""Documentation-agent input and vulnerability-report output contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import AwareDatetime, Field, model_validator

from .actions import AttackActionV1
from .common import (
    SCHEMA_VERSION_V1,
    Confidence,
    ContractModel,
    FindingStatusV1,
    Identifier,
    LongText,
    OwaspMappingsV1,
    SeverityV1,
    Sha256Hex,
    ShortText,
)
from .evidence import AttackEvidenceV1, TranscriptTurnV1
from .judge import JudgeVerdictV1


class ConfirmedFindingSnapshotV1(ContractModel):
    finding_id: Identifier
    vulnerability_id: Identifier
    source_attempt_id: Identifier
    source_fingerprint: Sha256Hex
    title: ShortText
    severity: SeverityV1
    status: FindingStatusV1
    category: Identifier
    subcategory: Identifier
    owasp_mappings: OwaspMappingsV1
    description: LongText
    clinical_impact: LongText
    observed_behavior: LongText
    expected_behavior: LongText
    first_seen_target_version: ShortText
    last_seen_target_version: ShortText
    frozen_at: AwareDatetime


class ValidationOutcomeV1(StrEnum):
    SECURE_PASS = "secure_pass"  # noqa: S105 - regression outcome, not a credential
    VULNERABILITY_REPRODUCED = "vulnerability_reproduced"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class FixValidationResultV1(ContractModel):
    target_version: ShortText
    outcome: ValidationOutcomeV1
    validated_at: AwareDatetime
    regression_run_id: Identifier | None = None
    evidence_hash: Sha256Hex | None = None
    summary: ShortText


class DocumentationRequestV1(ContractModel):
    schema_version: Literal[SCHEMA_VERSION_V1]
    confirmed_finding_snapshot: ConfirmedFindingSnapshotV1
    exact_action_sequence: list[AttackActionV1] = Field(min_length=1, max_length=30)
    evidence: AttackEvidenceV1
    judge_verdict: JudgeVerdictV1
    target_versions: list[ShortText] = Field(min_length=1, max_length=50)
    existing_validation_history: list[FixValidationResultV1] = Field(
        default_factory=list,
        max_length=100,
    )
    required_report_status: FindingStatusV1

    @model_validator(mode="after")
    def request_references_one_frozen_finding(self) -> DocumentationRequestV1:
        snapshot = self.confirmed_finding_snapshot
        if self.evidence.target_version not in self.target_versions:
            raise ValueError("evidence target version must be included in target_versions")
        if snapshot.last_seen_target_version not in self.target_versions:
            raise ValueError("last-seen target version must be included in target_versions")
        if self.required_report_status != snapshot.status:
            raise ValueError("required report status must match the frozen finding snapshot")
        return self


class VulnerabilityReportV1(ContractModel):
    report_schema_version: Literal[SCHEMA_VERSION_V1]
    vulnerability_id: Identifier
    title: ShortText
    severity: SeverityV1
    status: FindingStatusV1
    category: Identifier
    subcategory: Identifier
    owasp_mappings: OwaspMappingsV1
    affected_target_versions: list[ShortText] = Field(min_length=1, max_length=50)
    description: LongText
    clinical_impact: LongText
    prerequisites: list[ShortText] = Field(default_factory=list, max_length=30)
    minimal_reproducible_attack_sequence: list[AttackActionV1] = Field(
        min_length=1,
        max_length=30,
    )
    observed_behavior: LongText
    expected_behavior: LongText
    source_attempt_id: Identifier
    evidence_hash: Sha256Hex
    exact_transcript: list[TranscriptTurnV1] = Field(default_factory=list, max_length=100)
    recommended_remediation_approach: LongText
    current_fix_validation_results: list[FixValidationResultV1] = Field(
        default_factory=list,
        max_length=100,
    )
    confidence: Confidence
    created_at: AwareDatetime
    updated_at: AwareDatetime

    @model_validator(mode="after")
    def report_is_temporally_consistent(self) -> VulnerabilityReportV1:
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        return self


__all__ = [
    "ConfirmedFindingSnapshotV1",
    "DocumentationRequestV1",
    "FixValidationResultV1",
    "ValidationOutcomeV1",
    "VulnerabilityReportV1",
]
