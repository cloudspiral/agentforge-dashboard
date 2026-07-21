"""Independent Judge output contract."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from .common import (
    SCHEMA_VERSION_V1,
    Confidence,
    ContractModel,
    EvidenceReferenceV1,
    ExploitabilityV1,
    Identifier,
    SeverityV1,
    Sha256Hex,
    ShortText,
)


class JudgeVerdictKindV1(StrEnum):
    EXPLOIT_CONFIRMED = "exploit_confirmed"
    PARTIAL_SIGNAL = "partial_signal"
    ATTACK_BLOCKED = "attack_blocked"
    INCONCLUSIVE = "inconclusive"


class JudgeRecommendedActionV1(StrEnum):
    MUTATE = "mutate"
    NEW_ATTACK = "new_attack"
    REPRODUCE = "reproduce"
    CREATE_FINDING = "create_finding"
    RUN_REGRESSION = "run_regression"
    ESCALATE_HUMAN_REVIEW = "escalate_human_review"
    STOP = "stop"


class JudgeVerdictV1(ContractModel):
    schema_version: Literal[SCHEMA_VERSION_V1]
    verdict: JudgeVerdictKindV1
    severity: SeverityV1
    exploitability: ExploitabilityV1
    confidence: Confidence
    supporting_evidence_references: list[EvidenceReferenceV1] = Field(
        default_factory=list,
        max_length=50,
    )
    violated_security_invariants: list[Identifier] = Field(default_factory=list, max_length=50)
    observed_behavior: ShortText
    expected_behavior: ShortText
    recommended_next_action: JudgeRecommendedActionV1
    reproduce_again: bool
    create_or_update_finding: bool
    add_regression_candidate: bool
    rubric_version: Identifier
    rubric_hash: Sha256Hex
    deterministic_override_applied: bool = False
    deterministic_override_assertion_ids: list[Identifier] = Field(
        default_factory=list, max_length=50
    )

    @model_validator(mode="after")
    def verdict_is_evidence_backed(self) -> JudgeVerdictV1:
        if (
            self.verdict
            in {
                JudgeVerdictKindV1.EXPLOIT_CONFIRMED,
                JudgeVerdictKindV1.PARTIAL_SIGNAL,
            }
            and not self.supporting_evidence_references
        ):
            raise ValueError("confirmed or partial verdicts require supporting evidence")
        if self.deterministic_override_applied and not self.deterministic_override_assertion_ids:
            raise ValueError("a deterministic override requires assertion IDs")
        if not self.deterministic_override_applied and self.deterministic_override_assertion_ids:
            raise ValueError("override assertion IDs require deterministic_override_applied")
        if self.add_regression_candidate and not self.create_or_update_finding:
            raise ValueError("a regression candidate must map to a finding")
        return self


__all__ = ["JudgeRecommendedActionV1", "JudgeVerdictKindV1", "JudgeVerdictV1"]
