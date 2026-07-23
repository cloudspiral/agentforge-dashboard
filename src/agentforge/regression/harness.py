"""Judge-authoritative regression outcome semantics."""

from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from agentforge.contracts.v1 import (
    AttackEvidenceV1,
    JudgeVerdictKindV1,
    JudgeVerdictV1,
    ValidationOutcomeV1,
)

from .case_builder import RegressionCaseV1

RegressionOutcomeV1 = ValidationOutcomeV1


class RegressionResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["v1"] = "v1"
    case_id: str
    case_version: int = Field(ge=1)
    target_version: str = Field(min_length=1, max_length=512)
    outcome: RegressionOutcomeV1
    judge_verdict: JudgeVerdictV1 | None
    reopen_finding: bool
    evidence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    summary: str = Field(min_length=1, max_length=512)
    started_at: AwareDatetime
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def outcome_is_consistent(self) -> RegressionResultV1:
        if self.completed_at < self.started_at:
            raise ValueError("regression completion cannot precede start")
        if self.reopen_finding != (self.outcome == RegressionOutcomeV1.VULNERABILITY_REPRODUCED):
            raise ValueError("only a reproduced vulnerability reopens a finding")
        if self.outcome != RegressionOutcomeV1.ERROR and self.judge_verdict is None:
            raise ValueError("a non-error regression outcome requires a Judge verdict")
        return self


def _sequence_matches(case: RegressionCaseV1, evidence: AttackEvidenceV1) -> bool:
    return len(evidence.executed_action_sequence) == len(case.exact_ordered_sequence) and all(
        execution.action.model_dump(mode="json") == action.model_dump(mode="json")
        for execution, action in zip(
            evidence.executed_action_sequence,
            case.exact_ordered_sequence,
            strict=True,
        )
    )


def evaluate_regression(
    case: RegressionCaseV1,
    evidence: AttackEvidenceV1,
    *,
    judge_verdict: JudgeVerdictV1 | None,
) -> RegressionResultV1:
    """Map the Judge's verdict to one regression outcome without semantic overrides."""

    if not case.active:
        raise ValueError("inactive regression cases cannot be evaluated")
    if not _sequence_matches(case, evidence) or judge_verdict is None:
        outcome = RegressionOutcomeV1.ERROR
        summary = (
            "Executed sequence did not match the saved case"
            if not _sequence_matches(case, evidence)
            else "The Judge did not return a valid verdict"
        )
    elif judge_verdict.verdict == JudgeVerdictKindV1.EXPLOIT_CONFIRMED:
        outcome = RegressionOutcomeV1.VULNERABILITY_REPRODUCED
        summary = "The Judge confirmed that the saved vulnerability remains exploitable"
    elif judge_verdict.verdict == JudgeVerdictKindV1.ATTACK_BLOCKED:
        outcome = RegressionOutcomeV1.SECURE_PASS
        summary = "The Judge found the saved attack blocked by the target"
    else:
        outcome = RegressionOutcomeV1.INCONCLUSIVE
        summary = "The Judge returned partial or inconclusive evidence"

    return RegressionResultV1(
        case_id=case.case_id,
        case_version=case.case_version,
        target_version=evidence.target_version,
        outcome=outcome,
        judge_verdict=judge_verdict,
        reopen_finding=outcome == RegressionOutcomeV1.VULNERABILITY_REPRODUCED,
        evidence_hash=evidence.evidence_hash,
        summary=summary,
        started_at=evidence.started_at,
        completed_at=evidence.completed_at,
    )


__all__ = ["RegressionOutcomeV1", "RegressionResultV1", "evaluate_regression"]
