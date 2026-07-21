"""Deterministic severity floors for proven invariant violations."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from agentforge.contracts.v1 import SeverityV1
from agentforge.regression.invariants import SecurityInvariantV1

from .deterministic import DeterministicEvaluationV1

_SEVERITY_RANK = {
    SeverityV1.NONE: 0,
    SeverityV1.INFORMATIONAL: 1,
    SeverityV1.LOW: 2,
    SeverityV1.MEDIUM: 3,
    SeverityV1.HIGH: 4,
    SeverityV1.CRITICAL: 5,
}


class SeverityAssessmentV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    severity: SeverityV1
    source_invariant_ids: list[str] = Field(default_factory=list)
    rationale: str = Field(min_length=1, max_length=512)


def higher_severity(left: SeverityV1, right: SeverityV1) -> SeverityV1:
    """Return the higher value without relying on enum lexical ordering."""

    return left if _SEVERITY_RANK[left] >= _SEVERITY_RANK[right] else right


def assess_deterministic_severity(
    evaluation: DeterministicEvaluationV1,
    invariants: list[SecurityInvariantV1],
) -> SeverityAssessmentV1:
    """Apply invariant-owned severity floors only to proven violations."""

    by_id = {invariant.invariant_id: invariant for invariant in invariants}
    missing = set(evaluation.proven_violation_ids) - set(by_id)
    if missing:
        raise ValueError("deterministic evaluation references unknown invariant IDs")
    severity = SeverityV1.NONE
    for invariant_id in evaluation.proven_violation_ids:
        severity = higher_severity(severity, by_id[invariant_id].severity_on_failure)
    if not evaluation.proven_violation_ids:
        return SeverityAssessmentV1(
            severity=SeverityV1.NONE,
            rationale="No deterministic invariant violation was proven",
        )
    return SeverityAssessmentV1(
        severity=severity,
        source_invariant_ids=evaluation.proven_violation_ids,
        rationale="Severity floor comes from the highest failed versioned security invariant",
    )


__all__ = ["SeverityAssessmentV1", "assess_deterministic_severity", "higher_severity"]
