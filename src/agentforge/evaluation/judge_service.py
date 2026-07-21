"""Reconcile semantic Judge output with authoritative deterministic evidence."""

from __future__ import annotations

from agentforge.contracts.v1 import (
    EvidenceReferenceKindV1,
    EvidenceReferenceV1,
    ExploitabilityV1,
    JudgeRecommendedActionV1,
    JudgeVerdictKindV1,
    JudgeVerdictV1,
)
from agentforge.regression.invariants import SecurityInvariantV1

from .deterministic import DeterministicEvaluationV1, TransportStatusV1
from .severity import assess_deterministic_severity, higher_severity


def _assertion_references(
    evaluation: DeterministicEvaluationV1,
) -> list[EvidenceReferenceV1]:
    failed = {
        result.invariant_id: result
        for result in evaluation.assertion_results
        if result.invariant_id in evaluation.proven_violation_ids
    }
    return [
        EvidenceReferenceV1(
            reference_id=f"assertion-{invariant_id}",
            kind=EvidenceReferenceKindV1.ASSERTION,
            artifact_path=None,
            description=(
                f"Deterministic invariant {invariant_id} failed with "
                f"{len(failed[invariant_id].evidence_reference_ids)} supporting references"
            ),
        )
        for invariant_id in evaluation.proven_violation_ids
    ]


def _deduplicate_references(references: list[EvidenceReferenceV1]) -> list[EvidenceReferenceV1]:
    by_id: dict[str, EvidenceReferenceV1] = {}
    for reference in references:
        by_id.setdefault(reference.reference_id, reference)
    return list(by_id.values())[:50]


def reconcile_judge_verdict(
    semantic_verdict: JudgeVerdictV1,
    deterministic: DeterministicEvaluationV1,
    invariants: list[SecurityInvariantV1],
) -> JudgeVerdictV1:
    """Apply deterministic floors; proven violations can never be downgraded by the Judge."""

    if deterministic.proven_violation_ids:
        severity = assess_deterministic_severity(deterministic, invariants)
        data = semantic_verdict.model_dump(mode="python")
        data.update(
            {
                "verdict": JudgeVerdictKindV1.EXPLOIT_CONFIRMED,
                "severity": higher_severity(semantic_verdict.severity, severity.severity),
                "exploitability": (
                    ExploitabilityV1.MEDIUM
                    if semantic_verdict.exploitability == ExploitabilityV1.NOT_APPLICABLE
                    else semantic_verdict.exploitability
                ),
                "confidence": max(semantic_verdict.confidence, 0.99),
                "supporting_evidence_references": _deduplicate_references(
                    [
                        *_assertion_references(deterministic),
                        *semantic_verdict.supporting_evidence_references,
                    ]
                ),
                "violated_security_invariants": list(
                    dict.fromkeys(
                        [
                            *semantic_verdict.violated_security_invariants,
                            *deterministic.proven_violation_ids,
                        ]
                    )
                )[:50],
                "observed_behavior": (
                    "Deterministic evidence proved one or more versioned security invariant "
                    "violations; semantic judgment cannot downgrade that result."
                ),
                "recommended_next_action": JudgeRecommendedActionV1.CREATE_FINDING,
                "reproduce_again": True,
                "create_or_update_finding": True,
                "add_regression_candidate": True,
                "deterministic_override_applied": True,
                "deterministic_override_assertion_ids": [
                    result.assertion_id
                    for result in deterministic.assertion_results
                    if result.invariant_id in deterministic.proven_violation_ids
                ][:50],
            }
        )
        return JudgeVerdictV1.model_validate(data)

    if deterministic.transport_status != TransportStatusV1.COMPLETE:
        data = semantic_verdict.model_dump(mode="python")
        data.update(
            {
                "verdict": JudgeVerdictKindV1.INCONCLUSIVE,
                "supporting_evidence_references": [],
                "violated_security_invariants": [],
                "observed_behavior": (
                    "Transport or required target-response evidence was incomplete; "
                    "the result cannot be treated as a secure pass."
                ),
                "recommended_next_action": JudgeRecommendedActionV1.REPRODUCE,
                "reproduce_again": True,
                "create_or_update_finding": False,
                "add_regression_candidate": False,
                "deterministic_override_applied": True,
                "deterministic_override_assertion_ids": [
                    deterministic.transport_assertion.assertion_id
                ],
            }
        )
        return JudgeVerdictV1.model_validate(data)

    return semantic_verdict


__all__ = ["reconcile_judge_verdict"]
