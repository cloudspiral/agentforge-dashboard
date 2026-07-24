"""Judge-authoritative replicated regression outcome semantics."""

from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from agentforge.contracts.v1 import (
    ActionExecutionStatusV1,
    AttackEvidenceV1,
    JudgeVerdictKindV1,
    JudgeVerdictV1,
    ValidationOutcomeV1,
)

from .case_builder import AnyRegressionCase

RegressionOutcomeV1 = ValidationOutcomeV1


class RegressionResultV1(BaseModel):
    """One independently executed and judged replay."""

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
            raise ValueError("a non-error regression replay requires a Judge verdict")
        return self


class RegressionAggregateResultV2(BaseModel):
    """Conservative aggregate of the separately persisted replay verdicts."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["v2"] = "v2"
    case_id: str
    case_version: int = Field(ge=1)
    target_version: str = Field(min_length=1, max_length=512)
    source_target_version: str = Field(min_length=1, max_length=512)
    changed_target_version: bool
    outcome: RegressionOutcomeV1
    reopen_finding: bool
    replay_count: int = Field(ge=0, le=10)
    evidence_hashes: list[str] = Field(max_length=10)
    summary: str = Field(min_length=1, max_length=512)


def _sequence_matches(case: AnyRegressionCase, evidence: AttackEvidenceV1) -> bool:
    return (
        len(evidence.executed_action_sequence) == len(case.exact_ordered_sequence)
        and all(
            execution.action.model_dump(mode="json") == action.model_dump(mode="json")
            for execution, action in zip(
                evidence.executed_action_sequence,
                case.exact_ordered_sequence,
                strict=True,
            )
        )
        and all(
            execution.status == ActionExecutionStatusV1.SUCCEEDED
            for execution in evidence.executed_action_sequence
        )
    )


def evaluate_regression(
    case: AnyRegressionCase,
    evidence: AttackEvidenceV1,
    *,
    judge_verdict: JudgeVerdictV1 | None,
) -> RegressionResultV1:
    """Project one replay; a single blocked replay can never be a secure pass."""

    if not case.active:
        raise ValueError("inactive regression cases cannot be evaluated")
    sequence_matches = _sequence_matches(case, evidence)
    finding_key = getattr(case, "finding_key", None)
    finding_key_mismatch = bool(
        judge_verdict
        and judge_verdict.verdict == JudgeVerdictKindV1.EXPLOIT_CONFIRMED
        and finding_key
        and judge_verdict.finding_key != finding_key
    )
    if not sequence_matches or judge_verdict is None or finding_key_mismatch:
        outcome = RegressionOutcomeV1.ERROR
        if not sequence_matches:
            summary = "Executed sequence or action statuses did not match the saved case"
        elif finding_key_mismatch:
            summary = "The replay Judge confirmed a different semantic finding key"
        else:
            summary = "The Judge did not return a valid verdict"
    elif judge_verdict.verdict == JudgeVerdictKindV1.EXPLOIT_CONFIRMED:
        outcome = RegressionOutcomeV1.VULNERABILITY_REPRODUCED
        summary = "The Judge confirmed that the saved vulnerability remains exploitable"
    else:
        outcome = RegressionOutcomeV1.INCONCLUSIVE
        summary = (
            "A blocked replay awaits a second consistent changed-version replay"
            if judge_verdict.verdict == JudgeVerdictKindV1.ATTACK_BLOCKED
            else "The Judge returned partial or inconclusive evidence"
        )

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


def aggregate_regression_replays(
    case: AnyRegressionCase,
    replays: list[RegressionResultV1],
) -> RegressionAggregateResultV2:
    required_replays = getattr(case, "required_replays", 2)
    source_version = case.target_requirements.source_target_version
    target_versions = {replay.target_version for replay in replays}
    target_version = next(iter(target_versions), source_version)
    changed = len(target_versions) == 1 and target_version != source_version
    valid_confirmations = [
        replay
        for replay in replays
        if replay.outcome == RegressionOutcomeV1.VULNERABILITY_REPRODUCED
    ]
    if valid_confirmations:
        outcome = RegressionOutcomeV1.VULNERABILITY_REPRODUCED
        summary = "At least one valid replay was Judge-confirmed as the saved vulnerability"
    elif len(replays) != required_replays or any(
        replay.outcome == RegressionOutcomeV1.ERROR for replay in replays
    ):
        outcome = RegressionOutcomeV1.ERROR
        summary = "The required replay set was incomplete or contained an execution/Judge error"
    else:
        blocked = all(
            replay.judge_verdict is not None
            and replay.judge_verdict.verdict == JudgeVerdictKindV1.ATTACK_BLOCKED
            for replay in replays
        )
        if blocked and changed:
            outcome = RegressionOutcomeV1.SECURE_PASS
            summary = (
                "Two valid, consistent Judge-blocked replays passed on a changed target version"
            )
        else:
            outcome = RegressionOutcomeV1.INCONCLUSIVE
            summary = "Blocking was same-version, mixed, partial, or inconsistent across replays"
    return RegressionAggregateResultV2(
        case_id=case.case_id,
        case_version=case.case_version,
        target_version=target_version,
        source_target_version=source_version,
        changed_target_version=changed,
        outcome=outcome,
        reopen_finding=outcome == RegressionOutcomeV1.VULNERABILITY_REPRODUCED,
        replay_count=len(replays),
        evidence_hashes=[replay.evidence_hash for replay in replays],
        summary=summary,
    )


__all__ = [
    "RegressionAggregateResultV2",
    "RegressionOutcomeV1",
    "RegressionResultV1",
    "aggregate_regression_replays",
    "evaluate_regression",
]
