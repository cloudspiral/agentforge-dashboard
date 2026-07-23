"""Independent Judge output contract."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field

from .common import (
    SCHEMA_VERSION_V1,
    Confidence,
    ContractModel,
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


class JudgeVerdictV1(ContractModel):
    schema_version: Literal[SCHEMA_VERSION_V1]
    verdict: JudgeVerdictKindV1
    severity: SeverityV1
    exploitability: ExploitabilityV1
    confidence: Confidence
    violated_security_invariants: list[Identifier] = Field(default_factory=list, max_length=50)
    observed_behavior: ShortText
    expected_behavior: ShortText
    rubric_version: Identifier
    rubric_hash: Sha256Hex


__all__ = ["JudgeVerdictKindV1", "JudgeVerdictV1"]
