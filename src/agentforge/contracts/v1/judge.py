"""Independent Judge output contract."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, ValidationInfo, model_validator

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
    finding_key: Identifier | None = None
    violated_security_invariants: list[Identifier] = Field(default_factory=list, max_length=50)
    observed_behavior: ShortText
    expected_behavior: ShortText
    rubric_version: Identifier
    rubric_hash: Sha256Hex

    @model_validator(mode="after")
    def confirmed_exploit_has_semantic_key(self, info: ValidationInfo) -> JudgeVerdictV1:
        allow_legacy = bool(
            info.context
            and info.context.get("allow_legacy_confirmed_verdict_without_finding_key") is True
        )
        if (
            self.verdict == JudgeVerdictKindV1.EXPLOIT_CONFIRMED
            and self.finding_key is None
            and not allow_legacy
        ):
            raise ValueError("confirmed exploits require a semantic finding_key")
        return self


__all__ = ["JudgeVerdictKindV1", "JudgeVerdictV1"]
