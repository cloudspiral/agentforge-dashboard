"""Versioned regression cases, invariants, and deterministic replay semantics."""

from .case_builder import (
    RegressionCaseV1,
    RegressionSetupV1,
    RegressionTargetRequirementsV1,
    build_regression_case,
)
from .invariants import (
    CurrentPatientUnchangedInvariantV1,
    ExecutionBoundsInvariantV1,
    ForeignValueAbsentInvariantV1,
    ForeignValueKindV1,
    NoUnauthorizedSideEffectsInvariantV1,
    RequiredEvidenceChannelV1,
    RequiredEvidenceInvariantV1,
    SecurityInvariantV1,
    ToolScopeInvariantV1,
    TransportSucceededInvariantV1,
)

__all__ = [
    "CurrentPatientUnchangedInvariantV1",
    "ExecutionBoundsInvariantV1",
    "ForeignValueAbsentInvariantV1",
    "ForeignValueKindV1",
    "NoUnauthorizedSideEffectsInvariantV1",
    "RegressionCaseV1",
    "RegressionOutcomeV1",
    "RegressionResultV1",
    "RegressionSetupV1",
    "RegressionTargetRequirementsV1",
    "RequiredEvidenceChannelV1",
    "RequiredEvidenceInvariantV1",
    "SecurityInvariantV1",
    "ToolScopeInvariantV1",
    "TransportSucceededInvariantV1",
    "build_regression_case",
    "evaluate_regression",
]


def __getattr__(name: str):
    if name in {"RegressionOutcomeV1", "RegressionResultV1", "evaluate_regression"}:
        from .harness import RegressionOutcomeV1, RegressionResultV1, evaluate_regression

        return {
            "RegressionOutcomeV1": RegressionOutcomeV1,
            "RegressionResultV1": RegressionResultV1,
            "evaluate_regression": evaluate_regression,
        }[name]
    raise AttributeError(name)
