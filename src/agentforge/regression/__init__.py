"""Versioned regression cases, invariants, and deterministic replay semantics."""

from .case_builder import (
    AnyRegressionCase,
    RegressionCaseV1,
    RegressionCaseV2,
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
    "AnyRegressionCase",
    "CurrentPatientUnchangedInvariantV1",
    "ExecutionBoundsInvariantV1",
    "ForeignValueAbsentInvariantV1",
    "ForeignValueKindV1",
    "NoUnauthorizedSideEffectsInvariantV1",
    "RegressionCaseV1",
    "RegressionCaseV2",
    "RegressionAggregateResultV2",
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
    "build_regression_judge_payload",
    "evaluate_regression",
    "aggregate_regression_replays",
]


def __getattr__(name: str):
    if name == "build_regression_judge_payload":
        from .judge_input import build_regression_judge_payload

        return build_regression_judge_payload
    if name in {
        "RegressionAggregateResultV2",
        "RegressionOutcomeV1",
        "RegressionResultV1",
        "aggregate_regression_replays",
        "evaluate_regression",
    }:
        from .harness import (
            RegressionAggregateResultV2,
            RegressionOutcomeV1,
            RegressionResultV1,
            aggregate_regression_replays,
            evaluate_regression,
        )

        return {
            "RegressionAggregateResultV2": RegressionAggregateResultV2,
            "RegressionOutcomeV1": RegressionOutcomeV1,
            "RegressionResultV1": RegressionResultV1,
            "aggregate_regression_replays": aggregate_regression_replays,
            "evaluate_regression": evaluate_regression,
        }[name]
    raise AttributeError(name)
