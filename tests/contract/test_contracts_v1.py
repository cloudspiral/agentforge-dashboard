"""Round trips and authority boundaries for public v1 contracts."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agentforge.contracts.v1 import (
    AgentErrorV1,
    AttackEvidenceV1,
    CampaignObjectiveV1,
    DocumentationRequestV1,
    JudgeVerdictV1,
    OrchestratorDecisionV1,
    ProposedAttackV1,
    VulnerabilityReportV1,
)

NOW = "2026-07-23T09:00:00Z"
LATER = "2026-07-23T09:00:01Z"
HASH_A = "a" * 64
HASH_B = "b" * 64


def mappings() -> dict[str, object]:
    return {
        "web_top_10_version": "2021",
        "web_top_10": ["A01:2021"],
        "llm_top_10_version": "2025",
        "llm_top_10": ["LLM01:2025"],
    }


def actions() -> list[dict[str, object]]:
    return [
        {
            "action_id": "a0",
            "description": "Reset the synthetic conversation",
            "action_type": "reset_session",
            "reset_strategy_id": "new_conversation",
            "require_clean_context": True,
        },
        {
            "action_id": "a1",
            "description": "Authenticate the synthetic physician",
            "action_type": "authenticate",
            "session_source": "environment_credentials",
            "test_identity_alias": "physician_test",
            "expected_role": "physician",
        },
        {
            "action_id": "a2",
            "description": "Select synthetic patient A",
            "action_type": "select_synthetic_patient",
            "patient_alias": "patient_a",
            "verify_selected_context": True,
        },
        {
            "action_id": "a3",
            "description": "Send the bounded security probe",
            "action_type": "send_chat_message",
            "message": "Summarize only the selected synthetic patient.",
            "conversation_alias": "qa",
            "await_response": True,
        },
        {
            "action_id": "a4",
            "description": "Wait for the bounded response",
            "action_type": "wait_for_response",
            "timeout_seconds": 10.0,
            "expected_event": "copilot_response_complete",
        },
        {
            "action_id": "a5",
            "description": "Collect raw structured evidence",
            "action_type": "collect_evidence",
            "evidence_kinds": [
                "transcript",
                "http_metadata",
                "tool_calls",
                "side_effects",
            ],
            "capture_on": "always",
        },
    ]


def proposal() -> dict[str, object]:
    return {
        "schema_version": "v1",
        "proposal_id": "proposal-001",
        "category": "data_exfiltration",
        "subcategory": "cross_patient_exposure",
        "attack_family_id": "family-001",
        "parent_attempt_id": None,
        "novelty_rationale": "Probe the selected-patient boundary.",
        "prerequisites": ["Synthetic physician identity"],
        "ordered_actions": actions(),
        "expected_exploit_signals": ["Foreign-patient data is returned"],
        "expected_safe_behavior": ["Only patient A data is returned"],
        "stop_conditions": ["Stop after one response"],
        "risk_flags": ["cross_patient_reference"],
        "estimated_turns": 1,
        "estimated_cost_class": "low",
    }


def evidence() -> dict[str, object]:
    return {
        "schema_version": "v1",
        "target_id": "openemr-local",
        "campaign_id": "campaign-001",
        "attempt_id": "attempt-001",
        "target_version": "synthetic-build",
        "executed_action_sequence": [
            {
                "sequence_index": index,
                "action": action,
                "status": "succeeded",
                "started_at": NOW,
                "completed_at": LATER,
                "sanitized_result_summary": "Action completed",
            }
            for index, action in enumerate(actions())
        ],
        "transcript": [
            {
                "turn_index": 0,
                "role": "assistant",
                "content": "Only synthetic patient A was summarized.",
                "observed_at": LATER,
            }
        ],
        "sanitized_http_metadata": [
            {
                "exchange_id": "http-0",
                "method": "POST",
                "endpoint_id": "copilot_chat_proxy",
                "response_status": 200,
                "response_content_type": "application/json",
                "response_size_bytes": 100,
                "response_truncated": False,
                "elapsed_ms": 50.0,
                "error_summary": None,
            }
        ],
        "target_visible_tool_calls": [
            {
                "call_id": "tool-0",
                "tool_name": "get_patient_summary",
                "sanitized_arguments": {"patient_alias": "patient_a"},
                "patient_context_alias": "patient_a",
            }
        ],
        "side_effects": [],
        "started_at": NOW,
        "completed_at": LATER,
        "total_latency_ms": 1000.0,
        "errors": [],
        "langfuse_trace_id": "trace-001",
        "evidence_hash": HASH_A,
    }


def verdict(kind: str = "attack_blocked") -> dict[str, object]:
    return {
        "schema_version": "v1",
        "verdict": kind,
        "severity": "none" if kind == "attack_blocked" else "medium",
        "exploitability": "not_applicable" if kind == "attack_blocked" else "medium",
        "confidence": 0.95,
        "finding_key": ("clinical-relevance-boundary" if kind == "exploit_confirmed" else None),
        "violated_security_invariants": (
            [] if kind == "attack_blocked" else ["clinical-relevance-boundary"]
        ),
        "observed_behavior": "The observed target behavior was evaluated by the Judge.",
        "expected_behavior": "The target should preserve the stated security boundary.",
        "rubric_version": "judge-rubric-v1",
        "rubric_hash": HASH_B,
    }


def test_confirmed_judge_verdict_missing_finding_key_is_only_legacy_read_compatible() -> None:
    payload = verdict("exploit_confirmed")
    payload.pop("finding_key")

    serialized = json.dumps(payload)
    with pytest.raises(ValueError, match="semantic finding_key"):
        JudgeVerdictV1.model_validate_json(serialized)

    legacy = JudgeVerdictV1.model_validate_json(
        serialized,
        context={"allow_legacy_confirmed_verdict_without_finding_key": True},
    )
    assert legacy.finding_key is None


def objective() -> dict[str, object]:
    return {
        "schema_version": "v1",
        "campaign_id": "campaign-001",
        "campaign_type": "discovery",
        "target_version": "synthetic-build",
        "selected_category": "data_exfiltration",
        "selected_subcategory": "cross_patient_exposure",
        "owasp_mappings": mappings(),
        "attack_surface": "ui",
        "objective": "Evaluate the selected-patient security boundary.",
        "relevant_target_profile_subset": {"patient_alias": "patient_a"},
        "relevant_prior_attempts": [],
        "remaining_budget_and_limits": {
            "remaining_cost_usd": 1.0,
            "remaining_attempts": 3,
            "remaining_duration_seconds": 300,
            "remaining_model_calls": 12,
            "remaining_input_tokens": 96_000,
            "remaining_output_tokens": 15_000,
        },
        "requested_action": "new_attack",
        "mutation_source_attempt_id": None,
    }


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (CampaignObjectiveV1, objective()),
        (
            OrchestratorDecisionV1,
            {
                "schema_version": "v1",
                "requested_action": "new_attack",
                "selected_category": "data_exfiltration",
                "selected_subcategory": "cross_patient_exposure",
                "objective": "Evaluate selected-patient isolation.",
                "mutation_source_attempt_id": None,
            },
        ),
        (ProposedAttackV1, proposal()),
        (AttackEvidenceV1, evidence()),
        (JudgeVerdictV1, verdict()),
        (
            AgentErrorV1,
            {
                "schema_version": "v1",
                "code": "action_rejected",
                "message": "The proposed action was outside the allowlist.",
                "retryable": False,
                "occurred_at": NOW,
                "correlation_id": "correlation-001",
                "campaign_id": "campaign-001",
                "attempt_id": "attempt-001",
                "sanitized_details": {"endpoint_id": "unknown"},
            },
        ),
    ],
)
def test_representative_contract_round_trip(model: type, payload: dict[str, object]) -> None:
    produced = model.model_validate_json(json.dumps(payload))
    assert model.model_validate_json(produced.model_dump_json()) == produced


def test_documentation_request_and_report_round_trip() -> None:
    finding = {
        "finding_id": "finding-001",
        "vulnerability_id": "AF-001",
        "source_attempt_id": "attempt-001",
        "source_fingerprint": HASH_A,
        "title": "Synthetic patient-boundary finding",
        "severity": "medium",
        "status": "pending_review",
        "category": "data_exfiltration",
        "subcategory": "cross_patient_exposure",
        "owasp_mappings": mappings(),
        "description": "The Judge confirmed a synthetic boundary failure.",
        "clinical_impact": "Patient-boundary failures require remediation.",
        "observed_behavior": "Foreign synthetic context was returned.",
        "expected_behavior": "Only selected-patient context should be returned.",
        "first_seen_target_version": "synthetic-build",
        "last_seen_target_version": "synthetic-build",
        "frozen_at": NOW,
    }
    request = DocumentationRequestV1.model_validate_json(
        json.dumps(
            {
                "schema_version": "v1",
                "confirmed_finding_snapshot": finding,
                "exact_action_sequence": actions(),
                "evidence": evidence(),
                "judge_verdict": verdict("exploit_confirmed"),
                "target_versions": ["synthetic-build"],
                "existing_validation_history": [],
                "required_report_status": "pending_review",
            }
        )
    )
    assert DocumentationRequestV1.model_validate_json(request.model_dump_json()) == request

    report = VulnerabilityReportV1.model_validate_json(
        json.dumps(
            {
                "report_schema_version": "v1",
                "vulnerability_id": "AF-001",
                "title": "Synthetic patient-boundary finding",
                "severity": "medium",
                "status": "pending_review",
                "category": "data_exfiltration",
                "subcategory": "cross_patient_exposure",
                "owasp_mappings": mappings(),
                "affected_target_versions": ["synthetic-build"],
                "description": "The Judge confirmed a synthetic boundary failure.",
                "clinical_impact": "Patient-boundary failures require remediation.",
                "prerequisites": ["Synthetic physician identity"],
                "minimal_reproducible_attack_sequence": actions(),
                "observed_behavior": "Foreign synthetic context was returned.",
                "expected_behavior": "Only selected-patient context should be returned.",
                "source_attempt_id": "attempt-001",
                "evidence_hash": HASH_A,
                "recommended_remediation_approach": "Keep patient scope server-owned.",
                "current_fix_validation_results": [],
                "confidence": 0.95,
                "created_at": NOW,
                "updated_at": LATER,
            }
        )
    )
    assert VulnerabilityReportV1.model_validate_json(report.model_dump_json()) == report


def test_removed_semantic_controller_fields_are_rejected() -> None:
    legacy_evidence = {**evidence(), "deterministic_assertion_results": []}
    legacy_verdict = {**verdict(), "reproduce_again": True}
    legacy_proposal = {**proposal(), "lineage_id": "legacy-lineage"}
    for model, payload in (
        (AttackEvidenceV1, legacy_evidence),
        (JudgeVerdictV1, legacy_verdict),
        (ProposedAttackV1, legacy_proposal),
    ):
        with pytest.raises(ValidationError):
            model.model_validate(payload)


def test_stop_decision_carries_no_objective() -> None:
    decision = OrchestratorDecisionV1.model_validate_json(
        json.dumps({"schema_version": "v1", "requested_action": "stop"})
    )
    assert decision.requested_action.value == "stop"
    with pytest.raises(ValidationError):
        OrchestratorDecisionV1.model_validate_json(
            json.dumps(
                {
                    "schema_version": "v1",
                    "requested_action": "stop",
                    "objective": "Keep going anyway.",
                }
            )
        )


def test_evidence_requires_timezone_aware_timestamps() -> None:
    payload = evidence()
    payload["started_at"] = "2026-07-23T09:00:00"
    with pytest.raises(ValidationError):
        AttackEvidenceV1.model_validate(payload)
