from __future__ import annotations

import json
import os
import tempfile
import uuid
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentforge.contracts.v1 import (
    AttackEvidenceV1,
    SendChatMessageActionV1,
    TranscriptTurnV1,
)
from agentforge.evidence import (
    EvidenceArtifactCorrupt,
    EvidenceArtifactExportFailed,
    EvidenceArtifactMissing,
    EvidenceArtifactStore,
    EvidenceArtifactTooLarge,
    with_computed_evidence_hash,
)

TIMESTAMP = "2026-07-23T12:00:00Z"


def _evidence(
    campaign_id: uuid.UUID | None = None,
    attempt_id: uuid.UUID | None = None,
) -> AttackEvidenceV1:
    draft = AttackEvidenceV1.model_validate_json(
        json.dumps(
            {
                "schema_version": "v1",
                "target_id": "synthetic-copilot",
                "campaign_id": str(campaign_id or uuid.uuid4()),
                "attempt_id": str(attempt_id or uuid.uuid4()),
                "target_version": "target-build-1",
                "executed_action_sequence": [
                    {
                        "sequence_index": 0,
                        "action": {
                            "action_type": "reset_session",
                            "action_id": "reset-1",
                            "description": "Start a clean session.",
                            "reset_strategy_id": "fresh-context",
                            "require_clean_context": True,
                        },
                        "status": "succeeded",
                        "started_at": TIMESTAMP,
                        "completed_at": TIMESTAMP,
                        "sanitized_result_summary": "Clean session created.",
                    }
                ],
                "transcript": [
                    {
                        "turn_index": index,
                        "role": role,
                        "content": content,
                        "observed_at": TIMESTAMP,
                    }
                    for index, (role, content) in enumerate(
                        (
                            ("system", "Synthetic system context."),
                            ("user", "Authorized test prompt."),
                            ("assistant", "Bounded response."),
                            ("tool", "Synthetic tool result."),
                        )
                    )
                ],
                "sanitized_http_metadata": [],
                "target_visible_tool_calls": [],
                "side_effects": [],
                "started_at": TIMESTAMP,
                "completed_at": TIMESTAMP,
                "total_latency_ms": 0,
                "errors": [],
                "langfuse_trace_id": "trace-1",
                "evidence_hash": "a" * 64,
            }
        )
    )
    return with_computed_evidence_hash(draft)


def test_evidence_export_is_atomic_exact_and_database_anchored(tmp_path: Path) -> None:
    store = EvidenceArtifactStore(tmp_path / "evidence")
    evidence = _evidence()
    prepared = store.prepare(evidence)

    destination = store.export(prepared)

    assert destination.read_bytes() == prepared.serialized
    assert (
        store.load_verified(
            campaign_id=uuid.UUID(evidence.campaign_id),
            attempt_id=uuid.UUID(evidence.attempt_id),
            database_payload=prepared.payload,
        )
        == prepared.serialized
    )
    assert store.stale_temporary_paths() == []


def test_missing_corrupt_and_mismatched_evidence_are_never_served(tmp_path: Path) -> None:
    store = EvidenceArtifactStore(tmp_path / "evidence")
    evidence = _evidence()
    prepared = store.prepare(evidence)
    campaign_id = uuid.UUID(evidence.campaign_id)
    attempt_id = uuid.UUID(evidence.attempt_id)

    with pytest.raises(EvidenceArtifactMissing):
        store.load_verified(
            campaign_id=campaign_id,
            attempt_id=attempt_id,
            database_payload=prepared.payload,
        )

    destination = store.export(prepared)
    destination.write_text('{"evidence_hash":"' + ("b" * 64) + '"}', encoding="utf-8")
    with pytest.raises(EvidenceArtifactCorrupt):
        store.load_verified(
            campaign_id=campaign_id,
            attempt_id=attempt_id,
            database_payload=prepared.payload,
        )

    with pytest.raises(EvidenceArtifactCorrupt, match="hash"):
        store.prepare(evidence.model_copy(update={"evidence_hash": "b" * 64}))

    other_attempt = uuid.uuid4()
    mismatched_path = store.path_for(campaign_id, other_attempt)
    mismatched_path.parent.mkdir(parents=True, exist_ok=True)
    mismatched_path.write_bytes(prepared.serialized)
    with pytest.raises(EvidenceArtifactCorrupt):
        store.load_verified(
            campaign_id=campaign_id,
            attempt_id=other_attempt,
            database_payload=prepared.payload,
        )


def test_failed_atomic_replace_leaves_no_destination_or_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EvidenceArtifactStore(tmp_path / "evidence")
    prepared = store.prepare(_evidence())
    destination = store.path_for(
        uuid.UUID(prepared.evidence.campaign_id),
        uuid.UUID(prepared.evidence.attempt_id),
    )

    def fail_replace(_source: object, _destination: object) -> None:
        raise OSError("injected replace failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(EvidenceArtifactExportFailed, match="atomically"):
        store.export(prepared)

    assert not destination.exists()
    assert store.stale_temporary_paths() == []


def test_failure_before_temporary_write_leaves_no_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EvidenceArtifactStore(tmp_path / "evidence")
    prepared = store.prepare(_evidence())
    destination = store.path_for(
        uuid.UUID(prepared.evidence.campaign_id),
        uuid.UUID(prepared.evidence.attempt_id),
    )

    def fail_mkstemp(*_args: object, **_kwargs: object) -> tuple[int, str]:
        raise OSError("injected temporary-file creation failure")

    monkeypatch.setattr(tempfile, "mkstemp", fail_mkstemp)
    with pytest.raises(EvidenceArtifactExportFailed, match="atomically"):
        store.export(prepared)

    assert not destination.exists()
    assert store.stale_temporary_paths() == []


def test_post_rename_verification_failure_requires_fresh_read_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EvidenceArtifactStore(tmp_path / "evidence")
    prepared = store.prepare(_evidence())
    original_verify = store._verify_path
    verification_calls = 0

    def fail_post_rename(path: Path, *, expected: object) -> None:
        nonlocal verification_calls
        verification_calls += 1
        original_verify(path, expected=expected)
        if verification_calls == 2:
            raise EvidenceArtifactCorrupt("injected post-rename verification failure")

    monkeypatch.setattr(store, "_verify_path", fail_post_rename)
    with pytest.raises(EvidenceArtifactCorrupt, match="post-rename"):
        store.export(prepared)

    destination = store.path_for(
        uuid.UUID(prepared.evidence.campaign_id),
        uuid.UUID(prepared.evidence.attempt_id),
    )
    assert destination.read_bytes() == prepared.serialized
    monkeypatch.setattr(store, "_verify_path", original_verify)
    assert (
        store.load_verified(
            campaign_id=uuid.UUID(prepared.evidence.campaign_id),
            attempt_id=uuid.UUID(prepared.evidence.attempt_id),
            database_payload=prepared.payload,
        )
        == prepared.serialized
    )


def test_message_transcript_and_serialized_evidence_limits() -> None:
    base_action = {
        "action_type": "send_chat_message",
        "action_id": "message-1",
        "description": "Send the bounded prompt.",
        "conversation_alias": None,
        "await_response": True,
    }
    SendChatMessageActionV1.model_validate_json(json.dumps({**base_action, "message": "x" * 4_000}))
    with pytest.raises(ValidationError):
        SendChatMessageActionV1.model_validate_json(
            json.dumps({**base_action, "message": "x" * 4_001})
        )

    turn = {
        "turn_index": 0,
        "role": "assistant",
        "observed_at": TIMESTAMP,
    }
    TranscriptTurnV1.model_validate_json(json.dumps({**turn, "content": "x" * 20_000}))
    with pytest.raises(ValidationError):
        TranscriptTurnV1.model_validate_json(json.dumps({**turn, "content": "x" * 20_001}))

    evidence = _evidence()
    payload = evidence.model_dump(mode="json")
    payload["transcript"] = [
        {
            "turn_index": index,
            "role": "assistant",
            "content": "x",
            "observed_at": TIMESTAMP,
        }
        for index in range(100)
    ]
    AttackEvidenceV1.model_validate_json(json.dumps(payload))
    payload["transcript"].append(
        {
            "turn_index": 100,
            "role": "assistant",
            "content": "x",
            "observed_at": TIMESTAMP,
        }
    )
    with pytest.raises(ValidationError):
        AttackEvidenceV1.model_validate_json(json.dumps(payload))

    oversized_payload = evidence.model_dump(mode="json")
    oversized_payload["target_visible_tool_calls"] = [
        {
            "call_id": "call-1",
            "tool_name": "synthetic_tool",
            "sanitized_arguments": {"bounded_blob": "x" * (5 * 1024 * 1024)},
            "patient_context_alias": "patient_a",
        }
    ]
    oversized = with_computed_evidence_hash(
        AttackEvidenceV1.model_validate_json(json.dumps(oversized_payload))
    )
    with pytest.raises(EvidenceArtifactTooLarge):
        EvidenceArtifactStore.prepare(oversized)
