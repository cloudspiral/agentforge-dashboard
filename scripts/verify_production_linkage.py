#!/usr/bin/env python3
"""Inspect persisted evaluation and Langfuse linkage without exposing payload content."""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from collections.abc import Mapping, Sequence
from decimal import Decimal
from pathlib import Path
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
SOURCE_ROOT: Final = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from agentforge.persistence.db import Database  # noqa: E402
from agentforge.persistence.models import (  # noqa: E402
    AgentRun,
    AttackAttempt,
    Campaign,
    JudgeVerdict,
)
from agentforge.settings import Settings  # noqa: E402

_SAFE_IDENTIFIER: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_SAFE_NAME: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,254}$")
_FULL_MASK_MARKER: Final = "<fully masked due to failed mask function>"


def _money(value: Decimal) -> str:
    return format(value, "f")


def _safe_identifier(value: str | None) -> str | None:
    if value is None:
        return None
    return value if _SAFE_IDENTIFIER.fullmatch(value) else "invalid"


def _safe_name(value: object) -> str | None:
    return value if isinstance(value, str) and _SAFE_NAME.fullmatch(value) else None


def _payload_state(value: object) -> str:
    if value is None:
        return "absent"
    if value == _FULL_MASK_MARKER:
        return "fully_masked"
    return "unexpected_present"


def _assertion_count(payload: object) -> int:
    if not isinstance(payload, Mapping):
        return 0
    assertions = payload.get("deterministic_assertion_results")
    return len(assertions) if isinstance(assertions, Sequence) else 0


def _typed_error_code(value: object) -> str | None:
    if not isinstance(value, Mapping):
        return None
    code = value.get("code")
    return _safe_identifier(code) if isinstance(code, str) else "present"


def build_persistence_report(
    session: Session,
    *,
    campaign_id: uuid.UUID | None,
    attempt_id: uuid.UUID | None,
) -> dict[str, object]:
    """Return presence/count/usage linkage only; raw payloads are never serialized."""

    selected_attempt: AttackAttempt | None = None
    if attempt_id is not None:
        selected_attempt = session.scalar(
            select(AttackAttempt).where(AttackAttempt.id == attempt_id)
        )
        if selected_attempt is None:
            raise LookupError("attempt was not found")
        if campaign_id is not None and campaign_id != selected_attempt.campaign_id:
            raise LookupError("attempt does not belong to the requested campaign")
        campaign_id = selected_attempt.campaign_id
    if campaign_id is None:
        raise ValueError("campaign_id or attempt_id is required")

    campaign = session.scalar(select(Campaign).where(Campaign.id == campaign_id))
    if campaign is None:
        raise LookupError("campaign was not found")

    attempts = list(
        session.scalars(
            select(AttackAttempt)
            .where(AttackAttempt.campaign_id == campaign.id)
            .order_by(AttackAttempt.created_at)
        )
    )
    if selected_attempt is not None:
        attempts = [selected_attempt]
    attempt_ids = [attempt.id for attempt in attempts]
    verdicts = {
        verdict.attempt_id: verdict
        for verdict in session.scalars(
            select(JudgeVerdict).where(JudgeVerdict.attempt_id.in_(attempt_ids))
        )
    }

    agent_run_query = select(AgentRun).where(AgentRun.campaign_id == campaign.id)
    if selected_attempt is not None:
        agent_run_query = agent_run_query.where(AgentRun.attempt_id == selected_attempt.id)
    agent_runs = list(session.scalars(agent_run_query.order_by(AgentRun.created_at)))

    attempt_rows: list[dict[str, object]] = []
    for attempt in attempts:
        verdict = verdicts.get(attempt.id)
        attempt_rows.append(
            {
                "id": str(attempt.id),
                "category": _safe_identifier(attempt.category),
                "subcategory": _safe_identifier(attempt.subcategory),
                "status": _safe_identifier(attempt.status),
                "evidence_present": attempt.evidence_payload is not None,
                "evidence_hash": _safe_identifier(attempt.evidence_hash),
                "deterministic_assertions_persisted": _assertion_count(attempt.evidence_payload),
                "judge_verdict_present": verdict is not None,
                "judge_verdict": _safe_identifier(verdict.verdict) if verdict else None,
                "judge_typed_failure_present": any(
                    run.role == "judge"
                    and run.attempt_id == attempt.id
                    and run.typed_error is not None
                    for run in agent_runs
                ),
                "langfuse_trace_id": _safe_identifier(attempt.langfuse_trace_id),
                "input_tokens": attempt.input_tokens,
                "output_tokens": attempt.output_tokens,
                "estimated_cost_usd": _money(attempt.estimated_cost_usd),
                "latency_ms": attempt.latency_ms,
                "terminal_timestamp_present": attempt.completed_at is not None,
            }
        )

    agent_run_rows = [
        {
            "id": str(run.id),
            "attempt_id": str(run.attempt_id) if run.attempt_id else None,
            "role": _safe_identifier(run.role),
            "model": _safe_identifier(run.model),
            "prompt_version": _safe_identifier(run.prompt_version),
            "status": _safe_identifier(run.status),
            "input_tokens": run.input_tokens,
            "output_tokens": run.output_tokens,
            "estimated_cost_usd": _money(run.estimated_cost_usd),
            "latency_ms": run.latency_ms,
            "langfuse_trace_id": _safe_identifier(run.langfuse_trace_id),
            "typed_error_code": _typed_error_code(run.typed_error),
        }
        for run in agent_runs
    ]

    return {
        "schema_version": "1.0",
        "inspection_mode": "read_only_redacted",
        "campaign": {
            "id": str(campaign.id),
            "status": _safe_identifier(campaign.status),
            "trigger_type": _safe_identifier(campaign.trigger_type),
            "target_alias": _safe_identifier(campaign.target_alias),
            "target_version": _safe_identifier(campaign.target_version),
            "attempt_count": len(attempts),
            "actual_attempts": campaign.actual_attempts,
            "actual_cost_usd": _money(campaign.actual_cost_usd),
            "terminal_timestamp_present": campaign.completed_at is not None,
        },
        "attempts": attempt_rows,
        "agent_runs": agent_run_rows,
        "totals": {
            "agent_run_count": len(agent_runs),
            "input_tokens": sum(run.input_tokens for run in agent_runs),
            "output_tokens": sum(run.output_tokens for run in agent_runs),
            "estimated_cost_usd": _money(
                sum(
                    (run.estimated_cost_usd for run in agent_runs),
                    start=Decimal("0"),
                )
            ),
            "trace_linked_agent_runs": sum(run.langfuse_trace_id is not None for run in agent_runs),
        },
    }


def verify_langfuse_trace(settings: Settings, trace_id: str) -> dict[str, object]:
    """Read one trace and its observations; report metadata/IO presence, never values."""

    if not settings.has_langfuse_credentials:
        return {"status": "BLOCKED", "reason": "credentials_unavailable"}
    public_key = settings.langfuse_public_key
    secret_key = settings.langfuse_secret_key
    if public_key is None or secret_key is None:
        return {"status": "BLOCKED", "reason": "credentials_unavailable"}

    from langfuse import Langfuse

    client = Langfuse(
        public_key=public_key.get_secret_value(),
        secret_key=secret_key.get_secret_value(),
        base_url=settings.langfuse_base_url,
        tracing_enabled=False,
    )
    try:
        trace = client.api.trace.get(trace_id)
        response = client.api.observations.get_many(trace_id=trace_id, limit=100)
        observations = list(getattr(response, "data", ()) or ())
        metadata = getattr(trace, "metadata", None)
        metadata_keys = (
            sorted(str(key) for key in metadata) if isinstance(metadata, Mapping) else []
        )
        linkage_keys = (
            "campaignId",
            "attemptId",
            "agentRole",
            "category",
            "model",
            "promptVersion",
            "targetVersion",
        )
        linkage = {
            key: _safe_identifier(str(metadata[key]))
            for key in linkage_keys
            if isinstance(metadata, Mapping) and key in metadata
        }
        trace_input_state = _payload_state(getattr(trace, "input", None))
        trace_output_state = _payload_state(getattr(trace, "output", None))
        observations_without_payloads = all(
            getattr(item, "input", None) is None and getattr(item, "output", None) is None
            for item in observations
        )
        trace_private = getattr(trace, "public", None) is False
        return {
            "status": "VERIFIED",
            "trace_id": _safe_identifier(str(getattr(trace, "id", trace_id))),
            "trace_name": _safe_name(getattr(trace, "name", None)),
            "metadata_keys": metadata_keys,
            "linkage": linkage,
            "observation_count": len(observations),
            "observation_names": sorted(
                {
                    name
                    for item in observations
                    if (name := _safe_name(getattr(item, "name", None))) is not None
                }
            ),
            "observation_types": sorted(
                {
                    value
                    for item in observations
                    if (value := _safe_identifier(str(getattr(item, "type", ""))))
                    not in {None, "invalid"}
                }
            ),
            "trace_input_state": trace_input_state,
            "trace_output_state": trace_output_state,
            "observations_with_input": sum(
                getattr(item, "input", None) is not None for item in observations
            ),
            "observations_with_output": sum(
                getattr(item, "output", None) is not None for item in observations
            ),
            "trace_private": trace_private,
            "content_safety_status": (
                "VERIFIED"
                if trace_input_state in {"absent", "fully_masked"}
                and trace_output_state in {"absent", "fully_masked"}
                and observations_without_payloads
                and trace_private
                else "PARTIAL"
            ),
        }
    except Exception as exc:
        return {
            "status": "BLOCKED",
            "reason": f"langfuse_{type(exc).__name__.lower()}",
        }
    finally:
        client.shutdown()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--campaign-id", type=uuid.UUID)
    group.add_argument("--attempt-id", type=uuid.UUID)
    parser.add_argument(
        "--verify-langfuse",
        action="store_true",
        help="perform one authenticated read of the persisted trace",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    settings = Settings()
    database = Database(settings.database_url)
    try:
        with database.session_factory() as session:
            report = build_persistence_report(
                session,
                campaign_id=args.campaign_id,
                attempt_id=args.attempt_id,
            )
    except (LookupError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    finally:
        database.dispose()

    if args.verify_langfuse:
        trace_ids = [
            row["langfuse_trace_id"]
            for row in report["agent_runs"]
            if isinstance(row, dict) and row.get("langfuse_trace_id")
        ]
        report["langfuse"] = (
            verify_langfuse_trace(settings, str(trace_ids[-1]))
            if trace_ids
            else {"status": "BLOCKED", "reason": "persisted_trace_id_unavailable"}
        )

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
