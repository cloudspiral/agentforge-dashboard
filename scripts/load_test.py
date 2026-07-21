#!/usr/bin/env python3
"""Run a bounded, offline load check of deterministic AgentForge plumbing."""

from __future__ import annotations

import argparse
import json
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Final

REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
SOURCE_ROOT: Final = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from agentforge.contracts.v1 import AttackEvidenceV1, SeverityV1  # noqa: E402
from agentforge.evaluation.deterministic import evaluate_deterministically  # noqa: E402
from agentforge.regression.invariants import TransportSucceededInvariantV1  # noqa: E402

_SAFE_EVIDENCE_JSON: Final = json.dumps(
    {
        "schema_version": "v1",
        "target_id": "offline-synthetic-target",
        "campaign_id": "offline-load-campaign",
        "attempt_id": "offline-load-attempt",
        "target_version": "offline-fixture-v1",
        "executed_action_sequence": [
            {
                "sequence_index": 0,
                "action": {
                    "action_id": "reset-0",
                    "description": "Reset a fake in-memory session",
                    "action_type": "reset_session",
                    "reset_strategy_id": "fake_in_memory_reset",
                    "require_clean_context": True,
                },
                "status": "succeeded",
                "started_at": "2026-07-21T00:00:00Z",
                "completed_at": "2026-07-21T00:00:00.001Z",
                "sanitized_result_summary": "Offline synthetic reset completed",
            },
            {
                "sequence_index": 1,
                "action": {
                    "action_id": "fake-chat-1",
                    "description": "Exercise a fake synthetic chat operation",
                    "action_type": "send_chat_message",
                    "message": "Return the fixed offline fixture response.",
                    "conversation_alias": "offline-load-conversation",
                    "await_response": True,
                },
                "status": "succeeded",
                "started_at": "2026-07-21T00:00:00Z",
                "completed_at": "2026-07-21T00:00:00.001Z",
                "sanitized_result_summary": "Fake in-memory response completed",
            },
        ],
        "transcript": [
            {
                "turn_index": 0,
                "role": "assistant",
                "content": "Fixed offline synthetic response.",
                "observed_at": "2026-07-21T00:00:00.001Z",
            }
        ],
        "sanitized_http_metadata": [],
        "target_visible_tool_calls": [],
        "side_effects": [],
        "deterministic_assertion_results": [],
        "artifact_references": [],
        "started_at": "2026-07-21T00:00:00Z",
        "completed_at": "2026-07-21T00:00:00.001Z",
        "total_latency_ms": 1.0,
        "errors": [],
        "langfuse_trace_id": None,
        "evidence_hash": "0" * 64,
    }
)

_TRANSPORT_INVARIANT: Final = TransportSucceededInvariantV1(
    invariant_id="offline-transport-succeeded",
    description="The fake operation completes without a transport error",
    severity_on_failure=SeverityV1.NONE,
    invariant_type="transport_succeeded",
)


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + ((ordered[upper] - ordered[lower]) * fraction)


def run_offline_load_test(
    *,
    operations: int,
    max_seconds: float,
    max_cost_usd: float = 0,
    max_target_requests: int = 0,
) -> dict[str, object]:
    """Measure validation, deterministic evaluation, and serialization with zero I/O."""

    if not 1 <= operations <= 10_000:
        raise ValueError("operations must be between 1 and 10,000")
    if not 0.1 <= max_seconds <= 300:
        raise ValueError("max_seconds must be between 0.1 and 300")
    if max_cost_usd != 0:
        raise ValueError("offline mode requires max_cost_usd=0")
    if max_target_requests != 0:
        raise ValueError("offline mode requires max_target_requests=0")

    timings_ms: list[float] = []
    started = time.perf_counter()
    cpu_started = time.process_time()
    tracemalloc.start()
    try:
        for _ in range(operations):
            if time.perf_counter() - started >= max_seconds:
                break
            operation_started = time.perf_counter()
            evidence = AttackEvidenceV1.model_validate_json(_SAFE_EVIDENCE_JSON)
            result = evaluate_deterministically(evidence, [_TRANSPORT_INVARIANT])
            result.model_dump_json()
            if not result.secure_pass_eligible:
                raise RuntimeError("offline deterministic fixture unexpectedly failed")
            timings_ms.append((time.perf_counter() - operation_started) * 1_000)
        _, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    elapsed_seconds = time.perf_counter() - started
    cpu_seconds = time.process_time() - cpu_started
    completed = len(timings_ms)
    report: dict[str, object] = {
        "schema_version": "1.0",
        "mode": "synthetic_offline",
        "status": "passed" if completed == operations else "time_budget_exhausted",
        "requested_operations": operations,
        "completed_operations": completed,
        "max_seconds": max_seconds,
        "controls": {
            "target": "fake",
            "max_cost_usd": max_cost_usd,
            "max_target_requests": max_target_requests,
            "live_execution_enabled": False,
        },
        "elapsed_seconds": round(elapsed_seconds, 6),
        "process_cpu_seconds": round(cpu_seconds, 6),
        "process_cpu_percent_of_one_core": round((cpu_seconds / elapsed_seconds) * 100, 3),
        "throughput_operations_per_second": round(completed / elapsed_seconds, 3),
        "latency_ms": {
            "min": round(min(timings_ms), 6) if timings_ms else None,
            "p50": round(_percentile(timings_ms, 0.50), 6) if timings_ms else None,
            "p95": round(_percentile(timings_ms, 0.95), 6) if timings_ms else None,
            "max": round(max(timings_ms), 6) if timings_ms else None,
        },
        "peak_python_allocated_bytes": peak_bytes,
        "target_requests": 0,
        "simulated_target_operations": completed,
        "model_calls": 0,
        "database_writes": 0,
        "estimated_cost_usd": 0,
        "measured_layers": [
            "v1_contract_validation",
            "deterministic_invariant_evaluation",
            "result_serialization",
        ],
        "unmeasured_layers": [
            "postgresql_write_throughput",
            "worker_queue_behavior",
            "live_target_latency",
            "model_latency",
        ],
        "bottleneck_note": (
            "p95 covers the combined in-process validation/evaluation/serialization path; "
            "external layers are intentionally excluded"
        ),
        "recommended_scaling_change": (
            "Do not scale from this microbenchmark alone; next measure PostgreSQL claim/write "
            "throughput and queue wait time with fake workers while preserving the v1 single-app "
            "runtime topology"
        ),
    }
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["offline"], default="offline")
    parser.add_argument("--target", choices=["fake"], default="fake")
    parser.add_argument("--operations", type=int, default=100)
    parser.add_argument("--max-seconds", type=float, default=30.0)
    parser.add_argument("--max-cost-usd", type=float, default=0.0)
    parser.add_argument("--max-target-requests", type=int, default=0)
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = run_offline_load_test(
            operations=args.operations,
            max_seconds=args.max_seconds,
            max_cost_usd=args.max_cost_usd,
            max_target_requests=args.max_target_requests,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        print(
            f"completed {report['completed_operations']}/{report['requested_operations']} "
            f"offline operations; report={output}"
        )
    else:
        print(rendered, end="")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
