#!/usr/bin/env python3
"""Verify the fixed SSRF sentinel against the matching OpenEMR access-log window."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
SOURCE_ROOT: Final = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from agentforge.contracts.v1.common import utc_now  # noqa: E402
from agentforge.evaluation.owasp_controls import (  # noqa: E402
    BrowserControlEvidenceV1,
    ControlEvidenceEnvelopeV1,
    TargetAccessLogEvidenceV1,
    build_browser_result,
    case_provenance,
)

_CASE_PATH: Final = REPOSITORY_ROOT / "evals/control-cases/ssrf-url-sentinel.yaml"
_CONTROL_DIRECTORY: Final = REPOSITORY_ROOT / "evals/results/submission/controls"
_EVIDENCE_PATH: Final = _CONTROL_DIRECTORY / "AF-SSRF-001.evidence.json"
_RESULT_PATH: Final = _CONTROL_DIRECTORY / "AF-SSRF-001.json"
_LOG_EVIDENCE_PATH: Final = _CONTROL_DIRECTORY / "AF-SSRF-001.target-log.json"
_SENTINEL_PATH: Final = "/agentforge-ssrf-sentinel/AF-SSRF-001"
_PHP_TIMESTAMP = re.compile(r"\[([A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2}\.\d+ \d{4})\]")
_ACCESS_TIMESTAMP = re.compile(r"\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} \+0000)\]")
_CORRELATION_ID = re.compile(r'"correlation_id":"([0-9a-f-]{36})"')


def _line_timestamp(line: str) -> datetime | None:
    match = _PHP_TIMESTAMP.search(line)
    if match:
        return datetime.strptime(match.group(1), "%a %b %d %H:%M:%S.%f %Y").replace(tzinfo=UTC)
    match = _ACCESS_TIMESTAMP.search(line)
    if match:
        return datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S %z")
    return None


def _railway_output(railway: str, *arguments: str) -> str:
    result = subprocess.run(  # noqa: S603 - executable and arguments are fixed below
        [railway, *arguments],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError("authenticated Railway read failed")
    return result.stdout


def main() -> int:
    railway = shutil.which("railway")
    if railway is None:
        print("Railway CLI is unavailable", file=sys.stderr)
        return 2
    envelope = ControlEvidenceEnvelopeV1.model_validate_json(
        _EVIDENCE_PATH.read_text(encoding="utf-8")
    )
    if not isinstance(envelope.evidence, BrowserControlEvidenceV1):
        print("SSRF browser evidence is unavailable", file=sys.stderr)
        return 2
    case_source, current_sha = case_provenance(REPOSITORY_ROOT, _CASE_PATH)
    if envelope.case_source != case_source or envelope.case_sha256 != current_sha:
        print("SSRF evidence does not match the current control bytes", file=sys.stderr)
        return 2

    deployments = json.loads(
        _railway_output(
            railway,
            "deployment",
            "list",
            "--service",
            "openemr-web",
            "--json",
        )
    )
    current = next(
        (item for item in deployments if item.get("status") == "SUCCESS"),
        None,
    )
    deployment_id = current.get("id") if isinstance(current, dict) else None
    if not isinstance(deployment_id, str):
        print("current OpenEMR deployment could not be resolved", file=sys.stderr)
        return 2

    lines = _railway_output(
        railway,
        "logs",
        "--service",
        "openemr-web",
        "--lines",
        "500",
    ).splitlines()
    completions: list[tuple[datetime, str]] = []
    starts: list[tuple[datetime, str]] = []
    for line in lines:
        timestamp = _line_timestamp(line)
        correlation = _CORRELATION_ID.search(line)
        if timestamp is None or correlation is None:
            continue
        row = (timestamp, correlation.group(1))
        if '"event":"agent_request_completed"' in line:
            completions.append(row)
        elif '"event":"agent_request_started"' in line:
            starts.append(row)

    completion_candidates = [
        row for row in completions if abs(row[0] - envelope.executed_at) <= timedelta(seconds=10)
    ]
    if len(completion_candidates) != 1:
        print("matching target proxy completion was not uniquely attributable", file=sys.stderr)
        return 2
    completed_at, correlation_id = completion_candidates[0]
    matching_starts = [
        row
        for row in starts
        if row[1] == correlation_id
        and timedelta(0) <= completed_at - row[0] <= timedelta(seconds=30)
    ]
    if len(matching_starts) != 1:
        print("matching target proxy start was not uniquely attributable", file=sys.stderr)
        return 2
    started_at = matching_starts[0][0]
    sentinel_count = sum(
        _SENTINEL_PATH in line
        and (timestamp := _line_timestamp(line)) is not None
        and started_at <= timestamp <= completed_at
        for line in lines
    )
    log_evidence = TargetAccessLogEvidenceV1(
        case_id="AF-SSRF-001",
        target_service="openemr-web",
        target_deployment_id=deployment_id,
        inspected_at=utc_now(),
        source_line_limit=500,
        proxy_correlation_id=correlation_id,
        window_started_at=started_at,
        window_completed_at=completed_at,
        proxy_start_count=1,
        proxy_completion_count=1,
        sentinel_path=_SENTINEL_PATH,
        sentinel_request_count=sentinel_count,
        raw_logs_persisted=False,
    )
    log_reference = _LOG_EVIDENCE_PATH.relative_to(REPOSITORY_ROOT).as_posix()
    evidence_payload = envelope.evidence.model_dump(mode="python")
    evidence_payload.update(
        {
            "target_outbound_telemetry_inspected": True,
            "target_access_log_evidence_path": log_reference,
            "target_access_log_proxy_window_confirmed": True,
            "target_access_log_sentinel_request_count": sentinel_count,
        }
    )
    updated_evidence = BrowserControlEvidenceV1.model_validate(evidence_payload)
    envelope_payload = envelope.model_dump(mode="python")
    envelope_payload["evidence"] = updated_evidence
    updated_envelope = ControlEvidenceEnvelopeV1.model_validate(envelope_payload)
    result = build_browser_result(
        case=envelope.case_definition,
        case_sha256=envelope.case_sha256,
        evidence_path=_EVIDENCE_PATH.relative_to(REPOSITORY_ROOT).as_posix(),
        evidence=updated_evidence,
    )

    _LOG_EVIDENCE_PATH.write_text(
        json.dumps(log_evidence.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _EVIDENCE_PATH.write_text(
        json.dumps(updated_envelope.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _RESULT_PATH.write_text(
        json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "verified target access-log window: "
        f"sentinel_request_count={sentinel_count}, deployment={deployment_id}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
