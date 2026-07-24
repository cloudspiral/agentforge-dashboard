"""Deterministic report versioning for finding lifecycle and regression evidence."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from agentforge.contracts.v1 import FixValidationResultV1, VulnerabilityReportV1
from agentforge.persistence.models import Finding, VulnerabilityReport
from agentforge.persistence.repositories import ReportRepository

from .renderer import render_vulnerability_report

_LIFECYCLE_PROMPT_VERSION = "deterministic-report-lifecycle-v1"


def create_report_lifecycle_version(
    session: Session,
    *,
    finding: Finding,
    template_path: Path,
    event_details: dict[str, Any],
    validation_result: FixValidationResultV1 | None = None,
) -> VulnerabilityReport | None:
    """Mirror durable lifecycle/validation state into a new canonical report version."""

    repository = ReportRepository(session)
    try:
        previous = repository.latest_for_finding(finding.id)
    except LookupError:
        return None
    payload = dict(previous.structured_report)
    payload["status"] = finding.status
    payload["updated_at"] = datetime.now(UTC).isoformat()
    history = list(payload.get("current_fix_validation_results") or [])
    if validation_result is not None:
        serialized = validation_result.model_dump(mode="json")
        if serialized not in history:
            history.append(serialized)
        versions = list(payload.get("affected_target_versions") or [])
        if validation_result.target_version not in versions:
            versions.append(validation_result.target_version)
        payload["affected_target_versions"] = versions
    payload["current_fix_validation_results"] = history
    # Stored structured reports are JSON-shaped (enum and datetime values are
    # strings). Validate through the JSON boundary so strict contracts parse
    # those durable representations exactly as they do for agent output.
    report = VulnerabilityReportV1.model_validate_json(json.dumps(payload))
    markdown = render_vulnerability_report(report, template_path)
    return repository.create_versioned(
        finding_id=finding.id,
        structured_report=report.model_dump(mode="json"),
        markdown_body=markdown,
        validation_summary={
            "event": event_details,
            "validation_result": (
                validation_result.model_dump(mode="json") if validation_result is not None else None
            ),
        },
        prompt_version=_LIFECYCLE_PROMPT_VERSION,
        status=finding.status,
    )


__all__ = ["create_report_lifecycle_version"]
