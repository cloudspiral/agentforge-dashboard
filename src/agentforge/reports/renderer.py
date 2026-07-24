from __future__ import annotations

import os
import tempfile
from pathlib import Path

from jinja2 import Environment, StrictUndefined

from agentforge.contracts.v1 import VulnerabilityReportV1
from agentforge.persistence.models import VulnerabilityReport


def _bullets(items: list[object]) -> str:
    return "\n".join(f"- {item}" for item in items) if items else "- None recorded"


def _steps(items: list[object]) -> str:
    return "\n".join(
        f"{index}. `{item.model_dump_json() if hasattr(item, 'model_dump_json') else item}`"
        for index, item in enumerate(items, start=1)
    )


def _transcript(report: VulnerabilityReportV1) -> str:
    if not report.exact_transcript:
        return "_No durable transcript was available for this historical report._"
    sections: list[str] = []
    for turn in report.exact_transcript:
        content = turn.content.replace("```", "``\u200b`")
        sections.append(
            "\n".join(
                [
                    f"### Turn {turn.turn_index} — {turn.role.value}",
                    "",
                    f"Observed at: `{turn.observed_at.isoformat()}`",
                    "",
                    "```text",
                    content,
                    "```",
                ]
            )
        )
    return "\n\n".join(sections)


def render_vulnerability_report(report: VulnerabilityReportV1, template_path: Path) -> str:
    template = Environment(
        autoescape=False,
        undefined=StrictUndefined,
        keep_trailing_newline=True,
    ).from_string(template_path.read_text(encoding="utf-8"))
    values = report.model_dump(mode="python")
    values.update(
        {
            "owasp_mappings": report.owasp_mappings.model_dump_json(),
            "affected_target_versions": _bullets(report.affected_target_versions),
            "prerequisites": _bullets(report.prerequisites),
            "minimal_reproducible_attack_sequence": _steps(
                report.minimal_reproducible_attack_sequence
            ),
            "evidence_references": _bullets(
                [
                    f"Attempt `{report.source_attempt_id}`",
                    f"Evidence hash `{report.evidence_hash}`",
                ]
            ),
            "exact_transcript": _transcript(report),
            "current_fix_validation_results": _bullets(
                [
                    (f"`{result.target_version}` — {result.outcome.value}: {result.summary}")
                    for result in report.current_fix_validation_results
                ]
            ),
        }
    )
    return template.render(**values)


def export_stored_report(
    report: VulnerabilityReport,
    *,
    vulnerability_id: str,
    reports_dir: Path,
) -> Path:
    destination = stored_report_export_path(
        vulnerability_id=vulnerability_id,
        reports_dir=reports_dir,
    )
    root = destination.parent
    root.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=root,
            prefix=".agentforge-report-",
            suffix=".tmp",
        )
        temporary_path = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(report.markdown_body)
            stream.flush()
            os.fsync(stream.fileno())
        if temporary_path.read_text(encoding="utf-8") != report.markdown_body:
            raise OSError("temporary report export did not match the database body")
        os.replace(temporary_path, destination)
        temporary_path = None
        verify_stored_report_export(
            report,
            vulnerability_id=vulnerability_id,
            reports_dir=reports_dir,
        )
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return destination


def stored_report_export_path(*, vulnerability_id: str, reports_dir: Path) -> Path:
    safe_id = "".join(
        character for character in vulnerability_id if character.isalnum() or character in "-_"
    )
    if not safe_id or safe_id != vulnerability_id:
        raise ValueError("vulnerability ID is not safe for report export")
    root = reports_dir.resolve()
    destination = (root / f"{safe_id}.md").resolve()
    if root not in destination.parents:
        raise ValueError("report path escaped the configured reports directory")
    return destination


def verify_stored_report_export(
    report: VulnerabilityReport,
    *,
    vulnerability_id: str,
    reports_dir: Path,
) -> Path:
    destination = stored_report_export_path(
        vulnerability_id=vulnerability_id,
        reports_dir=reports_dir,
    )
    if not destination.is_file():
        raise FileNotFoundError("generated report export is unavailable")
    if destination.read_text(encoding="utf-8") != report.markdown_body:
        raise ValueError("generated report export does not match the database body")
    return destination
