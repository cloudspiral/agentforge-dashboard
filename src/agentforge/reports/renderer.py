from __future__ import annotations

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
            "current_fix_validation_results": _bullets(
                [result.summary for result in report.current_fix_validation_results]
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
    safe_id = "".join(
        character for character in vulnerability_id if character.isalnum() or character in "-_"
    )
    if not safe_id or safe_id != vulnerability_id:
        raise ValueError("vulnerability ID is not safe for report export")
    root = reports_dir.resolve()
    root.mkdir(parents=True, exist_ok=True)
    destination = (root / f"{safe_id}.md").resolve()
    if root not in destination.parents:
        raise ValueError("report path escaped the configured reports directory")
    destination.write_text(report.markdown_body, encoding="utf-8")
    return destination
