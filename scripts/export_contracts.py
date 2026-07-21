#!/usr/bin/env python3
"""Export deterministic JSON Schemas for AgentForge's public v1 contracts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Final

REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
SOURCE_ROOT: Final = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from pydantic import BaseModel  # noqa: E402

from agentforge.contracts.v1 import (  # noqa: E402
    AgentErrorV1,
    AttackEvidenceV1,
    CampaignObjectiveV1,
    DocumentationRequestV1,
    JudgeVerdictV1,
    ProposedAttackV1,
    VulnerabilityReportV1,
)

SCHEMA_MODELS: Final[dict[str, type[BaseModel]]] = {
    "campaign-objective.schema.json": CampaignObjectiveV1,
    "proposed-attack.schema.json": ProposedAttackV1,
    "attack-evidence.schema.json": AttackEvidenceV1,
    "judge-verdict.schema.json": JudgeVerdictV1,
    "documentation-request.schema.json": DocumentationRequestV1,
    "vulnerability-report.schema.json": VulnerabilityReportV1,
    "agent-error.schema.json": AgentErrorV1,
}


def render_schema(model: type[BaseModel]) -> str:
    """Return a stable, human-reviewable representation of one model schema."""

    schema = model.model_json_schema(mode="validation", ref_template="#/$defs/{model}")
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def schema_drift(output_dir: Path) -> list[str]:
    """Return filenames whose committed content differs from generated content."""

    drifted: list[str] = []
    for filename, model in SCHEMA_MODELS.items():
        path = output_dir / filename
        expected = render_schema(model)
        if not path.is_file() or path.read_text(encoding="utf-8") != expected:
            drifted.append(filename)
    return drifted


def export_schemas(output_dir: Path) -> list[Path]:
    """Write all public schemas and return their paths."""

    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for filename, model in SCHEMA_MODELS.items():
        path = output_dir / filename
        path.write_text(render_schema(model), encoding="utf-8")
        written.append(path)
    return written


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPOSITORY_ROOT / "contracts" / "v1",
        help="schema destination (default: contracts/v1)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero instead of writing when generated schemas have drifted",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    output_dir = args.output_dir.resolve()
    if args.check:
        drifted = schema_drift(output_dir)
        if drifted:
            print("Contract schema drift detected: " + ", ".join(drifted), file=sys.stderr)
            return 1
        print(f"Contract schemas are current ({len(SCHEMA_MODELS)} files).")
        return 0

    written = export_schemas(output_dir)
    for path in written:
        print(path.relative_to(REPOSITORY_ROOT) if path.is_relative_to(REPOSITORY_ROOT) else path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
