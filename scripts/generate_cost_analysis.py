#!/usr/bin/env python3
"""Generate the AI Cost Analysis and its redacted evidence snapshot."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Final

import yaml

REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
SOURCE_ROOT: Final = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from agentforge.observability.cost_analysis import (  # noqa: E402
    CostEvidenceSnapshotV1,
    collect_cost_evidence,
    evidence_digest,
    load_cost_assumptions,
    merge_cost_evidence,
    render_cost_analysis,
)
from agentforge.persistence import Database  # noqa: E402
from agentforge.settings import Settings  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", help="database URL; defaults to Settings")
    parser.add_argument("--source-label", default="local-development")
    parser.add_argument("--campaign-id", action="append", default=[])
    parser.add_argument("--merge-evidence", action="append", type=Path, default=[])
    parser.add_argument(
        "--assumptions",
        type=Path,
        default=REPOSITORY_ROOT / "config" / "cost-model-assumptions.yaml",
    )
    parser.add_argument(
        "--pricing",
        type=Path,
        default=REPOSITORY_ROOT / "config" / "pricing.yaml",
    )
    parser.add_argument(
        "--evidence-output",
        type=Path,
        default=REPOSITORY_ROOT / "artifacts" / "cost-analysis-evidence.json",
    )
    parser.add_argument(
        "--report-output",
        type=Path,
        default=REPOSITORY_ROOT / "AI_COST_ANALYSIS.md",
    )
    parser.add_argument(
        "--artifact-root",
        action="append",
        type=Path,
        default=[],
        help="artifact tree whose file bytes should be counted",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    pricing = yaml.safe_load(args.pricing.read_text(encoding="utf-8"))
    assumptions = load_cost_assumptions(args.assumptions)
    settings = Settings()
    database = Database(args.database_url or settings.database_url)
    try:
        with database.session_factory() as session:
            current = collect_cost_evidence(
                session,
                source_label=args.source_label,
                pricing_source=pricing["source"],
                pricing_verified_at=str(pricing["verified_at"]),
                artifact_roots=args.artifact_root,
                overnight_campaign_ids=set(args.campaign_id),
            )
    finally:
        database.dispose()
    previous = [
        CostEvidenceSnapshotV1.model_validate_json(path.read_text(encoding="utf-8"))
        for path in args.merge_evidence
    ]
    evidence = merge_cost_evidence([*previous, current]) if previous else current
    evidence_payload = evidence.model_dump(mode="json")
    evidence_payload["evidence_digest"] = evidence_digest(evidence)
    args.evidence_output.parent.mkdir(parents=True, exist_ok=True)
    args.evidence_output.write_text(
        json.dumps(evidence_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.report_output.write_text(
        render_cost_analysis(
            evidence,
            assumptions,
            pricing_models=pricing["models"],
        ),
        encoding="utf-8",
    )
    print(
        f"Wrote {args.report_output} and {args.evidence_output} "
        f"({len(evidence.agent_calls)} unique calls)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
