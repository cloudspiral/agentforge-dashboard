#!/usr/bin/env python3
"""Validate and export the versioned, synthetic AgentForge evaluation catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Final

REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
SOURCE_ROOT: Final = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from agentforge.evaluation.catalog import (  # noqa: E402
    JudgeRubricV1,
    SeedCaseV1,
    TaxonomyV1,
    load_judge_rubric,
    load_seed_cases,
    load_taxonomy,
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def load_catalog(repository_root: Path) -> tuple[TaxonomyV1, JudgeRubricV1, list[SeedCaseV1]]:
    """Load and cross-check every versioned input without reading runtime state."""

    taxonomy = load_taxonomy(repository_root / "config" / "attack-taxonomy.yaml")
    rubric = load_judge_rubric(repository_root / "config" / "judge-rubric.yaml")
    seeds = load_seed_cases(repository_root / "evals" / "seed-cases")

    taxonomy_by_category = {category.id: category for category in taxonomy.categories}
    for seed in seeds:
        category = taxonomy_by_category[seed.category]
        known_subcategories = {subcategory.id for subcategory in category.subcategories}
        if seed.subcategory not in known_subcategories:
            raise ValueError(
                f"seed {seed.id!r} references unknown subcategory {seed.subcategory!r}"
            )
        if seed.category not in rubric.categories:
            raise ValueError(f"seed {seed.id!r} has no judge rubric category")
    return taxonomy, rubric, seeds


def build_bundle(repository_root: Path) -> dict[str, object]:
    """Build a deterministic export containing definitions, never execution results."""

    taxonomy, rubric, seeds = load_catalog(repository_root)
    source_paths = [
        repository_root / "config" / "attack-taxonomy.yaml",
        repository_root / "config" / "judge-rubric.yaml",
        *sorted((repository_root / "evals" / "seed-cases").glob("*.yaml")),
    ]
    source_hashes = {
        path.relative_to(repository_root).as_posix(): _sha256_bytes(path.read_bytes())
        for path in source_paths
    }
    catalog = {
        "schema_version": "1.0",
        "artifact_kind": "synthetic_seed_definitions_not_execution_results",
        "taxonomy": taxonomy.model_dump(mode="json"),
        "judge_rubric": rubric.model_dump(mode="json"),
        "seed_cases": [seed.model_dump(mode="json") for seed in seeds],
        "source_sha256": source_hashes,
    }
    return {
        **catalog,
        "catalog_sha256": _sha256_bytes(_canonical_json(catalog)),
    }


def render_bundle(repository_root: Path) -> str:
    return (
        json.dumps(
            build_bundle(repository_root),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=REPOSITORY_ROOT,
        help="repository containing config/ and evals/ (default: this checkout)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPOSITORY_ROOT / "evals" / "results" / "seed-catalog.json",
        help="sanitized JSON destination",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the destination does not exactly match the deterministic export",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate all source files and cross-references without writing",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    repository_root = args.repository_root.resolve()
    rendered = render_bundle(repository_root)
    bundle = json.loads(rendered)

    if args.validate_only:
        print(
            "validated synthetic evaluation catalog: "
            f"{len(bundle['seed_cases'])} seeds, hash={bundle['catalog_sha256']}"
        )
        return 0

    output = args.output.resolve()
    if args.check:
        if not output.is_file() or output.read_text(encoding="utf-8") != rendered:
            print(f"evaluation export drift: {output}", file=sys.stderr)
            return 1
        print(f"evaluation export is current: {output}")
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    print(f"exported {len(bundle['seed_cases'])} synthetic seed definitions to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
