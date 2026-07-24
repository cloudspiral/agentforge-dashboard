#!/usr/bin/env python3
"""Fail when a current submission result drifts from its exact seed YAML bytes."""

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

from agentforge.evaluation.catalog import load_seed_cases  # noqa: E402
from agentforge.evaluation.live_local import LiveLocalEvaluationResultV1  # noqa: E402


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_current_results(
    repository_root: Path,
    current_directory: Path,
    *,
    minimum_categories: int,
) -> list[LiveLocalEvaluationResultV1]:
    """Validate only canonical root JSON files; nested historical/control evidence is excluded."""

    seed_directory = repository_root / "evals" / "seed-cases"
    seeds = load_seed_cases(seed_directory)
    seed_paths: dict[str, Path] = {}
    for path in sorted(seed_directory.glob("*.yaml")):
        case = next((item for item in seeds if item.id == _case_id(path)), None)
        if case is not None:
            seed_paths[case.id] = path

    errors: list[str] = []
    results: list[LiveLocalEvaluationResultV1] = []
    seen_ids: set[str] = set()
    for result_path in sorted(current_directory.glob("*.json")):
        try:
            result = LiveLocalEvaluationResultV1.model_validate_json(
                result_path.read_text(encoding="utf-8"),
                context={"allow_legacy_confirmed_verdict_without_finding_key": True},
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{result_path.name}: invalid result schema ({type(exc).__name__})")
            continue
        if result.case_id in seen_ids:
            errors.append(f"{result_path.name}: duplicate current case {result.case_id}")
            continue
        seen_ids.add(result.case_id)
        source = seed_paths.get(result.case_id)
        if source is None:
            errors.append(f"{result_path.name}: no current seed YAML for {result.case_id}")
            continue
        expected_source = source.relative_to(repository_root).as_posix()
        expected_result = f"evals/results/submission/{result_path.name}"
        expected_sha = _sha256(source)
        seed = next(item for item in seeds if item.id == result.case_id)
        checks = {
            "filename": result_path.name == f"{result.case_id}.json",
            "case_source": result.case_source == expected_source,
            "case_sha256": result.case_sha256 == expected_sha,
            "case_version": result.case_version == seed.schema_version,
            "result_path": result.result_path == expected_result,
            "run_mode": result.run_mode == "live_deployed",
            "target_alias": result.target_alias == "deployed",
            "target_version": bool(result.target_version.strip()),
            "target_profile_version": bool(result.target_profile_version.strip()),
            "evidence_target_version": (
                result.evidence is None or result.evidence.target_version == result.target_version
            ),
            "evidence_campaign_id": (
                result.evidence is None or result.evidence.campaign_id == result.campaign_id
            ),
            "evidence_attempt_id": (
                result.evidence is None or result.evidence.attempt_id == result.attempt_id
            ),
        }
        for check, passed in checks.items():
            if not passed:
                detail = (
                    f" expected exact YAML SHA-256 {expected_sha}" if check == "case_sha256" else ""
                )
                errors.append(f"{result_path.name}: {check} mismatch{detail}")
        results.append(result)

    represented_categories = {
        next(seed.category for seed in seeds if seed.id == result.case_id)
        for result in results
        if result.case_id in seed_paths
    }
    if len(represented_categories) < minimum_categories:
        errors.append(
            "current results cover "
            f"{len(represented_categories)} categories; required {minimum_categories}"
        )
    if errors:
        raise ValueError("\n".join(errors))
    return results


def _case_id(path: Path) -> str:
    import yaml

    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    value = payload.get("id") if isinstance(payload, dict) else None
    return value if isinstance(value, str) else ""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument(
        "--current-directory",
        type=Path,
        default=REPOSITORY_ROOT / "evals" / "results" / "submission",
    )
    parser.add_argument("--minimum-categories", type=int, default=3)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not 0 <= args.minimum_categories <= 20:
        print("minimum categories must be between 0 and 20", file=sys.stderr)
        return 2
    try:
        results = validate_current_results(
            args.repository_root.resolve(),
            args.current_directory.resolve(),
            minimum_categories=args.minimum_categories,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(
        "validated current submission results: "
        f"{len(results)} compatible-schema, exact-case-hash exports"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
