#!/usr/bin/env python3
"""Validate current OWASP control results, evidence, mappings, and exact case hashes."""

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

from agentforge.evaluation import (  # noqa: E402
    ControlResultV1,
    load_control_case,
    load_control_cases,
)
from agentforge.evaluation.owasp_controls import ControlEvidenceEnvelopeV1  # noqa: E402


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_control_results(repository_root: Path, results_directory: Path) -> int:
    case_directory = repository_root / "evals/control-cases"
    cases = load_control_cases(case_directory)
    case_paths = {
        load_control_case(path).id: path for path in sorted(case_directory.glob("*.yaml"))
    }
    errors: list[str] = []
    expected_ids = {case.id for case in cases}
    observed_ids: set[str] = set()

    for case in cases:
        result_path = results_directory / f"{case.id}.json"
        evidence_path = results_directory / f"{case.id}.evidence.json"
        if not result_path.is_file() or not evidence_path.is_file():
            errors.append(f"{case.id}: result or primary evidence file is missing")
            continue
        try:
            result = ControlResultV1.model_validate_json(result_path.read_text(encoding="utf-8"))
            evidence = ControlEvidenceEnvelopeV1.model_validate_json(
                evidence_path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{case.id}: invalid result/evidence schema ({type(exc).__name__})")
            continue
        observed_ids.add(result.case_id)
        expected_hash = _sha256(case_paths[case.id])
        expected_source = case_paths[case.id].relative_to(repository_root).as_posix()
        checks = {
            "result case ID": result.case_id == case.id,
            "evidence case ID": evidence.case_id == case.id,
            "result case hash": result.case_sha256 == expected_hash,
            "evidence case hash": evidence.case_sha256 == expected_hash,
            "case source": evidence.case_source == expected_source,
            "embedded case": evidence.case_definition == case,
            "target version": evidence.target_version == result.target_version,
            "profile version": bool(evidence.target_profile_version.strip()),
            "profile hash": len(evidence.target_profile_hash) == 64,
        }
        expected_mappings = {(mapping.framework, mapping.id) for mapping in case.mappings}
        observed_mappings = {(mapping.framework, mapping.id) for mapping in result.mapping_results}
        checks["mapping set"] = observed_mappings == expected_mappings
        for label, passed in checks.items():
            if not passed:
                detail = f"; expected {expected_hash}" if "case hash" in label else ""
                errors.append(f"{case.id}: {label} mismatch{detail}")
        for reference in result.evidence_paths:
            referenced = (repository_root / reference).resolve()
            if repository_root.resolve() not in referenced.parents or not referenced.is_file():
                errors.append(f"{case.id}: missing or out-of-repository evidence {reference}")

    if observed_ids != expected_ids:
        errors.append(
            "control result IDs differ: "
            f"expected {sorted(expected_ids)}, got {sorted(observed_ids)}"
        )
    if errors:
        raise ValueError("\n".join(errors))
    return len(cases)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument(
        "--results-directory",
        type=Path,
        default=REPOSITORY_ROOT / "evals/results/submission/controls",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        count = validate_control_results(
            args.repository_root.resolve(), args.results_directory.resolve()
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"validated {count} target-specific OWASP control results and evidence envelopes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
