#!/usr/bin/env python3
"""Run one fixed Clinical Co-Pilot OWASP control and export sanitized evidence."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Final, Literal

REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
SOURCE_ROOT: Final = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from agentforge.contracts.v1.common import utc_now  # noqa: E402
from agentforge.evaluation import load_control_case  # noqa: E402
from agentforge.evaluation.owasp_controls import (  # noqa: E402
    BrowserControlEvidenceV1,
    ControlEvidenceEnvelopeV1,
    build_auth_logging_result,
    build_browser_result,
    case_provenance,
    run_missing_session_control,
)
from agentforge.runners.playwright_runner import (  # noqa: E402
    run_live_owasp_browser_control,
)
from agentforge.settings import Settings  # noqa: E402
from agentforge.target.profile import load_target_profile  # noqa: E402

RunnableControlId = Literal["AF-AL-001", "AF-SSRF-001", "AF-OH-001"]
_CASE_PATHS: Final[dict[RunnableControlId, str]] = {
    "AF-AL-001": "authentication-logging-boundary.yaml",
    "AF-SSRF-001": "ssrf-url-sentinel.yaml",
    "AF-OH-001": "output-markup-canary.yaml",
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-id", choices=sorted(_CASE_PATHS), required=True)
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=REPOSITORY_ROOT / "evals" / "results" / "submission" / "controls",
    )
    return parser.parse_args(argv)


async def _run(case_id: RunnableControlId, output_directory: Path) -> tuple[Path, Path]:
    repository = REPOSITORY_ROOT.resolve()
    output = output_directory.resolve()
    allowed = repository / "evals" / "results" / "submission" / "controls"
    if output != allowed:
        raise ValueError("control evidence output is fixed to the submission controls directory")
    case_path = repository / "evals" / "control-cases" / _CASE_PATHS[case_id]
    case = load_control_case(case_path)
    case_source, case_sha256 = case_provenance(repository, case_path)
    settings = Settings()
    loaded_profile = load_target_profile(repository / settings.target_profile_path)
    evidence_path = output / f"{case.id}.evidence.json"
    result_path = output / f"{case.id}.json"
    evidence_reference = evidence_path.relative_to(repository).as_posix()

    if case_id == "AF-AL-001":
        target_version, evidence = await run_missing_session_control(
            loaded_profile=loaded_profile,
            settings=settings,
        )
        result = build_auth_logging_result(
            case=case,
            case_sha256=case_sha256,
            target_version=target_version,
            evidence_path=evidence_reference,
            evidence=evidence,
        )
    else:
        observation = await run_live_owasp_browser_control(
            case_id=case_id,
            loaded_profile=loaded_profile,
            settings=settings,
            repository_root=repository,
            timeout_seconds=settings.target_ui_smoke_timeout_seconds,
        )
        target_version = observation.target_version
        evidence = BrowserControlEvidenceV1(observation=observation)
        result = build_browser_result(
            case=case,
            case_sha256=case_sha256,
            evidence_path=evidence_reference,
            evidence=evidence,
        )

    envelope = ControlEvidenceEnvelopeV1(
        case_id=case.id,
        case_source=case_source,
        case_sha256=case_sha256,
        case_definition=case,
        target_version=target_version,
        target_source_sha256=target_version if len(target_version) == 64 else None,
        target_profile_version=loaded_profile.profile.profile_version,
        target_profile_hash=loaded_profile.profile_hash,
        executed_at=utc_now(),
        evidence=evidence,
    )
    output.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(
        json.dumps(envelope.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    result_path.write_text(
        json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result_path, evidence_path


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result_path, evidence_path = asyncio.run(_run(args.case_id, args.output_directory))
    except Exception as exc:
        print(f"control execution blocked ({type(exc).__name__})", file=sys.stderr)
        return 1
    print(
        "exported sanitized control result and evidence: "
        f"{result_path.relative_to(REPOSITORY_ROOT)}, "
        f"{evidence_path.relative_to(REPOSITORY_ROOT)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
