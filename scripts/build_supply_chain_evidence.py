#!/usr/bin/env python3
"""Build sanitized AF-SC-001 evidence from fixed Clinical Co-Pilot scan inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Final

REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
SOURCE_ROOT: Final = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from agentforge.contracts.v1.common import utc_now  # noqa: E402
from agentforge.evaluation import load_control_case  # noqa: E402
from agentforge.evaluation.owasp_controls import (  # noqa: E402
    ControlEvidenceEnvelopeV1,
    SupplyChainControlEvidenceV1,
    SupplyChainDeploymentInputV1,
    SupplyChainFindingV1,
    SupplyChainModelInputV1,
    build_supply_chain_result,
    case_provenance,
)
from agentforge.settings import Settings  # noqa: E402
from agentforge.target.profile import load_target_profile  # noqa: E402

_CASE_PATH: Final = REPOSITORY_ROOT / "evals/control-cases/sca-components-supply-chain.yaml"
_OUTPUT_DIRECTORY: Final = REPOSITORY_ROOT / "evals/results/submission/controls"
_OSV_PATH: Final = _OUTPUT_DIRECTORY / "sca/AF-SC-001.osv.json"
_CYCLONEDX_PATH: Final = _OUTPUT_DIRECTORY / "sca/AF-SC-001.cdx.json"
_TARGET_INPUTS: Final = (
    "composer.lock",
    "package-lock.json",
    "agent_service/requirements.txt",
    "Dockerfile",
    "agent_service/Dockerfile",
    "agent_service/app/config.py",
    "agent_service/app/llm.py",
)
_SCANNED_LOCKFILES: Final = (
    "composer.lock",
    "package-lock.json",
    "agent_service/requirements.txt",
)
_RUNTIME_PYTHON_VERSIONS: Final = {
    "idna": "3.18",
    "requests": "2.34.2",
    "tqdm": "4.69.0",
}
_SHA1: Final = re.compile(r"^[0-9a-f]{40}$")
_SHA256: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_UUID: Final = re.compile(r"^[0-9a-f-]{36}$")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git(target: Path, *args: str) -> bytes:
    completed = subprocess.run(  # noqa: S603 - fixed executable and read-only Git arguments
        ["/usr/bin/git", "-C", str(target), *args],
        check=True,
        capture_output=True,
    )
    return completed.stdout


def verify_target_inputs(target: Path, expected_commit: str) -> dict[str, str]:
    """Hash only selected inputs after proving their bytes match the requested commit."""

    if not target.is_dir():
        raise ValueError("target repository does not exist")
    actual_commit = _git(target, "rev-parse", "HEAD").decode().strip()
    if actual_commit != expected_commit:
        raise ValueError("target checkout HEAD does not match the deployed commit")
    hashes: dict[str, str] = {}
    for relative in _TARGET_INPUTS:
        working_bytes = (target / relative).read_bytes()
        committed_bytes = _git(target, "show", f"{expected_commit}:{relative}")
        if working_bytes != committed_bytes:
            raise ValueError(f"selected target input differs from deployed commit: {relative}")
        hashes[relative] = _sha256(working_bytes)
    return hashes


def _severity(vulnerability: Mapping[str, object]) -> str:
    database = vulnerability.get("database_specific")
    value = database.get("severity") if isinstance(database, Mapping) else None
    normalized = str(value).upper() if value else "UNKNOWN"
    if normalized == "MEDIUM":
        normalized = "MODERATE"
    return normalized if normalized in {"LOW", "MODERATE", "HIGH", "CRITICAL"} else "UNKNOWN"


def _advisories(vulnerabilities: Iterable[Mapping[str, object]]) -> tuple[list[str], list[str]]:
    identifiers: set[str] = set()
    severities: set[str] = set()
    for vulnerability in vulnerabilities:
        vulnerability_id = vulnerability.get("id")
        aliases = vulnerability.get("aliases")
        candidates = [vulnerability_id] if isinstance(vulnerability_id, str) else []
        if isinstance(aliases, list):
            candidates.extend(alias for alias in aliases if isinstance(alias, str))
        ghsa = {value for value in candidates if value.startswith("GHSA-")}
        identifiers.update(ghsa or candidates)
        severities.add(_severity(vulnerability))
    return sorted(identifiers), sorted(severities)


def _triage(ecosystem: str, package: str, scanned_version: str) -> tuple[str, str]:
    normalized = package.casefold()
    if ecosystem == "PyPI" and normalized in _RUNTIME_PYTHON_VERSIONS:
        runtime_version = _RUNTIME_PYTHON_VERSIONS[normalized]
        return (
            "not_applicable_runtime_version_mismatch",
            f"The manifest scan resolved {scanned_version}, but the deployed agent-service "
            f"container reports {package} {runtime_version}; this scanner match is not "
            "applicable to the running Python environment.",
        )
    if ecosystem == "Packagist" and normalized in {
        "guzzlehttp/guzzle",
        "guzzlehttp/psr7",
    }:
        return (
            "deployed_runtime_confirmed",
            f"The OpenEMR container reports {package} {scanned_version}, matching the "
            "Composer lockfile and the scanner finding. Exploitability was not tested.",
        )
    if ecosystem == "npm":
        return (
            "deployed_frontend_or_build_input",
            "The exact npm lockfile is a deployed frontend/build input. The final image omits "
            "root node_modules, so per-package runtime reachability remains unproven.",
        )
    raise ValueError(f"unreviewed scanner finding: {ecosystem}:{package}@{scanned_version}")


def parse_osv_findings(payload: Mapping[str, object]) -> list[SupplyChainFindingV1]:
    findings: list[SupplyChainFindingV1] = []
    results = payload.get("results")
    if not isinstance(results, list):
        raise ValueError("OSV result list is missing")
    for result in results:
        if not isinstance(result, Mapping):
            continue
        packages = result.get("packages")
        if not isinstance(packages, list):
            continue
        for entry in packages:
            if not isinstance(entry, Mapping):
                continue
            package_data = entry.get("package")
            vulnerabilities = entry.get("vulnerabilities")
            if not isinstance(package_data, Mapping) or not isinstance(vulnerabilities, list):
                continue
            typed_vulnerabilities = [item for item in vulnerabilities if isinstance(item, Mapping)]
            package = str(package_data.get("name", ""))
            version = str(package_data.get("version", ""))
            ecosystem = str(package_data.get("ecosystem", ""))
            advisory_ids, severities = _advisories(typed_vulnerabilities)
            applicability, triage = _triage(ecosystem, package, version)
            findings.append(
                SupplyChainFindingV1(
                    package=package,
                    version=version,
                    advisory_ids=advisory_ids,
                    severities=severities,
                    applicability=applicability,
                    triage=triage,
                )
            )
    if not findings:
        raise ValueError("OSV output contained no reviewable findings")
    return sorted(findings, key=lambda item: (item.package.casefold(), item.version))


def _package_count(target: Path) -> int:
    composer = json.loads((target / "composer.lock").read_text(encoding="utf-8"))
    npm = json.loads((target / "package-lock.json").read_text(encoding="utf-8"))
    requirements = (target / "agent_service/requirements.txt").read_text(encoding="utf-8")
    composer_count = len(composer.get("packages", [])) + len(composer.get("packages-dev", []))
    npm_packages = npm.get("packages", {})
    npm_count = (
        len([path for path in npm_packages if path]) if isinstance(npm_packages, dict) else 0
    )
    requirements_count = len(
        [
            line
            for line in requirements.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    )
    return composer_count + npm_count + requirements_count


def _validated(value: str, pattern: re.Pattern[str], label: str) -> str:
    if not pattern.fullmatch(value):
        raise ValueError(f"invalid {label}")
    return value


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-repository", type=Path, required=True)
    parser.add_argument("--target-commit", required=True)
    parser.add_argument("--openemr-deployment-id", required=True)
    parser.add_argument("--openemr-image-digest", required=True)
    parser.add_argument("--agent-deployment-id", required=True)
    parser.add_argument("--agent-image-digest", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    target_commit = _validated(args.target_commit, _SHA1, "target commit")
    openemr_deployment = _validated(args.openemr_deployment_id, _UUID, "deployment ID")
    agent_deployment = _validated(args.agent_deployment_id, _UUID, "deployment ID")
    openemr_digest = _validated(args.openemr_image_digest, _SHA256, "image digest")
    agent_digest = _validated(args.agent_image_digest, _SHA256, "image digest")
    target = args.target_repository.resolve()
    manifest_hashes = verify_target_inputs(target, target_commit)

    osv_bytes = _OSV_PATH.read_bytes()
    cyclonedx_bytes = _CYCLONEDX_PATH.read_bytes()
    osv = json.loads(osv_bytes)
    cyclonedx = json.loads(cyclonedx_bytes)
    findings = parse_osv_findings(osv)
    vulnerabilities = cyclonedx.get("vulnerabilities")
    if cyclonedx.get("bomFormat") != "CycloneDX" or not isinstance(vulnerabilities, list):
        raise ValueError("CycloneDX evidence is invalid")

    case = load_control_case(_CASE_PATH)
    case_source, case_sha256 = case_provenance(REPOSITORY_ROOT, _CASE_PATH)
    settings = Settings()
    loaded_profile = load_target_profile(REPOSITORY_ROOT / settings.target_profile_path)
    evidence_path = _OUTPUT_DIRECTORY / "AF-SC-001.evidence.json"
    result_path = _OUTPUT_DIRECTORY / "AF-SC-001.json"
    evidence_reference = evidence_path.relative_to(REPOSITORY_ROOT).as_posix()
    osv_reference = _OSV_PATH.relative_to(REPOSITORY_ROOT).as_posix()
    cyclonedx_reference = _CYCLONEDX_PATH.relative_to(REPOSITORY_ROOT).as_posix()

    evidence = SupplyChainControlEvidenceV1(
        target_source_commit=target_commit,
        selected_inputs_match_target_commit=True,
        manifest_sha256=manifest_hashes,
        deployments=[
            SupplyChainDeploymentInputV1(
                service="openemr-web",
                deployment_id=openemr_deployment,
                image_digest=openemr_digest,
                dockerfile_path="Dockerfile",
            ),
            SupplyChainDeploymentInputV1(
                service="agent-service",
                deployment_id=agent_deployment,
                image_digest=agent_digest,
                dockerfile_path="agent_service/Dockerfile",
            ),
        ],
        scanner_name="osv-scanner",
        scanner_version="2.3.8",
        scanner_commit="408fcd6f8707999a29e7ba45e15809764cf24f67",
        scanner_image_digest=(
            "sha256:64e86bec6df2466feea5137fc7c78fb3b7c21ec077f014d7130f64810e50676b"
        ),
        scanned_lockfiles=list(_SCANNED_LOCKFILES),
        scanned_package_count=_package_count(target),
        scanner_vulnerability_record_count=len(vulnerabilities),
        findings=findings,
        models=[
            SupplyChainModelInputV1(
                role="clinical_supervisor",
                model="gpt-4.1-mini",
                source="deployment_environment",
                provenance_attestation="unavailable",
            ),
            SupplyChainModelInputV1(
                role="document_extraction",
                model="gpt-5.6-terra",
                source="checked_in_default",
                provenance_attestation="unavailable",
            ),
            SupplyChainModelInputV1(
                role="document_verifier",
                model="gpt-4.1-mini",
                source="deployment_environment",
                provenance_attestation="unavailable",
            ),
        ],
        model_provenance_attestations_available=False,
        prompt_source_sha256=manifest_hashes["agent_service/app/llm.py"],
        osv_json_path=osv_reference,
        osv_json_sha256=_sha256(osv_bytes),
        cyclonedx_path=cyclonedx_reference,
        cyclonedx_sha256=_sha256(cyclonedx_bytes),
        limitations=[
            "Scanner matches are not proof of exploitability and were not actively exploited.",
            "npm package runtime reachability in compiled frontend assets was not proven.",
            "Provider model provenance attestations were unavailable.",
            "Container base-image operating-system packages were inventoried by image "
            "digest but not scanned.",
        ],
    )
    envelope = ControlEvidenceEnvelopeV1(
        case_id=case.id,
        case_source=case_source,
        case_sha256=case_sha256,
        case_definition=case,
        target_version=target_commit,
        target_source_sha256=None,
        target_profile_version=loaded_profile.profile.profile_version,
        target_profile_hash=loaded_profile.profile_hash,
        executed_at=utc_now(),
        evidence=evidence,
    )
    result = build_supply_chain_result(
        case=case,
        case_sha256=case_sha256,
        target_version=target_commit,
        evidence_path=evidence_reference,
        evidence=evidence,
    )
    evidence_path.write_text(
        json.dumps(envelope.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    result_path.write_text(
        json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"exported {result_path.relative_to(REPOSITORY_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
