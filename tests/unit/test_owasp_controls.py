from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from agentforge.evaluation.catalog import CoverageStatusV1, load_control_case
from agentforge.evaluation.owasp_controls import (
    BrowserControlEvidenceV1,
    SupplyChainControlEvidenceV1,
    SupplyChainDeploymentInputV1,
    SupplyChainFindingV1,
    SupplyChainModelInputV1,
    build_auth_logging_result,
    build_browser_result,
    build_supply_chain_result,
    run_missing_session_control,
)
from agentforge.runners.playwright_runner import OwaspBrowserControlObservationV1
from agentforge.settings import Settings
from agentforge.target.profile import load_target_profile

ROOT = Path(__file__).parents[2]


@pytest.mark.asyncio
async def test_missing_session_control_sends_one_credential_free_proxy_request() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/health":
            return httpx.Response(200, json={"build_sha": "a" * 64}, request=request)
        assert request.url.path == "/interface/patient_file/clinical_copilot/proxy.php"
        assert request.url.query == b"site=default"
        assert "authorization" not in request.headers
        assert "cookie" not in request.headers
        return httpx.Response(
            403,
            json={"error": "authentication required"},
            headers={"x-correlation-id": "afa10001-0000-4000-8000-000000000001"},
            request=request,
        )

    target_version, evidence = await run_missing_session_control(
        loaded_profile=load_target_profile(ROOT / "config/target-profile.yaml"),
        settings=Settings(target_ui_smoke_timeout_seconds=5),
        transport=httpx.MockTransport(handler),
    )

    assert target_version == "a" * 64
    assert [request.url.path for request in requests] == [
        "/health",
        "/interface/patient_file/clinical_copilot/proxy.php",
    ]
    assert evidence.request_count == 1
    assert evidence.access_denied is True
    assert evidence.patient_disclosure_markers_present is False
    assert evidence.login_boundary_marker_present is False
    assert evidence.response_correlation_id_present is True

    case = load_control_case(ROOT / "evals/control-cases/authentication-logging-boundary.yaml")
    result = build_auth_logging_result(
        case=case,
        case_sha256="0" * 64,
        target_version=target_version,
        evidence_path="evals/results/submission/controls/AF-AL-001.evidence.json",
        evidence=evidence,
    )
    statuses = {item.id: item.status for item in result.mapping_results}
    assert result.execution_status == CoverageStatusV1.PARTIAL
    assert statuses == {
        "A07": CoverageStatusV1.VERIFIED,
        "A09": CoverageStatusV1.PARTIAL,
    }


def test_output_control_requires_literal_text_without_a_rendered_element() -> None:
    case = load_control_case(ROOT / "evals/control-cases/output-markup-canary.yaml")
    evidence = BrowserControlEvidenceV1(
        observation=OwaspBrowserControlObservationV1(
            case_id="AF-OH-001",
            target_version="a" * 64,
            response_sha256="b" * 64,
            response_length=72,
            refusal_detected=False,
            unsupported_fetch_claim_detected=False,
            literal_markup_canary_returned=True,
            rendered_markup_canary_elements=0,
            browser_sentinel_request_count=0,
        )
    )

    result = build_browser_result(
        case=case,
        case_sha256="c" * 64,
        evidence_path="evals/results/submission/controls/AF-OH-001.evidence.json",
        evidence=evidence,
    )

    assert result.execution_status == CoverageStatusV1.VERIFIED
    assert result.mapping_results[0].status == CoverageStatusV1.VERIFIED
    assert result.regression_eligible is False


def test_ssrf_control_remains_partial_without_target_outbound_telemetry() -> None:
    case = load_control_case(ROOT / "evals/control-cases/ssrf-url-sentinel.yaml")
    evidence = BrowserControlEvidenceV1(
        observation=OwaspBrowserControlObservationV1(
            case_id="AF-SSRF-001",
            target_version="a" * 64,
            response_sha256="b" * 64,
            response_length=40,
            refusal_detected=True,
            unsupported_fetch_claim_detected=False,
            literal_markup_canary_returned=False,
            rendered_markup_canary_elements=0,
            browser_sentinel_request_count=0,
        )
    )

    result = build_browser_result(
        case=case,
        case_sha256="c" * 64,
        evidence_path="evals/results/submission/controls/AF-SSRF-001.evidence.json",
        evidence=evidence,
    )

    assert result.execution_status == CoverageStatusV1.PARTIAL
    assert result.mapping_results[0].status == CoverageStatusV1.PARTIAL
    assert "zero server traffic is not claimed" in result.observed_behavior


def test_supply_chain_result_separates_components_from_model_provenance() -> None:
    case = load_control_case(ROOT / "evals/control-cases/sca-components-supply-chain.yaml")
    evidence = SupplyChainControlEvidenceV1(
        target_source_commit="a" * 40,
        selected_inputs_match_target_commit=True,
        manifest_sha256={"composer.lock": "b" * 64},
        deployments=[
            SupplyChainDeploymentInputV1(
                service="openemr-web",
                deployment_id="531630f7-da13-4aa3-b365-bbbb15dfdd50",
                image_digest="sha256:" + "c" * 64,
                dockerfile_path="Dockerfile",
            ),
            SupplyChainDeploymentInputV1(
                service="agent-service",
                deployment_id="9b7d9985-1e57-4735-9fe4-dcc536a91bc7",
                image_digest="sha256:" + "d" * 64,
                dockerfile_path="agent_service/Dockerfile",
            ),
        ],
        scanner_name="osv-scanner",
        scanner_version="2.3.8",
        scanner_commit="408fcd6f8707999a29e7ba45e15809764cf24f67",
        scanner_image_digest=(
            "sha256:64e86bec6df2466feea5137fc7c78fb3b7c21ec077f014d7130f64810e50676b"
        ),
        scanned_lockfiles=[
            "composer.lock",
            "package-lock.json",
            "agent_service/requirements.txt",
        ],
        scanned_package_count=3,
        scanner_vulnerability_record_count=1,
        findings=[
            SupplyChainFindingV1(
                package="guzzlehttp/guzzle",
                version="7.12.1",
                advisory_ids=["GHSA-example"],
                severities=["HIGH"],
                applicability="deployed_runtime_confirmed",
                triage="The running container version matched; exploitability was not tested.",
            )
        ],
        models=[
            SupplyChainModelInputV1(
                role=role,
                model="gpt-test",
                source="checked_in_default",
                provenance_attestation="unavailable",
            )
            for role in ("clinical_supervisor", "document_extraction", "document_verifier")
        ],
        model_provenance_attestations_available=False,
        prompt_source_sha256="e" * 64,
        osv_json_path="evals/results/submission/controls/sca/AF-SC-001.osv.json",
        osv_json_sha256="f" * 64,
        cyclonedx_path="evals/results/submission/controls/sca/AF-SC-001.cdx.json",
        cyclonedx_sha256="0" * 64,
    )

    result = build_supply_chain_result(
        case=case,
        case_sha256="1" * 64,
        target_version="a" * 40,
        evidence_path="evals/results/submission/controls/AF-SC-001.evidence.json",
        evidence=evidence,
    )

    statuses = {mapping.id: mapping.status for mapping in result.mapping_results}
    assert result.execution_status == CoverageStatusV1.FAILED
    assert statuses == {
        "A06": CoverageStatusV1.FAILED,
        "LLM03": CoverageStatusV1.PARTIAL,
    }
    assert result.regression_eligible is True
