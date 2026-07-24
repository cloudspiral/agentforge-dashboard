from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def run_script(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - arguments are test-owned repository paths
        [sys.executable, *arguments],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "RUN_LIVE_E2E": "0"},
    )


def test_evaluation_export_is_reproducible_and_explicitly_not_results(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"

    for destination in (first, second):
        result = run_script("scripts/export_evals.py", "--output", str(destination))
        assert result.returncode == 0, result.stderr

    assert first.read_bytes() == second.read_bytes()
    payload = json.loads(first.read_text(encoding="utf-8"))
    assert payload["artifact_kind"] == "agentforge_evaluation_definitions_not_execution_results"
    assert len(payload["seed_cases"]) == 9
    assert len(payload["control_cases"]) == 4
    assert len(payload["catalog_sha256"]) == 64

    check = run_script("scripts/export_evals.py", "--output", str(first), "--check")
    assert check.returncode == 0, check.stderr


def test_evaluation_export_validate_only_does_not_write(tmp_path: Path) -> None:
    destination = tmp_path / "must-not-exist.json"
    result = run_script(
        "scripts/export_evals.py",
        "--output",
        str(destination),
        "--validate-only",
    )
    assert result.returncode == 0, result.stderr
    assert not destination.exists()


def test_current_result_hash_validation_accepts_only_exact_yaml_bytes(tmp_path: Path) -> None:
    current = tmp_path / "current"
    current.mkdir()
    submission = REPOSITORY_ROOT / "evals" / "results" / "submission"
    for case_id in ("AF-PI-001", "AF-DE-001"):
        shutil.copyfile(submission / f"{case_id}.json", current / f"{case_id}.json")

    result = run_script(
        "scripts/check_submission_results.py",
        "--current-directory",
        str(current),
        "--minimum-categories",
        "2",
    )

    assert result.returncode == 0, result.stderr
    assert "2 compatible-schema" in result.stdout


def test_current_result_hash_validation_rejects_historical_tool_case(tmp_path: Path) -> None:
    current = tmp_path / "current"
    current.mkdir()
    submission = REPOSITORY_ROOT / "evals" / "results" / "submission"
    historical = json.loads((submission / "AF-TM-002.json").read_text(encoding="utf-8"))
    historical["case_sha256"] = "45c1b71f03692e51bc0bdb18bb473cc58aeab4d34feea99d8d565f262764dc44"
    (current / "AF-TM-002.json").write_text(
        json.dumps(historical, indent=2) + "\n",
        encoding="utf-8",
    )

    result = run_script(
        "scripts/check_submission_results.py",
        "--current-directory",
        str(current),
        "--minimum-categories",
        "0",
    )

    assert result.returncode == 1
    assert "case_sha256 mismatch" in result.stderr


def test_offline_load_test_completes_without_external_operations(tmp_path: Path) -> None:
    destination = tmp_path / "load.json"
    result = run_script(
        "scripts/load_test.py",
        "--operations",
        "5",
        "--max-seconds",
        "5",
        "--output",
        str(destination),
    )
    assert result.returncode == 0, result.stderr

    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["status"] == "passed"
    assert payload["completed_operations"] == 5
    assert payload["target_requests"] == 0
    assert payload["model_calls"] == 0
    assert payload["database_writes"] == 0
    assert payload["estimated_cost_usd"] == 0
    assert "Do not scale" in payload["recommended_scaling_change"]
    assert payload["controls"] == {
        "live_execution_enabled": False,
        "max_cost_usd": 0.0,
        "max_target_requests": 0,
        "target": "fake",
    }


def test_offline_load_test_rejects_unbounded_operation_count() -> None:
    result = run_script("scripts/load_test.py", "--operations", "10001")
    assert result.returncode == 2
    assert "operations must be between" in result.stderr


def test_offline_load_test_rejects_nonzero_external_budgets() -> None:
    result = run_script("scripts/load_test.py", "--max-target-requests", "1")
    assert result.returncode == 2
    assert "requires max_target_requests=0" in result.stderr


def test_deployment_hook_fails_closed_before_network_without_credentials() -> None:
    environment = os.environ.copy()
    for key in (
        "AGENTFORGE_BASE_URL",
        "DEPLOY_WEBHOOK_SECRET",
        "DEPLOYMENT_ID",
        "TARGET_VERSION",
    ):
        environment.pop(key, None)
    result = subprocess.run(  # noqa: S603 - fixed local script, no user input
        ["/bin/sh", "scripts/trigger_deployment_regression.sh"],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        env=environment,
    )
    assert result.returncode != 0
    assert "AGENTFORGE_BASE_URL" in result.stderr


def test_deployment_hook_rejects_unbounded_timeout_before_network() -> None:
    environment = {
        **os.environ,
        "AGENTFORGE_BASE_URL": "https://platform.invalid",
        "DEPLOY_WEBHOOK_SECRET": "synthetic-secret",
        "DEPLOYMENT_ID": "deployment-1",
        "TARGET_VERSION": "target-v1",
        "CURL_MAX_TIME_SECONDS": "0",
    }
    result = subprocess.run(  # noqa: S603 - fixed local script, no user input
        ["/bin/sh", "scripts/trigger_deployment_regression.sh"],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        env=environment,
    )
    assert result.returncode != 0
    assert "between 1 and 300" in result.stderr


def test_compose_uses_one_application_container_with_embedded_worker() -> None:
    compose = yaml.safe_load((REPOSITORY_ROOT / "compose.yaml").read_text(encoding="utf-8"))
    assert set(compose["services"]) == {"app", "postgres"}
    application = compose["services"]["app"]
    assert application["environment"]["WORKER_ENABLED"] == "true"
    assert "alembic upgrade head" in application["command"][-1]
    assert application["healthcheck"]["test"][0] == "CMD"


def test_gitlab_pipeline_is_a_minimal_ephemeral_merge_request_gate() -> None:
    pipeline = yaml.safe_load((REPOSITORY_ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8"))
    assert pipeline["variables"]["RUN_LIVE_E2E"] == "0"
    assert pipeline["stages"] == ["verify"]
    assert pipeline["default"]["image"] == ("ghcr.io/astral-sh/uv:0.11.25-python3.12-trixie-slim")
    assert "cache" not in pipeline["default"]
    assert "artifacts" not in pipeline["verify"]
    assert pipeline["verify"]["services"] == [{"name": "postgres:17-alpine", "alias": "postgres"}]
    assert pipeline["variables"]["POSTGRES_DB"].endswith("_test")
    assert (
        pipeline["variables"]["DATABASE_URL"]
        == pipeline["variables"]["AGENTFORGE_TEST_DATABASE_URL"]
    )

    verification_script = "\n".join(pipeline["verify"]["script"])
    assert "ruff format --check" in verification_script
    assert "export_contracts.py --check" in verification_script
    assert "check_submission_results.py" in verification_script
    assert "check_control_results.py" in verification_script
    assert "alembic upgrade head" in verification_script
    assert "alembic check" in verification_script
    assert "pytest -q" in verification_script
    assert "load_test.py" not in verification_script
    assert "docker build" not in verification_script

    workflow_rules = pipeline["workflow"]["rules"]
    assert workflow_rules[0] == {"if": '$CI_PIPELINE_SOURCE == "merge_request_event"'}
    assert workflow_rules[-1] == {"when": "never"}
    assert not any("CI_DEFAULT_BRANCH" in rule.get("if", "") for rule in workflow_rules)


def test_dockerfile_installs_browser_and_runs_as_non_root() -> None:
    dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "uv sync --frozen --no-dev" in dockerfile
    assert "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright" in dockerfile
    assert "playwright install --with-deps chromium" in dockerfile
    assert "USER agentforge" in dockerfile
    assert "HEALTHCHECK" in dockerfile


def test_railway_runs_migrations_and_single_worker_app_with_readiness_probe() -> None:
    railway = tomllib.loads((REPOSITORY_ROOT / "railway.toml").read_text(encoding="utf-8"))
    deploy = railway["deploy"]
    assert "alembic upgrade head" in deploy["startCommand"]
    assert "--workers 1" in deploy["startCommand"]
    assert deploy["healthcheckPath"] == "/readyz"
