from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from prometheus_client import CollectorRegistry
from typer.testing import CliRunner

from agentforge.main import create_app
from agentforge.observability import AgentForgeMetrics
from agentforge.orchestration.worker import CampaignProcessResult
from agentforge.persistence import Base, Database
from agentforge.settings import Settings

PROJECT_ROOT = Path(__file__).resolve().parents[2]
cli_module = importlib.import_module("agentforge.cli.app")


class FakeTelemetry:
    enabled = True

    def __init__(self) -> None:
        self.flush_calls = 0
        self.shutdown_calls = 0

    def flush(self) -> bool:
        self.flush_calls += 1
        return True

    def shutdown(self) -> bool:
        self.shutdown_calls += 1
        return True


class FakeProcessor:
    def __init__(self) -> None:
        self.calls: list[Any] = []

    async def process(self, campaign_id: Any) -> CampaignProcessResult:
        self.calls.append(campaign_id)
        return CampaignProcessResult(status="completed")


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "test",
        "database_url": f"sqlite+pysqlite:///{tmp_path / 'agentforge.db'}",
        "worker_enabled": False,
        "langfuse_enabled": False,
        "platform_api_token": "unit-platform-token",
        "target_profile_path": PROJECT_ROOT / "config/target-profile.yaml",
        "attack_taxonomy_path": PROJECT_ROOT / "config/attack-taxonomy.yaml",
        "judge_rubric_path": PROJECT_ROOT / "config/judge-rubric.yaml",
        "pricing_path": PROJECT_ROOT / "config/pricing.yaml",
        "reports_dir": tmp_path / "reports",
        "artifacts_dir": tmp_path / "artifacts",
    }
    values.update(overrides)
    return Settings(**values)


def _database(settings: Settings) -> Database:
    database = Database(settings.database_url)
    # The production Alembic migration correctly creates this index once. The
    # ORM metadata currently also carries both explicit and column-flag copies,
    # which SQLite cannot create under the same name in a unit-test schema.
    campaign_table = Base.metadata.tables["campaigns"]
    duplicate_indexes = [
        index for index in campaign_table.indexes if index.name == "ix_campaigns_target_version"
    ]
    for duplicate in duplicate_indexes[1:]:
        campaign_table.indexes.remove(duplicate)
    Base.metadata.create_all(database.engine)
    return database


def test_app_wires_health_readiness_metrics_dashboard_api_and_shutdown(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    database = _database(settings)
    telemetry = FakeTelemetry()
    app_metrics = AgentForgeMetrics(CollectorRegistry())
    application = create_app(
        settings=settings,
        database=database,
        telemetry=telemetry,  # type: ignore[arg-type]
        app_metrics=app_metrics,
        processor_factory=lambda *_args: pytest.fail("disabled worker built a processor"),
    )

    with TestClient(application) as client:
        health = client.get("/healthz")
        ready = client.get("/readyz")
        prometheus = client.get("/metrics")
        dashboard = client.get("/")
        stylesheet = client.get("/static/agentforge.css")
        campaigns = client.get("/api/v1/campaigns")
        unauthorized = client.post(
            "/api/v1/campaigns",
            headers={"X-Correlation-ID": "test-correlation"},
            json={"campaign_type": "discovery", "target_alias": "local"},
        )

        assert health.status_code == 200
        assert health.json() == {"status": "ok"}
        assert ready.status_code == 200
        assert ready.json() == {
            "status": "ready",
            "checks": {
                "configuration": "ready",
                "database": "ready",
                "worker": "disabled",
            },
        }
        assert prometheus.status_code == 200
        assert prometheus.headers["content-type"].startswith("text/plain")
        assert "agentforge_queue_depth" in prometheus.text
        assert client.app.state.evaluation_manager.telemetry is telemetry
        assert "agentforge_persisted_queue_depth" in prometheus.text
        assert dashboard.status_code == 200
        assert "Synthetic-data, authorized targets only" in dashboard.text
        assert stylesheet.status_code == 200
        assert campaigns.json()["total"] == 0
        assert unauthorized.status_code == 401
        assert unauthorized.json() == {
            "code": "invalid_token",
            "message": "invalid bearer token",
            "correlation_id": "test-correlation",
        }
        assert unauthorized.headers["x-correlation-id"] == "test-correlation"

    assert telemetry.flush_calls == 1
    assert telemetry.shutdown_calls == 1


def test_production_protects_dashboard_api_and_metrics_but_not_health(
    tmp_path: Path,
) -> None:
    settings = _settings(
        tmp_path,
        environment="production",
        dashboard_auth_username="admin",
        dashboard_auth_password="pass",  # noqa: S106 - synthetic HTTP Basic fixture
    )
    database = _database(settings)
    application = create_app(
        settings=settings,
        database=database,
        telemetry=FakeTelemetry(),  # type: ignore[arg-type]
        app_metrics=AgentForgeMetrics(CollectorRegistry()),
    )
    bearer_headers = {"Authorization": "Bearer unit-platform-token"}

    with TestClient(application) as client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/readyz").status_code == 200

        dashboard = client.get("/")
        assert dashboard.status_code == 401
        assert dashboard.headers["www-authenticate"] == 'Basic realm="AgentForge"'
        assert client.get("/", auth=("admin", "wrong")).status_code == 401
        assert client.get("/", auth=("admin", "pass")).status_code == 200

        assert client.get("/api/v1/campaigns").status_code == 401
        assert client.get("/api/v1/campaigns", headers=bearer_headers).status_code == 200
        assert client.get("/metrics").status_code == 401
        assert client.get("/metrics", headers=bearer_headers).status_code == 200

        assert client.get("/docs").status_code == 404
        assert client.get("/redoc").status_code == 404
        assert client.get("/openapi.json").status_code == 404


def test_enabled_worker_is_started_once_and_stopped_with_lifespan(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path,
        worker_enabled=True,
        worker_poll_seconds=0.1,
        worker_stale_after_seconds=30,
    )
    database = _database(settings)
    telemetry = FakeTelemetry()
    processor = FakeProcessor()
    factory_calls = 0

    def processor_factory(*_args: Any) -> FakeProcessor:
        nonlocal factory_calls
        factory_calls += 1
        return processor

    application = create_app(
        settings=settings,
        database=database,
        telemetry=telemetry,  # type: ignore[arg-type]
        app_metrics=AgentForgeMetrics(CollectorRegistry()),
        processor_factory=processor_factory,
    )

    with TestClient(application) as client:
        task = application.state.worker_task
        assert factory_calls == 1
        assert application.state.worker is not None
        assert task is not None
        assert task.done() is False
        assert client.get("/readyz").json()["checks"]["worker"] == "ready"

    assert task.done() is True
    assert processor.calls == []
    assert telemetry.flush_calls == 1
    assert telemetry.shutdown_calls == 1


def test_readiness_rejects_an_unmigrated_database(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    database = Database(settings.database_url)
    telemetry = FakeTelemetry()
    application = create_app(
        settings=settings,
        database=database,
        telemetry=telemetry,  # type: ignore[arg-type]
        app_metrics=AgentForgeMetrics(CollectorRegistry()),
    )

    with TestClient(application) as client:
        response = client.get("/readyz")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert response.json()["checks"]["database"] == "unavailable"


def test_cli_campaign_seed_and_regression_commands_use_application_services(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path)
    database = _database(settings)
    database.dispose()
    monkeypatch.setattr(cli_module, "get_settings", lambda: settings)
    runner = CliRunner()

    created = runner.invoke(
        cli_module.app,
        [
            "campaign",
            "create",
            "--category",
            "prompt_injection",
            "--subcategory",
            "direct",
            "--max-attempts",
            "2",
            "--max-cost-usd",
            "0.5",
        ],
    )
    assert created.exit_code == 0, created.output
    created_payload = json.loads(created.stdout)
    campaign_id = created_payload["id"]
    assert created_payload["category"] == "prompt_injection"
    assert created_payload["max_attempts"] == 2
    assert created_payload["status"] == "queued"

    listed = runner.invoke(cli_module.app, ["campaign", "list"])
    assert listed.exit_code == 0, listed.output
    assert json.loads(listed.stdout)["total"] == 1

    shown = runner.invoke(cli_module.app, ["campaign", "show", campaign_id])
    assert shown.exit_code == 0, shown.output
    assert json.loads(shown.stdout)["attempts"] == []

    cancelled = runner.invoke(cli_module.app, ["campaign", "cancel", campaign_id])
    assert cancelled.exit_code == 0, cancelled.output
    assert json.loads(cancelled.stdout)["status"] == "cancelled"

    waited = runner.invoke(
        cli_module.app,
        ["campaign", "wait", campaign_id, "--timeout-seconds", "0.1"],
    )
    assert waited.exit_code == 0, waited.output
    assert json.loads(waited.stdout)["status"] == "cancelled"

    seeded = runner.invoke(cli_module.app, ["eval", "run-seeds", "--surface", "api"])
    assert seeded.exit_code == 0, seeded.output
    seed_payload = json.loads(seeded.stdout)
    expected_api_seeds = {
        seed.id
        for seed in cli_module.load_seed_cases(PROJECT_ROOT / "evals" / "seed-cases")
        if seed.surface == "api"
    }
    assert seed_payload["count"] == len(expected_api_seeds)
    assert {item["seed_id"] for item in seed_payload["campaigns"]} == expected_api_seeds

    regression = runner.invoke(
        cli_module.app,
        ["regression", "trigger", "--target-version", "synthetic-build-1"],
    )
    assert regression.exit_code == 0, regression.output
    regression_payload = json.loads(regression.stdout)
    assert regression_payload["target_version"] == "synthetic-build-1"
    assert regression_payload["status"] == "queued"


def test_cli_db_and_contract_export_entrypoints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upgrades: list[tuple[Any, str]] = []
    monkeypatch.setattr(
        cli_module.command,
        "upgrade",
        lambda configuration, revision: upgrades.append((configuration, revision)),
    )
    runner = CliRunner()

    upgraded = runner.invoke(cli_module.app, ["db", "upgrade"])
    assert upgraded.exit_code == 0, upgraded.output
    assert upgrades[0][1] == "head"

    output_dir = tmp_path / "schemas"
    exported = runner.invoke(
        cli_module.app,
        ["contracts", "export", "--output-dir", str(output_dir)],
    )
    assert exported.exit_code == 0, exported.output
    payload = json.loads(exported.stdout)
    assert payload["count"] == 7
    assert len(list(output_dir.glob("*.json"))) == 7
