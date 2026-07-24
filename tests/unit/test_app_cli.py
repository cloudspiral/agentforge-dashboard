from __future__ import annotations

import importlib
import json
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from prometheus_client import CollectorRegistry
from sqlalchemy import select
from typer.testing import CliRunner

from agentforge.contracts.v1 import AttackEvidenceV1
from agentforge.evidence import EvidenceArtifactStore, with_computed_evidence_hash
from agentforge.main import create_app
from agentforge.observability import AgentForgeMetrics
from agentforge.orchestration.worker import CampaignProcessResult
from agentforge.persistence import Base, Database
from agentforge.persistence.models import (
    AttackAttempt,
    Campaign,
    Finding,
    VulnerabilityReport,
)
from agentforge.persistence.repositories import CampaignRepository
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


def _artifact_evidence(
    campaign_id: uuid.UUID,
    attempt_id: uuid.UUID,
) -> AttackEvidenceV1:
    timestamp = "2026-07-23T12:00:00Z"
    draft = AttackEvidenceV1.model_validate_json(
        json.dumps(
            {
                "schema_version": "v1",
                "target_id": "synthetic-copilot",
                "campaign_id": str(campaign_id),
                "attempt_id": str(attempt_id),
                "target_version": "target-build-1",
                "executed_action_sequence": [
                    {
                        "sequence_index": 0,
                        "action": {
                            "action_type": "reset_session",
                            "action_id": "reset-1",
                            "description": "Create a clean context.",
                            "reset_strategy_id": "fresh-context",
                            "require_clean_context": True,
                        },
                        "status": "succeeded",
                        "started_at": timestamp,
                        "completed_at": timestamp,
                        "sanitized_result_summary": "Context ready.",
                    }
                ],
                "transcript": [
                    {
                        "turn_index": 0,
                        "role": "assistant",
                        "content": "Exact synthetic response.",
                        "observed_at": timestamp,
                    }
                ],
                "sanitized_http_metadata": [],
                "target_visible_tool_calls": [],
                "side_effects": [],
                "started_at": timestamp,
                "completed_at": timestamp,
                "total_latency_ms": 0,
                "errors": [],
                "langfuse_trace_id": "trace-1",
                "evidence_hash": "a" * 64,
            }
        )
    )
    return with_computed_evidence_hash(draft)


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
        campaign_id = uuid.uuid4()
        attempt_id = uuid.uuid4()
        dashboard_evidence = (
            f"/dashboard/campaigns/{campaign_id}/attempts/{attempt_id}/evidence.json"
        )
        api_evidence = f"/api/v1/campaigns/{campaign_id}/attempts/{attempt_id}/evidence"
        assert client.get(dashboard_evidence).status_code == 401
        assert client.get(dashboard_evidence, auth=("admin", "pass")).status_code == 404
        assert client.get(api_evidence).status_code == 401
        assert client.get(api_evidence, headers=bearer_headers).status_code == 404

        assert client.get("/docs").status_code == 404
        assert client.get("/redoc").status_code == 404
        assert client.get("/openapi.json").status_code == 404


def test_dashboard_campaign_launcher_is_csrf_protected_idempotent_and_token_free(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    database = _database(settings)
    application = create_app(
        settings=settings,
        database=database,
        telemetry=FakeTelemetry(),  # type: ignore[arg-type]
        app_metrics=AgentForgeMetrics(CollectorRegistry()),
    )

    with TestClient(application) as client:
        page = client.get("/dashboard/campaigns")
        assert page.status_code == 200
        assert "Launch a discovery campaign" in page.text
        assert "unit-platform-token" not in page.text

        form = {
            "csrf_token": application.state.dashboard_csrf_token,
            "idempotency_key": "dashboard-unit-launch",
            "target_alias": "local",
            "category": "prompt_injection",
            "subcategory": "direct",
            "max_attempts": "2",
            "max_cost_usd": "0.5",
            "max_duration_seconds": "120",
            "priority": "5",
        }
        created = client.post(
            "/dashboard/campaigns",
            data=form,
            follow_redirects=False,
        )
        duplicate = client.post(
            "/dashboard/campaigns",
            data=form,
            follow_redirects=False,
        )
        assert created.status_code == 303
        assert duplicate.status_code == 303
        assert duplicate.headers["location"] == created.headers["location"]

        deployed_without_confirmation = client.post(
            "/dashboard/campaigns",
            data={
                **form,
                "idempotency_key": "dashboard-deployed-without-confirmation",
                "target_alias": "deployed",
            },
        )
        assert deployed_without_confirmation.status_code == 400
        assert "require confirmation" in deployed_without_confirmation.text.lower()
        assert 'value="deployed" selected' in deployed_without_confirmation.text

        invalid_taxonomy = client.post(
            "/dashboard/campaigns",
            data={
                **form,
                "idempotency_key": "dashboard-invalid-taxonomy",
                "category": "not_a_real_category",
                "subcategory": "",
            },
        )
        assert invalid_taxonomy.status_code == 400
        assert "unknown taxonomy category" in invalid_taxonomy.text
        assert 'value="not_a_real_category" selected' in invalid_taxonomy.text
        assert 'value="2"' in invalid_taxonomy.text

        deployed = client.post(
            "/dashboard/campaigns",
            data={
                **form,
                "idempotency_key": "dashboard-deployed-confirmed",
                "target_alias": "deployed",
                "confirm_authorized": "yes",
            },
            follow_redirects=False,
        )
        assert deployed.status_code == 303
        assert (
            client.post(
                "/dashboard/campaigns",
                data={**form, "csrf_token": "wrong"},
            ).status_code
            == 403
        )

    with database.session_factory() as session:
        campaigns = list(session.scalars(select(Campaign).order_by(Campaign.created_at)))
        assert len(campaigns) == 2
        assert {item.target_alias for item in campaigns} == {"local", "deployed"}
        for campaign in campaigns:
            assert campaign.trigger_type == "dashboard"
            assert campaign.category_scope == "prompt_injection"
            assert campaign.subcategory_scope == "direct"
            assert campaign.max_attempts == 2
            assert campaign.priority == 5


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


def test_cli_reconciles_and_regenerates_only_database_anchored_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path)
    database = _database(settings)
    store = EvidenceArtifactStore(settings.artifacts_dir / "evidence")
    with database.session_factory() as session:
        campaign = CampaignRepository(session).create(
            campaign_type="discovery",
            trigger_type="unit",
            target_alias="local",
            target_version="target-build-1",
            category_scope=None,
            subcategory_scope=None,
            max_cost_usd=Decimal("1"),
            max_attempts=3,
            max_duration_seconds=60,
            idempotency_key="evidence-reconciliation",
        )
        attempt_ids = [uuid.uuid4() for _ in range(3)]
        evidence = [_artifact_evidence(campaign.id, attempt_id) for attempt_id in attempt_ids]
        prepared = [store.prepare(item) for item in evidence]
        for attempt_id, item in zip(attempt_ids, prepared, strict=True):
            campaign.attempts.append(
                AttackAttempt(
                    id=attempt_id,
                    attack_family_id=f"family-{attempt_id}",
                    proposal_source="agent_generated",
                    objective_source="orchestrator_selected",
                    category="prompt_injection",
                    subcategory="direct",
                    owasp_mappings=[],
                    objective="Reconcile this evidence.",
                    proposed_sequence={},
                    executed_sequence={"actions": item.payload["executed_action_sequence"]},
                    taxonomy_version="unit-taxonomy",
                    profile_version="unit-profile",
                    prompt_version="unit-prompt",
                    state="completed",
                    evidence_payload=item.payload,
                    evidence_hash=item.evidence.evidence_hash,
                    started_at=datetime.now(UTC),
                    completed_at=datetime.now(UTC),
                )
            )
        session.flush()
        finding = Finding(
            vulnerability_id="AF-UNIT-REPORT",
            fingerprint="f" * 64,
            source_attempt_id=attempt_ids[0],
            title="Unit report",
            category="prompt_injection",
            subcategory="direct",
            severity="medium",
            status="open",
            description="Unit report description.",
            clinical_impact="Synthetic impact.",
            expected_behavior="Remain secure.",
            observed_behavior="Synthetic behavior.",
            first_seen_target_version="target-build-1",
            last_seen_target_version="target-build-1",
        )
        session.add(finding)
        session.flush()
        report = VulnerabilityReport(
            finding_id=finding.id,
            report_version=1,
            structured_report={"vulnerability_id": finding.vulnerability_id},
            markdown_body="# Unit report\n\nDatabase-backed body.\n",
            markdown_path=None,
            status="draft",
            validation_summary={},
            prompt_version="unit-documentation-v1",
            schema_version="v1",
        )
        session.add(report)
        session.commit()
        campaign_id = campaign.id
        finding_id = finding.id
    store.export(prepared[0])
    corrupt_path = store.path_for(campaign_id, attempt_ids[2])
    corrupt_path.parent.mkdir(parents=True, exist_ok=True)
    corrupt_path.write_text('{"corrupt":true}', encoding="utf-8")
    orphan_path = store.path_for(uuid.uuid4(), uuid.uuid4())
    orphan_path.parent.mkdir(parents=True, exist_ok=True)
    orphan_path.write_text("{}", encoding="utf-8")
    stale_path = corrupt_path.parent / ".agentforge-evidence-stale.tmp"
    stale_path.write_text("partial", encoding="utf-8")
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    orphan_report = settings.reports_dir / "AF-ORPHAN.md"
    orphan_report.write_text("# Orphan\n", encoding="utf-8")
    stale_report = settings.reports_dir / ".agentforge-report-stale.tmp"
    stale_report.write_text("partial", encoding="utf-8")

    database.dispose()
    monkeypatch.setattr(cli_module, "get_settings", lambda: settings)
    runner = CliRunner()
    reconciled = runner.invoke(cli_module.app, ["artifacts", "reconcile"])

    assert reconciled.exit_code == 0, reconciled.output
    counts = json.loads(reconciled.stdout)["counts"]
    assert counts == {
        "database_valid_export": 1,
        "database_missing_export": 2,
        "database_corrupt_export": 1,
        "orphan_file": 2,
        "stale_temporary_file": 2,
    }

    regenerated = runner.invoke(
        cli_module.app,
        [
            "artifacts",
            "regenerate-evidence",
            str(campaign_id),
            str(attempt_ids[1]),
        ],
    )
    assert regenerated.exit_code == 0, regenerated.output
    assert json.loads(regenerated.stdout)["status"] == "regenerated_from_database"
    refused_corrupt = runner.invoke(
        cli_module.app,
        [
            "artifacts",
            "regenerate-evidence",
            str(campaign_id),
            str(attempt_ids[2]),
        ],
    )
    assert refused_corrupt.exit_code == 1
    assert "will not overwrite" in refused_corrupt.output
    assert corrupt_path.read_text(encoding="utf-8") == '{"corrupt":true}'
    assert orphan_path.exists()
    assert stale_path.exists()
    regenerated_report = runner.invoke(
        cli_module.app,
        ["reports", "export", str(finding_id)],
    )
    assert regenerated_report.exit_code == 0, regenerated_report.output
    report_path = Path(json.loads(regenerated_report.stdout)["path"])
    assert report_path.read_text(encoding="utf-8") == ("# Unit report\n\nDatabase-backed body.\n")
    assert orphan_report.exists()
    assert stale_report.exists()


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
    assert payload["count"] == 13
    assert len(list(output_dir.glob("*.json"))) == 13
