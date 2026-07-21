from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from prometheus_client import CollectorRegistry

from agentforge.api import router as api_router
from agentforge.dashboard import router as dashboard_router
from agentforge.observability import AgentForgeMetrics
from agentforge.persistence import Base, Database
from agentforge.persistence.models import Campaign
from agentforge.persistence.repositories import CampaignRepository, OperationalRepository


@pytest.fixture
def database(tmp_path: Path) -> Database:
    configured = Database(f"sqlite+pysqlite:///{tmp_path / 'dashboard.db'}")
    campaign_table = Base.metadata.tables["campaigns"]
    duplicate_indexes = [
        index for index in campaign_table.indexes if index.name == "ix_campaigns_target_version"
    ]
    for duplicate in duplicate_indexes[1:]:
        campaign_table.indexes.remove(duplicate)
    Base.metadata.create_all(configured.engine)
    yield configured
    configured.dispose()


@pytest.fixture
def client(database: Database) -> TestClient:
    application = FastAPI()
    application.state.database = database
    application.state.settings = SimpleNamespace(
        worker_stale_after_seconds=30,
        worker_enabled=False,
    )
    application.state.metrics = AgentForgeMetrics(CollectorRegistry())
    application.include_router(api_router)
    application.include_router(dashboard_router)
    return TestClient(application)


def _create(database: Database, *, key: str) -> Campaign:
    with database.session_factory() as session:
        return CampaignRepository(session).create(
            campaign_type="discovery",
            trigger_type="unit",
            target_alias="local",
            target_version="fixture-v1",
            category_scope=None,
            subcategory_scope=None,
            max_cost_usd=Decimal("1"),
            max_attempts=4,
            max_duration_seconds=60,
            max_mutations=0,
            no_signal_limit=1,
            idempotency_key=key,
        )


def _finish(
    database: Database,
    campaign: Campaign,
    *,
    status: str,
    worker_name: str,
    sanitized_error: dict[str, str] | None = None,
) -> None:
    with database.session_factory() as session:
        repository = CampaignRepository(session)
        claimed = repository.claim_next(worker_name=worker_name)
        assert claimed is not None
        assert claimed.id == campaign.id
    with database.session_factory() as session:
        CampaignRepository(session).finish(
            campaign.id,
            status=status,
            actual_cost_usd=Decimal("0.125"),
            sanitized_error=sanitized_error,
            worker_name=worker_name,
        )


def test_empty_dashboard_pages_and_metrics_render(client: TestClient) -> None:
    responses = {
        "overview": client.get("/"),
        "campaigns": client.get("/dashboard/campaigns"),
        "queue": client.get("/dashboard/queue"),
        "findings": client.get("/dashboard/findings"),
        "regressions": client.get("/dashboard/regression-runs"),
    }

    assert all(response.status_code == 200 for response in responses.values())
    assert "No campaigns yet." in responses["overview"].text
    assert "No campaigns yet." in responses["campaigns"].text
    assert "Queue depth" in responses["queue"].text
    assert "No confirmed findings" in responses["findings"].text
    assert "No regression runs yet." in responses["regressions"].text

    prometheus = client.get("/metrics")
    assert prometheus.status_code == 200
    assert prometheus.headers["content-type"].startswith("text/plain")
    assert "agentforge_persisted_queue_depth 0.0" in prometheus.text
    assert "agentforge_stale_running_campaigns 0.0" in prometheus.text


def test_campaign_pages_show_ordered_events_and_redact_secrets(
    database: Database,
    client: TestClient,
) -> None:
    secret = "-".join(("dashboard", "credential", "must", "not", "render"))
    campaign = _create(database, key="dashboard-detail")
    _finish(
        database,
        campaign,
        status="failed",
        worker_name="unit-worker",
        sanitized_error={"code": "fixture_failure", "password": secret},
    )

    overview = client.get("/")
    listing = client.get("/dashboard/campaigns?offset=0&limit=25")
    detail = client.get(f"/dashboard/campaigns/{campaign.id}")

    assert overview.status_code == 200
    assert "Recent lifecycle events" in overview.text
    assert listing.status_code == 200
    assert str(campaign.id) in listing.text
    assert "unit-worker" in listing.text
    assert "fixture-v1" in listing.text
    assert detail.status_code == 200
    assert (
        detail.text.index("created")
        < detail.text.index("claimed")
        < detail.text.index("finished")
    )
    assert "fixture_failure" in detail.text
    assert secret not in detail.text
    assert secret not in client.get("/metrics").text


def test_queue_aggregates_and_operational_api_are_database_backed(
    database: Database,
    client: TestClient,
) -> None:
    completed = _create(database, key="dashboard-completed")
    _finish(database, completed, status="completed", worker_name="worker-complete")

    running = _create(database, key="dashboard-running")
    with database.session_factory() as session:
        claimed = CampaignRepository(session).claim_next(worker_name="worker-stale")
        assert claimed is not None
        assert claimed.id == running.id
        claimed.heartbeat_at = datetime.now(UTC) - timedelta(minutes=5)
        session.commit()

    queued = _create(database, key="dashboard-queued")
    with database.session_factory() as session:
        queued_row = session.get(Campaign, queued.id)
        assert queued_row is not None
        queued_row.created_at = datetime.now(UTC) - timedelta(seconds=90)
        session.commit()

    with database.session_factory() as session:
        repository = OperationalRepository(session)
        queue = repository.queue_summary(stale_after_seconds=30)
        counts = repository.campaign_status_counts()
        snapshot = repository.metrics_snapshot(stale_after_seconds=30)

    assert queue["depth"] == 1
    assert queue["running"] == 1
    assert queue["stale_running"] == 1
    assert queue["oldest_age_seconds"] >= 89
    assert queue["worker_name"] == "worker-stale"
    assert counts == {"completed": 1, "queued": 1, "running": 1}
    assert snapshot["worker_claims"] == 2
    assert snapshot["event_counts"] == {"claimed": 2, "created": 3, "finished": 1}

    queue_page = client.get("/dashboard/queue")
    queue_api = client.get("/api/v1/operations/queue")
    summary_api = client.get("/api/v1/operations/summary")
    prometheus = client.get("/metrics")

    assert queue_page.status_code == 200
    assert "worker-stale" in queue_page.text
    assert queue_api.status_code == 200
    assert queue_api.json()["depth"] == 1
    assert queue_api.json()["stale_running"] == 1
    assert summary_api.status_code == 200
    assert summary_api.json()["campaigns"] == counts
    assert "agentforge_persisted_campaigns" in prometheus.text
    assert "agentforge_persisted_running_campaigns 1.0" in prometheus.text
    assert "agentforge_persisted_worker_claims_total 2.0" in prometheus.text
    assert 'event_type="claimed"' in prometheus.text


def test_pagination_parameters_are_bounded(client: TestClient) -> None:
    assert client.get("/dashboard/campaigns?offset=0&limit=200").status_code == 200
    assert client.get("/dashboard/campaigns?limit=201").status_code == 422
    assert client.get("/dashboard/findings?offset=-1").status_code == 422
    assert client.get("/dashboard/regression-runs?limit=0").status_code == 422
