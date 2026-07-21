from __future__ import annotations

import asyncio
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from fastapi import FastAPI
from fastapi.testclient import TestClient
from prometheus_client import CollectorRegistry
from pydantic import SecretStr
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError

from agentforge.api.routes import router
from agentforge.observability import AgentForgeMetrics
from agentforge.orchestration.worker import CampaignProcessResult, CampaignWorker
from agentforge.persistence import Base, Database
from agentforge.persistence.models import Campaign, CampaignEvent
from agentforge.persistence.repositories import CampaignRepository

TEST_DATABASE_URL = os.getenv("AGENTFORGE_TEST_DATABASE_URL")
MIGRATION_HEAD = "8a4f1c2d9e70"
API_TOKEN = uuid.UUID(int=0).hex
PROJECT_ROOT = Path(__file__).resolve().parents[2]

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        TEST_DATABASE_URL is None,
        reason="AGENTFORGE_TEST_DATABASE_URL is required for PostgreSQL integration tests",
    ),
]


class NoopProcessor:
    def __init__(self) -> None:
        self.calls: list[uuid.UUID] = []

    async def process(self, campaign_id: uuid.UUID) -> CampaignProcessResult:
        self.calls.append(campaign_id)
        return CampaignProcessResult(status="completed")


class FailingProcessor:
    async def process(self, campaign_id: uuid.UUID) -> CampaignProcessResult:
        raise RuntimeError(f"deterministic fixture failure for {campaign_id}")


class FinishFailureWorker(CampaignWorker):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.finish_failures = 0

    def _finish(self, campaign_id: uuid.UUID, result: CampaignProcessResult) -> str:
        if self.finish_failures == 0:
            self.finish_failures += 1
            raise OperationalError(
                "UPDATE campaigns",
                {},
                RuntimeError("deterministic fixture database failure"),
            )
        return super()._finish(campaign_id, result)


class CountingIdleWorker(CampaignWorker):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.run_once_calls = 0

    async def run_once(self) -> bool:
        self.run_once_calls += 1
        return False


@pytest.fixture(scope="module")
def database() -> Database:
    assert TEST_DATABASE_URL is not None
    database_name = make_url(TEST_DATABASE_URL).database or ""
    if not database_name.endswith("_test"):
        pytest.fail("PostgreSQL integration database name must end with '_test'")
    configured = Database(TEST_DATABASE_URL)
    configured.ping()
    with configured.engine.begin() as connection:
        connection.execute(text("DROP SCHEMA public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))
    migration_config = Config(str(PROJECT_ROOT / "alembic.ini"))
    migration_config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    with configured.engine.begin() as connection:
        migration_config.attributes["connection"] = connection
        command.upgrade(migration_config, "head")
    yield configured
    configured.dispose()


@pytest.fixture(autouse=True)
def clean_campaigns(database: Database) -> None:
    with database.engine.begin() as connection:
        connection.execute(text("TRUNCATE TABLE campaigns CASCADE"))


def _settings(*, poll_seconds: float = 0.05, stale_after_seconds: int = 30) -> Any:
    return SimpleNamespace(
        worker_poll_seconds=poll_seconds,
        worker_stale_after_seconds=stale_after_seconds,
    )


def _metrics() -> AgentForgeMetrics:
    return AgentForgeMetrics(CollectorRegistry())


def _create_campaign(database: Database, *, key: str) -> Campaign:
    with database.session_factory() as session:
        return CampaignRepository(session).create(
            campaign_type="discovery",
            trigger_type="integration",
            target_alias="local",
            target_version="fixture-v1",
            category_scope=None,
            subcategory_scope=None,
            max_cost_usd=Decimal("0.01"),
            max_attempts=1,
            max_duration_seconds=30,
            max_mutations=0,
            no_signal_limit=1,
            idempotency_key=key,
        )


def _api(database: Database) -> FastAPI:
    application = FastAPI()
    application.state.database = database
    application.state.settings = SimpleNamespace(
        platform_api_token=SecretStr(API_TOKEN),
        default_campaign_max_cost_usd=1.0,
        global_max_cost_usd=10.0,
        default_campaign_max_attempts=5,
        default_campaign_max_duration_seconds=60,
        default_max_mutations=0,
        default_no_signal_limit=2,
        target_version="fixture-v1",
    )
    application.state.target_profile = SimpleNamespace(
        profile=SimpleNamespace(aliases={"local": object()})
    )
    application.state.taxonomy = SimpleNamespace(categories=[])
    application.include_router(router)
    return application


def _campaign(database: Database, campaign_id: uuid.UUID) -> Campaign:
    with database.session_factory() as session:
        return CampaignRepository(session).get(campaign_id, include_attempts=True)


def test_migration_head_matches_sqlalchemy_models(database: Database) -> None:
    with database.engine.connect() as connection:
        revision = connection.scalar(text("SELECT version_num FROM alembic_version"))
        differences = compare_metadata(MigrationContext.configure(connection), Base.metadata)

    assert revision == MIGRATION_HEAD
    assert differences == []


@pytest.mark.asyncio
async def test_api_queue_worker_completed_lifecycle_is_persisted(database: Database) -> None:
    with TestClient(_api(database)) as client:
        created = client.post(
            "/api/v1/campaigns",
            headers={
                "Authorization": f"Bearer {API_TOKEN}",
                "Idempotency-Key": "api-noop-lifecycle",
            },
            json={
                "campaign_type": "discovery",
                "target_alias": "local",
                "max_attempts": 1,
                "max_cost_usd": "0.01",
            },
        )
        assert created.status_code == 202
        campaign_id = uuid.UUID(created.json()["id"])
        assert created.json()["status"] == "queued"

        processor = NoopProcessor()
        worker = CampaignWorker(
            database=database,
            settings=cast(Any, _settings()),
            processor=processor,
            metrics=_metrics(),
            worker_name="fixture-worker",
        )
        assert await worker.run_once() is True

        completed = client.get(f"/api/v1/campaigns/{campaign_id}")
        assert completed.status_code == 200
        payload = completed.json()

    assert processor.calls == [campaign_id]
    assert payload["status"] == "completed"
    assert [event["event_type"] for event in payload["events"]] == [
        "created",
        "claimed",
        "finished",
    ]
    assert [event["to_status"] for event in payload["events"]] == [
        "queued",
        "running",
        "completed",
    ]
    assert payload["events"][1]["worker_name"] == "fixture-worker"


def test_concurrent_workers_cannot_claim_the_same_campaign(database: Database) -> None:
    campaign = _create_campaign(database, key="concurrent-claim")
    barrier = threading.Barrier(2)

    def claim(worker_name: str) -> uuid.UUID | None:
        barrier.wait(timeout=2)
        with database.session_factory() as session:
            claimed = CampaignRepository(session).claim_next(worker_name=worker_name)
            return claimed.id if claimed else None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(claim, ["worker-a", "worker-b"]))

    assert results.count(campaign.id) == 1
    assert results.count(None) == 1
    persisted = _campaign(database, campaign.id)
    assert persisted.status == "running"
    assert [event.event_type for event in persisted.events].count("claimed") == 1


def test_queued_and_running_cancellation_are_persisted(database: Database) -> None:
    queued = _create_campaign(database, key="cancel-queued")
    with database.session_factory() as session:
        cancelled = CampaignRepository(session).cancel(queued.id)
        assert cancelled.status == "cancelled"

    queued_persisted = _campaign(database, queued.id)
    assert [event.to_status for event in queued_persisted.events] == ["queued", "cancelled"]

    running = _create_campaign(database, key="cancel-running")
    with database.session_factory() as session:
        repository = CampaignRepository(session)
        assert repository.claim_next(worker_name="fixture-worker") is not None
    with database.session_factory() as session:
        requested = CampaignRepository(session).cancel(running.id)
        assert requested.status == "running"
        assert requested.cancellation_requested is True
    with database.session_factory() as session:
        finished = CampaignRepository(session).finish(
            running.id,
            status="completed",
            worker_name="fixture-worker",
        )
        assert finished.status == "cancelled"
        assert finished.sanitized_error == {
            "code": "cancellation_requested",
            "message": "campaign cancellation was requested",
        }

    running_persisted = _campaign(database, running.id)
    assert [event.event_type for event in running_persisted.events] == [
        "created",
        "claimed",
        "cancellation_requested",
        "finished",
    ]
    assert running_persisted.events[-1].to_status == "cancelled"


@pytest.mark.asyncio
async def test_processor_failure_is_a_durable_terminal_state(database: Database) -> None:
    campaign = _create_campaign(database, key="processor-failure")
    worker = CampaignWorker(
        database=database,
        settings=cast(Any, _settings()),
        processor=FailingProcessor(),
        metrics=_metrics(),
        worker_name="failure-worker",
    )

    assert await worker.run_once() is True

    persisted = _campaign(database, campaign.id)
    assert persisted.status == "failed"
    assert persisted.sanitized_error is not None
    assert persisted.sanitized_error["code"] == "unexpected_internal_error"
    assert [event.to_status for event in persisted.events] == ["queued", "running", "failed"]


@pytest.mark.asyncio
async def test_finish_database_error_is_recovered_without_worker_restart(
    database: Database,
) -> None:
    campaign = _create_campaign(database, key="finish-database-error")
    worker = FinishFailureWorker(
        database=database,
        settings=cast(Any, _settings(poll_seconds=0.01, stale_after_seconds=0)),
        processor=NoopProcessor(),
        metrics=_metrics(),
        worker_name="recovery-worker",
    )
    task = asyncio.create_task(worker.run_forever())

    deadline = asyncio.get_running_loop().time() + 2
    while asyncio.get_running_loop().time() < deadline:
        if _campaign(database, campaign.id).status == "interrupted":
            break
        await asyncio.sleep(0.01)
    worker.request_stop()
    await asyncio.wait_for(task, timeout=1)

    persisted = _campaign(database, campaign.id)
    assert worker.finish_failures == 1
    assert persisted.status == "interrupted"
    assert persisted.sanitized_error is not None
    assert persisted.sanitized_error["code"] == "worker_heartbeat_stale"
    assert [event.event_type for event in persisted.events] == [
        "created",
        "claimed",
        "stale_recovered",
    ]


def test_explicit_stale_job_recovery_persists_an_audit_event(database: Database) -> None:
    campaign = _create_campaign(database, key="stale-recovery")
    with database.session_factory() as session:
        repository = CampaignRepository(session)
        claimed = repository.claim_next(worker_name="lost-worker")
        assert claimed is not None
        claimed.heartbeat_at = datetime.now(UTC) - timedelta(minutes=5)
        session.commit()
    with database.session_factory() as session:
        recovered = CampaignRepository(session).recover_stale(stale_after_seconds=30)

    assert recovered == 1
    persisted = _campaign(database, campaign.id)
    assert persisted.status == "interrupted"
    assert persisted.events[-1].event_type == "stale_recovered"
    assert persisted.events[-1].details_json == {"error_code": "worker_heartbeat_stale"}


@pytest.mark.asyncio
async def test_idle_polling_sleeps_and_worker_stops_gracefully(database: Database) -> None:
    worker = CountingIdleWorker(
        database=database,
        settings=cast(Any, _settings(poll_seconds=0.05)),
        processor=NoopProcessor(),
        metrics=_metrics(),
        worker_name="idle-worker",
    )
    task = asyncio.create_task(worker.run_forever())

    await asyncio.sleep(0.13)
    worker.request_stop()
    await asyncio.wait_for(task, timeout=1)

    assert 2 <= worker.run_once_calls <= 4
    with database.session_factory() as session:
        assert session.scalar(select(CampaignEvent).limit(1)) is None
