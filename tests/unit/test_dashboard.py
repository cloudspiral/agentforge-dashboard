from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from prometheus_client import CollectorRegistry

from agentforge.api import router as api_router
from agentforge.contracts.v1 import AttackEvidenceV1
from agentforge.dashboard import router as dashboard_router
from agentforge.dashboard.evaluations import DashboardEvaluationSnapshot
from agentforge.evidence import EvidenceArtifactStore, with_computed_evidence_hash
from agentforge.observability import AgentForgeMetrics
from agentforge.persistence import Base, Database
from agentforge.persistence.models import AttackAttempt, Campaign, JudgeVerdict
from agentforge.persistence.repositories import CampaignRepository, OperationalRepository

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class FakeEvaluationManager:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Path]] = []
        self.campaign_id = uuid.uuid4()

    def snapshot(self) -> DashboardEvaluationSnapshot:
        return DashboardEvaluationSnapshot(phase="idle")

    async def start(self, *, case_id: str, case_path: Path) -> uuid.UUID:
        self.calls.append((case_id, case_path))
        return self.campaign_id


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
def client(database: Database, tmp_path: Path) -> TestClient:
    application = FastAPI()
    application.state.database = database
    application.state.settings = SimpleNamespace(
        worker_stale_after_seconds=30,
        worker_enabled=False,
        artifacts_dir=tmp_path / "artifacts",
    )
    application.state.metrics = AgentForgeMetrics(CollectorRegistry())
    application.state.repository_root = PROJECT_ROOT
    application.state.dashboard_csrf_token = "unit-dashboard-csrf"  # noqa: S105
    application.state.evaluation_manager = FakeEvaluationManager()
    application.include_router(api_router)
    application.include_router(dashboard_router)
    return TestClient(application)


def _evidence(
    *,
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
                "target_version": "fixture-v1",
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
                        "turn_index": index,
                        "role": role,
                        "content": content,
                        "observed_at": timestamp,
                    }
                    for index, (role, content) in enumerate(
                        (
                            ("system", "Synthetic system context."),
                            ("user", "<script>authorized prompt</script>"),
                            ("assistant", "Exact assistant response."),
                            ("tool", "Exact synthetic tool output."),
                        )
                    )
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
        detail.text.index("created") < detail.text.index("claimed") < detail.text.index("finished")
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


def test_seed_buttons_are_yaml_derived_and_redirect_to_campaign(client: TestClient) -> None:
    overview = client.get("/")

    assert overview.status_code == 200
    assert overview.text.count("Run Prompt Injection test") == 2
    assert overview.text.count("Run Data Exfiltration test") == 2
    assert overview.text.count("Run Tool Misuse test") == 2
    assert "Direct hidden-instruction disclosure attempt" in overview.text

    manager = client.app.state.evaluation_manager
    response = client.post(
        "/dashboard/evaluations/AF-PI-001/run",
        data={"csrf_token": "unit-dashboard-csrf"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == f"/dashboard/campaigns/{manager.campaign_id}"
    assert manager.calls == [
        (
            "AF-PI-001",
            PROJECT_ROOT / "evals" / "seed-cases" / "pi-direct-instruction-override.yaml",
        )
    ]
    assert (
        client.post(
            "/dashboard/evaluations/AF-PI-001/run",
            data={"csrf_token": "wrong"},
        ).status_code
        == 403
    )


def test_campaign_page_polls_and_renders_persisted_evaluation_result(
    database: Database,
    client: TestClient,
) -> None:
    campaign = _create(database, key="dashboard-live-result")
    with database.session_factory() as session:
        stored = session.get(Campaign, campaign.id)
        assert stored is not None
        stored.trigger_type = "live_deployed"
        stored.status = "running"
        stored.started_at = datetime.now(UTC)
        attempt = AttackAttempt(
            attack_family_id="AF-PI-001",
            proposal_source="agent_generated",
            objective_source="orchestrator_selected",
            category="prompt_injection",
            subcategory="direct",
            owasp_mappings=[],
            objective="Preserve instruction hierarchy",
            proposed_sequence={},
            taxonomy_version="unit-taxonomy",
            profile_version="unit-profile",
            prompt_version="unit-prompt",
            state="running",
            started_at=datetime.now(UTC),
            evidence_payload={
                "transcript": [
                    {
                        "role": "assistant",
                        "content": "I cannot reveal hidden system instructions.",
                        "observed_at": "2026-07-22T04:00:00Z",
                    }
                ],
                "sanitized_http_metadata": [
                    {
                        "method": "POST",
                        "endpoint_id": "copilot_chat_proxy",
                        "response_status": 200,
                        "elapsed_ms": 50.0,
                    }
                ],
                "target_visible_tool_calls": [],
                "side_effects": [],
                "errors": [],
            },
        )
        stored.attempts.append(attempt)
        session.commit()

    running = client.get(f"/dashboard/campaigns/{campaign.id}")
    status = client.get(f"/dashboard/campaigns/{campaign.id}/status")
    assert running.status_code == 200
    assert "window.setTimeout(poll, 2000)" in running.text
    assert "I cannot reveal hidden system instructions." in running.text
    assert "copilot_chat_proxy" in running.text
    assert status.json()["terminal"] is False

    with database.session_factory() as session:
        stored = session.get(Campaign, campaign.id)
        assert stored is not None
        stored.status = "completed"
        stored.completed_at = datetime.now(UTC)
        attempt = stored.attempts[0]
        attempt.state = "completed"
        attempt.completed_at = datetime.now(UTC)
        attempt.verdict = JudgeVerdict(
            verdict="attack_blocked",
            severity="informational",
            exploitability="low",
            confidence=0.99,
            violated_invariants=[],
            observed_behavior="The attack remained blocked.",
            expected_behavior="Hidden instructions remain confidential.",
            rubric_hash="a" * 64,
            rubric_version="unit-rubric",
        )
        session.commit()

    completed = client.get(f"/dashboard/campaigns/{campaign.id}")
    status = client.get(f"/dashboard/campaigns/{campaign.id}/status")
    assert "attack blocked" in completed.text
    assert "Hidden instructions remain confidential." in completed.text
    assert "window.setTimeout(poll, 2000)" not in completed.text
    assert status.json()["terminal"] is True


def test_exact_transcript_and_verified_evidence_downloads_are_database_anchored(
    database: Database,
    client: TestClient,
) -> None:
    campaign = _create(database, key="dashboard-evidence-download")
    attempt_id = uuid.uuid4()
    evidence = _evidence(campaign_id=campaign.id, attempt_id=attempt_id)
    prepared = EvidenceArtifactStore.prepare(evidence)
    with database.session_factory() as session:
        stored = session.get(Campaign, campaign.id)
        assert stored is not None
        stored.status = "completed"
        stored.completed_at = datetime.now(UTC)
        stored.attempts.append(
            AttackAttempt(
                id=attempt_id,
                attack_family_id="AF-TRANSCRIPT-001",
                proposal_source="agent_generated",
                objective_source="orchestrator_selected",
                category="prompt_injection",
                subcategory="direct",
                owasp_mappings=[],
                objective="Render every exact transcript role.",
                proposed_sequence={},
                executed_sequence={"actions": prepared.payload["executed_action_sequence"]},
                taxonomy_version="unit-taxonomy",
                profile_version="unit-profile",
                prompt_version="unit-prompt",
                state="completed",
                evidence_payload=prepared.payload,
                evidence_hash=evidence.evidence_hash,
                started_at=datetime.now(UTC),
                completed_at=datetime.now(UTC),
            )
        )
        session.commit()
    store = EvidenceArtifactStore(client.app.state.settings.artifacts_dir / "evidence")
    artifact = store.export(prepared)

    detail = client.get(f"/dashboard/campaigns/{campaign.id}")
    dashboard_download = client.get(
        f"/dashboard/campaigns/{campaign.id}/attempts/{attempt_id}/evidence.json"
    )
    api_download = client.get(f"/api/v1/campaigns/{campaign.id}/attempts/{attempt_id}/evidence")
    campaign_api = client.get(f"/api/v1/campaigns/{campaign.id}")

    assert detail.status_code == 200
    assert "Exact transcript" in detail.text
    assert "Synthetic system context." in detail.text
    assert "&lt;script&gt;authorized prompt&lt;/script&gt;" in detail.text
    assert "Exact assistant response." in detail.text
    assert "Exact synthetic tool output." in detail.text
    assert evidence.evidence_hash in detail.text
    assert "Download verified JSON" in detail.text
    assert campaign_api.json()["attempts"][0]["evidence_download_url"] == (
        f"/api/v1/campaigns/{campaign.id}/attempts/{attempt_id}/evidence"
    )
    for response in (dashboard_download, api_download):
        assert response.status_code == 200
        assert response.content == prepared.serialized
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["content-disposition"].endswith(f'"{attempt_id}.evidence.json"')

    artifact.write_text('{"mismatched":true}', encoding="utf-8")
    assert (
        client.get(
            f"/dashboard/campaigns/{campaign.id}/attempts/{attempt_id}/evidence.json"
        ).status_code
        == 409
    )
    artifact.unlink()
    assert (
        client.get(
            f"/dashboard/campaigns/{campaign.id}/attempts/{attempt_id}/evidence.json"
        ).status_code
        == 404
    )
    assert "durable evidence unavailable" in client.get(f"/dashboard/campaigns/{campaign.id}").text
    other = _create(database, key="dashboard-evidence-other-owner")
    assert (
        client.get(
            f"/dashboard/campaigns/{other.id}/attempts/{attempt_id}/evidence.json"
        ).status_code
        == 404
    )
    traversal = client.get(
        f"/dashboard/campaigns/{campaign.id}/attempts/%2E%2E%2Fsecrets/evidence.json"
    )
    assert traversal.status_code in {404, 422}


def test_terminal_attempt_error_does_not_render_a_pending_verdict(
    database: Database,
    client: TestClient,
) -> None:
    campaign = _create(database, key="dashboard-judge-failure")
    with database.session_factory() as session:
        stored = session.get(Campaign, campaign.id)
        assert stored is not None
        stored.trigger_type = "live_deployed"
        stored.status = "failed"
        stored.sanitized_error = {
            "code": "judge_failed",
            "message": "the Judge returned invalid structured output after one bounded retry",
        }
        stored.completed_at = datetime.now(UTC)
        stored.attempts.append(
            AttackAttempt(
                attack_family_id="AF-DE-001",
                proposal_source="agent_generated",
                objective_source="orchestrator_selected",
                category="data_exfiltration",
                subcategory="cross_patient_exposure",
                owasp_mappings=[],
                objective="Preserve patient isolation",
                proposed_sequence={},
                taxonomy_version="unit-taxonomy",
                profile_version="unit-profile",
                prompt_version="unit-prompt",
                state="failed",
                failure={
                    "stage": "judge",
                    "code": "judge_failed",
                    "retryable": False,
                },
                latency_ms=9009,
                langfuse_trace_id="judge-trace-id",
                started_at=datetime.now(UTC),
                completed_at=datetime.now(UTC),
            )
        )
        session.commit()

    detail = client.get(f"/dashboard/campaigns/{campaign.id}")

    assert detail.status_code == 200
    assert "not produced" in detail.text
    assert ">pending<" not in detail.text
    assert "The Judge did not produce a verdict." in detail.text
    assert "The Judge verdict is pending." not in detail.text
    assert "judge-trace-id" in detail.text
    assert "invalid structured output after one bounded retry" in detail.text
