from __future__ import annotations

import json
import uuid
from collections import Counter
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
import yaml

from agentforge.contracts.v1 import RemainingBudgetAndLimitsV1
from agentforge.evaluation import load_seed_cases, load_taxonomy
from agentforge.observability import PlatformObservabilityService
from agentforge.observability.cost_analysis import (
    collect_cost_evidence,
    evidence_digest,
    load_cost_assumptions,
    load_cost_evidence_snapshot,
    merge_cost_evidence,
    project_costs,
    render_cost_analysis,
)
from agentforge.orchestration.objectives import surface_capability_facts
from agentforge.persistence import Base, Database
from agentforge.persistence.models import AgentRun, AttackAttempt, Campaign, JudgeVerdict
from agentforge.target import load_target_profile

ROOT = Path(__file__).resolve().parents[2]


def _database(tmp_path: Path) -> Database:
    database = Database(f"sqlite+pysqlite:///{tmp_path / 'observability.db'}")
    campaign_table = Base.metadata.tables["campaigns"]
    duplicates = [
        index for index in campaign_table.indexes if index.name == "ix_campaigns_target_version"
    ]
    for duplicate in duplicates[1:]:
        campaign_table.indexes.remove(duplicate)
    Base.metadata.create_all(database.engine)
    return database


def _campaign() -> Campaign:
    return Campaign(
        id=uuid.uuid4(),
        campaign_type="discovery",
        trigger_type="manual",
        status="running",
        target_alias="deployed",
        target_version="openemr-build-1",
        max_cost_usd=Decimal("5"),
        max_attempts=10,
        max_duration_seconds=3600,
        actual_cost_usd=Decimal("0.030000"),
        actual_attempts=1,
        started_at=datetime.now(UTC),
    )


def _attempt(campaign: Campaign) -> AttackAttempt:
    return AttackAttempt(
        id=uuid.uuid4(),
        campaign_id=campaign.id,
        attack_family_id="unit-fuzz-family",
        proposal_source="agent_generated",
        objective_source="orchestrator_selected",
        provenance="agent_fuzz",
        execution_surface="openemr_ui",
        technique="fuzzing",
        orchestrator_rationale="Exercise an observed coverage gap.",
        fuzz_plan={"rng_seed": 7, "maximum_variants": 1},
        fuzz_variant_id="variant-000",
        fuzz_variant_index=0,
        exact_payload_hash="a" * 64,
        target_executed=True,
        sequence_hash="b" * 64,
        category="denial_of_service",
        subcategory="token_exhaustion",
        owasp_mappings=["LLM10:2025"],
        objective="Bounded fuzz exercise.",
        proposed_sequence={"ordered_actions": [{"message": "bounded"}]},
        executed_sequence={"ordered_actions": [{"message": "bounded"}]},
        taxonomy_version="2026-07-21",
        profile_version="2026-07-24",
        prompt_version="attack-generator-v2",
        state="completed",
        evidence_payload={"transcript": [{"content": "bounded result"}]},
        evidence_hash="c" * 64,
        input_tokens=500,
        output_tokens=100,
        estimated_cost_usd=Decimal("0.020000"),
        latency_ms=1500,
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
    )


def test_dashboard_snapshot_and_orchestrator_use_identical_neutral_coverage(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    taxonomy = load_taxonomy(ROOT / "config" / "attack-taxonomy.yaml")
    seeds = load_seed_cases(ROOT / "evals" / "seed-cases")
    profile = load_target_profile(ROOT / "config" / "target-profile.yaml")
    capabilities = surface_capability_facts(profile.profile)
    try:
        with database.session_factory() as session:
            campaign = _campaign()
            attempt = _attempt(campaign)
            attempt.verdict = JudgeVerdict(
                verdict="attack_blocked",
                severity="informational",
                exploitability="low",
                confidence=0.97,
                violated_invariants=[],
                observed_behavior="The bounded target rejected the mutation.",
                expected_behavior="The request remains bounded.",
                rubric_hash="d" * 64,
                rubric_version="2026-07-21",
            )
            session.add_all([campaign, attempt])
            session.commit()

            service = PlatformObservabilityService(
                session,
                taxonomy=taxonomy,
                seed_cases=seeds,
                surface_capabilities=capabilities,
            )
            dashboard_snapshot = service.snapshot()
            orchestrator = service.orchestrator_context(
                campaign=campaign,
                remaining_limits=RemainingBudgetAndLimitsV1(
                    remaining_cost_usd=4.97,
                    remaining_attempts=9,
                    remaining_duration_seconds=3500,
                    remaining_model_calls=36,
                    remaining_input_tokens=288_000,
                    remaining_output_tokens=45_000,
                ),
                surface_capabilities=capabilities,
            )

            assert len(dashboard_snapshot.coverage) == 17
            assert [
                (item.category, item.subcategory) for item in dashboard_snapshot.coverage
            ] == sorted((item.category, item.subcategory) for item in dashboard_snapshot.coverage)
            dashboard_by_key = {
                (item.category, item.subcategory): item for item in dashboard_snapshot.coverage
            }
            for planning_fact in orchestrator.taxonomy_coverage:
                dashboard_fact = dashboard_by_key[
                    (planning_fact.category, planning_fact.subcategory)
                ]
                assert planning_fact.attempted == dashboard_fact.attempted
                assert planning_fact.executed == dashboard_fact.executed
                assert planning_fact.outcomes == dashboard_fact.outcomes
                assert planning_fact.by_surface == dashboard_fact.by_surface
                assert planning_fact.by_technique == dashboard_fact.by_technique
                assert planning_fact.by_provenance == dashboard_fact.by_provenance
            assert dashboard_snapshot.surface_capabilities == capabilities
            assert orchestrator.surface_capabilities == capabilities
    finally:
        database.dispose()


def test_cost_evidence_is_redacted_deduplicated_and_projects_full_workload(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    pricing = yaml.safe_load((ROOT / "config" / "pricing.yaml").read_text(encoding="utf-8"))
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    (artifact_root / "evidence.json").write_text('{"safe": true}', encoding="utf-8")
    try:
        with database.session_factory() as session:
            campaign = _campaign()
            attempt = _attempt(campaign)
            session.add_all([campaign, attempt])
            session.flush()
            session.add_all(
                [
                    AgentRun(
                        campaign_id=campaign.id,
                        role="orchestrator",
                        prompt_version="orchestrator-v2",
                        model="gpt-5.6-terra",
                        status="succeeded",
                        input_tokens=100,
                        output_tokens=20,
                        sdk_attempts=1,
                        estimated_cost_usd=Decimal("0.003000"),
                        latency_ms=200,
                        input_payload={"password": "must-never-export"},
                    ),
                    AgentRun(
                        campaign_id=campaign.id,
                        attempt_id=attempt.id,
                        role="judge",
                        prompt_version="judge-v2",
                        model="gpt-5.6-terra",
                        status="succeeded",
                        input_tokens=500,
                        output_tokens=100,
                        sdk_attempts=2,
                        estimated_cost_usd=Decimal("0.012000"),
                        latency_ms=800,
                        output_payload={"verdict": "attack_blocked"},
                    ),
                ]
            )
            session.commit()
            evidence = collect_cost_evidence(
                session,
                source_label="local-development",
                pricing_source=pricing["source"],
                pricing_verified_at=str(pricing["verified_at"]),
                artifact_roots=[artifact_root],
                overnight_campaign_ids={str(campaign.id)},
            )

        serialized = evidence.model_dump_json()
        assert "must-never-export" not in serialized
        assert evidence.counts["fuzz_variant"] == 1
        assert evidence.target_executions == 1
        assert evidence.browser_seconds == Decimal("1.5")
        assert evidence.artifact_bytes == 14
        assert evidence.overnight_campaign_cost_usd == Decimal("0.015000")
        assert evidence.retry_rate == Decimal("1") / Decimal("3")
        units = Counter(item.unit for item in evidence.unit_economics)
        assert all(count == 1 for count in units.values())

        duplicate = evidence.model_copy(
            update={"source_labels": ["production"], "generated_at": datetime.now(UTC)}
        )
        merged = merge_cost_evidence([evidence, duplicate])
        assert len(merged.agent_calls) == 2
        assert merged.total_agentforge_model_cost_usd == Decimal("0.015000")

        snapshot_path = tmp_path / "cost-evidence.json"
        snapshot_payload = evidence.model_dump(mode="json")
        snapshot_payload["evidence_digest"] = evidence_digest(evidence)
        snapshot_path.write_text(
            json.dumps(snapshot_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        assert load_cost_evidence_snapshot(snapshot_path) == evidence
        snapshot_payload["counts"]["attempts"] += 1
        snapshot_path.write_text(json.dumps(snapshot_payload), encoding="utf-8")
        with pytest.raises(ValueError, match="cost evidence digest mismatch"):
            load_cost_evidence_snapshot(snapshot_path)

        assumptions = load_cost_assumptions(ROOT / "config" / "cost-model-assumptions.yaml")
        projections = project_costs(assumptions)
        assert len(projections) == 12
        base_100 = next(
            item for item in projections if item.scenario == "base" and item.runs == 100
        )
        assert sum(base_100.workload_counts.values(), Decimal("0")) == Decimal("100")
        assert base_100.line_items.target_models > 0
        assert base_100.line_items.browser_and_api_workers > 0
        assert base_100.line_items.human_triage > base_100.line_items.attacker_models
        assert base_100.line_items.total > base_100.line_items.fixed_platform

        report = render_cost_analysis(
            evidence,
            assumptions,
            pricing_models=pricing["models"],
        )
        assert "## 1. Actual development and testing spend" in report
        assert "## 2. Observed unit economics" in report
        assert "## 3. Production projections at 100 / 1K / 10K / 100K runs" in report
        assert "## 4. Architecture required at each scale" in report
        assert "UNMEASURED" in report
        assert json.loads(evidence.model_dump_json())["target_executions"] == 1
    finally:
        database.dispose()
