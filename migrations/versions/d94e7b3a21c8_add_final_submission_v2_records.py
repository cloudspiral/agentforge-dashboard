"""add final-submission V2 planning, finding, replay, and observability records

Revision ID: d94e7b3a21c8
Revises: a812e4c97f30
Create Date: 2026-07-24 03:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "d94e7b3a21c8"
down_revision: str | None = "a812e4c97f30"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json_type() -> sa.JSON:
    return sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def _money() -> sa.Numeric:
    return sa.Numeric(12, 6)


def upgrade() -> None:
    json_type = _json_type()

    op.add_column(
        "attack_attempts",
        sa.Column("provenance", sa.String(40), server_default="legacy_unknown", nullable=False),
    )
    op.add_column(
        "attack_attempts",
        sa.Column(
            "execution_surface",
            sa.String(40),
            server_default="legacy_unknown",
            nullable=False,
        ),
    )
    op.add_column(
        "attack_attempts",
        sa.Column("technique", sa.String(32), server_default="scenario", nullable=False),
    )
    op.add_column("attack_attempts", sa.Column("seed_case_hash", sa.String(64), nullable=True))
    op.add_column("attack_attempts", sa.Column("orchestrator_rationale", sa.Text(), nullable=True))
    op.add_column("attack_attempts", sa.Column("fuzz_plan", json_type, nullable=True))
    op.add_column("attack_attempts", sa.Column("fuzz_variant_id", sa.String(128), nullable=True))
    op.add_column("attack_attempts", sa.Column("fuzz_variant_index", sa.Integer(), nullable=True))
    op.add_column("attack_attempts", sa.Column("exact_payload_hash", sa.String(64), nullable=True))
    op.add_column(
        "attack_attempts",
        sa.Column("target_executed", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.create_index(
        "ix_attack_attempts_seed_case_hash",
        "attack_attempts",
        ["seed_case_hash"],
    )
    op.create_index(
        "ix_attack_attempts_fuzz_variant_id",
        "attack_attempts",
        ["fuzz_variant_id"],
    )
    op.create_index(
        "ix_attack_attempts_exact_payload_hash",
        "attack_attempts",
        ["exact_payload_hash"],
    )
    op.execute(
        sa.text(
            """
            UPDATE attack_attempts
            SET target_executed = true
            WHERE evidence_hash IS NOT NULL
            """
        )
    )
    op.execute(
        sa.text(
            """
            UPDATE attack_attempts
            SET provenance = CASE
                WHEN attack_family_id = 'AF-PI-002' THEN 'curated_discovery_replay'
                WHEN proposal_source = 'fixed_yaml_case' THEN 'human_authored_seed'
                WHEN proposal_source = 'fixed_regression_case' THEN 'regression_replay'
                WHEN proposal_source = 'agent_generated_mutation' THEN 'agent_scenario'
                WHEN proposal_source = 'agent_generated' THEN 'agent_scenario'
                ELSE provenance
            END,
            execution_surface = CASE
                WHEN attack_family_id = 'AF-DE-002' THEN 'openemr_same_origin_api'
                WHEN proposal_source = 'fixed_yaml_case' THEN 'openemr_ui'
                ELSE execution_surface
            END
            """
        )
    )

    op.add_column("judge_verdicts", sa.Column("finding_key", sa.String(128), nullable=True))
    op.create_index("ix_judge_verdicts_finding_key", "judge_verdicts", ["finding_key"])

    op.add_column("findings", sa.Column("finding_key", sa.String(128), nullable=True))
    op.add_column(
        "findings",
        sa.Column("provenance", sa.String(40), server_default="legacy_unknown", nullable=False),
    )
    op.add_column(
        "findings",
        sa.Column("rediscovery_count", sa.Integer(), server_default="0", nullable=False),
    )
    op.execute(
        sa.text(
            """
            UPDATE findings
            SET finding_key = 'legacy-' || lower(vulnerability_id)
            WHERE finding_key IS NULL
            """
        )
    )
    op.alter_column("findings", "finding_key", nullable=False)
    op.alter_column("findings", "status", server_default="pending_review")
    op.execute(sa.text("UPDATE findings SET status = 'open' WHERE status = 'reopened'"))
    op.execute(
        sa.text(
            """
            UPDATE findings AS finding
            SET provenance = attempt.provenance
            FROM attack_attempts AS attempt
            WHERE attempt.id = finding.source_attempt_id
            """
        )
    )
    op.execute(
        sa.text(
            """
            UPDATE findings
            SET provenance = 'agent_scenario'
            WHERE vulnerability_id = 'AF-5860F03C4E00'
            """
        )
    )

    op.create_table(
        "finding_observations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("attempt_id", sa.Uuid(), nullable=False),
        sa.Column("target_version", sa.String(255), nullable=False),
        sa.Column("provenance", sa.String(40), nullable=False),
        sa.Column("evidence_hash", sa.String(64), nullable=False),
        sa.Column("judge_verdict", json_type, nullable=False),
        sa.Column(
            "observation_kind",
            sa.String(32),
            server_default="confirmation",
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["attempt_id"], ["attack_attempts.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id", "attempt_id"),
    )
    op.create_index(
        "ix_finding_observations_finding_created",
        "finding_observations",
        ["finding_id", "created_at"],
    )

    op.create_table(
        "finding_lifecycle_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("from_status", sa.String(32), nullable=True),
        sa.Column("to_status", sa.String(32), nullable=False),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("evidence_reference", sa.String(255), nullable=True),
        sa.Column("details_json", json_type, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_finding_lifecycle_finding_created",
        "finding_lifecycle_events",
        ["finding_id", "created_at"],
    )

    op.add_column(
        "regression_cases",
        sa.Column("schema_version", sa.String(32), server_default="v1", nullable=False),
    )
    op.add_column("regression_cases", sa.Column("finding_key", sa.String(128), nullable=True))
    op.add_column(
        "regression_cases",
        sa.Column("source_target_version", sa.String(255), nullable=True),
    )
    op.add_column(
        "regression_cases",
        sa.Column(
            "source_provenance",
            sa.String(40),
            server_default="legacy_unknown",
            nullable=False,
        ),
    )
    op.add_column(
        "regression_cases",
        sa.Column("required_replays", sa.Integer(), server_default="2", nullable=False),
    )
    op.execute(
        sa.text(
            """
            UPDATE regression_cases AS regression
            SET finding_key = finding.finding_key,
                source_target_version = finding.first_seen_target_version
            FROM findings AS finding
            WHERE regression.finding_id = finding.id
            """
        )
    )
    op.alter_column("regression_cases", "finding_key", nullable=False)
    op.alter_column("regression_cases", "source_target_version", nullable=False)
    op.alter_column("regression_cases", "schema_version", server_default="v2")

    op.add_column(
        "regression_runs",
        sa.Column("previous_target_version", sa.String(255), nullable=True),
    )
    op.add_column("regression_runs", sa.Column("cohort_hash", sa.String(64), nullable=True))
    op.add_column(
        "regression_runs",
        sa.Column("improved_cases", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column(
        "regression_runs",
        sa.Column("regressed_cases", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column(
        "regression_runs",
        sa.Column(
            "cross_category_regression",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
    )
    op.create_index("ix_regression_runs_cohort_hash", "regression_runs", ["cohort_hash"])

    op.add_column(
        "regression_results",
        sa.Column(
            "changed_target_version",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
    )
    op.add_column(
        "regression_results",
        sa.Column("aggregate_reason", sa.Text(), nullable=True),
    )

    op.create_table(
        "regression_replays",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("result_id", sa.Uuid(), nullable=False),
        sa.Column("attempt_id", sa.Uuid(), nullable=True),
        sa.Column("replay_index", sa.Integer(), nullable=False),
        sa.Column("target_version", sa.String(255), nullable=False),
        sa.Column(
            "valid_replay",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
        sa.Column("judge_verdict", json_type, nullable=True),
        sa.Column("evidence_hash", sa.String(64), nullable=True),
        sa.Column("error", json_type, nullable=True),
        sa.Column(
            "estimated_cost_usd",
            _money(),
            server_default="0",
            nullable=False,
        ),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("trace_id", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["attempt_id"], ["attack_attempts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["result_id"], ["regression_results.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("result_id", "replay_index"),
    )
    op.create_index(
        "ix_regression_replays_attempt_id",
        "regression_replays",
        ["attempt_id"],
    )
    op.create_index(
        "ix_regression_replays_result_index",
        "regression_replays",
        ["result_id", "replay_index"],
    )
    op.create_index("ix_regression_replays_trace_id", "regression_replays", ["trace_id"])

    op.add_column("agent_runs", sa.Column("input_payload", json_type, nullable=True))
    op.add_column("agent_runs", sa.Column("sdk_attempts", sa.Integer(), nullable=True))

    op.create_table(
        "platform_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("campaign_id", sa.Uuid(), nullable=True),
        sa.Column("attempt_id", sa.Uuid(), nullable=True),
        sa.Column("finding_id", sa.Uuid(), nullable=True),
        sa.Column("regression_run_id", sa.Uuid(), nullable=True),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("role", sa.String(64), nullable=True),
        sa.Column("model", sa.String(255), nullable=True),
        sa.Column("prompt_version", sa.String(64), nullable=True),
        sa.Column("trace_id", sa.String(255), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("cost_usd", _money(), server_default="0", nullable=False),
        sa.Column("details_json", json_type, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["attempt_id"], ["attack_attempts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["regression_run_id"],
            ["regression_runs.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_platform_events_attempt_id",
        "platform_events",
        ["attempt_id"],
    )
    op.create_index(
        "ix_platform_events_campaign_created",
        "platform_events",
        ["campaign_id", "created_at"],
    )
    op.create_index("ix_platform_events_campaign_id", "platform_events", ["campaign_id"])
    op.create_index("ix_platform_events_created", "platform_events", ["created_at"])
    op.create_index("ix_platform_events_finding_id", "platform_events", ["finding_id"])
    op.create_index(
        "ix_platform_events_regression_run_id",
        "platform_events",
        ["regression_run_id"],
    )
    op.create_index("ix_platform_events_trace_id", "platform_events", ["trace_id"])


def downgrade() -> None:
    op.drop_index("ix_platform_events_trace_id", table_name="platform_events")
    op.drop_index("ix_platform_events_regression_run_id", table_name="platform_events")
    op.drop_index("ix_platform_events_finding_id", table_name="platform_events")
    op.drop_index("ix_platform_events_created", table_name="platform_events")
    op.drop_index("ix_platform_events_campaign_id", table_name="platform_events")
    op.drop_index("ix_platform_events_campaign_created", table_name="platform_events")
    op.drop_index("ix_platform_events_attempt_id", table_name="platform_events")
    op.drop_table("platform_events")

    op.drop_column("agent_runs", "sdk_attempts")
    op.drop_column("agent_runs", "input_payload")

    op.drop_index("ix_regression_replays_trace_id", table_name="regression_replays")
    op.drop_index("ix_regression_replays_result_index", table_name="regression_replays")
    op.drop_index("ix_regression_replays_attempt_id", table_name="regression_replays")
    op.drop_table("regression_replays")
    op.drop_column("regression_results", "aggregate_reason")
    op.drop_column("regression_results", "changed_target_version")

    op.drop_index("ix_regression_runs_cohort_hash", table_name="regression_runs")
    op.drop_column("regression_runs", "cross_category_regression")
    op.drop_column("regression_runs", "regressed_cases")
    op.drop_column("regression_runs", "improved_cases")
    op.drop_column("regression_runs", "cohort_hash")
    op.drop_column("regression_runs", "previous_target_version")

    op.drop_column("regression_cases", "required_replays")
    op.drop_column("regression_cases", "source_provenance")
    op.drop_column("regression_cases", "source_target_version")
    op.drop_column("regression_cases", "finding_key")
    op.drop_column("regression_cases", "schema_version")

    op.drop_index(
        "ix_finding_lifecycle_finding_created",
        table_name="finding_lifecycle_events",
    )
    op.drop_table("finding_lifecycle_events")
    op.drop_index(
        "ix_finding_observations_finding_created",
        table_name="finding_observations",
    )
    op.drop_table("finding_observations")
    op.alter_column("findings", "status", server_default=None)
    op.drop_column("findings", "rediscovery_count")
    op.drop_column("findings", "provenance")
    op.drop_column("findings", "finding_key")

    op.drop_index("ix_judge_verdicts_finding_key", table_name="judge_verdicts")
    op.drop_column("judge_verdicts", "finding_key")

    op.drop_index("ix_attack_attempts_exact_payload_hash", table_name="attack_attempts")
    op.drop_index("ix_attack_attempts_fuzz_variant_id", table_name="attack_attempts")
    op.drop_index("ix_attack_attempts_seed_case_hash", table_name="attack_attempts")
    op.drop_column("attack_attempts", "target_executed")
    op.drop_column("attack_attempts", "exact_payload_hash")
    op.drop_column("attack_attempts", "fuzz_variant_index")
    op.drop_column("attack_attempts", "fuzz_variant_id")
    op.drop_column("attack_attempts", "fuzz_plan")
    op.drop_column("attack_attempts", "orchestrator_rationale")
    op.drop_column("attack_attempts", "seed_case_hash")
    op.drop_column("attack_attempts", "technique")
    op.drop_column("attack_attempts", "execution_surface")
    op.drop_column("attack_attempts", "provenance")
