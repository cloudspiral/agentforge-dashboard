"""simplify the agent-driven discovery pipeline

Revision ID: a812e4c97f30
Revises: f43a8d7e91b2
Create Date: 2026-07-23 17:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a812e4c97f30"
down_revision: str | None = "f43a8d7e91b2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json_type() -> sa.JSON:
    return sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    json_type = _json_type()

    op.add_column("agent_runs", sa.Column("output_payload", json_type, nullable=True))

    op.drop_column("campaigns", "max_mutations")
    op.drop_column("campaigns", "no_signal_limit")

    op.add_column(
        "attack_attempts",
        sa.Column("state", sa.String(32), server_default="pending", nullable=False),
    )
    op.add_column("attack_attempts", sa.Column("failure", json_type, nullable=True))
    op.execute(
        sa.text(
            """
            UPDATE attack_attempts
            SET state = CASE
                WHEN status = 'proposed' THEN 'pending'
                WHEN status IN ('executing', 'evaluating', 'documenting', 'running')
                    THEN 'running'
                WHEN status = 'cancelled' THEN 'cancelled'
                WHEN status IN ('rejected', 'error', 'documentation_failed')
                    THEN 'failed'
                ELSE 'completed'
            END
            """
        )
    )
    op.alter_column("attack_attempts", "state", server_default=None)
    op.drop_column("attack_attempts", "status")
    op.drop_column("attack_attempts", "lineage_id")
    op.drop_column("attack_attempts", "mutation_generation")
    op.drop_column("attack_attempts", "proposal_fallback_reason")
    op.drop_column("attack_attempts", "evidence_summary")

    op.add_column("judge_verdicts", sa.Column("observed_behavior", sa.Text(), nullable=True))
    op.add_column("judge_verdicts", sa.Column("expected_behavior", sa.Text(), nullable=True))
    op.execute(
        sa.text(
            """
            UPDATE judge_verdicts
            SET observed_behavior = 'Legacy verdict; narrative was not persisted.',
                expected_behavior = 'See the associated historical evidence package.'
            WHERE observed_behavior IS NULL OR expected_behavior IS NULL
            """
        )
    )
    op.alter_column("judge_verdicts", "observed_behavior", nullable=False)
    op.alter_column("judge_verdicts", "expected_behavior", nullable=False)
    op.drop_column("judge_verdicts", "evidence_references")
    op.drop_column("judge_verdicts", "next_recommendation")
    op.drop_column("judge_verdicts", "deterministic_override_applied")
    op.drop_column("judge_verdicts", "deterministic_override_reason")

    op.add_column(
        "regression_cases",
        sa.Column("judge_context", json_type, server_default=sa.text("'{}'"), nullable=False),
    )
    op.add_column("regression_cases", sa.Column("expected_behavior", sa.Text(), nullable=True))
    op.execute(
        sa.text(
            """
            UPDATE regression_cases
            SET judge_context = json_build_object(
                    'legacy_expected_security_invariants',
                    expected_security_invariants,
                    'legacy_judge_rubric_subset',
                    judge_rubric_subset
                ),
                expected_behavior =
                    'The saved attack should be blocked without a security violation.'
            """
        )
    )
    op.alter_column("regression_cases", "judge_context", server_default=None)
    op.alter_column("regression_cases", "expected_behavior", nullable=False)
    op.drop_column("regression_cases", "expected_security_invariants")
    op.drop_column("regression_cases", "deterministic_checks")
    op.drop_column("regression_cases", "judge_required")
    op.drop_column("regression_cases", "judge_rubric_subset")

    op.add_column("regression_results", sa.Column("evidence_hash", sa.String(64), nullable=True))
    op.drop_column("regression_results", "deterministic_results")
    op.drop_column("regression_results", "evidence_references")


def downgrade() -> None:
    json_type = _json_type()

    op.drop_column("agent_runs", "output_payload")

    op.add_column(
        "regression_results",
        sa.Column("evidence_references", json_type, server_default=sa.text("'[]'"), nullable=False),
    )
    op.add_column(
        "regression_results",
        sa.Column(
            "deterministic_results",
            json_type,
            server_default=sa.text("'[]'"),
            nullable=False,
        ),
    )
    op.drop_column("regression_results", "evidence_hash")

    op.add_column("regression_cases", sa.Column("judge_rubric_subset", json_type, nullable=True))
    op.add_column(
        "regression_cases",
        sa.Column("judge_required", sa.Boolean(), server_default=sa.true(), nullable=False),
    )
    op.add_column(
        "regression_cases",
        sa.Column(
            "deterministic_checks",
            json_type,
            server_default=sa.text("'[]'"),
            nullable=False,
        ),
    )
    op.add_column(
        "regression_cases",
        sa.Column(
            "expected_security_invariants",
            json_type,
            server_default=sa.text("'[]'"),
            nullable=False,
        ),
    )
    op.drop_column("regression_cases", "expected_behavior")
    op.drop_column("regression_cases", "judge_context")

    op.add_column(
        "judge_verdicts",
        sa.Column(
            "deterministic_override_reason",
            sa.Text(),
            nullable=True,
        ),
    )
    op.add_column(
        "judge_verdicts",
        sa.Column(
            "deterministic_override_applied",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
    )
    op.add_column(
        "judge_verdicts",
        sa.Column(
            "next_recommendation",
            sa.Text(),
            server_default="Legacy verdict",
            nullable=False,
        ),
    )
    op.add_column(
        "judge_verdicts",
        sa.Column("evidence_references", json_type, server_default=sa.text("'[]'"), nullable=False),
    )
    op.drop_column("judge_verdicts", "expected_behavior")
    op.drop_column("judge_verdicts", "observed_behavior")

    op.add_column(
        "attack_attempts",
        sa.Column("evidence_summary", json_type, nullable=True),
    )
    op.add_column(
        "attack_attempts",
        sa.Column("proposal_fallback_reason", sa.String(255), nullable=True),
    )
    op.add_column(
        "attack_attempts",
        sa.Column("mutation_generation", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column("attack_attempts", sa.Column("lineage_id", sa.String(255), nullable=True))
    op.add_column(
        "attack_attempts",
        sa.Column("status", sa.String(32), server_default="proposed", nullable=False),
    )
    op.execute(
        sa.text(
            """
            UPDATE attack_attempts
            SET status = CASE
                WHEN state = 'pending' THEN 'proposed'
                WHEN state = 'running' THEN 'executing'
                WHEN state = 'cancelled' THEN 'cancelled'
                WHEN state = 'failed' THEN 'error'
                ELSE 'completed'
            END
            """
        )
    )
    op.drop_column("attack_attempts", "failure")
    op.drop_column("attack_attempts", "state")

    op.add_column(
        "campaigns",
        sa.Column("no_signal_limit", sa.Integer(), server_default="4", nullable=False),
    )
    op.add_column(
        "campaigns",
        sa.Column("max_mutations", sa.Integer(), server_default="3", nullable=False),
    )
