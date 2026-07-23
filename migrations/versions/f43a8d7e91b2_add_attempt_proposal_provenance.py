"""add trusted attempt proposal provenance

Revision ID: f43a8d7e91b2
Revises: c71d9e5a4b20
Create Date: 2026-07-23 01:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f43a8d7e91b2"
down_revision: str | None = "c71d9e5a4b20"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("attack_attempts", sa.Column("lineage_id", sa.String(255), nullable=True))
    op.add_column(
        "attack_attempts",
        sa.Column(
            "proposal_source",
            sa.String(40),
            server_default="legacy_unknown",
            nullable=False,
        ),
    )
    op.add_column(
        "attack_attempts",
        sa.Column(
            "objective_source",
            sa.String(40),
            server_default="legacy_unknown",
            nullable=False,
        ),
    )
    op.add_column(
        "attack_attempts",
        sa.Column("proposal_fallback_reason", sa.String(255), nullable=True),
    )
    op.add_column("attack_attempts", sa.Column("sequence_hash", sa.String(64), nullable=True))
    op.create_index(
        op.f("ix_attack_attempts_sequence_hash"),
        "attack_attempts",
        ["sequence_hash"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_attack_attempts_sequence_hash"), table_name="attack_attempts")
    op.drop_column("attack_attempts", "sequence_hash")
    op.drop_column("attack_attempts", "proposal_fallback_reason")
    op.drop_column("attack_attempts", "objective_source")
    op.drop_column("attack_attempts", "proposal_source")
    op.drop_column("attack_attempts", "lineage_id")
