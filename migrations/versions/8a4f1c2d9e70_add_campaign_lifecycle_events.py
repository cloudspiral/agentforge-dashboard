"""add durable campaign lifecycle events

Revision ID: 8a4f1c2d9e70
Revises: 1b98633917fc
Create Date: 2026-07-21 13:20:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "8a4f1c2d9e70"
down_revision: str | None = "1b98633917fc"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "campaign_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("campaign_id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("from_status", sa.String(length=32), nullable=True),
        sa.Column("to_status", sa.String(length=32), nullable=False),
        sa.Column("worker_name", sa.String(length=128), nullable=True),
        sa.Column(
            "details_json",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["campaign_id"],
            ["campaigns.id"],
            name=op.f("fk_campaign_events_campaign_id_campaigns"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_campaign_events")),
    )
    op.create_index(
        "ix_campaign_events_campaign_created",
        "campaign_events",
        ["campaign_id", "created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_campaign_events_campaign_id"),
        "campaign_events",
        ["campaign_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_campaign_events_campaign_id"), table_name="campaign_events")
    op.drop_index("ix_campaign_events_campaign_created", table_name="campaign_events")
    op.drop_table("campaign_events")
