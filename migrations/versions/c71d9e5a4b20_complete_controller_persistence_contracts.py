"""complete controller persistence contracts

Revision ID: c71d9e5a4b20
Revises: 8a4f1c2d9e70
Create Date: 2026-07-21 14:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c71d9e5a4b20"
down_revision: str | None = "8a4f1c2d9e70"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    json_type = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
    op.add_column("attack_attempts", sa.Column("evidence_payload", json_type, nullable=True))

    op.add_column("regression_cases", sa.Column("case_id", sa.String(128), nullable=True))
    op.add_column(
        "regression_cases",
        sa.Column("judge_required", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column("regression_cases", sa.Column("subcategory", sa.String(100), nullable=True))
    op.add_column("regression_cases", sa.Column("sequence_hash", sa.String(64), nullable=True))
    op.add_column("regression_cases", sa.Column("fingerprint", sa.String(64), nullable=True))

    op.execute(
        sa.text(
            """
            UPDATE regression_cases
            SET case_id = 'REG-legacy-' || CAST(id AS VARCHAR),
                subcategory = 'legacy_unknown',
                sequence_hash = md5(CAST(id AS VARCHAR)) || md5('sequence-' || CAST(id AS VARCHAR)),
                fingerprint = md5(CAST(id AS VARCHAR)) || md5('fingerprint-' || CAST(id AS VARCHAR))
            WHERE case_id IS NULL
            """
        )
    )
    op.alter_column("regression_cases", "case_id", nullable=False)
    op.alter_column("regression_cases", "subcategory", nullable=False)
    op.alter_column("regression_cases", "sequence_hash", nullable=False)
    op.alter_column("regression_cases", "fingerprint", nullable=False)
    op.alter_column("regression_cases", "judge_required", server_default=None)
    op.create_unique_constraint(
        op.f("uq_regression_cases_case_id"), "regression_cases", ["case_id"]
    )
    op.create_index(
        op.f("ix_regression_cases_fingerprint"),
        "regression_cases",
        ["fingerprint"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_regression_cases_fingerprint"), table_name="regression_cases")
    op.drop_constraint(
        op.f("uq_regression_cases_case_id"),
        "regression_cases",
        type_="unique",
    )
    op.drop_column("regression_cases", "fingerprint")
    op.drop_column("regression_cases", "sequence_hash")
    op.drop_column("regression_cases", "subcategory")
    op.drop_column("regression_cases", "judge_required")
    op.drop_column("regression_cases", "case_id")
    op.drop_column("attack_attempts", "evidence_payload")
