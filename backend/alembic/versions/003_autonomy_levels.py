"""autonomy levels

Revision ID: 003
Revises: 002
Create Date: 2026-01-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "engagements",
        sa.Column("autonomy_level", sa.String(30), server_default="human_gated"),
    )


def downgrade() -> None:
    op.drop_column("engagements", "autonomy_level")
