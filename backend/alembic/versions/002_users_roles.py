"""users and audit columns

Revision ID: 002
Revises: 001
Create Date: 2026-01-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("username", sa.Text, nullable=False, unique=True),
        sa.Column("email", sa.Text, unique=True),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("role", sa.String(20), server_default="analyst"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )

    op.add_column(
        "reasoning_log",
        sa.Column("approved_by_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id")),
    )


def downgrade() -> None:
    op.drop_column("reasoning_log", "approved_by_user_id")
    op.drop_table("users")
