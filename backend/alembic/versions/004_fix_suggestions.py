"""fix suggestions schema

Revision ID: 004
Revises: 003
Create Date: 2026-01-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "fix_style_configs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("engagement_id", UUID(as_uuid=True), sa.ForeignKey("engagements.id"), nullable=False),
        sa.Column("name", sa.Text, server_default="default"),
        sa.Column("language", sa.String(20), server_default="auto"),
        sa.Column("style_rules", sa.Text, nullable=False),
        sa.Column("created_by_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )

    op.create_table(
        "fix_suggestions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("engagement_id", UUID(as_uuid=True), sa.ForeignKey("engagements.id"), nullable=False),
        sa.Column("finding_id", UUID(as_uuid=True), sa.ForeignKey("findings.id")),
        sa.Column("status", sa.String(20), server_default="suggested"),
        sa.Column("language", sa.String(20)),
        sa.Column("file_path", sa.Text),
        sa.Column("before_code", sa.Text),
        sa.Column("after_code", sa.Text),
        sa.Column("git_diff", sa.Text),
        sa.Column("waf_rule", sa.Text),
        sa.Column("waf_engine", sa.String(20)),
        sa.Column("curl_replay", sa.Text),
        sa.Column("explanation", sa.Text),
        sa.Column("lint_check", sa.Text),
        sa.Column("created_by_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("approved_by_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("pr_url", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    op.drop_table("fix_suggestions")
    op.drop_table("fix_style_configs")
