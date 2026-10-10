"""initial schema

Revision ID: 001
Revises:
Create Date: 2025-01-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB, ARRAY
from pgvector.sqlalchemy import Vector

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        "engagements",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("client_name", sa.Text),
        sa.Column("status", sa.String(20), server_default="draft"),
        sa.Column("test_type", sa.String(30)),
        sa.Column("start_date", sa.DateTime(timezone=True)),
        sa.Column("end_date", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )

    op.create_table(
        "scope_authorizations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("engagement_id", UUID(as_uuid=True), sa.ForeignKey("engagements.id"), nullable=False),
        sa.Column("allowed_targets", ARRAY(sa.Text), nullable=False),
        sa.Column("excluded_targets", ARRAY(sa.Text), server_default="{}"),
        sa.Column("allowed_window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("allowed_window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rules_of_engagement", sa.Text),
        sa.Column("signed_by", sa.Text),
        sa.Column("signed_document_path", sa.Text),
        sa.Column("approved", sa.Boolean, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )

    op.create_table(
        "hosts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("engagement_id", UUID(as_uuid=True), sa.ForeignKey("engagements.id"), nullable=False),
        sa.Column("ip_address", INET),
        sa.Column("hostname", sa.Text),
        sa.Column("os_guess", sa.Text),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )

    op.create_table(
        "services",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("host_id", UUID(as_uuid=True), sa.ForeignKey("hosts.id"), nullable=False),
        sa.Column("port", sa.Integer),
        sa.Column("protocol", sa.String(10)),
        sa.Column("service_name", sa.Text),
        sa.Column("version", sa.Text),
        sa.Column("banner", sa.Text),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )

    op.create_table(
        "findings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("engagement_id", UUID(as_uuid=True), sa.ForeignKey("engagements.id"), nullable=False),
        sa.Column("host_id", UUID(as_uuid=True), sa.ForeignKey("hosts.id")),
        sa.Column("service_id", UUID(as_uuid=True), sa.ForeignKey("services.id")),
        sa.Column("source_tool", sa.Text),
        sa.Column("vuln_type", sa.Text),
        sa.Column("parameter", sa.Text),
        sa.Column("severity", sa.String(20)),
        sa.Column("description", sa.Text),
        sa.Column("evidence", sa.Text),
        sa.Column("cvss_score", sa.Numeric),
        sa.Column("fingerprint", sa.Text),
        sa.Column("embedding", Vector(1536)),
        sa.Column("status", sa.String(30), server_default="open"),
        sa.Column("duplicate_of", UUID(as_uuid=True), sa.ForeignKey("findings.id")),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )

    op.create_table(
        "credentials",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("engagement_id", UUID(as_uuid=True), sa.ForeignKey("engagements.id"), nullable=False),
        sa.Column("username", sa.Text),
        sa.Column("secret_hash", sa.Text),
        sa.Column("cracked_plaintext", sa.Text),
        sa.Column("source", sa.Text),
        sa.Column("valid_on_service_ids", ARRAY(UUID(as_uuid=True))),
        sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )

    op.create_table(
        "reasoning_log",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("engagement_id", UUID(as_uuid=True), sa.ForeignKey("engagements.id"), nullable=False),
        sa.Column("parent_event_id", UUID(as_uuid=True), sa.ForeignKey("reasoning_log.id")),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("actor", sa.String(10)),
        sa.Column("action_type", sa.String(30)),
        sa.Column("target", sa.Text),
        sa.Column("input_summary", sa.Text),
        sa.Column("reasoning", sa.Text),
        sa.Column("proposed_action", sa.Text),
        sa.Column("status", sa.String(20)),
        sa.Column("result_summary", sa.Text),
        sa.Column("linked_finding_id", UUID(as_uuid=True), sa.ForeignKey("findings.id")),
    )

    op.create_table(
        "tool_jobs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("engagement_id", UUID(as_uuid=True), sa.ForeignKey("engagements.id"), nullable=False),
        sa.Column("reasoning_log_id", UUID(as_uuid=True), sa.ForeignKey("reasoning_log.id")),
        sa.Column("tool_name", sa.Text),
        sa.Column("parameters", JSONB),
        sa.Column("status", sa.String(20)),
        sa.Column("raw_output", sa.Text),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    op.drop_table("tool_jobs")
    op.drop_table("reasoning_log")
    op.drop_table("credentials")
    op.drop_table("findings")
    op.drop_table("services")
    op.drop_table("hosts")
    op.drop_table("scope_authorizations")
    op.drop_table("engagements")
    op.execute("DROP EXTENSION IF EXISTS vector")
