import json
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship
from sqlalchemy.types import CHAR, JSON, TypeDecorator

from app.models.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class GUID(TypeDecorator):
    """
    Platform-independent UUID/GUID type.
    Uses native UUID on PostgreSQL, CHAR(36) string fallback on SQLite.
    """
    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if dialect.name == "postgresql":
            return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))


class CompatVector(TypeDecorator):
    """
    Vector type abstraction:
    - PostgreSQL: pgvector.sqlalchemy.Vector(1536) for semantic indexing.
    - SQLite: JSON-serialized list of floats.
    """
    impl = JSON
    cache_ok = True

    def __init__(self, dimensions: int = 1536, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dimensions = dimensions

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            try:
                from pgvector.sqlalchemy import Vector
                return dialect.type_descriptor(Vector(self.dimensions))
            except ImportError:
                return dialect.type_descriptor(JSON())
        return dialect.type_descriptor(JSON())

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if dialect.name == "postgresql":
            return value
        return value if isinstance(value, (list, dict)) else json.loads(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if dialect.name == "postgresql":
            return list(value)
        if isinstance(value, str):
            return json.loads(value)
        return list(value)


# =====================================================================
# Full Relational Enterprise Models
# =====================================================================

class User(Base):
    """Operators and analysts managing engagements with RBAC enforcement."""
    __tablename__ = "users"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    username = Column(Text, nullable=False, unique=True, index=True)
    email = Column(Text, unique=True, index=True)
    password_hash = Column(Text, nullable=False)
    role = Column(String(20), default="analyst", nullable=False)  # "lead" | "analyst"
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    # Relationships
    approved_reasoning_logs = relationship("ReasoningLog", back_populates="approved_by_user")
    created_styles = relationship("FixStyleConfig", back_populates="created_by_user")
    approved_fixes = relationship("FixSuggestion", foreign_keys="FixSuggestion.approved_by_user_id", back_populates="approved_by_user")

    reset_otp = Column(String(10), nullable=True)
    otp_expires_at = Column(DateTime, nullable=True)
    phone_number = Column(String(20), nullable=True)
    full_name = Column(String(100), nullable=True)
    bio = Column(Text, nullable=True, default="")
    is_founder = Column(Boolean, default=False)
    totp_secret = Column(Text, nullable=True)
    totp_enabled = Column(Boolean, default=False)


class Engagement(Base):
    """Top-level assessment tracking client metadata, autonomy mode, and state."""
    __tablename__ = "engagements"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    name = Column(Text, nullable=False)
    client_name = Column(Text, nullable=False)
    status = Column(String(20), default="draft", index=True)  # draft, active, paused, completed, archived
    test_type = Column(String(30), default="blackbox")        # blackbox, whitebox, graybox, web_only
    autonomy_level = Column(String(30), default="human_gated")  # autonomous, human_gated, interactive
    start_date = Column(DateTime(timezone=True))
    end_date = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow)

    # Cascade Relationships
    scope_authorizations = relationship("ScopeAuthorization", back_populates="engagement", cascade="all, delete-orphan")
    hosts = relationship("Host", back_populates="engagement", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="engagement", cascade="all, delete-orphan")
    credentials = relationship("Credential", back_populates="engagement", cascade="all, delete-orphan")
    reasoning_logs = relationship("ReasoningLog", back_populates="engagement", cascade="all, delete-orphan")
    tool_jobs = relationship("ToolJob", back_populates="engagement", cascade="all, delete-orphan")
    fix_suggestions = relationship("FixSuggestion", back_populates="engagement", cascade="all, delete-orphan")


class ScopeAuthorization(Base):
    """Cryptographically verifiable RoE constraints and authorized target boundaries."""
    __tablename__ = "scope_authorizations"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    engagement_id = Column(GUID, ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True)
    allowed_targets = Column(JSON, default=list, nullable=False)   # CIDR blocks, hostnames, domains
    excluded_targets = Column(JSON, default=list, nullable=False)  # Blacklisted assets/endpoints
    allowed_window_start = Column(DateTime(timezone=True), nullable=False)
    allowed_window_end = Column(DateTime(timezone=True), nullable=False)
    rules_of_engagement = Column(Text, default="")
    signed_by = Column(Text, default="system", nullable=False)
    signed_document_path = Column(Text, default="")                # Immutable storage pointer
    approved = Column(Boolean, default=False, nullable=False)
    # HMAC-SHA256 pin over (engagement_id, allowed/excluded targets, window).
    # Verified on every scan dispatch; any DB-level tampering with the scope
    # invalidates the pin and blocks execution (feature #3).
    signature = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow)

    engagement = relationship("Engagement", back_populates="scope_authorizations")


class Host(Base):
    """Network asset inventory discovered during reconnaissance."""
    __tablename__ = "hosts"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    engagement_id = Column(GUID, ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    hostname = Column(Text, default="")
    os_guess = Column(Text, default="")
    status = Column(String(20), default="up")  # up | down | filtered
    first_seen = Column(DateTime(timezone=True), default=utcnow)
    last_seen = Column(DateTime(timezone=True), default=utcnow)

    engagement = relationship("Engagement", back_populates="hosts")
    services = relationship("Service", back_populates="host", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="host", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("engagement_id", "ip_address", name="uq_engagement_host_ip"),
    )


class Service(Base):
    """Active network ports and applications mapped to a discovered host."""
    __tablename__ = "services"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    host_id = Column(GUID, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp", nullable=False)
    service_name = Column(Text, default="unknown")
    version = Column(Text, default="")
    banner = Column(Text, default="")
    first_seen = Column(DateTime(timezone=True), default=utcnow)

    host = relationship("Host", back_populates="services")
    findings = relationship("Finding", back_populates="service")

    __table_args__ = (
        UniqueConstraint("host_id", "port", "protocol", name="uq_service_host_port_proto"),
    )


class Finding(Base):
    """Vulnerability detections with vector embeddings and deduplication tracking."""
    __tablename__ = "findings"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    engagement_id = Column(GUID, ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True)
    host_id = Column(GUID, ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True, index=True)
    service_id = Column(GUID, ForeignKey("services.id", ondelete="SET NULL"), nullable=True, index=True)

    source_tool = Column(Text, default="")
    vuln_type = Column(Text, nullable=False, index=True)
    parameter = Column(Text, default="")
    severity = Column(String(20), default="info", index=True)  # info, low, medium, high, critical
    description = Column(Text, default="")
    evidence = Column(Text, default="")
    cvss_score = Column(Float, default=0.0)

    fingerprint = Column(String(64), nullable=False, index=True)
    embedding = Column(CompatVector(1536), nullable=True)
    occurrences = Column(Integer, default=1)

    status = Column(String(30), default="open", index=True)  # open, verified, duplicate, resolved, false_positive
    duplicate_of = Column(GUID, ForeignKey("findings.id", ondelete="SET NULL"), nullable=True)

    first_seen = Column(DateTime(timezone=True), default=utcnow)
    last_seen = Column(DateTime(timezone=True), default=utcnow)

    # Relationships
    engagement = relationship("Engagement", back_populates="findings")
    host = relationship("Host", back_populates="findings")
    service = relationship("Service", back_populates="findings")
    fix_suggestions = relationship("FixSuggestion", back_populates="finding", cascade="all, delete-orphan")
    duplicates = relationship("Finding", remote_side=[id])

    __table_args__ = (
        Index("idx_finding_eng_fingerprint", "engagement_id", "fingerprint"),
        Index("idx_finding_eng_status", "engagement_id", "status"),
    )


class Credential(Base):
    """Harvested secrets, hashes, and recovered plaintexts linked to valid services."""
    __tablename__ = "credentials"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    engagement_id = Column(GUID, ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True)
    username = Column(Text, default="")
    secret_hash = Column(Text, default="")
    cracked_plaintext = Column(Text, default="")
    source = Column(Text, default="")                     # hashcat, mimikatz, config_leak, etc.
    valid_on_service_ids = Column(JSON, default=list)      # Array of Service UUID strings
    discovered_at = Column(DateTime(timezone=True), default=utcnow)

    engagement = relationship("Engagement", back_populates="credentials")


class ReasoningLog(Base):
    """Step-by-step causal chain of AI reasoning, intent, and operator decisions."""
    __tablename__ = "reasoning_log"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    engagement_id = Column(GUID, ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True)
    parent_event_id = Column(GUID, ForeignKey("reasoning_log.id", ondelete="SET NULL"), nullable=True)
    timestamp = Column(DateTime(timezone=True), default=utcnow, index=True)
    actor = Column(String(10), default="agent")            # agent | human
    action_type = Column(String(30), nullable=False)       # recon_plan, exploit_decision, scope_halt
    target = Column(Text, default="")
    input_summary = Column(Text, default="")
    reasoning = Column(Text, default="")                   # LLM scratchpad / reasoning text
    proposed_action = Column(Text, default="")             # Next step to dispatch
    status = Column(String(20), default="proposed")        # proposed, approved, rejected, executed
    result_summary = Column(Text, default="")
    linked_finding_id = Column(GUID, ForeignKey("findings.id", ondelete="SET NULL"), nullable=True)
    approved_by_user_id = Column(GUID, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    engagement = relationship("Engagement", back_populates="reasoning_logs")
    approved_by_user = relationship("User", back_populates="approved_reasoning_logs")
    tool_jobs = relationship("ToolJob", back_populates="reasoning_log")


class ToolJob(Base):
    """Asynchronous tool execution tracking with stdout/stderr persistence."""
    __tablename__ = "tool_jobs"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    engagement_id = Column(GUID, ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True)
    reasoning_log_id = Column(GUID, ForeignKey("reasoning_log.id", ondelete="SET NULL"), nullable=True)
    tool_name = Column(Text, nullable=False)
    parameters = Column(JSON, default=dict)
    status = Column(String(20), default="queued", index=True)  # queued, running, completed, failed
    raw_output = Column(Text, default="")
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))

    engagement = relationship("Engagement", back_populates="tool_jobs")
    reasoning_log = relationship("ReasoningLog", back_populates="tool_jobs")


class FixStyleConfig(Base):
    """Coding style preferences enforced during AI remediation generation."""
    __tablename__ = "fix_style_configs"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    engagement_id = Column(GUID, ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(Text, default="default")
    language = Column(String(20), default="auto")
    style_rules = Column(Text, nullable=False)
    created_by_user_id = Column(GUID, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    created_by_user = relationship("User", back_populates="created_styles")


class FixSuggestion(Base):
    """Human-approved remediation diffs, WAF mitigation rules, and curl replays."""
    __tablename__ = "fix_suggestions"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    engagement_id = Column(GUID, ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(GUID, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(20), default="suggested")  # suggested, approved, rejected, applied, failed_lint
    language = Column(String(20))
    file_path = Column(Text)
    before_code = Column(Text)
    after_code = Column(Text)
    git_diff = Column(Text)
    waf_rule = Column(Text)
    waf_engine = Column(String(20))                   # nginx | cloudflare
    curl_replay = Column(Text)
    explanation = Column(Text)
    lint_check = Column(Text)
    created_by_user_id = Column(GUID, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_by_user_id = Column(GUID, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    pr_url = Column(Text)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    approved_at = Column(DateTime(timezone=True))

    engagement = relationship("Engagement", back_populates="fix_suggestions")
    finding = relationship("Finding", back_populates="fix_suggestions")
    approved_by_user = relationship("User", foreign_keys=[approved_by_user_id], back_populates="approved_fixes")


# =====================================================================
# Group / Team Collaboration (one group per engagement, additive)
# =====================================================================

class Group(Base):
    """Team workspace bound 1:1 to an engagement. Only founder can create."""
    __tablename__ = "groups"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    name = Column(Text, nullable=False)  # app type e.g. E-Commerce — Q3
    engagement_id = Column(GUID, ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    lead_id = Column(GUID, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    members = relationship("GroupMember", back_populates="group", cascade="all, delete-orphan")
    activities = relationship("GroupActivity", back_populates="group", cascade="all, delete-orphan")
    messages = relationship("GroupMessage", back_populates="group", cascade="all, delete-orphan")


class GroupMember(Base):
    """analyst | co_lead | lead inside a group. Mute stored as muted_until."""
    __tablename__ = "group_members"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    group_id = Column(GUID, ForeignKey("groups.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(20), default="analyst", nullable=False)  # analyst | co_lead | lead
    muted_until = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)
    joined_at = Column(DateTime(timezone=True), default=utcnow)

    group = relationship("Group", back_populates="members")

    __table_args__ = (
        UniqueConstraint("group_id", "user_id", name="uq_group_user"),
    )


class GroupActivity(Base):
    """Human-readable log: 'Depanshu started nmap port scanning on 10.0.0.5'."""
    __tablename__ = "group_activities"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    group_id = Column(GUID, ForeignKey("groups.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(GUID, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    engagement_id = Column(GUID, ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True)
    action_type = Column(String(50), nullable=False, index=True)  # nmap_scan, crawl, zap, finding_created...
    target = Column(Text, default="")
    tool = Column(Text, default="")
    parameters = Column(JSON, default=dict)
    result_summary = Column(Text, default="")
    job_id = Column(GUID, ForeignKey("tool_jobs.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)

    group = relationship("Group", back_populates="activities")

    __table_args__ = (
        Index("idx_group_activity_group_created", "group_id", "created_at"),
    )


class GroupMessage(Base):
    """Group chat. Muted sender still stored but notify=False (no popup)."""
    __tablename__ = "group_messages"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    group_id = Column(GUID, ForeignKey("groups.id", ondelete="CASCADE"), nullable=False, index=True)
    sender_id = Column(GUID, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    message = Column(Text, nullable=False)
    notify = Column(Boolean, default=True)  # False if sender was muted at send time
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)

    group = relationship("Group", back_populates="messages")


class GroupShare(Base):
    """Analyst shares finding/fix/log to lead."""
    __tablename__ = "group_shares"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    group_id = Column(GUID, ForeignKey("groups.id", ondelete="CASCADE"), nullable=False, index=True)
    sender_id = Column(GUID, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    lead_id = Column(GUID, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    payload_type = Column(String(20), nullable=False)  # finding | fix | log
    payload_id = Column(Text, nullable=False)
    note = Column(Text, default="")
    status = Column(String(20), default="pending")  # pending | seen
    created_at = Column(DateTime(timezone=True), default=utcnow)


# =====================================================================
# Security hardening tables (additive — old tables untouched)
# =====================================================================

class UserSession(Base):
    """Track active JWTs per device so users can list + revoke sessions."""
    __tablename__ = "user_sessions"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    jti = Column(String(64), nullable=False, unique=True, index=True)
    user_agent = Column(Text, default="")
    ip = Column(String(64), default="")
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    """Who did what, when — approvals, role changes, PRs, logins."""
    __tablename__ = "audit_log"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    actor_id = Column(GUID, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    actor_name = Column(Text, default="")
    action = Column(String(60), nullable=False, index=True)
    target_type = Column(String(30), default="")
    target_id = Column(Text, default="")
    detail = Column(Text, default="")
    ip = Column(String(64), default="")
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)


class ApiToken(Base):
    """Long-lived CI tokens (ptx_...) with expiry. Only the hash is stored."""
    __tablename__ = "api_tokens"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(Text, nullable=False, default="")
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    prefix = Column(String(16), nullable=False, default="")
    expires_at = Column(DateTime(timezone=True), nullable=True)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)