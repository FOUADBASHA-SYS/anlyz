"""
SQLAlchemy ORM Models for Cloud XDR URL Threat Analyzer.
Fully normalized models with UTC timestamps, foreign keys, indexes, and JSON evidence.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime,
    ForeignKey, Text, Index
)
from sqlalchemy.orm import relationship
from backend.database import Base, get_json_type

JsonType = get_json_type()


def utcnow():
    return datetime.now(timezone.utc)


def gen_uuid():
    return uuid.uuid4().hex


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="analyst")  # 'admin' or 'analyst'
    is_active = Column(Boolean, default=True, nullable=False)
    is_approved = Column(Boolean, default=True, nullable=False)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    totp_secret = Column(String(64), nullable=True)
    totp_enabled = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    # Relationships
    scans = relationship("Scan", back_populates="initiator", cascade="all, delete-orphan")
    feedbacks = relationship("AnalystFeedback", back_populates="user")
    api_tokens = relationship("ApiToken", back_populates="user", cascade="all, delete-orphan")
    audit_events = relationship("AuditLog", back_populates="actor")


class Invitation(Base):
    __tablename__ = "invitations"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    token = Column(String(128), unique=True, nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    role = Column(String(50), default="analyst", nullable=False)
    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class RevokedToken(Base):
    """Tracks revoked session identifiers (JTI) for instant invalidation."""
    __tablename__ = "revoked_tokens"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    jti = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    url = Column(Text, nullable=False, index=True)
    normalized_domain = Column(String(255), nullable=False, index=True)
    status = Column(String(30), default="queued", nullable=False, index=True)
    threat_score = Column(Integer, default=0, nullable=False, index=True)
    threat_level = Column(String(20), default="Low", nullable=False, index=True)
    hygiene_score = Column(Integer, default=0, nullable=False)
    hygiene_level = Column(String(20), default="Good", nullable=False)
    summary = Column(Text, default="", nullable=False)
    initiated_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    evidence = Column(JsonType, nullable=True)
    screenshot_path = Column(String(512), nullable=True)
    is_bulk = Column(Boolean, default=False, nullable=False)
    batch_id = Column(String(36), nullable=True, index=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    initiator = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    feedback = relationship("AnalystFeedback", back_populates="scan", cascade="all, delete-orphan")
    chat_messages = relationship("ChatMessage", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scans_domain_created", "normalized_domain", "created_at"),
        Index("idx_scans_status_score", "status", "threat_score"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(100), nullable=False, index=True)
    group = Column(String(50), nullable=False)  # 'threat' or 'hygiene'
    category = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)  # 'info', 'low', 'medium', 'high', 'critical'
    confidence = Column(Float, default=0.8, nullable=False)
    title = Column(String(255), nullable=False)
    detail = Column(Text, default="", nullable=False)
    evidence = Column(JsonType, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="findings")


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    verdict = Column(String(30), nullable=False)  # 'true_positive', 'false_positive', 'needs_review'
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="feedback")
    user = relationship("User", back_populates="feedbacks")


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(20), nullable=False)  # 'user', 'assistant', 'system'
    content = Column(Text, nullable=False)
    evidence_context = Column(JsonType, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="chat_messages")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    user_email = Column(String(255), nullable=True)
    action = Column(String(100), nullable=False, index=True)
    target_type = Column(String(50), nullable=False)
    target_id = Column(String(100), nullable=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)
    extra_metadata = Column("metadata", JsonType, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)

    # Relationships
    actor = relationship("User", back_populates="audit_events")


class Blocklist(Base):
    __tablename__ = "blocklist"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    pattern = Column(String(255), unique=True, nullable=False, index=True)
    pattern_type = Column(String(20), default="domain", nullable=False)  # 'domain', 'url', 'ip'
    reason = Column(Text, default="", nullable=False)
    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class Allowlist(Base):
    __tablename__ = "allowlist"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    pattern = Column(String(255), unique=True, nullable=False, index=True)
    pattern_type = Column(String(20), default="domain", nullable=False)  # 'domain', 'url', 'ip'
    reason = Column(Text, default="", nullable=False)
    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class Watchlist(Base):
    __tablename__ = "watchlists"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    name = Column(String(100), nullable=False)
    target = Column(String(512), nullable=False, index=True)
    target_type = Column(String(20), default="url", nullable=False)  # 'url' or 'domain'
    interval_minutes = Column(Integer, default=1440, nullable=False)  # default 24h
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    next_run_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class BulkJob(Base):
    __tablename__ = "bulk_jobs"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    total_urls = Column(Integer, default=0, nullable=False)
    processed_urls = Column(Integer, default=0, nullable=False)
    successful_urls = Column(Integer, default=0, nullable=False)
    failed_urls = Column(Integer, default=0, nullable=False)
    status = Column(String(30), default="queued", nullable=False, index=True)
    errors = Column(JsonType, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    finished_at = Column(DateTime(timezone=True), nullable=True)


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    token_prefix = Column(String(16), nullable=False)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)  # SHA-256
    scopes = Column(JsonType, nullable=False)  # ['scans:read', 'scans:write', ...]
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    user = relationship("User", back_populates="api_tokens")
