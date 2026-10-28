"""
Pydantic v2 schemas for request validation and response serialization.
"""
from typing import Optional, List, Any, Dict
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


# ============================================================================
# Auth & User Schemas
# ============================================================================
class UserLogin(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=8)


class RegisterWithInvite(BaseModel):
    token: str = Field(..., description="Invitation token")
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=8)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    role: str
    is_active: bool
    is_approved: bool
    totp_enabled: bool
    created_at: datetime


class InviteCreate(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    role: str = Field(default="analyst", pattern="^(admin|analyst)$")
    expires_in_days: int = Field(default=7, ge=1, le=30)


class InviteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    token: str
    email: str
    role: str
    expires_at: datetime
    created_at: datetime


class UserRoleUpdate(BaseModel):
    role: str = Field(..., pattern="^(admin|analyst)$")
    is_active: Optional[bool] = None
    is_approved: Optional[bool] = None


# ============================================================================
# Scan Schemas
# ============================================================================
class ScanCreate(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)
    allow_private: bool = False


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    group: str
    category: str
    severity: str
    confidence: float
    title: str
    detail: str
    evidence: Optional[List[str]] = None
    created_at: datetime


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    url: str
    normalized_domain: str
    status: str
    threat_score: int
    threat_level: str
    hygiene_score: int
    hygiene_level: str
    summary: str
    is_bulk: bool
    error: Optional[str] = None
    created_at: datetime
    finished_at: Optional[datetime] = None


class ScanDetailResponse(ScanResponse):
    evidence: Optional[Dict[str, Any]] = None
    screenshot_path: Optional[str] = None
    findings: List[FindingResponse] = []


class ScanCompareResponse(BaseModel):
    base_scan: ScanResponse
    compare_scan: ScanResponse
    threat_score_delta: int
    hygiene_score_delta: int
    new_findings: List[Dict[str, Any]]
    resolved_findings: List[Dict[str, Any]]
    unchanged_findings: List[Dict[str, Any]]
    redirect_chain_changed: bool


# ============================================================================
# Rule Schemas (Allowlist & Blocklist)
# ============================================================================
class RuleCreate(BaseModel):
    pattern: str = Field(..., min_length=2, max_length=255)
    pattern_type: str = Field(default="domain", pattern="^(domain|url|ip)$")
    reason: str = Field(..., min_length=3, max_length=500)
    expires_at: Optional[datetime] = None


class RuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    pattern: str
    pattern_type: str
    reason: str
    created_by_id: Optional[str] = None
    expires_at: Optional[datetime] = None
    is_active: bool
    created_at: datetime


# ============================================================================
# Watchlist Schemas
# ============================================================================
class WatchlistCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    target: str = Field(..., min_length=3, max_length=512)
    target_type: str = Field(default="url", pattern="^(url|domain)$")
    interval_minutes: int = Field(default=1440, ge=15, le=10080)  # 15m to 7 days


class WatchlistResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    target: str
    target_type: str
    interval_minutes: int
    last_run_at: Optional[datetime] = None
    next_run_at: datetime
    is_active: bool
    created_at: datetime


# ============================================================================
# Bulk Scan Schemas
# ============================================================================
class BulkJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    filename: str
    total_urls: int
    processed_urls: int
    successful_urls: int
    failed_urls: int
    status: str
    errors: Optional[List[Dict[str, Any]]] = None
    created_at: datetime
    finished_at: Optional[datetime] = None


# ============================================================================
# Analyst Feedback Schemas
# ============================================================================
class FeedbackCreate(BaseModel):
    verdict: str = Field(..., pattern="^(true_positive|false_positive|needs_review)$")
    finding_id: Optional[str] = None
    notes: Optional[str] = Field(None, max_length=1000)


class FeedbackResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    finding_id: Optional[str] = None
    user_id: str
    verdict: str
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime


# ============================================================================
# Chat & Assistant Schemas
# ============================================================================
class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)


class ChatMessageResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    role: str
    content: str
    created_at: datetime


# ============================================================================
# API Token Schemas
# ============================================================================
class TokenCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    scopes: List[str] = Field(default=["scans:read", "scans:write"])
    expires_in_days: Optional[int] = Field(default=90, ge=1, le=365)


class TokenCreateResponse(BaseModel):
    id: str
    name: str
    token: str  # Only returned once!
    token_prefix: str
    scopes: List[str]
    expires_at: Optional[datetime] = None
    created_at: datetime


class TokenResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    token_prefix: str
    scopes: List[str]
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    is_active: bool
    created_at: datetime


# ============================================================================
# Dashboard & Audit Schemas
# ============================================================================
class TopDomainItem(BaseModel):
    domain: str
    count: int
    max_threat_score: int


class DashboardStats(BaseModel):
    total_scans: int
    scans_today: int
    scans_this_week: int
    risk_distribution: Dict[str, int]
    severity_distribution: Dict[str, int]
    top_suspicious_domains: List[TopDomainItem]
    recent_scans: List[ScanResponse]
    active_watchlists: int
    blocked_count: int
    allowlist_count: int
    worker_status: str


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    action: str
    target_type: str
    target_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    extra_metadata: Optional[Dict[str, Any]] = None
    created_at: datetime
