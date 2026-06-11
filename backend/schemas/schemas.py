"""
🛡️ Cyber Sentinel - API Schemas
Pydantic models for request/response validation.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, Field


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Auth Schemas
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., min_length=5, max_length=100)
    password: str = Field(..., min_length=6)
    full_name: Optional[str] = None


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    last_login: Optional[str]
    created_at: Optional[str]

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Threat Schemas
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ThreatCreate(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    attack_type: str
    severity: str = "medium"
    confidence: float = 0.0
    severity_score: float = 0.0
    model_used: Optional[str] = None
    feature_importance: Optional[Dict] = None
    explanation: Optional[str] = None
    packet_size: Optional[int] = None
    flow_duration: Optional[float] = None
    flags: Optional[str] = None
    raw_features: Optional[Dict] = None


class ThreatResponse(BaseModel):
    id: int
    timestamp: Optional[str]
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    attack_type: str
    severity: str
    confidence: float
    severity_score: float
    model_used: Optional[str]
    feature_importance: Optional[Dict]
    explanation: Optional[str]
    is_mitigated: bool
    is_false_positive: bool
    mitigated_at: Optional[str]
    mitigation_action: Optional[str]
    geo_location: Optional[Dict]
    created_at: Optional[str]

    class Config:
        from_attributes = True


class ThreatFilter(BaseModel):
    severity: Optional[str] = None
    attack_type: Optional[str] = None
    src_ip: Optional[str] = None
    is_mitigated: Optional[bool] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    page: int = 1
    per_page: int = 50


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Dashboard Schemas
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class DashboardStats(BaseModel):
    threats_today: int
    threats_total: int
    blocked_ips: int
    active_sessions: int
    critical_threats: int
    mitigated_today: int
    false_positive_rate: float
    model_accuracy: float
    packets_analyzed: int
    most_targeted_port: Optional[int]
    top_attacker_ip: Optional[str]
    severity_distribution: Dict[str, int]
    attack_categories: Dict[str, int]
    weekly_trend: List[Dict[str, Any]]
    hourly_trend: List[Dict[str, Any]]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Blocked IP Schemas
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class BlockIPRequest(BaseModel):
    ip_address: str
    reason: Optional[str] = None
    is_permanent: bool = False
    duration_hours: Optional[int] = 24


class BlockedIPResponse(BaseModel):
    id: int
    ip_address: str
    reason: Optional[str]
    blocked_by: Optional[str]
    threat_count: int
    is_permanent: bool
    expires_at: Optional[str]
    blocked_at: Optional[str]
    is_active: bool

    class Config:
        from_attributes = True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Incident Schemas
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    category: Optional[str] = None
    threat_ids: Optional[List[int]] = None
    affected_ips: Optional[List[str]] = None


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    actions_taken: Optional[List[str]] = None


class IncidentResponse(BaseModel):
    id: int
    incident_id: str
    title: str
    description: Optional[str]
    severity: str
    status: str
    category: Optional[str]
    threat_ids: Optional[List]
    affected_ips: Optional[List]
    assigned_to: Optional[str]
    created_by: Optional[str]
    detected_at: Optional[str]
    actions_taken: Optional[List]
    notes: Optional[str]
    created_at: Optional[str]

    class Config:
        from_attributes = True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PCAP Analysis
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class PcapAnalysisResponse(BaseModel):
    filename: str
    total_packets: int
    duration: float
    threats_detected: int
    protocols: Dict[str, int]
    top_sources: List[Dict[str, Any]]
    top_destinations: List[Dict[str, Any]]
    threats: List[ThreatResponse]
    summary: str


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AI Chat
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ChatMessage(BaseModel):
    message: str


class ChatResponse(BaseModel):
    response: str
    context: Optional[Dict] = None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Model Performance
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ModelPerformance(BaseModel):
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: float
    training_samples: int
    feature_count: int
    last_trained: Optional[str]
