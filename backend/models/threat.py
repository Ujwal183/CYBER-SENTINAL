"""
🛡️ Cyber Sentinel - Threat Model
Stores detected threats with severity scores, attack classifications, and AI explanations.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, JSON
from backend.core.database import Base


class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    # ── Source / Destination ──
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=False)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)

    # ── Classification ──
    attack_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, default="medium")  # critical, high, medium, low, info
    confidence = Column(Float, nullable=False, default=0.0)
    severity_score = Column(Float, nullable=False, default=0.0)  # 0-100

    # ── AI Details ──
    model_used = Column(String(50), nullable=True)
    feature_importance = Column(JSON, nullable=True)
    explanation = Column(Text, nullable=True)

    # ── Network Details ──
    packet_size = Column(Integer, nullable=True)
    flow_duration = Column(Float, nullable=True)
    flags = Column(String(20), nullable=True)
    payload_preview = Column(Text, nullable=True)

    # ── Status ──
    is_mitigated = Column(Boolean, default=False)
    is_false_positive = Column(Boolean, default=False)
    mitigated_at = Column(DateTime, nullable=True)
    mitigated_by = Column(String(50), nullable=True)
    mitigation_action = Column(String(100), nullable=True)

    # ── Metadata ──
    raw_features = Column(JSON, nullable=True)
    geo_location = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "confidence": round(self.confidence, 4),
            "severity_score": round(self.severity_score, 2),
            "model_used": self.model_used,
            "feature_importance": self.feature_importance,
            "explanation": self.explanation,
            "packet_size": self.packet_size,
            "flow_duration": self.flow_duration,
            "flags": self.flags,
            "is_mitigated": self.is_mitigated,
            "is_false_positive": self.is_false_positive,
            "mitigated_at": self.mitigated_at.isoformat() if self.mitigated_at else None,
            "mitigation_action": self.mitigation_action,
            "geo_location": self.geo_location,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ip_address = Column(String(45), nullable=False, unique=True, index=True)
    reason = Column(Text, nullable=True)
    blocked_by = Column(String(50), nullable=True)
    threat_count = Column(Integer, default=1)
    is_permanent = Column(Boolean, default=False)
    expires_at = Column(DateTime, nullable=True)
    blocked_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    unblocked_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "reason": self.reason,
            "blocked_by": self.blocked_by,
            "threat_count": self.threat_count,
            "is_permanent": self.is_permanent,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "blocked_at": self.blocked_at.isoformat() if self.blocked_at else None,
            "is_active": self.is_active,
        }
