"""
🛡️ Cyber Sentinel - Mitigation Engine
Auto-mitigates threats based on severity and confidence thresholds.
Supports DRY RUN mode for safe testing.
"""
from datetime import datetime, timezone
from typing import Dict, List
from sqlalchemy.orm import Session
from backend.models.threat import Threat, BlockedIP
from backend.models.incident import Incident
from backend.services.threat_service import block_ip, create_incident, log_audit

# Thresholds
CRITICAL_THRESHOLD = 0.85
HIGH_THRESHOLD = 0.70
AUTO_BLOCK_THRESHOLD = 0.90

class MitigationEngine:
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.actions_log = []

    def evaluate_threat(self, threat_data: Dict, db: Session, username: str = "system") -> Dict:
        """Evaluate a threat and determine mitigation actions."""
        actions = []
        confidence = threat_data.get("confidence", 0)
        severity = threat_data.get("severity", "low")
        attack_type = threat_data.get("attack_type", "Unknown")
        src_ip = threat_data.get("src_ip", "0.0.0.0")
        severity_score = threat_data.get("severity_score", 0)

        # Alert for any non-normal traffic above threshold
        if confidence >= HIGH_THRESHOLD and attack_type != "Normal":
            actions.append({"action": "alert", "message": f"High confidence {attack_type} detected from {src_ip}", "priority": "high"})

        # Auto-block for critical threats
        if confidence >= AUTO_BLOCK_THRESHOLD and severity in ("critical", "high"):
            action = {"action": "block_ip", "ip": src_ip, "reason": f"Auto-blocked: {attack_type} (confidence: {confidence:.2f})", "duration_hours": 24}
            actions.append(action)
            if not self.dry_run:
                block_ip(db, src_ip, action["reason"], username, 24)

        # Create incident for critical
        if severity_score >= 80:
            inc_action = {"action": "create_incident", "title": f"Critical: {attack_type} from {src_ip}", "severity": "critical"}
            actions.append(inc_action)
            if not self.dry_run:
                create_incident(db, {"title": inc_action["title"], "severity": "critical", "category": attack_type, "affected_ips": [src_ip]}, username)

        # Mark as mitigated
        if actions and not self.dry_run:
            threat_id = threat_data.get("id")
            if threat_id:
                t = db.query(Threat).filter(Threat.id == threat_id).first()
                if t:
                    t.is_mitigated = True
                    t.mitigated_at = datetime.now(timezone.utc)
                    t.mitigated_by = username
                    t.mitigation_action = ", ".join([a["action"] for a in actions])
                    db.commit()

        result = {"threat_id": threat_data.get("id"), "actions": actions, "dry_run": self.dry_run, "total_actions": len(actions)}
        self.actions_log.append(result)
        return result

    def get_actions_log(self) -> List[Dict]:
        return self.actions_log

# Singleton
_engine = None
def get_mitigation_engine(dry_run: bool = True) -> MitigationEngine:
    global _engine
    if _engine is None or _engine.dry_run != dry_run:
        _engine = MitigationEngine(dry_run=dry_run)
    return _engine
