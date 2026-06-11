"""
🛡️ Cyber Sentinel - Dashboard & Threats API Routes
Includes REAL system monitoring endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from backend.core.database import get_db
from backend.core.security import get_current_user
from backend.services.threat_service import get_dashboard_stats, get_threats, block_ip, unblock_ip, get_blocked_ips, create_incident
from backend.services.mitigation_engine import get_mitigation_engine
from backend.schemas.schemas import BlockIPRequest, IncidentCreate, IncidentUpdate
from backend.models.threat import Threat
from backend.models.incident import Incident, AuditLog
from ml.predictor import get_predictor
from sqlalchemy import desc
from typing import Optional

router = APIRouter(tags=["Dashboard & Threats"])

@router.get("/dashboard/stats")
def dashboard_stats(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    return get_dashboard_stats(db)

@router.get("/threats")
def list_threats(page: int = 1, per_page: int = 50, severity: Optional[str] = None, attack_type: Optional[str] = None, src_ip: Optional[str] = None, current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    return get_threats(db, page, per_page, severity, attack_type, src_ip)

@router.get("/threats/live")
def live_threats(limit: int = 20, current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    threats = db.query(Threat).order_by(desc(Threat.timestamp)).limit(limit).all()
    return [t.to_dict() for t in threats]

@router.get("/threats/{threat_id}")
def get_threat(threat_id: int, current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    t = db.query(Threat).filter(Threat.id == threat_id).first()
    if not t: raise HTTPException(404, "Threat not found")
    return t.to_dict()

@router.post("/threats/{threat_id}/false-positive")
def mark_false_positive(threat_id: int, current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    t = db.query(Threat).filter(Threat.id == threat_id).first()
    if not t: raise HTTPException(404)
    t.is_false_positive = True; db.commit()
    return {"status": "marked as false positive"}

@router.post("/block/ip")
def block_ip_route(data: BlockIPRequest, current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    result = block_ip(db, data.ip_address, data.reason, current_user.username, data.duration_hours, data.is_permanent)
    return result

@router.delete("/block/ip/{ip_address}")
def unblock_ip_route(ip_address: str, current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    result = unblock_ip(db, ip_address, current_user.username)
    if not result: raise HTTPException(404, "IP not found")
    return result

@router.get("/blocked-ips")
def list_blocked_ips(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    return get_blocked_ips(db)

@router.post("/incidents")
def create_incident_route(data: IncidentCreate, current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    return create_incident(db, data.model_dump(), current_user.username)

@router.get("/incidents")
def list_incidents(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    incs = db.query(Incident).order_by(desc(Incident.detected_at)).all()
    return [i.to_dict() for i in incs]

@router.put("/incidents/{incident_id}")
def update_incident(incident_id: str, data: IncidentUpdate, current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc: raise HTTPException(404)
    if data.status: inc.status = data.status
    if data.assigned_to: inc.assigned_to = data.assigned_to
    if data.notes: inc.notes = data.notes
    db.commit(); db.refresh(inc)
    return inc.to_dict()

@router.get("/models/performance")
def model_performance(current_user=Depends(get_current_user)):
    pred = get_predictor()
    if not pred.is_loaded:
        return {"models": [], "message": "Model not trained yet"}
    results = []
    for name, metrics in pred.results.items():
        results.append({"model_name": name, "accuracy": metrics["accuracy"], "precision": metrics["precision"], "recall": metrics["recall"], "f1_score": metrics["f1_score"], "roc_auc": metrics.get("roc_auc", 0)})
    return {"models": results, "feature_importance": pred.feature_importance}

@router.get("/audit-logs")
def get_audit_logs(limit: int = 100, current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit).all()
    return [l.to_dict() for l in logs]

@router.post("/analyze/packet")
def analyze_single_packet(packet: dict, current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    from backend.services.threat_service import analyze_packet
    result = analyze_packet(packet, db)
    return result or {"message": "Normal traffic, no threat detected"}

@router.post("/simulate/threat")
def simulate_threat(attack_type: Optional[str] = None, current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    from backend.services.simulator import generate_threat
    from backend.services.threat_service import analyze_packet
    pkt = generate_threat(attack_type)
    result = analyze_packet(pkt, db)
    return {"packet": pkt, "analysis": result or {"message": "Classified as normal"}}

# ═══════════════════════════════════════════════════════
# 🆕 REAL SYSTEM MONITORING ENDPOINTS
# ═══════════════════════════════════════════════════════

@router.get("/system/metrics")
def system_metrics(current_user=Depends(get_current_user)):
    """Get real-time CPU, memory, disk, and network stats from this machine."""
    from backend.services.real_monitor import get_real_system_metrics
    return get_real_system_metrics()

@router.get("/system/connections")
def system_connections(current_user=Depends(get_current_user)):
    """List all active network connections on this host."""
    from backend.services.real_monitor import get_real_connections
    conns = get_real_connections()
    return {"connections": conns, "total": len(conns)}

@router.get("/system/listening")
def system_listening(current_user=Depends(get_current_user)):
    """List all listening ports on this host."""
    from backend.services.real_monitor import get_listening_ports
    ports = get_listening_ports()
    return {"listening_ports": ports, "total": len(ports)}

@router.get("/system/suspicious")
def system_suspicious(current_user=Depends(get_current_user)):
    """List processes flagged as suspicious."""
    from backend.services.real_monitor import get_suspicious_processes
    procs = get_suspicious_processes()
    return {"suspicious_processes": procs, "total": len(procs)}

@router.get("/system/network-summary")
def network_summary(current_user=Depends(get_current_user)):
    """High-level network overview."""
    from backend.services.real_monitor import get_network_summary
    return get_network_summary()

@router.get("/system/scan")
def run_scan(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    """Run an on-demand security scan and return findings."""
    from backend.services.real_monitor import analyze_real_connections, get_real_system_metrics, get_network_summary
    threats = analyze_real_connections()
    system = get_real_system_metrics()
    network = get_network_summary()

    # Persist any threats found
    if threats:
        for t_data in threats:
            t = Threat(
                src_ip=t_data["src_ip"], dst_ip=t_data["dst_ip"],
                src_port=t_data.get("src_port"), dst_port=t_data.get("dst_port"),
                protocol=t_data.get("protocol", "TCP"),
                attack_type=t_data["attack_type"], severity=t_data["severity"],
                confidence=t_data["confidence"], severity_score=t_data["severity_score"],
                model_used="Real-Time Monitor", explanation=t_data.get("explanation"),
            )
            db.add(t)
        db.commit()

    return {
        "threats_found": len(threats),
        "threats": threats,
        "system": system,
        "network": network,
        "message": f"Scan complete: {len(threats)} anomalies detected" if threats else "Scan complete: System is clean",
    }

@router.get("/chat")
def ai_chat(message: str = Query(...), current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    """AI security assistant — now with real system awareness."""
    msg = message.lower()
    stats = get_dashboard_stats(db)

    # Get real-time system info for context
    try:
        from backend.services.real_monitor import get_real_system_metrics, get_network_summary
        system = get_real_system_metrics()
        network = get_network_summary()
    except Exception:
        system = {}
        network = {}

    if any(w in msg for w in ["status", "overview", "summary", "dashboard"]):
        cpu = system.get("cpu_percent", "N/A")
        mem = system.get("memory_percent", "N/A")
        resp = (
            f"📊 Live System Status:\n"
            f"• CPU: {cpu}% | Memory: {mem}%\n"
            f"• Active connections: {network.get('total_connections', 'N/A')} ({network.get('external_connections', 0)} external)\n"
            f"• Threats detected today: {stats['threats_today']} | Blocked IPs: {stats['blocked_ips']}\n"
            f"• Critical alerts: {stats['critical_threats']} | Model accuracy: {stats['model_accuracy']}%"
        )
    elif any(w in msg for w in ["connection", "network", "traffic"]):
        resp = (
            f"🌐 Network Summary:\n"
            f"• Total connections: {network.get('total_connections', 0)}\n"
            f"• External connections: {network.get('external_connections', 0)}\n"
            f"• Unique remote IPs: {network.get('unique_remote_ips', 0)}\n"
            f"• Listening ports: {network.get('listening_ports', 0)} ({network.get('high_risk_listening', 0)} high-risk)\n"
            f"• Protocol breakdown: {network.get('protocol_breakdown', {})}"
        )
    elif any(w in msg for w in ["cpu", "memory", "ram", "disk", "system", "health"]):
        resp = (
            f"💻 System Health:\n"
            f"• Host: {system.get('hostname', 'N/A')} ({system.get('os', 'N/A')})\n"
            f"• CPU: {system.get('cpu_percent', 'N/A')}% ({system.get('cpu_count', 'N/A')} cores)\n"
            f"• RAM: {system.get('memory_used_gb', 'N/A')}GB / {system.get('memory_total_gb', 'N/A')}GB ({system.get('memory_percent', 'N/A')}%)\n"
            f"• Disk: {system.get('disk_used_percent', 'N/A')}% used\n"
            f"• Uptime: {system.get('uptime_hours', 'N/A')} hours\n"
            f"• Network I/O: ↑ {_fmt_bytes(system.get('net_bytes_sent', 0))} | ↓ {_fmt_bytes(system.get('net_bytes_recv', 0))}"
        )
    elif any(w in msg for w in ["threat", "attack", "danger"]):
        resp = f"Top attack categories: {', '.join(f'{k}: {v}' for k,v in list(stats['attack_categories'].items())[:5])}. Most targeted port: {stats['most_targeted_port']}."
    elif any(w in msg for w in ["block", "ip", "ban"]):
        resp = f"Currently {stats['blocked_ips']} IPs are blocked. Top attacker: {stats['top_attacker_ip']}."
    elif any(w in msg for w in ["model", "accuracy", "ai", "ml"]):
        resp = f"Model accuracy: {stats['model_accuracy']}%. False positive rate: {stats['false_positive_rate']}%."
    elif any(w in msg for w in ["scan", "check", "audit"]):
        resp = (
            f"🔍 To run an on-demand scan, click the ⚡ button in the top bar.\n"
            f"Current state: {network.get('total_connections', 0)} connections, "
            f"{stats['threats_today']} threats today."
        )
    else:
        resp = (
            f"I'm your AI security assistant with REAL system access. Try asking about:\n"
            f"• 'system health' — CPU, memory, disk status\n"
            f"• 'network connections' — live connection info\n"
            f"• 'threat status' — detected attacks\n"
            f"• 'scan' — run a security check\n"
            f"Current: {stats['threats_today']} threats today, CPU at {system.get('cpu_percent', 'N/A')}%"
        )
    return {"response": resp, "context": {"threats_today": stats["threats_today"], "blocked_ips": stats["blocked_ips"]}}


def _fmt_bytes(b: int) -> str:
    """Format bytes to human readable."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f}{unit}"
        b /= 1024
    return f"{b:.1f}PB"
