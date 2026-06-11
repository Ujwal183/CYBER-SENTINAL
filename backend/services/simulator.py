"""
🛡️ Cyber Sentinel - Threat Simulator
Generates realistic simulated threats for demo/testing.
"""
import random, time, math
from datetime import datetime, timezone, timedelta
from typing import Dict, List
from sqlalchemy.orm import Session
from backend.models.threat import Threat

ATTACK_PROFILES = {
    "DDoS": {"dst_ports":[80,443,8080],"packet_size":(60,150),"conn_rate":(200,1000),"entropy":(0.5,2.0),"rep":(0.6,1.0),"severity":"critical","flags":"S"},
    "Port Scan": {"dst_ports":list(range(1,1024)),"packet_size":(40,80),"conn_rate":(100,500),"entropy":(6.0,8.0),"rep":(0.3,0.7),"severity":"medium","flags":"S"},
    "Brute Force": {"dst_ports":[22,3389,21],"packet_size":(150,300),"conn_rate":(30,100),"entropy":(2.0,4.0),"rep":(0.4,0.8),"severity":"high","flags":"SA"},
    "Botnet": {"dst_ports":[6667,8080,4444],"packet_size":(100,250),"conn_rate":(5,30),"entropy":(4.0,7.0),"rep":(0.5,0.9),"severity":"critical","flags":"SAP"},
    "SQL Injection": {"dst_ports":[80,443,3306],"packet_size":(500,1200),"conn_rate":(3,15),"entropy":(5.0,7.5),"rep":(0.3,0.6),"severity":"high","flags":"SAF"},
    "Web Attack": {"dst_ports":[80,443,8080],"packet_size":(400,900),"conn_rate":(5,25),"entropy":(5.5,7.5),"rep":(0.2,0.5),"severity":"medium","flags":"SAP"},
    "DoS Slowloris": {"dst_ports":[80],"packet_size":(20,60),"conn_rate":(100,400),"entropy":(0.5,2.0),"rep":(0.5,0.9),"severity":"high","flags":"S"},
}

def _rand_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def generate_threat(attack_type: str = None) -> Dict:
    if not attack_type:
        attack_type = random.choice(list(ATTACK_PROFILES.keys()))
    p = ATTACK_PROFILES[attack_type]
    return {
        "src_ip": _rand_ip(), "dst_ip": "192.168.1." + str(random.randint(1,50)),
        "src_port": random.randint(1024, 65535), "dst_port": random.choice(p["dst_ports"]),
        "protocol": random.choice(["TCP","UDP"]) if attack_type != "Port Scan" else "TCP",
        "packet_size": random.randint(*p["packet_size"]),
        "flow_duration": round(random.uniform(0.1, 30), 2),
        "fwd_packets": random.randint(1, 500), "bwd_packets": random.randint(0, 50),
        "flow_bytes_per_sec": round(random.uniform(100, 150000), 2),
        "flow_packets_per_sec": round(random.uniform(1, 5000), 2),
        "flags": p["flags"],
        "connection_rate": round(random.uniform(*p["conn_rate"]), 2),
        "entropy_score": round(random.uniform(*p["entropy"]), 2),
        "payload_length": random.randint(0, 1500),
        "header_length": random.choice([20, 40, 60]),
        "ttl": random.randint(30, 128),
        "window_size": random.randint(100, 65535),
        "ip_reputation_score": round(random.uniform(*p["rep"]), 2),
        "port_frequency": random.randint(1, 200),
        "unique_dst_ports": random.randint(1, 100) if attack_type == "Port Scan" else random.randint(1, 5),
        "bytes_ratio": round(random.uniform(0.1, 1.0), 2),
        "attack_type_hint": attack_type,
    }

def seed_threats(db: Session, count: int = 200):
    """Seed database with simulated threats for demo.
    Distribution: 40% in last 6 hours (today), 30% in last 24h, 30% over last 7 days.
    Ensures the dashboard always shows populated 'today' stats.
    """
    print(f"🌱 Seeding {count} simulated threats...")
    types = list(ATTACK_PROFILES.keys()) + ["Normal"] * 3
    now = datetime.now(timezone.utc)
    for i in range(count):
        at = random.choice(types)
        if at == "Normal":
            pkt = {"src_ip": _rand_ip(), "dst_ip": "192.168.1.1", "src_port": random.randint(1024,65535),
                   "dst_port": random.choice([80,443,22]), "protocol": "TCP", "packet_size": random.randint(200,800),
                   "flow_duration": round(random.uniform(1,10),2), "fwd_packets": random.randint(1,30),
                   "bwd_packets": random.randint(1,30), "flags": "SA", "connection_rate": round(random.uniform(1,10),2),
                   "entropy_score": round(random.uniform(3,5),2), "payload_length": random.randint(100,500),
                   "header_length": 20, "ttl": 64, "window_size": 30000, "ip_reputation_score": round(random.uniform(0,0.2),2),
                   "port_frequency": random.randint(1,5), "unique_dst_ports": random.randint(1,3), "bytes_ratio": 0.5}
        else:
            pkt = generate_threat(at)
        # Distribute timestamps: 40% recent (0-6h), 30% today (6-24h), 30% older (1-7d)
        bucket = random.random()
        if bucket < 0.40:
            hours_ago = random.uniform(0, 6)
        elif bucket < 0.70:
            hours_ago = random.uniform(6, 24)
        else:
            hours_ago = random.uniform(24, 168)
        ts = now - timedelta(hours=hours_ago)
        sev = ATTACK_PROFILES.get(at, {}).get("severity", "info")
        score = round(random.uniform(10, 95), 2)
        if at == "Normal":
            sev = "info"
            score = round(random.uniform(0, 15), 2)
        # Randomly mitigate some threats for realistic dashboard
        is_mitigated = random.random() < 0.3 and at != "Normal"
        t = Threat(
            src_ip=pkt["src_ip"], dst_ip=pkt["dst_ip"], src_port=pkt.get("src_port"),
            dst_port=pkt.get("dst_port"), protocol=pkt.get("protocol", "TCP"),
            attack_type=at if at != "Normal" else "Normal", severity=sev,
            confidence=round(random.uniform(0.6, 0.99), 4), severity_score=score,
            model_used="Ensemble Hybrid", packet_size=pkt.get("packet_size"),
            flow_duration=pkt.get("flow_duration"), flags=pkt.get("flags"),
            timestamp=ts,
            is_mitigated=is_mitigated,
            mitigated_at=ts + timedelta(minutes=random.randint(1, 30)) if is_mitigated else None,
            mitigated_by="system" if is_mitigated else None,
            mitigation_action="auto_block" if is_mitigated else None,
        )
        db.add(t)
    db.commit()
    print(f"✅ Seeded {count} threats (40% recent, 30% today, 30% historical)")
