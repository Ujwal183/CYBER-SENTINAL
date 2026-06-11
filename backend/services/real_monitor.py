"""
🛡️ Cyber Sentinel - Real System & Network Monitor
Captures REAL network connections, system metrics, and detects actual anomalies.
Uses psutil to monitor the host machine's live state.
"""
import psutil
import socket
import time
import math
import platform
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import threading

# ────────────────────────────────────────────────────
# Known suspicious / commonly-attacked ports
# ────────────────────────────────────────────────────
HIGH_RISK_PORTS = {
    20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1434: "MSSQL", 3306: "MySQL", 3389: "RDP", 4444: "Metasploit",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

MALICIOUS_PROCESS_NAMES = {
    "mimikatz", "meterpreter", "cobalt", "nmap", "netcat", "nc",
    "powershell_empire", "lazagne", "hydra", "hashcat", "john",
    "aircrack", "ettercap", "bettercap", "wireshark", "tcpdump",
    "sqlmap", "nikto", "dirb", "gobuster", "masscan", "zmap",
}


class ConnectionTracker:
    """Tracks connection patterns to detect anomalies over time."""

    def __init__(self, window_seconds: int = 60):
        self._lock = threading.Lock()
        self._window = window_seconds
        # ip -> list of (timestamp, dst_port)
        self._connections: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        # ip -> count of failed / rapidly-repeated connections
        self._rapid_connects: Dict[str, int] = defaultdict(int)

    def record(self, remote_ip: str, dst_port: int):
        now = time.time()
        with self._lock:
            self._connections[remote_ip].append((now, dst_port))
            # Prune old entries
            cutoff = now - self._window
            self._connections[remote_ip] = [
                (t, p) for t, p in self._connections[remote_ip] if t >= cutoff
            ]

    def get_unique_ports(self, remote_ip: str) -> int:
        with self._lock:
            ports = set(p for _, p in self._connections.get(remote_ip, []))
            return len(ports)

    def get_connection_rate(self, remote_ip: str) -> float:
        """Connections per second in the current window."""
        with self._lock:
            entries = self._connections.get(remote_ip, [])
            if len(entries) < 2:
                return 0.0
            span = entries[-1][0] - entries[0][0]
            if span <= 0:
                return float(len(entries))
            return len(entries) / span

    def get_all_tracked_ips(self) -> List[str]:
        with self._lock:
            return list(self._connections.keys())


# Singleton tracker
_tracker = ConnectionTracker(window_seconds=120)


def _resolve_hostname(ip: str) -> str:
    """Try reverse-DNS lookup (cached, best-effort)."""
    try:
        return socket.getfqdn(ip)
    except Exception:
        return ip


def get_real_system_metrics() -> Dict:
    """Gather real-time system health metrics."""
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net_io = psutil.net_io_counters()
    boot = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
    uptime = datetime.now(timezone.utc) - boot

    return {
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "cpu_percent": cpu,
        "cpu_count": psutil.cpu_count(),
        "memory_total_gb": round(mem.total / (1024**3), 2),
        "memory_used_gb": round(mem.used / (1024**3), 2),
        "memory_percent": mem.percent,
        "disk_total_gb": round(disk.total / (1024**3), 2),
        "disk_used_percent": disk.percent,
        "net_bytes_sent": net_io.bytes_sent,
        "net_bytes_recv": net_io.bytes_recv,
        "net_packets_sent": net_io.packets_sent,
        "net_packets_recv": net_io.packets_recv,
        "net_errors_in": net_io.errin,
        "net_errors_out": net_io.errout,
        "uptime_hours": round(uptime.total_seconds() / 3600, 1),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def get_real_connections() -> List[Dict]:
    """
    Snapshot every active TCP/UDP connection on the host.
    Returns a list of enriched connection dicts.
    """
    connections = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "NONE":
                continue

            local_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
            local_port = conn.laddr.port if conn.laddr else 0
            remote_ip = conn.raddr.ip if conn.raddr else "0.0.0.0"
            remote_port = conn.raddr.port if conn.raddr else 0

            # Determine protocol
            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"

            # Lookup process
            proc_name = ""
            proc_pid = conn.pid or 0
            if conn.pid:
                try:
                    p = psutil.Process(conn.pid)
                    proc_name = p.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "unknown"

            # Track connection
            if remote_ip and remote_ip not in ("0.0.0.0", "127.0.0.1", "::1", "::"):
                _tracker.record(remote_ip, remote_port)

            connections.append({
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "protocol": proto,
                "status": conn.status,
                "pid": proc_pid,
                "process": proc_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
    except (psutil.AccessDenied, PermissionError):
        pass  # Need elevated privileges on some OSes
    return connections


def get_listening_ports() -> List[Dict]:
    """List all ports currently listening on this host."""
    listening = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN":
                proc_name = ""
                if conn.pid:
                    try:
                        proc_name = psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "unknown"
                listening.append({
                    "port": conn.laddr.port,
                    "ip": conn.laddr.ip,
                    "protocol": "TCP",
                    "process": proc_name,
                    "pid": conn.pid or 0,
                    "risk": "high" if conn.laddr.port in HIGH_RISK_PORTS else "normal",
                    "service": HIGH_RISK_PORTS.get(conn.laddr.port, ""),
                })
    except (psutil.AccessDenied, PermissionError):
        pass
    return listening


def get_suspicious_processes() -> List[Dict]:
    """Identify potentially suspicious processes."""
    suspicious = []
    for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "create_time"]):
        try:
            info = proc.info
            name_lower = info["name"].lower() if info["name"] else ""

            is_suspicious = False
            reason = ""

            # Check against known malicious tools
            for mal in MALICIOUS_PROCESS_NAMES:
                if mal in name_lower:
                    is_suspicious = True
                    reason = f"Known offensive tool: {mal}"
                    break

            # Extremely high CPU (possible crypto miner or DoS)
            cpu = info.get("cpu_percent", 0) or 0
            if cpu > 90:
                is_suspicious = True
                reason = f"Extreme CPU usage: {cpu:.0f}%"

            # Process with many network connections
            try:
                conn_count = len(proc.connections(kind="inet"))
                if conn_count > 50:
                    is_suspicious = True
                    reason = f"High connection count: {conn_count}"
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                conn_count = 0

            if is_suspicious:
                suspicious.append({
                    "pid": info["pid"],
                    "name": info["name"],
                    "username": info.get("username", "N/A"),
                    "cpu_percent": cpu,
                    "memory_percent": round(info.get("memory_percent", 0) or 0, 2),
                    "connections": conn_count,
                    "reason": reason,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return suspicious


def analyze_real_connections() -> List[Dict]:
    """
    Analyze live connections and return a list of detected threats / anomalies.
    Each item mirrors the shape expected by the Threat model.
    """
    threats: List[Dict] = []
    connections = get_real_connections()
    system = get_real_system_metrics()
    now = datetime.now(timezone.utc)

    # Skip loopback / unconnected
    external = [
        c for c in connections
        if c["remote_ip"] not in ("0.0.0.0", "127.0.0.1", "::1", "::", "")
        and c["status"] not in ("NONE", "CLOSE_WAIT", "TIME_WAIT")
    ]

    # ──── Detect port-scan behaviour ────
    for ip in _tracker.get_all_tracked_ips():
        unique = _tracker.get_unique_ports(ip)
        rate = _tracker.get_connection_rate(ip)
        if unique >= 10:
            threats.append(_build_threat(
                src_ip=ip, dst_ip=system["hostname"],
                dst_port=0, protocol="TCP",
                attack_type="Port Scan",
                severity="high" if unique >= 20 else "medium",
                confidence=min(0.99, 0.5 + unique * 0.02),
                severity_score=min(95, 40 + unique * 2),
                explanation=f"IP {ip} contacted {unique} unique ports in 2 min window. Connection rate: {rate:.1f}/sec.",
                connection_rate=rate,
                unique_dst_ports=unique,
            ))

        # ──── High connection rate (potential DDoS / brute-force) ────
        if rate > 10:
            attack = "DDoS" if rate > 50 else "Brute Force"
            sev = "critical" if rate > 50 else "high"
            threats.append(_build_threat(
                src_ip=ip, dst_ip=system["hostname"],
                dst_port=0, protocol="TCP",
                attack_type=attack,
                severity=sev,
                confidence=min(0.99, 0.6 + rate * 0.005),
                severity_score=min(100, 50 + rate),
                explanation=f"High connection rate from {ip}: {rate:.1f} connections/sec.",
                connection_rate=rate,
            ))

    # ──── Connections to high-risk ports ────
    for c in external:
        rp = c["remote_port"]
        if rp in HIGH_RISK_PORTS and rp not in (80, 443, 53):
            service = HIGH_RISK_PORTS[rp]
            threats.append(_build_threat(
                src_ip=c["local_ip"], dst_ip=c["remote_ip"],
                src_port=c["local_port"], dst_port=rp,
                protocol=c["protocol"],
                attack_type="Suspicious Connection",
                severity="medium",
                confidence=0.65,
                severity_score=45,
                explanation=f"Outbound connection to {service} ({rp}) on {c['remote_ip']}. Process: {c['process']} (PID {c['pid']}).",
                process_name=c["process"],
            ))

    # ──── Suspicious processes ────
    for p in get_suspicious_processes():
        threats.append(_build_threat(
            src_ip="127.0.0.1", dst_ip=system["hostname"],
            dst_port=0, protocol="LOCAL",
            attack_type="Suspicious Process",
            severity="high",
            confidence=0.80,
            severity_score=70,
            explanation=f"Suspicious process '{p['name']}' (PID {p['pid']}): {p['reason']}. User: {p['username']}",
            process_name=p["name"],
        ))

    # ──── System resource anomalies ────
    if system["cpu_percent"] > 90:
        threats.append(_build_threat(
            src_ip="127.0.0.1", dst_ip=system["hostname"],
            dst_port=0, protocol="SYSTEM",
            attack_type="Resource Anomaly",
            severity="high" if system["cpu_percent"] > 95 else "medium",
            confidence=0.75,
            severity_score=min(85, system["cpu_percent"]),
            explanation=f"CPU usage critically high: {system['cpu_percent']}%. Possible crypto-miner or DoS.",
        ))

    if system["memory_percent"] > 95:
        threats.append(_build_threat(
            src_ip="127.0.0.1", dst_ip=system["hostname"],
            dst_port=0, protocol="SYSTEM",
            attack_type="Resource Anomaly",
            severity="high",
            confidence=0.70,
            severity_score=80,
            explanation=f"Memory usage critically high: {system['memory_percent']}%. Possible memory exhaustion attack.",
        ))

    return threats


def _build_threat(
    src_ip: str,
    dst_ip: str,
    dst_port: int = 0,
    src_port: int = 0,
    protocol: str = "TCP",
    attack_type: str = "Unknown",
    severity: str = "medium",
    confidence: float = 0.5,
    severity_score: float = 50,
    explanation: str = "",
    connection_rate: float = 0,
    unique_dst_ports: int = 1,
    process_name: str = "",
) -> Dict:
    """Build a threat dict matching the schema used by the rest of the system."""
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "attack_type": attack_type,
        "severity": severity,
        "confidence": round(confidence, 4),
        "severity_score": round(severity_score, 2),
        "explanation": explanation,
        "model_used": "Real-Time Monitor",
        "packet_size": 0,
        "flow_duration": 0,
        "flags": "",
        "connection_rate": connection_rate,
        "unique_dst_ports": unique_dst_ports,
        "process_name": process_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "is_real": True,
    }


def get_network_summary() -> Dict:
    """High-level summary of current network state."""
    connections = get_real_connections()
    external = [c for c in connections if c["remote_ip"] not in ("0.0.0.0", "127.0.0.1", "::1", "::", "")]
    listening = get_listening_ports()
    unique_remote = set(c["remote_ip"] for c in external)
    protocols = defaultdict(int)
    for c in connections:
        protocols[c["protocol"]] += 1

    return {
        "total_connections": len(connections),
        "external_connections": len(external),
        "unique_remote_ips": len(unique_remote),
        "listening_ports": len(listening),
        "high_risk_listening": sum(1 for p in listening if p["risk"] == "high"),
        "protocol_breakdown": dict(protocols),
        "top_remote_ips": list(unique_remote)[:20],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
