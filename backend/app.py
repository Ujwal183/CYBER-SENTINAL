"""
🛡️ Cyber Sentinel - FastAPI Application Entry Point
AI-Based Network Intrusion Detection & Mitigation System
Now with REAL system & network monitoring.
"""
import asyncio, json
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from backend.core.config import get_settings
from backend.core.database import init_db, SessionLocal
from backend.core.security import hash_password
from backend.api.auth import router as auth_router
from backend.api.routes import router as main_router
from backend.models.user import User

settings = get_settings()

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []
    async def connect(self, ws: WebSocket):
        await ws.accept(); self.active.append(ws)
    def disconnect(self, ws: WebSocket):
        if ws in self.active: self.active.remove(ws)
    async def broadcast(self, data: dict):
        for ws in self.active[:]:
            try: await ws.send_json(data)
            except: self.disconnect(ws)

manager = ConnectionManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("[*] Cyber Sentinel starting...")
    print("[*] Mode: REAL SYSTEM MONITORING (live data)")
    init_db()
    _seed_admin()
    # Start REAL background monitor (replaces fake simulator)
    task = asyncio.create_task(_real_monitor_loop())
    yield
    # Shutdown
    task.cancel()
    print("[*] Cyber Sentinel stopped.")

def _seed_admin():
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.username == "admin").first():
            admin = User(username="admin", email="admin@cybersentinel.io", hashed_password=hash_password("admin123"), full_name="System Administrator", role="admin")
            db.add(admin)
            analyst = User(username="analyst", email="analyst@cybersentinel.io", hashed_password=hash_password("analyst123"), full_name="Security Analyst", role="analyst")
            db.add(analyst)
            viewer = User(username="viewer", email="viewer@cybersentinel.io", hashed_password=hash_password("viewer123"), full_name="SOC Viewer", role="viewer")
            db.add(viewer)
            db.commit()
            print("[+] Default users created (admin/admin123, analyst/analyst123, viewer/viewer123)")
    finally:
        db.close()


async def _real_monitor_loop():
    """
    Periodically scan REAL network connections & system metrics,
    detect anomalies, save threats to DB, and broadcast via WebSocket.
    """
    from backend.services.real_monitor import (
        analyze_real_connections,
        get_real_system_metrics,
        get_network_summary,
    )
    from backend.models.threat import Threat

    await asyncio.sleep(3)  # Let the server finish starting
    print("[*] Real-time system monitor started (scanning every 10s)")

    scan_count = 0
    while True:
        try:
            scan_count += 1

            # Run blocking I/O in a thread so we don't block the event loop
            loop = asyncio.get_event_loop()
            threats = await loop.run_in_executor(None, analyze_real_connections)
            system = await loop.run_in_executor(None, get_real_system_metrics)
            network = await loop.run_in_executor(None, get_network_summary)

            # Persist real threats to database
            if threats:
                db = SessionLocal()
                try:
                    for t_data in threats:
                        t = Threat(
                            src_ip=t_data["src_ip"],
                            dst_ip=t_data["dst_ip"],
                            src_port=t_data.get("src_port"),
                            dst_port=t_data.get("dst_port"),
                            protocol=t_data.get("protocol", "TCP"),
                            attack_type=t_data["attack_type"],
                            severity=t_data["severity"],
                            confidence=t_data["confidence"],
                            severity_score=t_data["severity_score"],
                            model_used="Real-Time Monitor",
                            explanation=t_data.get("explanation"),
                            packet_size=t_data.get("packet_size"),
                            flow_duration=t_data.get("flow_duration"),
                            flags=t_data.get("flags"),
                        )
                        db.add(t)
                    db.commit()
                finally:
                    db.close()

            # Broadcast via WebSocket
            if manager.active:
                # Always send system health update
                await manager.broadcast({
                    "type": "system_health",
                    "data": system,
                    "network": network,
                    "scan_number": scan_count,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

                # Send each detected threat as a live alert
                for t_data in threats:
                    await manager.broadcast({
                        "type": "threat_alert",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "src_ip": t_data["src_ip"],
                        "dst_ip": t_data["dst_ip"],
                        "attack_type": t_data["attack_type"],
                        "severity": t_data["severity"],
                        "confidence": t_data["confidence"],
                        "severity_score": t_data["severity_score"],
                        "dst_port": t_data.get("dst_port", 0),
                        "protocol": t_data.get("protocol", "TCP"),
                        "explanation": t_data.get("explanation", ""),
                        "is_real": True,
                    })

                # If no threats, send a status heartbeat
                if not threats:
                    await manager.broadcast({
                        "type": "status",
                        "message": "System clean — no anomalies detected",
                        "connections": network["total_connections"],
                        "external": network["external_connections"],
                        "scan_number": scan_count,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })

            await asyncio.sleep(10)  # Scan every 10 seconds

        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[!] Monitor error: {e}")
            await asyncio.sleep(10)


# Create app
app = FastAPI(
    title="🛡️ Cyber Sentinel API",
    description="AI-Based Network Intrusion Detection & Mitigation System — REAL Monitoring",
    version="3.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list + ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(auth_router, prefix="/api/v1")
app.include_router(main_router, prefix="/api/v1")

# Serve frontend
from pathlib import Path
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR / "static")), name="static")

from fastapi.responses import FileResponse

@app.get("/")
def root():
    index = FRONTEND_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    return {"name": "Cyber Sentinel", "version": "3.0.0", "status": "operational", "docs": "/docs"}

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo or handle client messages
            await websocket.send_json({"type": "ack", "message": "received"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app:app", host=settings.APP_HOST, port=settings.APP_PORT, reload=settings.APP_DEBUG)
