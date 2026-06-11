"""
🛡️ Cyber Sentinel - Test Suite
"""
import pytest, json
from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)

# ── Auth Tests ──
def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"

def test_register():
    r = client.post("/api/v1/auth/register", json={"username":"testuser","email":"test@test.com","password":"test123"})
    assert r.status_code == 200
    assert "access_token" in r.json()

def test_login():
    r = client.post("/api/v1/auth/login", json={"username":"admin","password":"admin123"})
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert data["user"]["role"] == "admin"

def test_login_invalid():
    r = client.post("/api/v1/auth/login", json={"username":"admin","password":"wrong"})
    assert r.status_code == 401

def _get_token():
    r = client.post("/api/v1/auth/login", json={"username":"admin","password":"admin123"})
    return r.json()["access_token"]

# ── Dashboard Tests ──
def test_dashboard_stats():
    token = _get_token()
    r = client.get("/api/v1/dashboard/stats", headers={"Authorization":f"Bearer {token}"})
    assert r.status_code == 200
    data = r.json()
    assert "threats_today" in data
    assert "severity_distribution" in data

def test_dashboard_unauthorized():
    r = client.get("/api/v1/dashboard/stats")
    assert r.status_code == 401

# ── Threats Tests ──
def test_list_threats():
    token = _get_token()
    r = client.get("/api/v1/threats", headers={"Authorization":f"Bearer {token}"})
    assert r.status_code == 200
    assert "items" in r.json()

def test_live_threats():
    token = _get_token()
    r = client.get("/api/v1/threats/live", headers={"Authorization":f"Bearer {token}"})
    assert r.status_code == 200

# ── Block IP Tests ──
def test_block_ip():
    token = _get_token()
    r = client.post("/api/v1/block/ip", json={"ip_address":"10.0.0.99","reason":"Test block"}, headers={"Authorization":f"Bearer {token}"})
    assert r.status_code == 200

def test_list_blocked():
    token = _get_token()
    r = client.get("/api/v1/blocked-ips", headers={"Authorization":f"Bearer {token}"})
    assert r.status_code == 200

# ── Incidents Tests ──
def test_create_incident():
    token = _get_token()
    r = client.post("/api/v1/incidents", json={"title":"Test Incident","severity":"high"}, headers={"Authorization":f"Bearer {token}"})
    assert r.status_code == 200
    assert "incident_id" in r.json()

# ── Model Tests ──
def test_model_performance():
    token = _get_token()
    r = client.get("/api/v1/models/performance", headers={"Authorization":f"Bearer {token}"})
    assert r.status_code == 200

# ── Simulate Tests ──
def test_simulate_threat():
    token = _get_token()
    r = client.post("/api/v1/simulate/threat", headers={"Authorization":f"Bearer {token}"})
    assert r.status_code == 200

# ── Chat Tests ──
def test_ai_chat():
    token = _get_token()
    r = client.get("/api/v1/chat?message=status", headers={"Authorization":f"Bearer {token}"})
    assert r.status_code == 200
    assert "response" in r.json()

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
