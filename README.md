# 🛡️ Cyber Sentinel

## AI-Based Network Intrusion Detection & Mitigation System

> An enterprise-grade, AI-powered cybersecurity platform that detects, classifies, and mitigates network threats in real-time using machine learning ensemble models.

---

## 🎯 Features

| Feature | Description |
|---------|-------------|
| **Real-Time Detection** | Live threat monitoring with WebSocket alerts |
| **ML Classification** | Ensemble model (RF + XGBoost + LightGBM) for attack detection |
| **Attack Types** | DDoS, Port Scan, Brute Force, Botnet, SQL Injection, Web Attack |
| **Severity Scoring** | 0-100 severity score with confidence levels |
| **Auto-Mitigation** | IP blocking, incident creation, with safe dry-run mode |
| **SOC Dashboard** | Charts, analytics, threat timeline, heatmaps |
| **AI Assistant** | Security chatbot for quick insights |
| **RBAC** | Admin, Analyst, Viewer roles with JWT auth |
| **Incident Response** | Create, track, and resolve security incidents |
| **Audit Logging** | Complete action audit trail |
| **CSV Export** | Export threat data for reporting |
| **Docker Ready** | One-command deployment with Docker Compose |

## 🏗️ Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│   Frontend   │────▶│   FastAPI     │────▶│   ML Engine   │
│  HTML/JS/CSS │◀────│   Backend     │◀────│  Ensemble     │
│  Chart.js    │     │  WebSocket    │     │  RF+XGB+LGBM  │
└─────────────┘     └──────┬───────┘     └──────────────┘
                           │
                    ┌──────┴───────┐
                    │   SQLite/    │
                    │  PostgreSQL  │
                    └──────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- pip

### 1. Install Dependencies
```bash
cd "Cyber Sentinel project"
pip install -r requirements.txt
```

### 2. Train ML Model
```bash
python -m ml.train_model
```

### 3. Start Server
```bash
python -m backend.app
```

### 4. Open Dashboard
Navigate to **http://localhost:8000** in your browser.

**Default Credentials:**
| Role | Username | Password |
|------|----------|----------|
| Admin | admin | admin123 |
| Analyst | analyst | analyst123 |
| Viewer | viewer | viewer123 |

## 📁 Project Structure

```
Cyber Sentinel project/
├── backend/
│   ├── api/           # REST API routes
│   ├── core/          # Config, database, security
│   ├── models/        # SQLAlchemy ORM models
│   ├── schemas/       # Pydantic validation schemas
│   ├── services/      # Business logic & threat engine
│   └── app.py         # FastAPI entry point
├── frontend/
│   ├── index.html     # SPA dashboard
│   └── static/
│       ├── css/       # Dark cybersecurity theme
│       └── js/        # Frontend application logic
├── ml/
│   ├── train_model.py # Training pipeline
│   ├── predictor.py   # Prediction engine
│   ├── models/        # Saved model artifacts
│   └── data/          # Training datasets
├── tests/             # Test suite
├── docker/            # Nginx config
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env
```

## 📌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/login` | User login |
| POST | `/api/v1/auth/register` | User registration |
| GET | `/api/v1/auth/me` | Current user info |
| GET | `/api/v1/dashboard/stats` | Dashboard analytics |
| GET | `/api/v1/threats` | List threats (paginated) |
| GET | `/api/v1/threats/live` | Recent live threats |
| POST | `/api/v1/block/ip` | Block an IP address |
| GET | `/api/v1/blocked-ips` | List blocked IPs |
| POST | `/api/v1/incidents` | Create incident |
| GET | `/api/v1/incidents` | List incidents |
| GET | `/api/v1/models/performance` | ML model metrics |
| POST | `/api/v1/simulate/threat` | Simulate a threat |
| GET | `/api/v1/chat` | AI security assistant |
| GET | `/api/v1/audit-logs` | Audit log history |
| WS | `/ws/alerts` | Real-time WebSocket alerts |

## 🧠 ML Models

| Model | Role |
|-------|------|
| Random Forest | Primary classifier |
| XGBoost | Gradient boosting classifier |
| LightGBM | Fast gradient boosting |
| Isolation Forest | Anomaly detection |
| **Ensemble Hybrid** | Soft-voting combination of all |

**Metrics tracked:** Accuracy, Precision, Recall, F1-Score, ROC AUC, Confusion Matrix

## 🐳 Docker Deployment

```bash
docker-compose up --build -d
```

Access at http://localhost (nginx) or http://localhost:8000 (direct).

## 🧪 Testing

```bash
pytest tests/ -v
```

## 📄 License

MIT License - Built for academic and research purposes.

## 👤 Author

Cyber Sentinel Project Team
