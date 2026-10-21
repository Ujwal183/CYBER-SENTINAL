# Cyber Sentinel

A cybersecurity project that brings together a Python API, a browser dashboard, and machine-learning components to explore network-threat detection and incident workflows.

## Project overview

The application is organized into three main areas:

- **Backend:** FastAPI endpoints, authentication, incident management, and threat operations
- **ML:** Model training and prediction code for classifying network events
- **Frontend:** A browser-based dashboard for reviewing alerts and security activity

The repository also includes Docker Compose files, environment examples, and a test suite.

## Features

- Threat event classification and severity scoring
- Dashboard views for alerts, incidents, and activity
- WebSocket alert updates
- Incident tracking and CSV export
- Role-based application access
- Configurable IP-blocking workflow with a dry-run option
- Docker Compose setup

## Technology

- Python and FastAPI
- scikit-learn, XGBoost, and LightGBM
- HTML, CSS, and JavaScript
- SQLite by default, with database configuration support
- Docker and Docker Compose

## Run locally on Windows

**Requirements:** Python 3.10+ and pip

From the repository directory, run the included PowerShell launcher:

```powershell
.\run.ps1
```

The launcher creates a virtual environment, installs dependencies when needed, and starts the application. Then open [http://localhost:8000](http://localhost:8000). The API documentation is available at [http://localhost:8000/docs](http://localhost:8000/docs).

For a manual setup:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m backend.app
```

## Run with Docker

```bash
docker compose up --build
```

The Compose configuration exposes the application on port 8000 and the Nginx service on port 80.

## Tests

```bash
pytest tests/ -v
```

## Project structure

```text
backend/       FastAPI application, API routes, models, and services
frontend/      Dashboard assets
ml/            Model training and prediction code
tests/         Automated tests
docker/        Nginx configuration
.env.example   Example environment configuration
```

## Security and scope

This repository is an educational project. Run it only in a local or otherwise controlled environment. It is not a production intrusion-detection service. Before any deployment, replace example secrets and credentials, review authentication and network exposure, and keep IP-blocking actions in dry-run mode until they have been tested in an authorized environment. Never use it against systems you do not own or have permission to assess.

## License

The repository includes an MIT license.
