"""
🛡️ Cyber Sentinel - Core Configuration
Centralized configuration management using Pydantic Settings.
"""

import os
from pathlib import Path
from typing import List, Optional
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application-wide settings loaded from environment variables."""

    # ── Application ──
    APP_NAME: str = "Cyber Sentinel"
    APP_ENV: str = "development"
    APP_DEBUG: bool = True
    APP_PORT: int = 8000
    APP_HOST: str = "0.0.0.0"
    APP_VERSION: str = "2.0.0"

    # ── Security ──
    SECRET_KEY: str = "cyber-sentinel-super-secret-key-change-in-production-2026"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 1440  # 24 hours

    # ── Database ──
    DATABASE_URL: str = "sqlite:///./cyber_sentinel.db"

    # ── ML Model ──
    MODEL_PATH: str = "ml/models/ensemble_model.pkl"
    MODEL_THRESHOLD: float = 0.75
    ANOMALY_THRESHOLD: float = 0.85

    # ── Network Capture ──
    CAPTURE_INTERFACE: str = "auto"
    CAPTURE_TIMEOUT: int = 30
    MAX_PACKETS_PER_BATCH: int = 100

    # ── Rate Limiting ──
    RATE_LIMIT_PER_MINUTE: int = 60

    # ── CORS ──
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000"

    # ── Logging ──
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/cyber_sentinel.log"

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

    @property
    def is_development(self) -> bool:
        return self.APP_ENV == "development"

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """Cache and return settings singleton."""
    return Settings()


# Base directory for the project
BASE_DIR = Path(__file__).resolve().parent.parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
LOG_DIR = BASE_DIR / "logs"
ML_DIR = BASE_DIR / "ml"

# Ensure directories exist
UPLOAD_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)
(ML_DIR / "models").mkdir(parents=True, exist_ok=True)
(ML_DIR / "data").mkdir(parents=True, exist_ok=True)
