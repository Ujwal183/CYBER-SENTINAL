"""
🛡️ Cyber Sentinel - API for serving frontend static files
"""
from fastapi import APIRouter
from fastapi.responses import FileResponse
from pathlib import Path

router = APIRouter()
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

@router.get("/app")
@router.get("/app/{path:path}")
def serve_frontend(path: str = ""):
    if path and (FRONTEND_DIR / path).is_file():
        return FileResponse(FRONTEND_DIR / path)
    return FileResponse(FRONTEND_DIR / "index.html")
