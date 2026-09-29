"""
STATEFLUX — Vercel Serverless Function Adapter
==============================================
Exposes the canonical FastAPI application instance for Vercel deployment.
Adds backend and project root directories to sys.path so existing application
logic, routes, and data models are preserved without modification.
"""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.main import app
from app.services.data_loader import load_dataset, _current_dataset

# Serverless cold-start initialization: ensure dataset is loaded immediately
if not _current_dataset.is_loaded:
    candidates = [
        BACKEND_DIR / "app" / "data" / "seed",
        PROJECT_ROOT / "data" / "seed",
        Path.cwd() / "data" / "seed",
        Path("/var/task/backend/app/data/seed"),
        Path("/var/task/data/seed"),
    ]
    for c in candidates:
        if c.exists() and any(c.glob("*.json")):
            load_dataset(c)
            break
