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
