"""
STATEFLUX — Development Server Runner
======================================
Launches the FastAPI backend with uvicorn.

Usage:
    python run.py
    python run.py --port 8080
"""

import sys
import argparse
from pathlib import Path

# Prepend backend directory to sys.path
backend_dir = Path(__file__).resolve().parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import uvicorn


def main():
    parser = argparse.ArgumentParser(description="Start STATEFLUX development server.")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to (default: 8000)")
    parser.add_argument("--no-reload", action="store_true", help="Disable auto-reload")
    args = parser.parse_args()

    print("=" * 60)
    print("STATEFLUX — AI-Assisted IPsec Intelligence Platform")
    print(f"Starting server on http://{args.host}:{args.port}")
    print(f"API Documentation: http://{args.host}:{args.port}/docs")
    print("=" * 60)

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=not args.no_reload,
        app_dir=str(backend_dir),
    )


if __name__ == "__main__":
    main()
