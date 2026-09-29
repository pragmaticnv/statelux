"""
STATEFLUX — Production Import Verification Test
===============================================
Validates that the production Vercel entrypoint (api/index.py) can be cleanly
imported without errors and exposes the canonical FastAPI application.
"""

import sys
from pathlib import Path
import pytest
from fastapi import FastAPI


class TestProductionImport:
    """Verifies that the serverless entrypoint and all production dependencies load cleanly."""

    def test_production_runtime_dependencies_importable(self):
        """Verify that every required runtime dependency is importable."""
        import fastapi
        import uvicorn
        import pydantic
        import httpx
        import anyio
        import jinja2
        import reportlab

        assert hasattr(fastapi, "FastAPI")
        assert hasattr(pydantic, "BaseModel")
        assert hasattr(jinja2, "Environment")
        assert hasattr(reportlab, "__version__")

    def test_production_entrypoint_imports_app(self):
        """Verify that api.index exposes the canonical FastAPI app instance."""
        repo_root = Path(__file__).resolve().parent.parent.parent
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))

        from api.index import app
        assert isinstance(app, FastAPI)
        assert app.title == "STATEFLUX"

    def test_production_entrypoint_routes_complete(self):
        """Ensure the deployed app contains all core route paths."""
        from api.index import app

        paths = set(app.openapi()["paths"].keys())
        assert "/api/v1/health" in paths
        assert "/api/v1/fleet" in paths
        assert "/api/v1/graph/fleet" in paths
        assert "/api/v1/security/fleet" in paths
        assert "/api/v1/simulations" in paths
        assert "/api/v1/findings" in paths
        assert "/api/v1/lab/validation" in paths
        assert "/api/v1/reports/executive" in paths
        assert "/api/v1/reports/technical" in paths
        assert "/api/v1/reports/export/{report_type}/pdf" in paths
