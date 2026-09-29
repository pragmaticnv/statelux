"""
STATEFLUX — FastAPI Application Entry Point
=============================================
Phase 1A — Foundation + Canonical Data Model + Synthetic Dataset Engine

Startup sequence:
  1. Load seed dataset from data/seed/*.json
  2. Validate all Pydantic schemas
  3. Perform cross-reference integrity checks
  4. Expose dataset via API routes
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from app.core.config import settings
from app.services.data_loader import load_dataset

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — load dataset on startup."""
    seed_dir = settings.SEED_DIR
    logger.info("STATEFLUX %s starting up", settings.VERSION)
    logger.info("Seed directory: %s", seed_dir)

    if not seed_dir.exists() or not any(seed_dir.glob("*.json")):
        logger.warning(
            "No seed data found in %s. "
            "Run: python scripts/generate_dataset.py",
            seed_dir,
        )
    else:
        try:
            ds = load_dataset(seed_dir)
            logger.info(
                "Dataset ready: %d tunnels | %d endpoints | %d proposals",
                len(ds.tunnels),
                len(ds.endpoints),
                len(ds.proposals),
            )
        except Exception as exc:
            logger.error("Dataset load FAILED: %s", exc)
            # Do not prevent startup — health endpoint will report unloaded state

    yield

    logger.info("STATEFLUX shutting down")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title=settings.APP_NAME,
        description=settings.DESCRIPTION,
        version=settings.VERSION,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # CORS — permissive for Phase 1 local development
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Import and register routers
    from app.api.routes.health import router as health_router
    from app.api.routes.fleet import router as fleet_router
    from app.api.routes.endpoints_route import router as endpoints_router
    from app.api.routes.tunnels import router as tunnels_router
    from app.api.routes.analysis import router as analysis_router
    from app.api.routes.security import router as security_router
    from app.api.routes.twin import router as twin_router
    from app.api.routes.simulation import router as simulation_router
    from app.api.routes.graph import router as graph_router
    from app.api.routes.migrations import router as migrations_router
    from app.api.routes.lab import router as lab_router
    from app.api.routes.evidence_route import router as evidence_router
    from app.api.routes.findings_route import router as findings_router
    from app.api.routes.ai_route import router as ai_router
    from app.api.routes.reports_route import router as reports_router

    prefix = settings.API_PREFIX
    app.include_router(health_router,      prefix=prefix)
    app.include_router(fleet_router,       prefix=prefix)
    app.include_router(endpoints_router,   prefix=prefix)
    app.include_router(tunnels_router,     prefix=prefix)
    app.include_router(analysis_router,    prefix=prefix)
    app.include_router(security_router,    prefix=prefix)
    app.include_router(twin_router,        prefix=prefix)
    app.include_router(simulation_router,  prefix=prefix)
    app.include_router(graph_router,       prefix=prefix)
    app.include_router(migrations_router,  prefix=prefix)
    app.include_router(lab_router,         prefix=prefix)
    app.include_router(evidence_router,    prefix=prefix)
    app.include_router(findings_router,    prefix=prefix)
    app.include_router(ai_router,          prefix=prefix)
    app.include_router(reports_router,     prefix=prefix)

    @app.get("/", include_in_schema=False)
    async def root(request: Request):
        accept = request.headers.get("accept", "")
        if "text/html" in accept and "application/json" not in accept:
            return RedirectResponse(url="/ui/", status_code=307)
        return {
            "service": settings.APP_NAME,
            "version": settings.VERSION,
            "status": "online",
            "documentation": "/docs",
            "redoc": "/redoc",
            "api_prefix": prefix,
            "endpoints": {
                "command_center": "/ui",
                "health": f"{prefix}/health",
                "fleet": f"{prefix}/fleet",
                "fleet_stats": f"{prefix}/fleet/stats",
                "endpoints_list": f"{prefix}/endpoints",
                "tunnels_list": f"{prefix}/tunnels",
                "fleet_analysis": f"{prefix}/analysis/fleet",
                "security_fleet": f"{prefix}/security/fleet",
                "digital_twin": f"{prefix}/twin",
                "simulations": f"{prefix}/simulations",
                "graph_fleet": f"{prefix}/graph/fleet",
                "migrations_plan": f"{prefix}/migrations/plan",
                "lab_run": f"{prefix}/lab/run",
                "lab_validation": f"{prefix}/lab/validation",
                "evidence": f"{prefix}/evidence",
                "findings": f"{prefix}/findings",
                "pcap_analyze": f"{prefix}/pcap/analyze",
                "ai_explain_finding": f"{prefix}/ai/explain/finding",
                "reports_executive": f"{prefix}/reports/executive",
                "reports_technical": f"{prefix}/reports/technical",
            },
        }

    # Mount frontend static files if present
    from pathlib import Path
    from fastapi.staticfiles import StaticFiles

    candidates = [
        Path(__file__).resolve().parent.parent.parent / "frontend",
        Path.cwd() / "frontend",
        Path("/var/task/frontend"),
    ]
    frontend_dir = next((c for c in candidates if c.exists()), candidates[0])
    if frontend_dir.exists():
        app.mount("/ui", StaticFiles(directory=str(frontend_dir), html=True), name="ui")

    return app


app = create_app()
