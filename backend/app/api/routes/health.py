"""STATEFLUX — Health Route"""
from fastapi import APIRouter

from app.services import data_loader
from app.core.config import settings
from app.core.constants import SYNTHETIC_DATA_DISCLAIMER
from app.schemas.responses import HealthResponse

router = APIRouter(prefix="/health", tags=["health"])


@router.get("", response_model=HealthResponse)
async def get_health() -> HealthResponse:
    """Service health check — includes dataset status."""
    ds = data_loader._current_dataset
    return HealthResponse(
        status="ok",
        version=settings.VERSION,
        dataset_loaded=ds.is_loaded,
        dataset_source=ds.dataset_source if ds.is_loaded else None,
        load_timestamp=ds.load_timestamp if ds.is_loaded else None,
        entity_counts=ds.stats if ds.is_loaded else {},
        is_synthetic=ds.is_synthetic,
        disclaimer=SYNTHETIC_DATA_DISCLAIMER,
    )
