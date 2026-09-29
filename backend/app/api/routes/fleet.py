"""STATEFLUX — Fleet Routes"""
from fastapi import APIRouter, HTTPException

from app.services.data_loader import get_dataset
from app.schemas.responses import FleetSummary, DatasetStatsResponse
from app.core.constants import SYNTHETIC_DATA_DISCLAIMER

router = APIRouter(prefix="/fleet", tags=["fleet"])


@router.get("", response_model=FleetSummary)
async def get_fleet() -> FleetSummary:
    """Return the fleet summary."""
    try:
        ds = get_dataset()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    fleet = ds.fleet
    return FleetSummary(
        fleet_id=fleet.fleet_id,
        name=fleet.name,
        description=fleet.description,
        environment=fleet.environment,
        created_at=fleet.created_at,
        endpoint_count=len(fleet.endpoint_ids),
        tunnel_count=len(fleet.tunnel_ids),
        notes=fleet.notes,
    )


@router.get("/stats", response_model=DatasetStatsResponse)
async def get_dataset_stats() -> DatasetStatsResponse:
    """Return dataset statistics and load status."""
    try:
        ds = get_dataset()
        return DatasetStatsResponse(
            is_loaded=ds.is_loaded,
            is_synthetic=ds.is_synthetic,
            dataset_source=ds.dataset_source,
            load_timestamp=ds.load_timestamp,
            entity_counts=ds.stats,
            disclaimer=SYNTHETIC_DATA_DISCLAIMER,
        )
    except RuntimeError:
        return DatasetStatsResponse(
            is_loaded=False,
            is_synthetic=True,
            dataset_source=None,
            load_timestamp=None,
            entity_counts={},
            disclaimer=SYNTHETIC_DATA_DISCLAIMER,
        )
