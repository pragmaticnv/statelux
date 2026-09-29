"""
STATEFLUX — Digital Twin Routes
===============================
Phase 2 — Security Intelligence Layer

Exposes:
  - GET /api/v1/twin
  - GET /api/v1/twin/tunnels/{tunnel_id}
  - GET /api/v1/twin/endpoints/{endpoint_id}
"""

from fastapi import APIRouter, HTTPException

from app.models.digital_twin import (
    FleetTwinOverview,
    TunnelTwinState,
    EndpointTwinState,
)
from app.services.twin_service import DigitalTwinService
from app.services.data_loader import get_dataset

router = APIRouter(prefix="/twin", tags=["digital-twin"])

_twin_service = DigitalTwinService()


@router.get("", response_model=FleetTwinOverview)
async def get_fleet_twin() -> FleetTwinOverview:
    """Return the complete Fleet Digital Twin overview with posture metrics."""
    try:
        get_dataset()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    return _twin_service.build_fleet_twin()


@router.get("/tunnels/{tunnel_id}", response_model=TunnelTwinState)
async def get_tunnel_twin(tunnel_id: str) -> TunnelTwinState:
    """Return the derived Digital Twin state for a specific tunnel."""
    try:
        get_dataset()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    try:
        return _twin_service.build_tunnel_twin(tunnel_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Tunnel '{tunnel_id}' not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/endpoints/{endpoint_id}", response_model=EndpointTwinState)
async def get_endpoint_twin(endpoint_id: str) -> EndpointTwinState:
    """Return the derived Digital Twin state for a specific endpoint."""
    try:
        get_dataset()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    try:
        return _twin_service.build_endpoint_twin(endpoint_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Endpoint '{endpoint_id}' not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
