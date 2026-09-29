"""
STATEFLUX — Security Intelligence Routes
=========================================
Phase 2 — Security Intelligence Layer

Exposes:
  - GET /api/v1/security/floor/{tunnel_id}
  - GET /api/v1/security/posture/{tunnel_id}
  - GET /api/v1/security/findings/{tunnel_id}
  - GET /api/v1/security/fleet
"""

from typing import Optional, Any
from fastapi import APIRouter, HTTPException

from app.models.security_floor import SecurityFloorResult
from app.models.digital_twin import FleetSecurityAggregation
from app.services.twin_service import DigitalTwinService
from app.services.data_loader import get_dataset

router = APIRouter(prefix="/security", tags=["security"])

_twin_service = DigitalTwinService()


@router.get("/floor/{tunnel_id}", response_model=SecurityFloorResult)
@router.get("/floors/{tunnel_id}", response_model=SecurityFloorResult, include_in_schema=False)
async def get_tunnel_security_floor(tunnel_id: str) -> SecurityFloorResult:
    """Return the dynamically computed Security Floor result for a tunnel."""
    try:
        get_dataset()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    try:
        twin = _twin_service.build_tunnel_twin(tunnel_id)
        # Return composite / primary protocol floor (ESP if present, else IKE)
        if twin.child_sa_floor and twin.child_sa_floor.floor_status != "NO_COMMON_PROPOSALS":
            return twin.child_sa_floor
        return twin.ike_floor
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Tunnel '{tunnel_id}' not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/posture/{tunnel_id}", response_model=dict)
async def get_tunnel_posture(tunnel_id: str) -> dict:
    """Return the full multidimensional security posture for a tunnel."""
    try:
        get_dataset()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    try:
        twin = _twin_service.build_tunnel_twin(tunnel_id)
        return {
            "tunnel_id": twin.tunnel_id,
            "status": twin.status,
            "cryptographic_posture": twin.cryptographic_posture,
            "pfs_posture": twin.pfs_posture,
            "replay_posture": twin.replay_posture,
            "compatibility": twin.compatibility.value,
            "confidence": twin.confidence.value,
            "composite_gap": twin.composite_gap.model_dump(),
            "risk_score": twin.risk_score,
            "risk_level": twin.risk_level,
            "finding_count": twin.finding_count,
            "selected_ike": twin.ike_floor.selected.model_dump() if twin.ike_floor.selected else None,
            "floor_ike": twin.ike_floor.display_floor.model_dump() if twin.ike_floor.display_floor else None,
            "selected_esp": twin.child_sa_floor.selected.model_dump() if twin.child_sa_floor and twin.child_sa_floor.selected else None,
            "floor_esp": twin.child_sa_floor.display_floor.model_dump() if twin.child_sa_floor and twin.child_sa_floor.display_floor else None,
        }
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Tunnel '{tunnel_id}' not found")


@router.get("/findings/{tunnel_id}", response_model=list[dict])
async def get_tunnel_findings(tunnel_id: str) -> list[dict]:
    """Return all security findings (rule engine + floor gap) for a tunnel."""
    try:
        get_dataset()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    try:
        twin = _twin_service.build_tunnel_twin(tunnel_id)
        return twin.findings
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Tunnel '{tunnel_id}' not found")


@router.get("/fleet", response_model=FleetSecurityAggregation)
async def get_fleet_security_summary() -> FleetSecurityAggregation:
    """Return aggregate security intelligence across the entire fleet."""
    try:
        get_dataset()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    fleet_twin = _twin_service.build_fleet_twin()
    return fleet_twin.aggregate_posture
