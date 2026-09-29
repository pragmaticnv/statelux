"""STATEFLUX — Tunnel Routes"""
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from app.services.data_loader import get_dataset
from app.schemas.responses import TunnelSummary
from app.models.tunnel import Tunnel

router = APIRouter(prefix="/tunnels", tags=["tunnels"])


def _to_summary(tunnel: Tunnel, ds) -> TunnelSummary:
    # Get risk level from security state if available
    risk_level = None
    risk_score = None
    if tunnel.security_state_id:
        ss = ds.security_states.get(tunnel.security_state_id)
        if ss:
            risk_level = ss.risk.level.value
            risk_score = ss.risk.score

    scenario = tunnel.annotations.get("scenario")
    return TunnelSummary(
        tunnel_id=tunnel.tunnel_id,
        endpoint_a=tunnel.endpoint_a,
        endpoint_b=tunnel.endpoint_b,
        mode=tunnel.mode.value,
        status=tunnel.status.value,
        negotiation_id=tunnel.negotiation_id,
        security_state_id=tunnel.security_state_id,
        rekey_interval=tunnel.rekey_interval,
        scenario=scenario,
        risk_level=risk_level,
        risk_score=risk_score,
    )


@router.get("", response_model=list[TunnelSummary])
async def list_tunnels(
    status:   Optional[str] = Query(None, description="Filter by status (UP/DOWN/UNKNOWN)"),
    scenario: Optional[str] = Query(None, description="Filter by scenario annotation"),
    endpoint: Optional[str] = Query(None, description="Filter by endpoint ID (either side)"),
) -> list[TunnelSummary]:
    """List all tunnels with optional filters."""
    try:
        ds = get_dataset()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    tunnels = list(ds.tunnels.values())

    if status:
        tunnels = [t for t in tunnels
                   if t.status.value == status.upper()]
    if scenario:
        tunnels = [t for t in tunnels
                   if t.annotations.get("scenario", "").upper() == scenario.upper()]
    if endpoint:
        tunnels = [t for t in tunnels
                   if t.endpoint_a == endpoint or t.endpoint_b == endpoint]

    return [_to_summary(t, ds) for t in tunnels]


@router.get("/{tunnel_id}", response_model=dict)
async def get_tunnel(tunnel_id: str) -> dict:
    """Return the full tunnel record including negotiation and security state."""
    try:
        ds = get_dataset()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    tunnel = ds.tunnels.get(tunnel_id)
    if tunnel is None:
        raise HTTPException(status_code=404, detail=f"Tunnel '{tunnel_id}' not found")

    result = tunnel.model_dump()

    # Embed related records for convenience
    if tunnel.negotiation_id:
        neg = ds.negotiations.get(tunnel.negotiation_id)
        result["_negotiation"] = neg.model_dump() if neg else None

    if tunnel.security_state_id:
        ss = ds.security_states.get(tunnel.security_state_id)
        result["_security_state"] = ss.model_dump() if ss else None

    return result


@router.get("/{tunnel_id}/evidence", response_model=list[dict])
async def get_tunnel_evidence(tunnel_id: str) -> list[dict]:
    """Return all evidence items linked to this specific tunnel."""
    from app.api.routes.evidence_route import get_evidence_engine
    ev_engine = get_evidence_engine()
    evidence_items = ev_engine.get_evidence_for_tunnel(tunnel_id)
    return [e.model_dump() for e in evidence_items]


@router.get("/{tunnel_id}/findings", response_model=list[dict])
async def get_tunnel_findings(tunnel_id: str) -> list[dict]:
    """Return all deterministic findings affecting this specific tunnel."""
    from app.api.routes.findings_route import get_finding_engine
    f_engine = get_finding_engine()
    findings = f_engine.get_findings_for_tunnel(tunnel_id)
    return [f.model_dump() for f in findings]

