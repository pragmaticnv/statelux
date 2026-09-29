"""
STATEFLUX — Fleet Negotiation Graph API Routes
==============================================
Phase 3 — Fleet Intelligence & Change-Impact Engine

Provides endpoints for retrieving the machine-readable Fleet Negotiation Graph:
  - Nodes: VPN Endpoints (gateways, clients, hubs) with security posture and degree
  - Edges: IPsec Tunnels linking endpoints with negotiated suite, floor, gap, and risk
"""

from fastapi import APIRouter, HTTPException

from app.models.graph import FleetNegotiationGraph
from app.services.graph_service import FleetGraphService

router = APIRouter(prefix="/graph", tags=["Graph"])

_graph_service = FleetGraphService()


def get_graph_service() -> FleetGraphService:
    return _graph_service


@router.get(
    "/fleet",
    response_model=FleetNegotiationGraph,
    summary="Get Fleet Negotiation Graph",
    description="Retrieve the machine-readable Fleet Negotiation Graph with endpoints as nodes and tunnels as edges.",
)
async def get_fleet_graph() -> FleetNegotiationGraph:
    try:
        graph = _graph_service.build_graph()
        return graph
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate fleet graph: {str(exc)}",
        )
