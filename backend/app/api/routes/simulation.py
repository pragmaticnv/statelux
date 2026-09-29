"""
STATEFLUX — Change Impact & Simulation API Routes
=================================================
Phase 3 — Fleet Intelligence & Change-Impact Engine

Provides endpoints for running what-if policy simulations, querying results,
inspecting fleet blast radius, and retrieving per-tunnel impact breakdowns.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status

from app.models.change_request import ChangeRequest
from app.models.simulation import (
    SimulationResult,
    FleetBlastRadius,
    TunnelSimulationResult,
    TunnelSimulationClassification,
)
from app.services.simulation_engine import SimulationEngine

router = APIRouter(prefix="/simulations", tags=["Simulations"])

# Singleton engine instance (in-memory storage of simulation runs)
_engine = SimulationEngine()


def get_simulation_engine() -> SimulationEngine:
    return _engine


@router.post(
    "",
    response_model=SimulationResult,
    status_code=status.HTTP_201_CREATED,
    summary="Run What-If Policy Simulation",
    description="Simulate the fleet-wide impact of a structured policy ChangeRequest without mutating current state.",
)
async def run_simulation(change_request: ChangeRequest) -> SimulationResult:
    try:
        result = _engine.run_simulation(change_request)
        return result
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Simulation failed: {str(exc)}",
        )


@router.get(
    "/{simulation_id}",
    response_model=SimulationResult,
    summary="Get Simulation Full Result",
    description="Retrieve the complete simulation report by simulation ID.",
)
async def get_simulation(simulation_id: str) -> SimulationResult:
    result = _engine.get_simulation(simulation_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Simulation '{simulation_id}' not found.",
        )
    return result


@router.get(
    "/{simulation_id}/summary",
    response_model=FleetBlastRadius,
    summary="Get Simulation Fleet Blast Radius Summary",
    description="Retrieve the high-level blast radius and aggregation summary for a simulation.",
)
async def get_simulation_summary(simulation_id: str) -> FleetBlastRadius:
    result = _engine.get_simulation(simulation_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Simulation '{simulation_id}' not found.",
        )
    return result.fleet_summary


@router.get(
    "/{simulation_id}/tunnels",
    response_model=list[TunnelSimulationResult],
    summary="Get Simulated Tunnels",
    description="Retrieve individual tunnel simulation results, optionally filtered by classification.",
)
async def get_simulated_tunnels(
    simulation_id: str,
    classification: Optional[TunnelSimulationClassification] = Query(
        None,
        description="Filter by classification (HARDENED, UNCHANGED, DEGRADED, INCOMPATIBLE, LATENT_FAILURE, UNKNOWN)",
    ),
) -> list[TunnelSimulationResult]:
    result = _engine.get_simulation(simulation_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Simulation '{simulation_id}' not found.",
        )
    
    if classification:
        return [t for t in result.tunnel_results if t.classification == classification]
    return result.tunnel_results


@router.get(
    "/{simulation_id}/tunnels/{tunnel_id}",
    response_model=TunnelSimulationResult,
    summary="Get Single Simulated Tunnel Result",
    description="Retrieve the detailed before/after comparison and reasoning for a specific tunnel.",
)
async def get_simulated_tunnel(simulation_id: str, tunnel_id: str) -> TunnelSimulationResult:
    result = _engine.get_simulation(simulation_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Simulation '{simulation_id}' not found.",
        )
    
    for t in result.tunnel_results:
        if t.tunnel_id == tunnel_id:
            return t

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Tunnel '{tunnel_id}' not found in simulation '{simulation_id}'.",
    )
