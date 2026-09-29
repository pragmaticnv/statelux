"""
STATEFLUX — Migration Planner API Routes
========================================
Phase 4 — Migration Planner + Real IPsec Lab + Prediction Validation

Provides endpoints for generating and inspecting dependency-ordered migration waves,
operational risk scores, validation checks, and rollback procedures.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import Field

from app.models.base import StatefluxBaseModel
from app.models.change_request import ChangeRequest
from app.models.migration import MigrationPlan, MigrationWave
from app.services.migration_planner import MigrationPlannerService
from app.api.routes.simulation import get_simulation_engine
from app.api.routes.graph import get_graph_service

router = APIRouter(prefix="/migrations", tags=["Migrations"])

_planner = MigrationPlannerService()


def get_migration_planner() -> MigrationPlannerService:
    return _planner


class CreateMigrationPlanRequest(StatefluxBaseModel):
    """Payload to trigger migration wave generation."""
    simulation_id: Optional[str] = Field(None, description="Existing simulation run ID to plan from.")
    change_request: Optional[ChangeRequest] = Field(None, description="Change request payload if triggering fresh simulation.")
    objective: str = Field("Roll out verified policy change without service disruption", description="Operational objective.")


@router.post(
    "/plan",
    response_model=MigrationPlan,
    status_code=status.HTTP_201_CREATED,
    summary="Generate Migration Plan",
    description="Partition simulated tunnels into dependency-ordered rollout waves with rollback artifacts and safety invariants.",
)
async def generate_migration_plan(request: CreateMigrationPlanRequest) -> MigrationPlan:
    sim_engine = get_simulation_engine()
    graph_service = get_graph_service()

    sim_result = None
    change = request.change_request

    if request.simulation_id:
        sim_result = sim_engine.get_simulation(request.simulation_id)
        if not sim_result and not change:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Simulation '{request.simulation_id}' not found.",
            )

    if not sim_result:
        # Run simulation first
        if not change:
            change = ChangeRequest(
                change_id="CHG-AUTO-PLAN",
                title="Automated Policy Hardening",
            )
        sim_result = sim_engine.run_simulation(change)

    graph = graph_service.build_graph()

    plan = _planner.generate_plan(
        simulation_result=sim_result,
        graph=graph,
        change_request=change,
        objective=request.objective,
    )
    return plan


@router.get(
    "/{plan_id}",
    response_model=MigrationPlan,
    summary="Get Migration Plan",
    description="Retrieve a complete migration plan by plan ID.",
)
async def get_plan(plan_id: str) -> MigrationPlan:
    plan = _planner.get_plan(plan_id)
    if not plan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Migration plan '{plan_id}' not found.",
        )
    return plan


@router.get(
    "/{plan_id}/waves",
    response_model=list[MigrationWave],
    summary="Get Migration Waves",
    description="Retrieve the ordered list of rollout waves for a plan.",
)
async def get_plan_waves(plan_id: str) -> list[MigrationWave]:
    plan = _planner.get_plan(plan_id)
    if not plan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Migration plan '{plan_id}' not found.",
        )
    return plan.waves


@router.get(
    "/{plan_id}/waves/{wave_id}",
    response_model=MigrationWave,
    summary="Get Single Migration Wave",
    description="Retrieve specific wave details including tunnel IDs, preconditions, and rollback plan.",
)
async def get_plan_wave(plan_id: str, wave_id: str) -> MigrationWave:
    plan = _planner.get_plan(plan_id)
    if not plan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Migration plan '{plan_id}' not found.",
        )

    for w in plan.waves:
        if w.wave_id == wave_id:
            return w

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Wave '{wave_id}' not found in migration plan '{plan_id}'.",
    )
