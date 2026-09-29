"""
STATEFLUX — Phase 4 Migration Planner Tests
===========================================
Tests for MigrationPlannerService:
  - Canary creation and selection
  - Low-risk batch grouping
  - Dependency ordering
  - Migration invariant: INCOMPATIBLE and LATENT_FAILURE tunnels strictly blocked
  - Structured rollback generation
  - REST API endpoints for migration plans and waves
"""

import pytest

from app.models.change_request import (
    ChangeRequest,
    ChangeScope,
    ChangeScopeType,
    EncryptionAction,
    DHAction,
    PFSAction,
)
from app.models.migration import MigrationStrategy, WaveRiskLevel
from app.services.simulation_engine import SimulationEngine
from app.services.graph_service import FleetGraphService
from app.services.migration_planner import MigrationPlannerService


@pytest.fixture
def sim_engine(dataset):
    return SimulationEngine(dataset=dataset)


@pytest.fixture
def planner_service(dataset):
    return MigrationPlannerService(dataset=dataset)


@pytest.fixture
def simulation_result(dataset, sim_engine):
    """Run a realistic fleet-wide hardening simulation."""
    change = ChangeRequest(
        change_id="CHG-MIGRATION-TEST",
        title="Fleet-Wide Modern Cryptography Policy",
        scope=ChangeScope(type=ChangeScopeType.FLEET),
        encryption=EncryptionAction(
            remove=["3DES", "AES-128-CBC"],
            require=["AES-256-GCM"],
        ),
        dh_groups=DHAction(
            remove=[1, 2, 5, 14],
            minimum_dh=19,
        ),
        pfs=PFSAction(mode="REQUIRE"),
    )
    return sim_engine.run_simulation(change), change


def test_migration_planner_generation(dataset, planner_service, simulation_result):
    """Test generating a multi-wave migration plan from a simulation result."""
    sim_res, change = simulation_result
    graph = FleetGraphService(dataset=dataset).build_graph()

    plan = planner_service.generate_plan(
        simulation_result=sim_res,
        graph=graph,
        change_request=change,
        objective="Enforce AES-256-GCM and eliminate 3DES/DH14",
    )

    assert plan.migration_plan_id.startswith("plan-")
    assert plan.simulation_id == sim_res.simulation_id
    assert plan.summary.total_tunnels == len(sim_res.tunnel_results)
    assert plan.summary.eligible + plan.summary.blocked == plan.summary.total_tunnels
    assert len(plan.waves) > 0


def test_migration_canary_wave(dataset, planner_service, simulation_result):
    """Test Wave 1 is CANARY strategy with low risk and up to 3 tunnels."""
    sim_res, change = simulation_result
    plan = planner_service.generate_plan(simulation_result=sim_res, change_request=change)

    w1 = plan.waves[0]
    assert w1.order == 1
    assert w1.strategy == MigrationStrategy.CANARY
    assert w1.risk == WaveRiskLevel.LOW
    assert len(w1.tunnel_ids) >= 1
    assert len(w1.tunnel_ids) <= 3
    assert len(w1.prerequisites) > 0
    assert "IKE_SA_ESTABLISHED" in w1.validation_checks


def test_migration_invariant_no_blocked_in_waves(dataset, planner_service, simulation_result):
    """MIGRATION INVARIANT: Incompatible and Latent Failure tunnels must NEVER be placed in a rollout wave."""
    sim_res, change = simulation_result
    plan = planner_service.generate_plan(simulation_result=sim_res, change_request=change)

    blocked_tunnel_ids = {b.tunnel_id for b in plan.blocked_tunnels}
    assert len(blocked_tunnel_ids) > 0  # Our test change removes 3DES and DH14, which breaks legacy tunnels

    # Check each wave
    for wave in plan.waves:
        for tn_id in wave.tunnel_ids:
            assert tn_id not in blocked_tunnel_ids, f"Invariant violation: Blocked tunnel {tn_id} found in {wave.wave_id}"

    # Verify blocked tunnels have required remediation
    for b in plan.blocked_tunnels:
        assert b.classification in ("INCOMPATIBLE", "LATENT_FAILURE", "UNKNOWN")
        assert len(b.blocked_reason) > 0
        assert len(b.required_remediation) > 0


def test_dependency_ordering_of_waves(dataset, planner_service, simulation_result):
    """Test that later waves depend on previous waves."""
    sim_res, change = simulation_result
    plan = planner_service.generate_plan(simulation_result=sim_res, change_request=change)

    if len(plan.waves) > 1:
        for i in range(1, len(plan.waves)):
            current = plan.waves[i]
            prev = plan.waves[i - 1]
            assert prev.wave_id in current.depends_on_wave


def test_rollback_plan_synthesis(dataset, planner_service, simulation_result):
    """Test structured forward and rollback actions are generated."""
    sim_res, change = simulation_result
    plan = planner_service.generate_plan(simulation_result=sim_res, change_request=change)

    for wave in plan.waves:
        rb = wave.rollback
        assert rb.available is True
        assert len(rb.forward_actions) > 0
        assert len(rb.rollback_actions) > 0
        assert any("Restore legacy ciphers" in a for a in rb.rollback_actions)
        assert any("Restore DH groups" in a for a in rb.rollback_actions)


def test_migration_api_endpoints(client):
    """Test REST API endpoints: POST /plan, GET /plan/{id}, GET /waves, GET /waves/{wave_id}."""
    # 1. POST /api/v1/migrations/plan
    payload = {
        "objective": "API Test Migration Rollout",
        "change_request": {
            "change_id": "CHG-API-MIGRATION",
            "title": "API Hardening",
            "scope": {"type": "FLEET"},
            "encryption": {"remove": ["3DES"]},
        },
    }
    res = client.post("/api/v1/migrations/plan", json=payload)
    assert res.status_code == 201
    plan_data = res.json()
    plan_id = plan_data["migration_plan_id"]
    assert len(plan_data["waves"]) > 0

    # 2. GET /api/v1/migrations/{id}
    res_get = client.get(f"/api/v1/migrations/{plan_id}")
    assert res_get.status_code == 200
    assert res_get.json()["migration_plan_id"] == plan_id

    # 3. GET /api/v1/migrations/{id}/waves
    res_waves = client.get(f"/api/v1/migrations/{plan_id}/waves")
    assert res_waves.status_code == 200
    waves_list = res_waves.json()
    assert len(waves_list) > 0
    w1_id = waves_list[0]["wave_id"]

    # 4. GET /api/v1/migrations/{id}/waves/{wave_id}
    res_w1 = client.get(f"/api/v1/migrations/{plan_id}/waves/{w1_id}")
    assert res_w1.status_code == 200
    assert res_w1.json()["wave_id"] == w1_id
    assert res_w1.json()["strategy"] == "CANARY"

    # 5. 404 for unknown plan
    res_404 = client.get("/api/v1/migrations/plan-non-existent")
    assert res_404.status_code == 404
