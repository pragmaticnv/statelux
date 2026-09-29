"""
STATEFLUX — Phase 3 What-If Simulation Tests
=============================================
Tests the Change Impact & Simulation Engine:
  - TEST 01: Secure hardening (weak suite -> require AES-256-GCM -> HARDENED)
  - TEST 02: Encryption incompatibility (remove shared cipher -> INCOMPATIBLE)
  - TEST 03: DH incompatibility (remove shared DH group -> INCOMPATIBLE)
  - TEST 04: Latent rekey failure (active UP tunnel loses proposals on next rekey -> LATENT_FAILURE)
  - TEST 05: Unrelated change (tunnel unaffected by scoped change -> UNCHANGED)
  - TEST 06: Unknown / incomplete data handling (tunnel with low confidence -> UNKNOWN)
  - TEST 07: Fleet blast radius calculation (scoped endpoint impact tracking)
  - TEST 08: Future Twin / current state immutability (dataset unchanged after simulation)
  - TEST 09: Simulation REST APIs
"""

import pytest
import copy

from app.models.change_request import (
    ChangeRequest,
    ChangeScope,
    ChangeScopeType,
    EncryptionAction,
    DHAction,
    PFSAction,
    IKEAction,
)
from app.models.simulation import TunnelSimulationClassification
from app.services.simulation_engine import SimulationEngine
from app.services.twin_service import DigitalTwinService


@pytest.fixture
def sim_engine(dataset):
    """Instantiate a SimulationEngine with the session dataset."""
    return SimulationEngine(dataset=dataset)


# --------------------------------------------------------------------------
# TEST 01: Secure Hardening
# --------------------------------------------------------------------------
def test_simulation_01_secure_hardening(dataset, sim_engine):
    """TEST 01: Requiring modern AES-256-GCM hardens tunnels with weak/fallback suites."""
    # Find a tunnel that has fallback or non-GCM suite (e.g. S03 or S02)
    change = ChangeRequest(
        change_id="CHG-TEST-01",
        title="Require AES-256-GCM fleet-wide",
        scope=ChangeScope(type=ChangeScopeType.FLEET),
        encryption=EncryptionAction(
            remove=["3DES", "DES", "AES-128-CBC"],
            require=["AES-256-GCM"],
        ),
    )

    result = sim_engine.run_simulation(change)
    assert result.simulation_id is not None
    assert result.is_simulated is True
    assert result.fleet_summary.hardened > 0

    # Verify at least one hardened tunnel has IMPROVED security delta
    hardened = [t for t in result.tunnel_results if t.classification == TunnelSimulationClassification.HARDENED]
    assert len(hardened) > 0
    sample = hardened[0]
    assert sample.security_delta.overall == "IMPROVED"
    assert "hardened" in sample.reason.lower() or "eliminated" in sample.reason.lower()


# --------------------------------------------------------------------------
# TEST 02: Encryption Incompatibility
# --------------------------------------------------------------------------
def test_simulation_02_encryption_incompatibility(dataset, sim_engine):
    """TEST 02: Removing a cipher when it's the only one supported causes INCOMPATIBLE or LATENT_FAILURE."""
    # S01: tn-delhi-mumbai-01 uses 3DES or AES-128-CBC
    # If we remove AES-128-CBC and 3DES and AES-256-CBC, it will break legacy tunnels
    change = ChangeRequest(
        change_id="CHG-TEST-02",
        title="Remove Legacy Ciphers",
        scope=ChangeScope(type=ChangeScopeType.FLEET),
        encryption=EncryptionAction(
            remove=["AES-128-CBC", "3DES", "AES-256-CBC"],
        ),
    )

    result = sim_engine.run_simulation(change)
    broken = [
        t for t in result.tunnel_results
        if t.classification in (TunnelSimulationClassification.INCOMPATIBLE, TunnelSimulationClassification.LATENT_FAILURE)
    ]
    assert len(broken) > 0
    # Every broken tunnel should have INCOMPATIBLE overall delta
    for b in broken:
        assert b.security_delta.overall == "INCOMPATIBLE"


# --------------------------------------------------------------------------
# TEST 03: DH Incompatibility
# --------------------------------------------------------------------------
def test_simulation_03_dh_incompatibility(dataset, sim_engine):
    """TEST 03: Removing DH groups 1, 2, 5, 14 causes incompatibility for legacy devices restricted to them."""
    change = ChangeRequest(
        change_id="CHG-TEST-03",
        title="Disallow Low DH Groups",
        scope=ChangeScope(type=ChangeScopeType.FLEET),
        dh_groups=DHAction(
            remove=[1, 2, 5, 14],
            minimum_dh=19,
        ),
    )

    result = sim_engine.run_simulation(change)
    # Endpoints stuck at DH 14 or lower will fail
    assert (result.fleet_summary.incompatible + result.fleet_summary.latent_failure) > 0


# --------------------------------------------------------------------------
# TEST 04: Latent Rekey Failure
# --------------------------------------------------------------------------
def test_simulation_04_latent_rekey_failure(dataset, sim_engine):
    """TEST 04: Tunnels that are currently UP but have no common proposals under new policy produce LATENT_FAILURE with derived timing."""
    # Find a tunnel that is currently UP
    up_tunnels = [t for t in dataset.tunnels.values() if t.status.value == "UP"]
    assert len(up_tunnels) > 0
    target_tunnel = up_tunnels[0]

    # Target only this tunnel and strip its ciphers
    change = ChangeRequest(
        change_id="CHG-TEST-04",
        title="Policy breaking target UP tunnel",
        scope=ChangeScope(
            type=ChangeScopeType.SINGLE_TUNNEL,
            target_ids=[target_tunnel.tunnel_id],
        ),
        encryption=EncryptionAction(
            remove=["AES-256-GCM", "AES-128-GCM", "AES-256-CBC", "AES-128-CBC", "3DES"],
        ),
    )

    result = sim_engine.run_simulation(change)
    tn_res = [t for t in result.tunnel_results if t.tunnel_id == target_tunnel.tunnel_id][0]

    assert tn_res.classification == TunnelSimulationClassification.LATENT_FAILURE
    assert tn_res.rekey_impact.will_fail_at_rekey is True
    assert tn_res.rekey_impact.next_rekey_seconds == target_tunnel.rekey_interval
    assert tn_res.rekey_impact.time_to_failure is not None
    assert str(target_tunnel.rekey_interval) in tn_res.rekey_impact.time_to_failure
    assert "LATENT FAILURE" in tn_res.reason


# --------------------------------------------------------------------------
# TEST 05: Unrelated Change (UNCHANGED)
# --------------------------------------------------------------------------
def test_simulation_05_unrelated_change(dataset, sim_engine):
    """TEST 05: Changing an isolated endpoint does not affect unrelated tunnels."""
    # Find an endpoint and an unrelated tunnel that does not touch it
    ep_id = list(dataset.endpoints.keys())[0]
    unrelated_tunnels = [
        t for t in dataset.tunnels.values()
        if t.endpoint_a != ep_id and t.endpoint_b != ep_id
    ]
    assert len(unrelated_tunnels) > 0

    change = ChangeRequest(
        change_id="CHG-TEST-05",
        title="Isolated endpoint change",
        scope=ChangeScope(
            type=ChangeScopeType.ENDPOINT,
            target_ids=[ep_id],
        ),
        encryption=EncryptionAction(remove=["3DES"]),
    )

    result = sim_engine.run_simulation(change)
    unrelated_id = unrelated_tunnels[0].tunnel_id
    unrelated_res = [t for t in result.tunnel_results if t.tunnel_id == unrelated_id][0]

    assert unrelated_res.classification == TunnelSimulationClassification.UNCHANGED
    assert unrelated_res.security_delta.overall == "UNCHANGED"


# --------------------------------------------------------------------------
# TEST 06: Unknown Data
# --------------------------------------------------------------------------
def test_simulation_06_unknown_data(dataset, sim_engine):
    """TEST 06: Missing or unobserved peer data yields UNKNOWN classification with conservative reasoning."""
    # Find S12 or an incomplete tunnel if present
    s12_tunnels = [t for t in dataset.tunnels.values() if t.annotations.get("scenario") == "S12"]
    if not s12_tunnels:
        # Check any tunnel with 'incomplete' in id or scenario
        s12_tunnels = [t for t in dataset.tunnels.values() if "incomplete" in t.tunnel_id]

    if s12_tunnels:
        target_s12 = s12_tunnels[0]
        change = ChangeRequest(
            change_id="CHG-TEST-06",
            title="Policy test on unknown/incomplete tunnel",
            scope=ChangeScope(
                type=ChangeScopeType.SINGLE_TUNNEL,
                target_ids=[target_s12.tunnel_id],
            ),
            encryption=EncryptionAction(require=["AES-256-GCM"]),
        )
        result = sim_engine.run_simulation(change)
        res = [t for t in result.tunnel_results if t.tunnel_id == target_s12.tunnel_id][0]
        assert res.classification == TunnelSimulationClassification.UNKNOWN
        assert "cannot be safely determined" in res.reason or "incomplete" in res.reason.lower()


# --------------------------------------------------------------------------
# TEST 07: Fleet Blast Radius
# --------------------------------------------------------------------------
def test_simulation_07_fleet_blast_radius(dataset, sim_engine):
    """TEST 07: Modifying an endpoint reports accurate blast radius containing directly and indirectly affected tunnels."""
    # Pick a hub endpoint with high degree
    ep_id = "ep-delhi-hub-01"
    if ep_id not in dataset.endpoints:
        ep_id = list(dataset.endpoints.keys())[0]

    change = ChangeRequest(
        change_id="CHG-TEST-07",
        title="Hub endpoint policy modification",
        scope=ChangeScope(
            type=ChangeScopeType.ENDPOINT,
            target_ids=[ep_id],
        ),
        encryption=EncryptionAction(remove=["3DES", "AES-128-CBC"]),
    )

    result = sim_engine.run_simulation(change)
    br = result.fleet_summary

    assert br.total_tunnels == len(dataset.tunnels)
    assert ep_id in br.directly_affected_endpoints
    assert br.affected_endpoint_count >= 1
    # Check that affected_tunnel_ids only includes tunnels connected to ep_id
    for tn_id in br.affected_tunnel_ids:
        t = dataset.tunnels[tn_id]
        assert t.endpoint_a == ep_id or t.endpoint_b == ep_id


# --------------------------------------------------------------------------
# TEST 08: Future Twin Immutability
# --------------------------------------------------------------------------
def test_simulation_08_twin_immutability(dataset, sim_engine):
    """TEST 08: Running simulations NEVER mutates the current dataset or current Digital Twin."""
    twin_service = DigitalTwinService(dataset=dataset)
    twin_before = twin_service.build_fleet_twin()

    # Capture raw configurations before simulation
    ep_configs_before = {
        ep_id: copy.deepcopy(ep.configuration.model_dump())
        for ep_id, ep in dataset.endpoints.items()
    }

    # Run aggressive fleet-wide breaking simulation
    change = ChangeRequest(
        change_id="CHG-TEST-08-DESTRUCTIVE",
        title="Aggressive Fleet-Wide Wipeout",
        scope=ChangeScope(type=ChangeScopeType.FLEET),
        encryption=EncryptionAction(remove=["AES-256-GCM", "AES-128-GCM", "AES-256-CBC", "AES-128-CBC", "3DES"]),
        dh_groups=DHAction(remove=[1, 2, 5, 14, 15, 16, 19, 20, 21]),
    )
    sim_result = sim_engine.run_simulation(change)
    assert sim_result is not None

    # Verify dataset endpoints were NOT mutated
    ep_configs_after = {
        ep_id: ep.configuration.model_dump()
        for ep_id, ep in dataset.endpoints.items()
    }
    assert ep_configs_before == ep_configs_after

    # Verify Digital Twin remains identical
    twin_after = twin_service.build_fleet_twin()
    assert twin_before.model_dump() == twin_after.model_dump()


# --------------------------------------------------------------------------
# TEST 09: Simulation REST APIs
# --------------------------------------------------------------------------
def test_simulation_api_endpoints(client):
    """TEST 09: FastAPI simulation endpoints (POST, GET, summary, tunnels, tunnel_id)."""
    payload = {
        "change_id": "CHG-API-01",
        "title": "API Simulation Test",
        "scope": {"type": "FLEET"},
        "encryption": {
            "add": [],
            "remove": ["3DES"],
            "require": ["AES-256-GCM"],
        },
    }

    # 1. POST /api/v1/simulations
    res = client.post("/api/v1/simulations", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["change_id"] == "CHG-API-01"
    sim_id = data["simulation_id"]
    assert data["is_simulated"] is True
    assert "fleet_summary" in data

    # 2. GET /api/v1/simulations/{id}
    res_get = client.get(f"/api/v1/simulations/{sim_id}")
    assert res_get.status_code == 200
    assert res_get.json()["simulation_id"] == sim_id

    # 3. GET /api/v1/simulations/{id}/summary
    res_sum = client.get(f"/api/v1/simulations/{sim_id}/summary")
    assert res_sum.status_code == 200
    assert res_sum.json()["total_tunnels"] > 0

    # 4. GET /api/v1/simulations/{id}/tunnels
    res_tns = client.get(f"/api/v1/simulations/{sim_id}/tunnels")
    assert res_tns.status_code == 200
    tunnels_list = res_tns.json()
    assert len(tunnels_list) > 0
    sample_tn_id = tunnels_list[0]["tunnel_id"]

    # 5. GET /api/v1/simulations/{id}/tunnels?classification=HARDENED
    res_filter = client.get(f"/api/v1/simulations/{sim_id}/tunnels?classification=HARDENED")
    assert res_filter.status_code == 200
    for t in res_filter.json():
        assert t["classification"] == "HARDENED"

    # 6. GET /api/v1/simulations/{id}/tunnels/{tunnel_id}
    res_tn = client.get(f"/api/v1/simulations/{sim_id}/tunnels/{sample_tn_id}")
    assert res_tn.status_code == 200
    assert res_tn.json()["tunnel_id"] == sample_tn_id

    # 7. 404 for unknown simulation
    res_404 = client.get("/api/v1/simulations/sim-non-existent")
    assert res_404.status_code == 404
