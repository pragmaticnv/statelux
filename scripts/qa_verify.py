"""
STATEFLUX — Final QA Verification Script
Validates data consistency across API endpoints, graph, simulation, migration, lab, and reports.
"""

import sys
from pathlib import Path

# Add backend to sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from app.main import app


def run_qa_checks():
    with TestClient(app) as client:
        print("--- 1. Fleet Stats Check ---")
        f_res = client.get("/api/v1/fleet/stats")
        assert f_res.status_code == 200
        fleet_data = f_res.json()
        tunnels_count = fleet_data["entity_counts"]["tunnels"]
        endpoints_count = fleet_data["entity_counts"]["endpoints"]
        print(f"PASS: {tunnels_count} tunnels, {endpoints_count} endpoints")

        print("--- 2. Graph Topology Check ---")
        g_res = client.get("/api/v1/graph/fleet")
        assert g_res.status_code == 200
        g_data = g_res.json()
        assert len(g_data["nodes"]) == 20
        assert len(g_data["edges"]) == 40
        print(f"PASS: {len(g_data['nodes'])} nodes, {len(g_data['edges'])} edges")

        print("--- 3. Simulation & Blast Radius Check ---")
        sim_payload = {
            "change_id": "QA-VERIFY-SIM",
            "title": "Strict AEAD Baseline",
            "scope": {"type": "FLEET"},
            "encryption": {
                "remove": ["3DES", "AES-128-CBC"],
                "require": ["AES-256-GCM"],
            },
            "dh_groups": {
                "remove": [2, 5, 14],
                "minimum_dh": 19,
            },
            "pfs": {"mode": "REQUIRE"},
            "ike": {"require_ikev2": True},
        }
        s_res = client.post("/api/v1/simulations", json=sim_payload)
        assert s_res.status_code == 201
        s_data = s_res.json()
        blast = s_data["fleet_summary"]
        total = blast["total_tunnels"]
        sum_classes = (
            blast["hardened"]
            + blast["unchanged"]
            + blast["degraded"]
            + blast["incompatible"]
            + blast["latent_failure"]
            + blast["unknown"]
        )
        assert total == 40
        assert sum_classes == 40
        print(f"PASS: Blast radius reconciles perfectly (Total={total}, Sum={sum_classes}): "
              f"H={blast['hardened']}, U={blast['unchanged']}, D={blast['degraded']}, "
              f"I={blast['incompatible']}, L={blast['latent_failure']}, Unk={blast['unknown']}")

        print("--- 4. Migration Planner & Blockers Invariant Check ---")
        m_payload = {
            "objective": "QA Modern Migration",
            "change_request": sim_payload,
        }
        m_res = client.post("/api/v1/migrations/plan", json=m_payload)
        assert m_res.status_code == 201
        m_data = m_res.json()
        waves = m_data["waves"]
        blockers = m_data["blocked_tunnels"]
        assert len(waves) >= 1
        assert len(blockers) > 0
        all_wave_tunnels = []
        for w in waves:
            all_wave_tunnels.extend(w["tunnel_ids"])
        for b in blockers:
            assert b["tunnel_id"] not in all_wave_tunnels
        print(f"PASS: {len(waves)} waves generated. {len(blockers)} blocked tunnels strictly excluded from rollout.")

        print("--- 5. Prediction vs Reality Check ---")
        l_res = client.get("/api/v1/lab/validation")
        assert l_res.status_code == 200
        l_data = l_res.json()
        assert l_data["total_scenarios"] >= 5
        assert l_data["match_rate"] == 1.0
        lab05 = next(r for r in l_data["runs"] if r["scenario_id"] == "LAB-05")
        assert lab05["predicted_result"] == "LATENT_FAILURE"
        assert lab05["actual_result"] == "LATENT_FAILURE"
        assert lab05["prediction_match"] is True
        print("PASS: 5/5 controlled testbed scenarios matched. LAB-05 latent rekey failure verified.")

        print("--- 6. Findings & Grounded Evidence Chain Check ---")
        f_res = client.get("/api/v1/findings")
        assert f_res.status_code == 200
        findings = f_res.json()
        assert len(findings) > 0
        sample_fid = findings[0]["finding_id"]
        chain_res = client.get(f"/api/v1/evidence/chain/{sample_fid}")
        assert chain_res.status_code == 200
        chain = chain_res.json()
        assert chain["count"] >= 1
        print(f"PASS: Finding {sample_fid} linked to {chain['count']} verified evidence artifacts.")

        print("--- 7. Reports Reconciliation Check ---")
        rep_res = client.post("/api/v1/reports/executive")
        assert rep_res.status_code == 200
        rep_data = rep_res.json()
        assert rep_data["total_tunnels"] == 40
        print(f"PASS: Executive Report reconciles: total_tunnels={rep_data['total_tunnels']}.")

        print("--- ALL QA CONSISTENCY CHECKS PASSED ---")


if __name__ == "__main__":
    run_qa_checks()
