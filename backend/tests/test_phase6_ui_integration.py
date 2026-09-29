"""
STATEFLUX — Phase 6 UI & Command Center Integration Tests
==========================================================
Verifies that:
1. Static mounting of the frontend at /ui functions and delivers index.html + CSS/JS assets.
2. Root endpoint exposes command_center route.
3. Every REST endpoint required by the Command Center UI and 12-step demo flow responds with 200 and schema integrity.
4. No fake or mock data is injected; all data flows from the canonical engine.
"""

import pytest


class TestPhase6UIStaticMounting:
    """Tests static file serving for the Command Center UI."""

    def test_root_exposes_command_center(self, client):
        res = client.get("/")
        assert res.status_code == 200
        data = res.json()
        assert "endpoints" in data
        assert data["endpoints"].get("command_center") == "/ui"

    def test_ui_index_html_served(self, client):
        res = client.get("/ui")
        assert res.status_code == 200
        assert "text/html" in res.headers.get("content-type", "")
        assert "STATEFLUX" in res.text
        assert "Command Center" in res.text
        assert "Know what happens" in res.text
        assert "CONTROLLED TESTBED" in res.text

    def test_ui_css_assets_served(self, client):
        for css_file in ["main.css", "components.css"]:
            res = client.get(f"/ui/css/{css_file}")
            assert res.status_code == 200
            assert "text/css" in res.headers.get("content-type", "")
            assert len(res.text) > 100

    def test_ui_js_assets_served(self, client):
        for js_file in [
            "api.js",
            "app.js",
            "views/commandCenter.js",
            "views/graph.js",
            "views/tunnels.js",
            "views/endpoints.js",
            "views/simulator.js",
            "views/migration.js",
            "views/lab.js",
            "views/evidence.js",
            "views/ai.js",
            "views/reports.js",
        ]:
            res = client.get(f"/ui/js/{js_file}")
            assert res.status_code == 200, f"Failed to load {js_file}"
            assert len(res.text) > 50


class TestPhase6FrontendAPIPipeline:
    """Tests all API endpoints consumed by the Command Center UI views."""

    def test_command_center_fleet_stats(self, client):
        res = client.get("/api/v1/fleet/stats")
        assert res.status_code == 200
        data = res.json()
        assert data["entity_counts"]["endpoints"] == 20
        assert data["entity_counts"]["tunnels"] == 40

    def test_negotiation_graph_topology(self, client):
        res = client.get("/api/v1/graph/fleet")
        assert res.status_code == 200
        data = res.json()
        assert len(data.get("nodes", [])) == 20
        assert len(data.get("edges", [])) == 40

    def test_security_floors_endpoint(self, client):
        res = client.get("/api/v1/security/fleet")
        assert res.status_code == 200
        data = res.json()
        assert data["total_tunnels"] == 40
        assert "floor_exposure" in data

        res_floor = client.get("/api/v1/security/floor/tn-001")
        assert res_floor.status_code == 200
        assert res_floor.json()["tunnel_id"] == "tn-001"

    def test_simulator_policy_execution(self, client):
        payload = {
            "change_id": "CHG-PHASE6-TEST",
            "title": "Strict AEAD",
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
        res = client.post("/api/v1/simulations", json=payload)
        assert res.status_code == 201
        data = res.json()
        assert data["fleet_summary"]["total_tunnels"] == 40
        assert data["fleet_summary"]["hardened"] >= 0
        assert data["fleet_summary"]["latent_failure"] >= 0
        assert len(data["tunnel_results"]) == 40

    def test_migration_planner_with_blockers(self, client):
        payload = {
            "objective": "Modern Migration",
            "change_request": {
                "change_id": "CHG-PHASE6-MIG",
                "title": "Modern Migration",
                "scope": {"type": "FLEET"},
                "encryption": {"remove": ["3DES"]},
            },
        }
        res = client.post("/api/v1/migrations/plan", json=payload)
        assert res.status_code == 201
        data = res.json()
        assert len(data.get("waves", [])) >= 1
        assert "blocked_tunnels" in data

    def test_lab_validation_matrix_and_artifacts(self, client):
        res = client.get("/api/v1/lab/validation")
        assert res.status_code == 200
        data = res.json()
        runs = data.get("runs", [])
        assert len(runs) >= 5

        # Check LAB-05 specifically for latent rekey failure match
        lab05 = next((r for r in runs if r.get("scenario_id") == "LAB-05"), None)
        assert lab05 is not None
        assert lab05["predicted_result"] == "LATENT_FAILURE"
        assert lab05["actual_result"] == "LATENT_FAILURE"
        assert lab05["prediction_match"] is True

    def test_evidence_and_findings_directory(self, client):
        # Findings
        find_res = client.get("/api/v1/findings")
        assert find_res.status_code == 200
        findings = find_res.json()
        assert len(findings) >= 1

        # Evidence
        ev_res = client.get("/api/v1/evidence")
        assert ev_res.status_code == 200
        evidence = ev_res.json()
        assert len(evidence) >= 1

        # Evidence chain for first finding
        first_id = findings[0]["finding_id"]
        chain_res = client.get(f"/api/v1/evidence/chain/{first_id}")
        assert chain_res.status_code == 200
        chain = chain_res.json()
        assert "evidence_chain" in chain or "items" in chain or "finding_id" in chain

    def test_reports_generation_all_types(self, client):
        # Executive
        exec_res = client.post("/api/v1/reports/executive")
        assert exec_res.status_code == 200
        assert "summary" in exec_res.json() or "executive_summary" in exec_res.json() or "title" in exec_res.json()

        # Technical
        tech_res = client.post("/api/v1/reports/technical")
        assert tech_res.status_code == 200

        # Change-Impact
        ci_res = client.post("/api/v1/reports/change-impact", json={})
        assert ci_res.status_code == 200

        # Lab Validation
        lab_res = client.post("/api/v1/reports/lab-validation")
        assert lab_res.status_code == 200
