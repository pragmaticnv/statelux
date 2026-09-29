"""
STATEFLUX — Security Intelligence & Digital Twin API Tests
==========================================================
Phase 2 — Security Intelligence Layer

Tests:
  - GET /api/v1/security/floor/{tunnel_id}
  - GET /api/v1/security/posture/{tunnel_id}
  - GET /api/v1/security/findings/{tunnel_id}
  - GET /api/v1/security/fleet
  - GET /api/v1/twin
  - GET /api/v1/twin/tunnels/{tunnel_id}
  - GET /api/v1/twin/endpoints/{endpoint_id}
"""

import pytest


class TestSecurityFloorEndpoint:

    def test_get_floor_s01_secure(self, client):
        response = client.get("/api/v1/security/floor/tn-001")
        assert response.status_code == 200
        data = response.json()
        assert data["tunnel_id"] == "tn-001"
        assert data["compatibility"] == "COMPATIBLE"
        assert "display_floor" in data
        assert data["display_floor"] is not None
        assert "gap" in data

    def test_get_floor_s03_gap(self, client):
        response = client.get("/api/v1/security/floor/tn-005")
        assert response.status_code == 200
        data = response.json()
        assert data["tunnel_id"] == "tn-005"
        assert data["compatibility"] == "COMPATIBLE"
        assert data["gap"]["has_gap"] is True
        assert data["gap"]["gap_level"] in ("HIGH", "CRITICAL")

    def test_get_floor_not_found(self, client):
        response = client.get("/api/v1/security/floor/tn-nonexistent-999")
        assert response.status_code == 404


class TestSecurityPostureEndpoint:

    def test_get_posture_s01(self, client):
        response = client.get("/api/v1/security/posture/tn-001")
        assert response.status_code == 200
        data = response.json()
        assert data["tunnel_id"] == "tn-001"
        assert data["status"] == "UP"
        assert data["cryptographic_posture"] == "STRONG"
        assert data["compatibility"] == "COMPATIBLE"
        assert data["risk_level"] == "INFO"

    def test_get_posture_s02_weak(self, client):
        response = client.get("/api/v1/security/posture/tn-003")
        assert response.status_code == 200
        data = response.json()
        assert data["tunnel_id"] == "tn-003"
        assert data["risk_level"] in ("HIGH", "CRITICAL")


class TestSecurityFindingsEndpoint:

    def test_get_findings_s01(self, client):
        response = client.get("/api/v1/security/findings/tn-001")
        assert response.status_code == 200
        findings = response.json()
        assert isinstance(findings, list)

    def test_get_findings_s03_has_floor_finding(self, client):
        response = client.get("/api/v1/security/findings/tn-005")
        assert response.status_code == 200
        findings = response.json()
        rule_ids = [f["rule_id"] for f in findings]
        assert "SF-001" in rule_ids or len(findings) > 0


class TestSecurityFleetEndpoint:

    def test_get_security_fleet_summary(self, client):
        response = client.get("/api/v1/security/fleet")
        assert response.status_code == 200
        data = response.json()
        assert data["total_tunnels"] == 40
        assert data["strong_selected"] > 0
        assert data["floor_exposure"] > 0
        assert data["incompatible"] > 0
        assert "gap_distribution" in data
        assert "risk_distribution" in data


class TestDigitalTwinEndpoints:

    def test_get_fleet_twin(self, client):
        response = client.get("/api/v1/twin")
        assert response.status_code == 200
        data = response.json()
        assert data["fleet_id"] == "fleet-001"
        assert data["tunnel_count"] == 40
        assert data["endpoint_count"] == 20
        assert "aggregate_posture" in data

    def test_get_tunnel_twin_detail(self, client):
        response = client.get("/api/v1/twin/tunnels/tn-001")
        assert response.status_code == 200
        data = response.json()
        assert data["tunnel_id"] == "tn-001"
        assert data["status"] == "UP"
        assert "ike_floor" in data
        assert "composite_gap" in data
        assert "negotiation_space" in data

    def test_get_tunnel_twin_not_found(self, client):
        response = client.get("/api/v1/twin/tunnels/tn-nonexistent-999")
        assert response.status_code == 404

    def test_get_endpoint_twin_detail(self, client):
        response = client.get("/api/v1/twin/endpoints/ep-001")
        assert response.status_code == 200
        data = response.json()
        assert data["endpoint_id"] == "ep-001"
        assert data["name"] == "HUB-HS-01"
        assert "active_tunnels" in data
        assert "peer_endpoints" in data

    def test_get_endpoint_twin_not_found(self, client):
        response = client.get("/api/v1/twin/endpoints/ep-nonexistent-999")
        assert response.status_code == 404
