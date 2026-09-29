"""
STATEFLUX — API Route Integration Tests
========================================
Tests all REST endpoints exposed by the Phase 1A backend:
  - /api/v1/health
  - /api/v1/fleet
  - /api/v1/fleet/stats
  - /api/v1/endpoints (listing, filtering, detail, 404)
  - /api/v1/tunnels (listing, filtering, detail, 404)
  - /api/v1/analysis/fleet (fleet baseline assessment)
  - /api/v1/analysis/tunnel/{tunnel_id} (per-tunnel baseline assessment)
"""

import pytest


class TestRootEndpoint:

    def test_root_returns_200(self, client):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "STATEFLUX"
        assert data["version"] == "1.0.0-phase1a"
        assert data["documentation"] == "/docs"
        assert "endpoints" in data


class TestHealthEndpoint:

    def test_health_returns_200(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == "1.0.0-phase1a"
        assert data["dataset_loaded"] is True
        assert data["is_synthetic"] is True
        assert "disclaimer" in data
        assert "SYNTHETIC" in data["disclaimer"]
        assert "entity_counts" in data
        assert data["entity_counts"]["endpoints"] == 20
        assert data["entity_counts"]["tunnels"] == 40


class TestFleetEndpoints:

    def test_get_fleet_summary(self, client):
        response = client.get("/api/v1/fleet")
        assert response.status_code == 200
        data = response.json()
        assert data["fleet_id"] == "fleet-001"
        assert "STATEFLUX" in data["name"]
        assert data["endpoint_count"] == 20
        assert data["tunnel_count"] == 40

    def test_get_fleet_stats(self, client):
        response = client.get("/api/v1/fleet/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["is_loaded"] is True
        assert data["is_synthetic"] is True
        assert data["entity_counts"]["endpoints"] == 20
        assert data["entity_counts"]["tunnels"] == 40
        assert data["entity_counts"]["proposals"] >= 100


class TestEndpointsRoutes:

    def test_list_all_endpoints(self, client):
        response = client.get("/api/v1/endpoints")
        assert response.status_code == 200
        endpoints = response.json()
        assert len(endpoints) == 20
        first = endpoints[0]
        assert "endpoint_id" in first
        assert "name" in first
        assert "platform" in first
        assert "profile_type" in first
        assert "validation_status" in first

    def test_filter_endpoints_by_profile(self, client):
        response = client.get("/api/v1/endpoints?profile_type=HIGH_SECURITY")
        assert response.status_code == 200
        endpoints = response.json()
        assert len(endpoints) >= 1
        for ep in endpoints:
            assert ep["profile_type"] == "HIGH_SECURITY"

    def test_filter_endpoints_by_validation_status(self, client):
        response = client.get("/api/v1/endpoints?validation_status=VALIDATED")
        assert response.status_code == 200
        endpoints = response.json()
        assert len(endpoints) > 0
        for ep in endpoints:
            assert ep["validation_status"] == "VALIDATED"

    def test_get_endpoint_detail_success(self, client):
        response = client.get("/api/v1/endpoints/ep-001")
        assert response.status_code == 200
        data = response.json()
        assert data["endpoint_id"] == "ep-001"
        assert data["name"] == "HUB-HS-01"
        assert data["platform"] == "strongSwan"
        assert "configuration" in data
        assert "capabilities" in data

    def test_get_endpoint_detail_not_found(self, client):
        response = client.get("/api/v1/endpoints/ep-nonexistent-999")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()


class TestTunnelsRoutes:

    def test_list_all_tunnels(self, client):
        response = client.get("/api/v1/tunnels")
        assert response.status_code == 200
        tunnels = response.json()
        assert len(tunnels) == 40
        first = tunnels[0]
        assert "tunnel_id" in first
        assert "endpoint_a" in first
        assert "endpoint_b" in first
        assert "status" in first

    def test_filter_tunnels_by_status(self, client):
        response = client.get("/api/v1/tunnels?status=UP")
        assert response.status_code == 200
        tunnels = response.json()
        assert len(tunnels) > 0
        for t in tunnels:
            assert t["status"] == "UP"

    def test_filter_tunnels_by_scenario(self, client):
        response = client.get("/api/v1/tunnels?scenario=S01")
        assert response.status_code == 200
        tunnels = response.json()
        assert len(tunnels) >= 2
        for t in tunnels:
            assert t["scenario"] == "S01"

    def test_filter_tunnels_by_endpoint(self, client):
        response = client.get("/api/v1/tunnels?endpoint=ep-001")
        assert response.status_code == 200
        tunnels = response.json()
        assert len(tunnels) > 0
        for t in tunnels:
            assert t["endpoint_a"] == "ep-001" or t["endpoint_b"] == "ep-001"

    def test_get_tunnel_detail_success(self, client):
        response = client.get("/api/v1/tunnels/tn-001")
        assert response.status_code == 200
        data = response.json()
        assert data["tunnel_id"] == "tn-001"
        assert data["endpoint_a"] == "ep-001"
        assert data["endpoint_b"] == "ep-004"
        assert "_negotiation" in data
        assert data["_negotiation"] is not None
        assert "_security_state" in data
        assert data["_security_state"] is not None

    def test_get_tunnel_detail_not_found(self, client):
        response = client.get("/api/v1/tunnels/tn-nonexistent-999")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()


class TestAnalysisRoutes:

    def test_analyze_fleet(self, client):
        response = client.get("/api/v1/analysis/fleet")
        assert response.status_code == 200
        data = response.json()
        assert data["fleet_id"] == "fleet-001"
        assert data["total_tunnels"] == 40
        assert data["tunnels_analyzed"] == 40
        assert data["is_synthetic"] is True
        assert "SYNTHETIC" in data["disclaimer"]
        assert "risk_distribution" in data
        assert "assessments" in data
        assert len(data["assessments"]) == 40

        # Verify risk distribution counts sum to total
        risk_dist = data["risk_distribution"]
        total_in_dist = sum(risk_dist.values())
        assert total_in_dist == 40

    def test_analyze_secure_tunnel(self, client):
        response = client.get("/api/v1/analysis/tunnel/tn-001")
        assert response.status_code == 200
        data = response.json()
        assert data["tunnel_id"] == "tn-001"
        assert data["risk_level"] == "INFO"
        assert data["risk_score"] == 0.0
        assert data["encryption"] == "AES-256-GCM"
        assert data["dh_group"] == 20
        assert data["sa_status"] == "UP"

    def test_analyze_weak_tunnel(self, client):
        response = client.get("/api/v1/analysis/tunnel/tn-003")
        assert response.status_code == 200
        data = response.json()
        assert data["tunnel_id"] == "tn-003"
        assert data["risk_level"] in ("HIGH", "CRITICAL")
        assert data["risk_score"] >= 55.0
        assert data["encryption"] == "3DES"
        assert len(data["findings"]) > 0

    def test_analyze_tunnel_not_found(self, client):
        response = client.get("/api/v1/analysis/tunnel/tn-nonexistent-999")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()
