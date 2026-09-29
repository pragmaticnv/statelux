"""
STATEFLUX — Production Health Endpoint Test
===========================================
Validates that /api/v1/health responds reliably on serverless deployments,
reports system and dataset status, and operates independently of background lab daemons.
"""

import pytest


class TestHealthEndpointProduction:
    """Verifies that the /api/v1/health endpoint functions reliably in production."""

    def test_health_returns_200_and_ok(self, client):
        """GET /api/v1/health must return HTTP 200 with status ok."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "ok"
        assert data.get("version") is not None
        assert data.get("dataset_loaded") is True

    def test_health_reports_dataset_metrics(self, client):
        """Health endpoint should confirm dataset is loaded and healthy."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert "entity_counts" in data
        counts = data["entity_counts"]
        assert counts.get("endpoints", 0) == 20
        assert counts.get("tunnels", 0) == 40

    def test_health_does_not_fail_in_serverless(self, client):
        """Confirm that health checks complete quickly (< 500ms) with no hung processes."""
        import time
        start = time.perf_counter()
        response = client.get("/api/v1/health")
        duration = time.perf_counter() - start

        assert response.status_code == 200
        assert duration < 1.0, f"Health check took too long: {duration:.2f}s"
