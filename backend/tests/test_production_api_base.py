"""
STATEFLUX — Production API Base & Same-Origin Test
==================================================
Validates that frontend API configuration uses same-origin relative URLs (/api/v1)
in production and does not leak localhost:8000 to external browsers.
Also verifies root routing and content negotiation.
"""

from pathlib import Path
from app.core.config import settings


class TestProductionApiBase:
    """Verifies same-origin configuration and root endpoint routing."""

    def test_frontend_api_js_defaults_to_same_origin(self):
        """Verify frontend/js/api.js uses same-origin /api/v1 in production."""
        api_js_path = settings.BASE_DIR / "frontend" / "js" / "api.js"
        assert api_js_path.exists(), "frontend/js/api.js must exist"

        content = api_js_path.read_text(encoding="utf-8")

        # Must contain /api/v1 relative base
        assert "'/api/v1'" in content or '"/api/v1"' in content

        # Check the logic for API_BASE
        assert "startsWith('http')" in content or "API_BASE = '/api/v1'" in content

    def test_no_hardcoded_localhost_in_frontend(self):
        """Audit entire frontend directory for hardcoded production localhost/127.0.0.1 API calls."""
        frontend_dir = settings.BASE_DIR / "frontend"
        
        for file_path in frontend_dir.rglob("*.js"):
            content = file_path.read_text(encoding="utf-8")
            lines = content.splitlines()
            for line_no, line in enumerate(lines, 1):
                # Only fallback assignment in api.js is allowed
                if "127.0.0.1:8000" in line or "localhost:8000" in line:
                    assert file_path.name == "api.js", (
                        f"Found hardcoded localhost in {file_path.name}:{line_no}: {line}"
                    )

    def test_browser_root_navigation_redirects_to_ui(self, client):
        """When an evaluator accesses / in a browser (Accept: text/html), it redirects to /ui/."""
        response = client.get("/", headers={"Accept": "text/html,application/xhtml+xml"}, follow_redirects=False)
        assert response.status_code in (307, 301, 302, 308)
        assert response.headers["location"] == "/ui/"

    def test_api_client_root_returns_json(self, client):
        """When an API client accesses / (Accept: application/json), it returns the service registry JSON."""
        response = client.get("/", headers={"Accept": "application/json"})
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "STATEFLUX"
        assert data["endpoints"]["command_center"] == "/ui"

    def test_ui_command_center_served(self, client):
        """Verify /ui/ returns the Command Center web application."""
        response = client.get("/ui/")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
        assert "STATEFLUX" in response.text
