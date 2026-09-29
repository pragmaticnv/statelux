"""
STATEFLUX — Production Paths & Asset Availability Test
======================================================
Validates that project-root resolution, static assets, templates,
and seed datasets are found and readable in production runtime layout.
"""

from pathlib import Path
from app.core.config import settings
from app.services.report_export_service import ReportExportService, TEMPLATE_DIR, STYLE_DIR


class TestProductionPaths:
    """Verifies that all required filesystem assets are present and accessible."""

    def test_project_root_resolution(self):
        """Verify settings.BASE_DIR points to repository root."""
        base_dir = settings.BASE_DIR
        assert base_dir.exists(), f"BASE_DIR {base_dir} does not exist"
        assert (base_dir / "backend").exists(), "backend/ directory missing from BASE_DIR"
        assert (base_dir / "frontend").exists(), "frontend/ directory missing from BASE_DIR"
        assert (base_dir / "data").exists(), "data/ directory missing from BASE_DIR"

    def test_seed_dataset_availability(self):
        """Verify seed dataset files exist and are readable."""
        seed_dir = settings.SEED_DIR
        assert seed_dir.exists(), f"SEED_DIR {seed_dir} does not exist"
        seed_files = list(seed_dir.glob("*.json"))
        assert len(seed_files) >= 5, f"Expected at least 5 seed JSON files, found {len(seed_files)}"
        
        required_files = ["endpoints.json", "tunnels.json", "proposals.json", "negotiations.json", "observations.json"]
        for fname in required_files:
            assert (seed_dir / fname).exists(), f"Required seed file {fname} is missing"

    def test_frontend_assets_availability(self):
        """Verify frontend index.html and asset subdirectories exist."""
        frontend_dir = settings.BASE_DIR / "frontend"
        assert (frontend_dir / "index.html").exists(), "frontend/index.html is missing"
        assert (frontend_dir / "js" / "api.js").exists(), "frontend/js/api.js is missing"
        assert (frontend_dir / "js" / "app.js").exists(), "frontend/js/app.js is missing"
        assert (frontend_dir / "css" / "main.css").exists(), "frontend/css/main.css is missing"

    def test_report_templates_and_styles_availability(self):
        """Verify report templates and styling sheets are present."""
        assert TEMPLATE_DIR.exists(), f"TEMPLATE_DIR {TEMPLATE_DIR} does not exist"
        assert STYLE_DIR.exists(), f"STYLE_DIR {STYLE_DIR} does not exist"

        expected_templates = [
            "executive_report.html",
            "technical_report.html",
            "change_impact_report.html",
            "lab_validation_report.html",
        ]
        for tpl in expected_templates:
            assert (TEMPLATE_DIR / tpl).exists(), f"Report template {tpl} missing"

        assert (STYLE_DIR / "report.css").exists(), "report_styles/report.css missing"

    def test_report_service_asset_binding(self):
        """Verify ReportExportService can read templates and CSS without errors."""
        svc = ReportExportService()
        css = svc._get_css()
        assert "/* report.css not found */" not in css
        assert len(css) > 500, "report.css appears empty"

        # Verify Jinja environment can locate templates
        template = svc.jinja_env.get_template("executive_report.html")
        assert template is not None
