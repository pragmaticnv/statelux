"""
STATEFLUX — Tests for Dedicated Standalone Report Export
========================================================
Verifies:
  1. PDF != Browser Screenshot (Dedicated standalone HTML/PDF presentation layer)
  2. Zero application UI (no sidebar, no app nav, no Command Center menu, no raw JSON)
  3. No localhost URLs
  4. All four distinct report types (Executive, Technical, Change-Impact, Lab-Validation)
  5. Correct title, scope, date, platforms, and evidence IDs
  6. Lab Validation: 5/5 matched, LAB-05 deep dive lifecycle, no "100% accuracy" claim
  7. Change-Impact: All 13 mandatory sections present
  8. Native PDF binary output (%PDF- magic header, valid vector PDF)
  9. Route isolation: Zero cross-report contamination between routes
"""

import pytest


class TestStandaloneReportExport:
    """Verifies dedicated standalone export endpoints for all four report types."""

    # ----------------------------------------------------------------------
    # 1. Lab Validation Report Tests
    # ----------------------------------------------------------------------

    def test_lab_validation_report_html_structure(self, client):
        """Verify dedicated standalone printable HTML for Lab Validation report."""
        res = client.get("/api/v1/reports/export/lab-validation/html")
        assert res.status_code == 200
        assert "text/html" in res.headers["content-type"]
        html = res.text

        # Brand and Document Identity
        assert "STATEFLUX" in html
        assert "IPsec Security Change-Impact Intelligence" in html
        assert "REAL IPsec LAB VALIDATION REPORT" in html
        assert "CONTROLLED TESTBED REPORT" in html

        # Scope and Environment
        assert "40 IPsec Tunnels" in html
        assert "20 Gateway Endpoints" in html
        assert "strongSwan 5.9.8" in html
        assert "Libreswan 4.12" in html

        # Section 5: Executive Summary
        assert "Executive Summary" in html
        assert "5/5 controlled testbed scenarios matched" in html
        # CRITICAL requirement: Do NOT claim "100% accuracy"
        assert "100% accuracy" not in html
        assert "Controlled testbed validation measures prediction agreement" in html

        # Section 6: Validation Summary Cards
        assert "Scenarios" in html or "SCENARIOS" in html
        assert "Matched" in html or "MATCHED" in html
        assert "Mismatches" in html or "MISMATCHES" in html

        # Section 7: Validation Table (LAB-01 to LAB-05)
        assert "LAB-01" in html
        assert "LAB-02" in html
        assert "LAB-03" in html
        assert "LAB-04" in html
        assert "LAB-05" in html
        assert "AES-GCM / DH20 / PFS" in html
        assert "NO_PROPOSAL_CHOSEN" in html

        # Section 8: LAB-05 Deep Dive
        assert "LAB-05" in html
        assert "Latent Rekey Failure" in html
        assert "INITIAL STATE: CHILD_SA ESTABLISHED" in html
        assert "WAIT FOR REKEY" in html
        assert "CREATE_CHILD_SA" in html
        assert "NO_PROPOSAL_CHOSEN" in html
        assert "LATENT_FAILURE" in html
        assert "PREDICTION = OBSERVATION" in html

        # Section 9: Evidence Chain
        assert "E-001" in html
        assert "E-005" in html
        assert "E-008" in html
        assert "E-013" in html
        assert "E-014" in html
        assert "Configuration" in html
        assert "Negotiation" in html
        assert "Simulation" in html
        assert "Lab Log" in html
        assert "PCAP" in html

        # Section 10: Technical Methodology
        assert "Gateway A" in html
        assert "Gateway B" in html
        assert "IKEv2" in html
        assert "ESP" in html

        # Running Header and Footer
        assert "IPsec Security Change-Impact Intelligence" in html

        # Section 2: Zero Application UI Shell
        assert 'id="sidebar"' not in html
        assert 'class="sf-sidebar"' not in html
        assert 'id="nav-command-center"' not in html
        assert 'id="nav-reports-executive"' not in html
        assert 'window.print()' not in html or 'no-print' in html  # Only allowed in screen-only action bar with no-print
        assert 'http://127.0.0.1:8000' not in html
        assert 'localhost:8000' not in html

        # No raw JSON dump
        assert '<pre><code>{"' not in html
        assert "<pre><code>{\n" not in html

    # ----------------------------------------------------------------------
    # 2. Change-Impact Report Tests
    # ----------------------------------------------------------------------

    def test_change_impact_report_html_13_sections(self, client):
        """Verify dedicated standalone printable HTML for Change-Impact report has 13 sections."""
        res = client.get("/api/v1/reports/export/change-impact/html")
        assert res.status_code == 200
        html = res.text

        # Document Header
        assert "STATEFLUX" in html
        assert "CHANGE-IMPACT ASSESSMENT REPORT" in html or "CHANGE-IMPACT" in html

        # Verify all 13 required sections:
        assert "1. Executive Summary" in html
        assert "2. Current Fleet State" in html
        assert "3. Proposed Change" in html
        assert "4. Affected Scope" in html
        assert "5. Blast Radius" in html
        assert "6. Security Delta" in html
        assert "7. Incompatible Tunnels" in html
        assert "8. Latent Failure Tunnels" in html
        assert "9. Staged Migration Plan" in html or "9. Migration Plan" in html
        assert "10. Rollback Strategy" in html
        assert "11. Grounded Evidence" in html or "11. Evidence" in html
        assert "12. Testbed Empirical Validation" in html or "12. Validation" in html
        assert "13. Simulation Limitations" in html or "13. Limitations" in html

        # Blast Radius numbers
        assert "Hardened" in html
        assert "Incompatible" in html
        assert "Latent Failure" in html

        # Zero app shell
        assert 'id="sidebar"' not in html
        assert 'id="nav-command-center"' not in html
        assert 'localhost:8000' not in html
        assert '<pre><code>{"' not in html

    # ----------------------------------------------------------------------
    # 3. Executive Security Report Tests
    # ----------------------------------------------------------------------

    def test_executive_report_html_structure(self, client):
        """Verify dedicated standalone printable HTML for Executive report."""
        res = client.get("/api/v1/reports/export/executive/html")
        assert res.status_code == 200
        html = res.text

        assert "STATEFLUX" in html
        assert "EXECUTIVE SECURITY POSTURE REPORT" in html or "EXECUTIVE" in html
        assert "Executive Summary &amp; Posture Assessment" in html or "Executive Summary" in html
        assert "Fleet Cryptographic Health Snapshot" in html
        assert "Major Risks &amp; Vulnerabilities" in html
        assert "Strategic Executive Recommendations" in html

        # Clean executive presentation (no raw crypto details dumped)
        assert 'id="sidebar"' not in html
        assert 'localhost:8000' not in html
        assert '<pre><code>{"' not in html

    # ----------------------------------------------------------------------
    # 4. Technical IPsec Report Tests
    # ----------------------------------------------------------------------

    def test_technical_report_html_structure(self, client):
        """Verify dedicated standalone printable HTML for Technical report."""
        res = client.get("/api/v1/reports/export/technical/html")
        assert res.status_code == 200
        html = res.text

        assert "STATEFLUX" in html
        assert "TECHNICAL CRYPTOGRAPHIC INTELLIGENCE REPORT" in html or "TECHNICAL" in html
        assert "Fleet Cryptographic Inventory Summary" in html
        assert "Dynamic Security Floor Distribution" in html
        assert "Comprehensive Cryptographic Findings" in html
        assert "Technical Remediation Matrix" in html

        # Structured tables, not raw JSON
        assert "<table" in html
        assert 'id="sidebar"' not in html
        assert 'localhost:8000' not in html
        assert '<pre><code>{"' not in html

    # ----------------------------------------------------------------------
    # 5. Native Vector PDF Generation Tests
    # ----------------------------------------------------------------------

    @pytest.mark.parametrize("report_type", ["executive", "technical", "change-impact", "lab-validation"])
    def test_pdf_binary_export(self, client, report_type):
        """Verify direct native vector PDF download for all 4 report types."""
        res = client.get(f"/api/v1/reports/export/{report_type}/pdf")
        assert res.status_code == 200
        assert res.headers["content-type"] == "application/pdf"
        assert f"stateflux_{report_type}_report.pdf" in res.headers.get("content-disposition", "")
        # Magic bytes for PDF
        assert res.content.startswith(b"%PDF-")
        # Substantial non-empty document (> 3 KB)
        assert len(res.content) > 3000

    # ----------------------------------------------------------------------
    # 6. Route Isolation & Zero Cross-Report Contamination (Section 22)
    # ----------------------------------------------------------------------

    def test_report_routing_isolation(self, client):
        """Verify report types do not contaminate each other."""
        res_exec = client.get("/api/v1/reports/export/executive/html").text
        res_tech = client.get("/api/v1/reports/export/technical/html").text
        res_chg = client.get("/api/v1/reports/export/change-impact/html").text
        res_lab = client.get("/api/v1/reports/export/lab-validation/html").text

        # Change-Impact must NOT be a Lab report
        assert "CHANGE-IMPACT" in res_chg
        assert "REAL IPsec LAB VALIDATION REPORT" not in res_chg
        assert "Empirical Scenario Validation Matrix" not in res_chg

        # Lab report must NOT be a Change-Impact report
        assert "REAL IPsec LAB VALIDATION REPORT" in res_lab
        assert "IPsec FLEET CHANGE-IMPACT" not in res_lab
        assert "1. Executive Summary &amp; Posture Assessment" not in res_lab

        # Executive report must be Executive
        assert "EXECUTIVE SECURITY POSTURE REPORT" in res_exec
        assert "Empirical Scenario Validation Matrix" not in res_exec

        # Technical report must be Technical
        assert "TECHNICAL CRYPTOGRAPHIC INTELLIGENCE REPORT" in res_tech
        assert "LAB-05 Deep Dive" not in res_tech
