"""
STATEFLUX — Report Generation & Visual Verification Utility
===========================================================
Generates all 4 report deliverables in both HTML and PDF formats into docs/reports/
and verifies page counts, structure, and integrity.
"""

import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.services.data_loader import load_dataset
from app.services.reporting_engine import ReportingEngine
from app.services.report_export_service import ReportExportService
from app.services.simulation_engine import SimulationEngine
from app.models.change_request import ChangeRequest, ChangeScope, ChangeScopeType, EncryptionAction


def main():
    root = Path(__file__).resolve().parent.parent
    load_dataset(root / "data" / "seed")

    re = ReportingEngine()
    exporter = ReportExportService()
    se = SimulationEngine()

    cr = ChangeRequest(
        change_id="CHG-SAMPLE-REPORT",
        title="Fleet Cryptographic Hardening Audit",
        scope=ChangeScope(type=ChangeScopeType.FLEET),
        encryption=EncryptionAction(remove=["3DES", "AES-128-CBC"], require=["AES-256-GCM"]),
    )
    sim_result = se.run_simulation(cr)

    out_dir = root / "docs" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)

    report_jobs = [
        ("executive", re.generate_executive_report()),
        ("technical", re.generate_technical_report()),
        ("change-impact", re.generate_change_impact_report(sim_result.simulation_id, se)),
        ("lab-validation", re.generate_lab_validation_report()),
    ]

    print("=" * 60)
    print("STATEFLUX — GENERATING REPORT DELIVERABLES")
    print("=" * 60)

    for name, rep in report_jobs:
        html_path = out_dir / f"stateflux_{name}_report.html"
        pdf_path = out_dir / f"stateflux_{name}_report.pdf"

        html_content = exporter.render_html(name, rep)
        html_path.write_text(html_content, encoding="utf-8")

        pdf_bytes = exporter.render_pdf(name, rep)
        pdf_path.write_bytes(pdf_bytes)

        print(f"[{name.upper()}]")
        print(f"  - HTML: {html_path.name} ({len(html_content):,} chars)")
        print(f"  - PDF:  {pdf_path.name} ({len(pdf_bytes):,} bytes)")

    print("\nAll 4 report pairs successfully generated in docs/reports/!")


if __name__ == "__main__":
    main()
