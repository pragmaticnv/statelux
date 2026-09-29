"""
STATEFLUX — Security & Change Impact Reports API Routes
=======================================================
Phase 5 & Final Export Fix

Provides endpoints for generating executive, technical, change-impact, and lab validation reports.
All reports are available as:
  1. Structured, machine-readable JSON artifacts
  2. Standalone, publication-grade printable HTML (no app UI/sidebar)
  3. Direct native vector PDF documents (ReportLab)
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, status, Query, Response
from fastapi.responses import HTMLResponse
from pydantic import Field

from app.models.base import StatefluxBaseModel
from app.models.report import (
    ExecutiveSecurityReport,
    TechnicalIPsecReport,
    ChangeImpactReport,
    LabValidationReport,
)
from app.services.reporting_engine import ReportingEngine
from app.services.report_export_service import ReportExportService
from app.api.routes.simulation import get_simulation_engine
from app.api.routes.migrations import get_migration_planner

router = APIRouter(prefix="/reports", tags=["Reports"])

_reporting_engine = ReportingEngine()
_export_service = ReportExportService()


def get_reporting_engine() -> ReportingEngine:
    return _reporting_engine


def get_export_service() -> ReportExportService:
    return _export_service


class ChangeImpactReportRequest(StatefluxBaseModel):
    simulation_id: Optional[str] = Field(None, description="Simulation ID for which to generate change-impact report.")


def _resolve_simulation_id(sim_id: Optional[str] = None) -> str:
    """Helper to ensure a simulation ID exists, creating a baseline if none has been run."""
    sim_engine = get_simulation_engine()
    if sim_id:
        return sim_id
    sims = sim_engine.get_all_simulations()
    if sims:
        return sims[0].simulation_id

    from app.models.change_request import ChangeRequest, ChangeScope, ChangeScopeType, EncryptionAction
    baseline_change = ChangeRequest(
        change_id="CHG-BASELINE-REPORT",
        title="Baseline Hardening Simulation",
        scope=ChangeScope(type=ChangeScopeType.FLEET),
        encryption=EncryptionAction(remove=["3DES", "AES-128-CBC"], require=["AES-256-GCM"]),
    )
    sim_result = sim_engine.run_simulation(baseline_change)
    return sim_result.simulation_id


def _get_report_model(report_type: str, simulation_id: Optional[str] = None):
    """Retrieve the canonical report object for a given report type."""
    type_norm = report_type.lower().replace("_", "-")
    if type_norm in ["executive", "executive-security"]:
        return _reporting_engine.generate_executive_report()
    elif type_norm in ["technical", "technical-ipsec"]:
        return _reporting_engine.generate_technical_report()
    elif type_norm in ["change-impact", "change_impact"]:
        sim_id = _resolve_simulation_id(simulation_id)
        return _reporting_engine.generate_change_impact_report(
            simulation_id=sim_id,
            sim_engine=get_simulation_engine(),
            planner_service=get_migration_planner(),
        )
    elif type_norm in ["lab-validation", "lab_validation", "lab"]:
        return _reporting_engine.generate_lab_validation_report()
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown report type: '{report_type}'. Must be one of: executive, technical, change-impact, lab-validation.",
        )


# ===========================================================================
# 1. JSON Report Endpoints (GET and POST for client flexibility)
# ===========================================================================

@router.get("/executive", response_model=ExecutiveSecurityReport, summary="Get Executive Security Report")
@router.post("/executive", response_model=ExecutiveSecurityReport, summary="Generate Executive Security Report")
async def generate_executive_report() -> ExecutiveSecurityReport:
    try:
        return _reporting_engine.generate_executive_report()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {str(exc)}",
        )


@router.get("/technical", response_model=TechnicalIPsecReport, summary="Get Technical IPsec Report")
@router.post("/technical", response_model=TechnicalIPsecReport, summary="Generate Technical IPsec Report")
async def generate_technical_report() -> TechnicalIPsecReport:
    try:
        return _reporting_engine.generate_technical_report()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {str(exc)}",
        )


@router.get("/change-impact", response_model=ChangeImpactReport, summary="Get Change-Impact Report")
async def get_change_impact_report(simulation_id: Optional[str] = Query(None)) -> ChangeImpactReport:
    try:
        sim_id = _resolve_simulation_id(simulation_id)
        return _reporting_engine.generate_change_impact_report(
            simulation_id=sim_id,
            sim_engine=get_simulation_engine(),
            planner_service=get_migration_planner(),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {str(exc)}",
        )


@router.post("/change-impact", response_model=ChangeImpactReport, summary="Generate Change-Impact Report")
async def generate_change_impact_report(request: Optional[ChangeImpactReportRequest] = None) -> ChangeImpactReport:
    try:
        sim_id = _resolve_simulation_id(request.simulation_id if request else None)
        return _reporting_engine.generate_change_impact_report(
            simulation_id=sim_id,
            sim_engine=get_simulation_engine(),
            planner_service=get_migration_planner(),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {str(exc)}",
        )


@router.get("/lab-validation", response_model=LabValidationReport, summary="Get Real IPsec Lab Validation Report")
@router.post("/lab-validation", response_model=LabValidationReport, summary="Generate Real IPsec Lab Validation Report")
async def generate_lab_validation_report() -> LabValidationReport:
    try:
        return _reporting_engine.generate_lab_validation_report()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {str(exc)}",
        )


# ===========================================================================
# 2. Standalone HTML Printable Export Endpoints (NO App UI, Print CSS)
# ===========================================================================

@router.get(
    "/export/{report_type}/html",
    response_class=HTMLResponse,
    summary="Export Standalone Printable HTML Report",
    description="Renders dedicated standalone report HTML with print stylesheet and zero application UI shell.",
)
async def export_report_html(
    report_type: str,
    simulation_id: Optional[str] = Query(None),
) -> HTMLResponse:
    try:
        report_obj = _get_report_model(report_type, simulation_id=simulation_id)
        html_content = _export_service.render_html(report_type, report_obj)
        return HTMLResponse(content=html_content, status_code=status.HTTP_200_OK)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"HTML report export failed: {str(exc)}",
        )


@router.post(
    "/export/{report_type}/html",
    response_class=HTMLResponse,
    summary="Export Standalone Printable HTML Report (POST)",
)
async def export_report_html_post(
    report_type: str,
    request: Optional[ChangeImpactReportRequest] = None,
) -> HTMLResponse:
    try:
        sim_id = request.simulation_id if request else None
        report_obj = _get_report_model(report_type, simulation_id=sim_id)
        html_content = _export_service.render_html(report_type, report_obj)
        return HTMLResponse(content=html_content, status_code=status.HTTP_200_OK)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"HTML report export failed: {str(exc)}",
        )


# ===========================================================================
# 3. Native Vector PDF Export Endpoints (ReportLab Engine)
# ===========================================================================

@router.get(
    "/export/{report_type}/pdf",
    summary="Download Standalone Native Vector PDF Report",
    description="Generates publication-grade vector PDF with clean cover, running headers/footers, and page-break control.",
)
async def export_report_pdf(
    report_type: str,
    simulation_id: Optional[str] = Query(None),
) -> Response:
    try:
        report_obj = _get_report_model(report_type, simulation_id=simulation_id)
        pdf_bytes = _export_service.render_pdf(report_type, report_obj)
        filename = f"stateflux_{report_type.lower().replace('_', '-')}_report.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PDF report export failed: {str(exc)}",
        )


@router.post(
    "/export/{report_type}/pdf",
    summary="Download Standalone Native Vector PDF Report (POST)",
)
async def export_report_pdf_post(
    report_type: str,
    request: Optional[ChangeImpactReportRequest] = None,
) -> Response:
    try:
        sim_id = request.simulation_id if request else None
        report_obj = _get_report_model(report_type, simulation_id=sim_id)
        pdf_bytes = _export_service.render_pdf(report_type, report_obj)
        filename = f"stateflux_{report_type.lower().replace('_', '-')}_report.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PDF report export failed: {str(exc)}",
        )


# ===========================================================================
# 4. JSON Attachment Download Endpoint
# ===========================================================================

@router.get(
    "/export/{report_type}/json",
    summary="Download Structured JSON Report Artifact",
)
async def export_report_json(
    report_type: str,
    simulation_id: Optional[str] = Query(None),
) -> Response:
    try:
        report_obj = _get_report_model(report_type, simulation_id=simulation_id)
        json_content = report_obj.model_dump_json(indent=2)
        filename = f"stateflux_{report_type.lower().replace('_', '-')}_report.json"
        return Response(
            content=json_content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"JSON report export failed: {str(exc)}",
        )
