"""
STATEFLUX — Deterministic Findings API Routes
=============================================
Phase 5 — AI + Evidence Engine + PCAP Analysis + Security Reporting

Provides endpoints for listing, filtering, and retrieving deterministic security findings
grounded in standards (Rule Pack 2026.1).
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status

from app.models.finding import Finding, FindingSeverity, FindingType
from app.services.finding_engine import FindingEngine

router = APIRouter(prefix="/findings", tags=["Findings"])

_finding_engine = FindingEngine()


def get_finding_engine() -> FindingEngine:
    return _finding_engine


@router.get(
    "",
    response_model=list[Finding],
    summary="List Deterministic Findings",
    description="Retrieve all deterministic cryptographic findings across the fleet, with optional severity and type filters.",
)
async def list_findings(
    severity: Optional[FindingSeverity] = Query(None, description="Filter by finding severity"),
    finding_type: Optional[FindingType] = Query(None, description="Filter by finding taxonomy type"),
) -> list[Finding]:
    findings = _finding_engine.get_all_findings()
    if severity:
        findings = [f for f in findings if f.severity == severity]
    if finding_type:
        findings = [f for f in findings if f.finding_type == finding_type]
    return findings


@router.get(
    "/{finding_id}",
    response_model=Finding,
    summary="Get Single Finding",
    description="Retrieve detailed finding specification including remediation, evidence IDs, and RFC/NIST standard citations.",
)
async def get_finding(finding_id: str) -> Finding:
    finding = _finding_engine.get_finding(finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found.",
        )
    return finding
