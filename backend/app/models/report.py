"""
STATEFLUX — Security & Change Impact Report Models
==================================================
Phase 5 — AI + Evidence Engine + PCAP Analysis + Security Reporting

Defines structured report artifacts:
  1. Executive Security Report
  2. Technical IPsec Report
  3. Change-Impact Report
  4. Lab Validation Report
"""

from enum import Enum
from typing import Optional, Any
from datetime import datetime, timezone
from pydantic import Field

from app.models.base import StatefluxBaseModel
from app.models.finding import Finding
from app.models.simulation import FleetBlastRadius, SecurityDelta
from app.models.lab import LabResult, LabValidationMetrics


class ReportType(str, Enum):
    EXECUTIVE_SECURITY = "EXECUTIVE_SECURITY"
    TECHNICAL_IPSEC = "TECHNICAL_IPSEC"
    CHANGE_IMPACT = "CHANGE_IMPACT"
    LAB_VALIDATION = "LAB_VALIDATION"


class ExecutiveSecurityReport(StatefluxBaseModel):
    """Executive-level synthesis of fleet cryptographic posture, exposure, and risk."""
    report_id: str
    report_type: ReportType = ReportType.EXECUTIVE_SECURITY
    title: str = "STATEFLUX Executive Fleet Security Posture Report"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    fleet_posture: str                         # "STRONG" | "ACCEPTABLE" | "DEGRADED" | "CRITICAL"
    total_tunnels: int
    compliant_tunnels: int
    tunnels_with_critical_exposure: int
    weak_floor_exposure_count: int
    latent_failure_candidates: int
    key_executive_findings: list[dict[str, Any]] = Field(default_factory=list)
    strategic_recommendations: list[str] = Field(default_factory=list)
    overall_confidence: str = "HIGH"
    ai_executive_summary: Optional[str] = None


class TechnicalIPsecReport(StatefluxBaseModel):
    """Deep technical breakdown of fleet cryptographic configurations, floors, and observations."""
    report_id: str
    report_type: ReportType = ReportType.TECHNICAL_IPSEC
    title: str = "STATEFLUX Technical Cryptographic Intelligence Report"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    endpoint_count: int
    tunnel_count: int
    proposal_count: int
    detailed_findings: list[Finding] = Field(default_factory=list)
    pcap_observations_summary: dict[str, Any] = Field(default_factory=dict)
    log_events_summary: dict[str, Any] = Field(default_factory=dict)
    negotiation_floor_distribution: dict[str, int] = Field(default_factory=dict)
    evidence_chain_count: int = 0
    technical_remediation_matrix: list[dict[str, Any]] = Field(default_factory=list)


class ChangeImpactReport(StatefluxBaseModel):
    """Evaluation of proposed policy change, blast radius, latent risks, and wave rollout."""
    report_id: str
    report_type: ReportType = ReportType.CHANGE_IMPACT
    title: str = "STATEFLUX Change-Impact & Safe Rollout Assessment"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    simulation_id: str
    migration_plan_id: Optional[str] = None
    change_objective: str
    blast_radius: FleetBlastRadius
    security_delta_summary: dict[str, int] = Field(default_factory=dict)
    latent_failure_tunnels: list[dict[str, Any]] = Field(default_factory=list)
    blocked_migration_tunnels: list[dict[str, Any]] = Field(default_factory=list)
    wave_sequence_summary: list[dict[str, Any]] = Field(default_factory=list)
    rollback_safeguards: list[str] = Field(default_factory=list)
    ai_impact_analysis: Optional[str] = None


class LabValidationReport(StatefluxBaseModel):
    """Controlled testbed validation results comparing simulation predictions against real daemons."""
    report_id: str
    report_type: ReportType = ReportType.LAB_VALIDATION
    title: str = "STATEFLUX Real IPsec Lab Validation Report"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    validation_metrics: LabValidationMetrics
    scenarios_evaluated: list[LabResult] = Field(default_factory=list)
    daemon_platforms: list[str] = Field(default_factory=list)
    rekey_validation_notes: str
    mismatch_analysis: list[dict[str, Any]] = Field(default_factory=list)
    methodology_statement: str = "Controlled testbed validation measures prediction agreement in isolated containers; does not claim broad production ML accuracy."
