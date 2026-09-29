"""
STATEFLUX — Canonical Deterministic Finding Model
=================================================
Phase 5 — AI + Evidence Engine + PCAP Analysis + Security Reporting

Defines deterministic findings produced by the security rules, floor engine,
simulation blast-radius analysis, lab validation, and PCAP observation fusion.
Severity and confidence are strictly derived from deterministic rules, never invented by AI.
"""

from enum import Enum
from typing import Optional, Any
from datetime import datetime, timezone
from pydantic import Field

from app.models.base import StatefluxBaseModel
from app.models.negotiation_space import ConfidenceLevel


class FindingType(str, Enum):
    """Categorical taxonomy of deterministic findings."""
    WEAK_SELECTED_ALGORITHM = "WEAK_SELECTED_ALGORITHM"
    WEAK_NEGOTIATION_FLOOR = "WEAK_NEGOTIATION_FLOOR"
    INSECURE_FALLBACK = "INSECURE_FALLBACK"
    PFS_GAP = "PFS_GAP"
    WEAK_DH = "WEAK_DH"
    LEGACY_IKE = "LEGACY_IKE"
    REPLAY_PROTECTION_GAP = "REPLAY_PROTECTION_GAP"
    REKEY_LATENT_FAILURE = "REKEY_LATENT_FAILURE"
    NEGOTIATION_INCOMPATIBILITY = "NEGOTIATION_INCOMPATIBILITY"
    TRAFFIC_METADATA_EXPOSURE = "TRAFFIC_METADATA_EXPOSURE"
    EVIDENCE_CONFLICT = "EVIDENCE_CONFLICT"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    SIMULATION_RISK = "SIMULATION_RISK"
    MIGRATION_BLOCKED = "MIGRATION_BLOCKED"
    LAB_PREDICTION_MISMATCH = "LAB_PREDICTION_MISMATCH"


class FindingSeverity(str, Enum):
    """Deterministic severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingReference(StatefluxBaseModel):
    """Security standard or cryptographic specification reference."""
    reference_type: str = "NIST"              # "NIST" | "RFC" | "ANSSI" | "BSI"
    reference_id: str                          # E.g. "NIST SP 800-77 Rev. 1", "RFC 8247"
    reference_title: str
    url_or_identifier: Optional[str] = None


class Finding(StatefluxBaseModel):
    """A deterministic, evidence-backed security finding."""
    finding_id: str
    finding_type: FindingType
    title: str
    severity: FindingSeverity
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    status: str = "ACTIVE"                     # "ACTIVE" | "SUPPRESSED" | "RESOLVED"
    affected_assets: list[str] = Field(default_factory=list)
    affected_tunnels: list[str] = Field(default_factory=list)
    description: str
    evidence_ids: list[str] = Field(default_factory=list)
    derived_from: str                          # Engine or rule generating finding
    remediation: str                           # Actionable remediation instructions
    simulation_reference: Optional[str] = None
    lab_validation_reference: Optional[str] = None
    references: list[FindingReference] = Field(default_factory=list)
    rule_pack_version: str = "2026.1"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)
