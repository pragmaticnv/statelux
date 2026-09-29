"""
STATEFLUX — Canonical Evidence & Provenance Model
=================================================
Phase 5 — AI + Evidence Engine + PCAP Analysis + Security Reporting

Defines the atomic unit of the STATEFLUX provenance chain.
Every finding, prediction, and security assessment links back to one or more
immutable Evidence records with explicit source tracing and provenance classification.
"""

from enum import Enum
from typing import Optional, Any
from datetime import datetime, timezone
from pydantic import Field

from app.models.base import StatefluxBaseModel
from app.models.negotiation_space import ConfidenceLevel


class EvidenceType(str, Enum):
    """Categorical source type of an evidence item."""
    CONFIGURATION = "CONFIGURATION"
    NEGOTIATION = "NEGOTIATION"
    SECURITY_FLOOR = "SECURITY_FLOOR"
    OBSERVATION = "OBSERVATION"
    SIMULATION = "SIMULATION"
    MIGRATION_PLAN = "MIGRATION_PLAN"
    LAB_RESULT = "LAB_RESULT"
    LOG = "LOG"
    PCAP = "PCAP"
    DERIVED = "DERIVED"


class EvidenceProvenance(str, Enum):
    """Strict epistemic classification of how the evidence was obtained."""
    OBSERVED = "OBSERVED"      # Directly captured from live wire, kernel, or daemon log
    DERIVED = "DERIVED"        # Computed deterministically by security rules or floor algorithms
    SIMULATED = "SIMULATED"    # Calculated in what-if simulation from modified policy
    PREDICTED = "PREDICTED"    # Projected future state (e.g. latent rekey failure)
    UNKNOWN = "UNKNOWN"        # Explicit lack of verifiable data


class Evidence(StatefluxBaseModel):
    """An atomic evidence record anchoring observations and findings."""
    evidence_id: str
    evidence_type: EvidenceType
    provenance: EvidenceProvenance
    source_id: str                             # E.g. tunnel_id, endpoint_id, simulation_id, pcap_file
    source_path: Optional[str] = None          # E.g. "data/seed/tunnels.json", "lab/captures/lab01.pcap"
    source_reference: Optional[str] = None     # E.g. "packet_frame_14", "charon_syslog_line_8"
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scope: str = "TUNNEL"                      # "TUNNEL" | "ENDPOINT" | "FLEET" | "LAB"
    asset_ids: list[str] = Field(default_factory=list)
    tunnel_ids: list[str] = Field(default_factory=list)
    observation_ids: list[str] = Field(default_factory=list)
    content_summary: str
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    raw_data: Optional[dict[str, Any]] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
