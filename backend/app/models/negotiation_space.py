"""
STATEFLUX — Negotiation Space Models
====================================
Phase 2 — Security Intelligence Layer

Represents the common negotiation space between two endpoints:
  Endpoint A proposals ∩ Endpoint B proposals

Maintains separate semantic evaluation for:
  - IKE Common Space
  - Child-SA / ESP Common Space
"""

from enum import Enum
from typing import Optional, Any
from pydantic import Field

from app.models.base import StatefluxBaseModel, NegotiationStatus


class CompatibilityStatus(str, Enum):
    """Compatibility status between two negotiating endpoints."""
    COMPATIBLE = "COMPATIBLE"
    INCOMPATIBLE_IKE = "INCOMPATIBLE_IKE"
    INCOMPATIBLE_CHILD_SA = "INCOMPATIBLE_CHILD_SA"
    INCOMPATIBLE = "INCOMPATIBLE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class ConfidenceLevel(str, Enum):
    """Confidence level of assessment based on input completeness and provenance."""
    HIGH = "HIGH"          # Both endpoint configurations verified & complete
    MEDIUM = "MEDIUM"      # Partial config or observed negotiation without full config
    LOW = "LOW"            # Inferred from incomplete/telemetry observations
    UNKNOWN = "UNKNOWN"    # Insufficient data to determine posture


class ProposalMatch(StatefluxBaseModel):
    """A match between an offer from initiator (Endpoint A) and responder (Endpoint B)."""
    proposal_id_a: str
    proposal_id_b: str
    protocol: str
    is_identical: bool
    common_encryption: str
    common_integrity: Optional[str] = None
    common_dh_group: Optional[int] = None
    pfs_agreed: Optional[bool] = None


class TunnelNegotiationSpace(StatefluxBaseModel):
    """The computed negotiation space for a single tunnel."""
    tunnel_id: str
    endpoint_a: str
    endpoint_b: str

    # Separate spaces
    ike_common_space: list[str] = Field(default_factory=list)
    child_sa_common_space: list[str] = Field(default_factory=list)

    # Offers preserved in priority order
    ike_offers_a: list[str] = Field(default_factory=list)
    ike_offers_b: list[str] = Field(default_factory=list)
    esp_offers_a: list[str] = Field(default_factory=list)
    esp_offers_b: list[str] = Field(default_factory=list)

    # Detailed match records
    ike_matches: list[ProposalMatch] = Field(default_factory=list)
    esp_matches: list[ProposalMatch] = Field(default_factory=list)

    # Selected suites (if active/negotiated)
    selected_ike_proposal: Optional[str] = None
    selected_esp_proposal: Optional[str] = None
    selection_rule: str = "HIGHEST_PRIORITY_COMMON"

    # Outcome
    compatibility_status: CompatibilityStatus = CompatibilityStatus.UNKNOWN
    failure_reason: Optional[str] = None
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    provenance_notes: list[str] = Field(default_factory=list)

    @property
    def has_ike_intersection(self) -> bool:
        return len(self.ike_common_space) > 0

    @property
    def has_child_sa_intersection(self) -> bool:
        return len(self.child_sa_common_space) > 0

    @property
    def is_fully_compatible(self) -> bool:
        return self.compatibility_status == CompatibilityStatus.COMPATIBLE
