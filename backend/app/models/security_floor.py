"""
STATEFLUX — Security Floor & Gap Models
=======================================
Phase 2 — Security Intelligence Layer

Represents:
  - Security Floor Frontier: The Pareto-minimal (weakest non-dominated permitted) proposals.
  - Display Floor: The representative worst permitted state derived from the frontier.
  - Floor Gap: Structured multidimensional degradation between selected and floor posture.
"""

from enum import Enum
from typing import Optional, Any
from pydantic import Field

from app.models.base import StatefluxBaseModel, Protocol
from app.models.security_vector import SecurityVector, StrengthClass
from app.models.negotiation_space import CompatibilityStatus, ConfidenceLevel


class GapLevel(str, Enum):
    """Categorical severity of a security floor gap."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        mapping = {
            GapLevel.NONE: 0,
            GapLevel.LOW: 1,
            GapLevel.MEDIUM: 2,
            GapLevel.HIGH: 3,
            GapLevel.CRITICAL: 4,
            GapLevel.UNKNOWN: -1,
        }
        return mapping[self]


class FloorGapDimension(StatefluxBaseModel):
    """Degradation details for a single security dimension."""
    dimension: str  # "encryption", "integrity", "dh_group", "pfs"
    selected_value: str
    selected_class: StrengthClass
    floor_value: str
    floor_class: StrengthClass
    degradation_level: GapLevel
    description: str


class FloorGap(StatefluxBaseModel):
    """The structured gap between the selected suite and the security floor."""
    gap_level: GapLevel = GapLevel.NONE
    has_gap: bool = False
    summary: str = "No security gap detected."
    dimension_gaps: list[FloorGapDimension] = Field(default_factory=list)


class SecurityFloorResult(StatefluxBaseModel):
    """Detailed Security Floor result for a tunnel or protocol context."""
    tunnel_id: str
    protocol: Protocol

    # Current selected state
    selected: Optional[SecurityVector] = None

    # Full common space (normalized vectors)
    common_space: list[SecurityVector] = Field(default_factory=list)

    # Floor Frontier: all Pareto-minimal (weakest non-dominated) permitted proposals
    floor_frontier: list[SecurityVector] = Field(default_factory=list)

    # Representative display floor
    display_floor: Optional[SecurityVector] = None

    # Operational status
    compatibility: CompatibilityStatus = CompatibilityStatus.UNKNOWN
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    floor_status: str = "COMPUTED"  # "COMPUTED" | "NO_COMMON_SPACE" | "PARTIAL" | "UNKNOWN"

    # Multidimensional gap
    gap: FloorGap = Field(default_factory=FloorGap)
