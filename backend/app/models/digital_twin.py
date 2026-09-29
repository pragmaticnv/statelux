"""
STATEFLUX — Digital Twin Models
===============================
Phase 2 — Security Intelligence Layer

Represents derived Digital Twin state for:
  - Fleet (identity, topology maps, aggregate security posture)
  - Endpoint (modeled capabilities, proposal inventory, peer relationships)
  - Tunnel (selected security, floor frontier, display floor, multidimensional gap)
"""

from typing import Optional, Any
from pydantic import Field

from app.models.base import StatefluxBaseModel
from app.models.security_floor import SecurityFloorResult, FloorGap, GapLevel
from app.models.negotiation_space import TunnelNegotiationSpace, CompatibilityStatus, ConfidenceLevel


class FleetSecurityAggregation(StatefluxBaseModel):
    """Aggregate security intelligence across the entire fleet."""
    total_tunnels: int = 0
    strong_selected: int = 0
    floor_exposure: int = 0          # Tunnels where floor gap is HIGH or CRITICAL
    policy_violations: int = 0       # Tunnels with legacy/insecure ciphers or IKEv1
    incompatible: int = 0            # Tunnels that failed negotiation
    unknown: int = 0                 # Tunnels with partial/unknown data
    gap_distribution: dict[str, int] = Field(default_factory=dict)
    risk_distribution: dict[str, int] = Field(default_factory=dict)
    confidence_distribution: dict[str, int] = Field(default_factory=dict)


class TunnelTwinState(StatefluxBaseModel):
    """Derived Digital Twin state for a single tunnel."""
    tunnel_id: str
    endpoint_a: str
    endpoint_b: str
    mode: str
    status: str
    rekey_interval: int

    # Separate protocol floors
    ike_floor: SecurityFloorResult
    child_sa_floor: Optional[SecurityFloorResult] = None

    # Common negotiation space
    negotiation_space: TunnelNegotiationSpace

    # Composite postures
    composite_gap: FloorGap
    compatibility: CompatibilityStatus
    confidence: ConfidenceLevel

    # Posture dimensions
    cryptographic_posture: str
    pfs_posture: str
    replay_posture: str

    # Baseline risk assessment & findings
    risk_score: float = 0.0
    risk_level: str = "INFO"
    finding_count: int = 0
    findings: list[dict[str, Any]] = Field(default_factory=list)


class EndpointTwinState(StatefluxBaseModel):
    """Derived Digital Twin state for a single endpoint."""
    endpoint_id: str
    fleet_id: str
    name: str
    platform: str
    platform_version: Optional[str] = None
    profile_type: str
    validation_status: str

    # Capabilities & configuration summary
    pfs_supported: bool
    ike_versions: list[str] = Field(default_factory=list)
    ike_proposals_count: int = 0
    esp_proposals_count: int = 0

    # Graph relationships
    active_tunnels: list[str] = Field(default_factory=list)
    peer_endpoints: list[str] = Field(default_factory=list)

    # Posture summary
    posture_summary: dict[str, Any] = Field(default_factory=dict)


class FleetTwinOverview(StatefluxBaseModel):
    """Derived Digital Twin state for the fleet."""
    fleet_id: str
    name: str
    environment: str
    endpoint_count: int
    tunnel_count: int
    aggregate_posture: FleetSecurityAggregation
    disclaimer: str
