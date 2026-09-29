"""
STATEFLUX — Simulation Result & Change Impact Models
====================================================
Phase 3 — Fleet Intelligence & Change-Impact Engine

Models simulation classifications, multidimensional security deltas,
latent rekey failure timing, and fleet blast radius.
"""

from enum import Enum
from typing import Optional, Any
from datetime import datetime, timezone
from pydantic import Field

from app.models.base import StatefluxBaseModel
from app.models.change_request import ChangeScope
from app.models.negotiation_space import ConfidenceLevel


class TunnelSimulationClassification(str, Enum):
    """Primary classification of a tunnel's simulated outcome."""
    HARDENED = "HARDENED"
    UNCHANGED = "UNCHANGED"
    DEGRADED = "DEGRADED"
    INCOMPATIBLE = "INCOMPATIBLE"
    LATENT_FAILURE = "LATENT_FAILURE"
    UNKNOWN = "UNKNOWN"


class SecurityDelta(StatefluxBaseModel):
    """Multidimensional delta between before and after security postures."""
    encryption: str = "UNCHANGED"  # "IMPROVED" | "UNCHANGED" | "DEGRADED" | "UNKNOWN"
    dh: str = "UNCHANGED"
    pfs: str = "UNCHANGED"
    floor: str = "UNCHANGED"
    risk_delta: float = 0.0        # Negative means risk reduced; positive means increased
    overall: str = "UNCHANGED"     # "IMPROVED" | "UNCHANGED" | "DEGRADED" | "INCOMPATIBLE"


class RekeyImpact(StatefluxBaseModel):
    """Modeled rekey and lifetime failure projection."""
    current_status: str = "UP"
    next_rekey_seconds: Optional[int] = None
    next_rekey_timestamp: Optional[datetime] = None
    time_to_failure: Optional[str] = None
    will_fail_at_rekey: bool = False
    future_compatibility: str = "COMPATIBLE"


class TunnelSimulationResult(StatefluxBaseModel):
    """Detailed impact result for a single tunnel."""
    tunnel_id: str
    classification: TunnelSimulationClassification
    before_state: dict[str, Any] = Field(default_factory=dict)
    after_state: dict[str, Any] = Field(default_factory=dict)
    security_delta: SecurityDelta = Field(default_factory=SecurityDelta)
    compatibility_impact: str = "UNCHANGED"
    rekey_impact: RekeyImpact = Field(default_factory=RekeyImpact)
    reason: str
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH


class FleetBlastRadius(StatefluxBaseModel):
    """Fleet-wide aggregation of simulation outcomes and affected graph scope."""
    total_tunnels: int = 0
    hardened: int = 0
    unchanged: int = 0
    degraded: int = 0
    incompatible: int = 0
    latent_failure: int = 0
    unknown: int = 0
    affected_endpoint_count: int = 0
    affected_tunnel_ids: list[str] = Field(default_factory=list)
    directly_affected_endpoints: list[str] = Field(default_factory=list)
    indirectly_affected_tunnels: list[str] = Field(default_factory=list)


class SimulationResult(StatefluxBaseModel):
    """Authoritative top-level simulation report."""
    simulation_id: str
    change_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scope: ChangeScope
    fleet_summary: FleetBlastRadius
    tunnel_results: list[TunnelSimulationResult] = Field(default_factory=list)
    is_simulated: bool = True
