"""
STATEFLUX — Migration Planner Data Models
=========================================
Phase 4 — Migration Planner + Real IPsec Lab + Prediction Validation

Defines the data models for dependency-ordered migration waves,
operational risk scoring, preconditions, validation checks,
and structured rollback procedures.
"""

from enum import Enum
from typing import Optional, Any
from datetime import datetime, timezone
from pydantic import Field

from app.models.base import StatefluxBaseModel
from app.models.simulation import TunnelSimulationClassification


class MigrationStrategy(str, Enum):
    """Operational rollout strategy for a migration wave."""
    CANARY = "CANARY"
    LOW_RISK_BATCH = "LOW_RISK_BATCH"
    DEPENDENCY_ORDERED = "DEPENDENCY_ORDERED"
    FINAL_HIGH_RISK = "FINAL_HIGH_RISK"


class WaveRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RollbackPlan(StatefluxBaseModel):
    """Structured, reversible forward and rollback steps for a wave."""
    available: bool = True
    forward_actions: list[str] = Field(default_factory=list, description="Policy actions applied forward.")
    rollback_actions: list[str] = Field(default_factory=list, description="Exact operations required to reverse forward actions.")
    estimated_rollback_seconds: int = 300
    pre_rollback_validation: list[str] = Field(default_factory=lambda: ["VERIFY_DEVICE_CONNECTIVITY", "LOG_ACTIVE_SA_STATE"])


class MigrationWave(StatefluxBaseModel):
    """An ordered, dependency-aware rollout wave."""
    wave_id: str
    order: int
    strategy: MigrationStrategy
    tunnel_ids: list[str] = Field(default_factory=list)
    risk: WaveRiskLevel = WaveRiskLevel.LOW
    modeled_centrality_score: float = 0.0
    prerequisites: list[str] = Field(default_factory=list)
    validation_checks: list[str] = Field(
        default_factory=lambda: [
            "IKE_ESTABLISHED",
            "CHILD_SA_ESTABLISHED",
            "TRAFFIC_FLOW_VERIFIED",
            "EXPECTED_CRYPTOGRAPHIC_SUITE_OBSERVED",
            "NO_UNEXPECTED_NEGOTIATION_FAILURE",
        ]
    )
    rollback: RollbackPlan = Field(default_factory=RollbackPlan)
    depends_on_wave: list[str] = Field(default_factory=list)


class BlockedTunnel(StatefluxBaseModel):
    """Tunnel excluded from waves due to safety invariant violations (e.g. INCOMPATIBLE or LATENT_FAILURE)."""
    tunnel_id: str
    classification: TunnelSimulationClassification
    blocked_reason: str
    required_remediation: str
    endpoint_a: str
    endpoint_b: str


class MigrationPlanSummary(StatefluxBaseModel):
    """Summary statistics for the generated migration plan."""
    total_tunnels: int
    eligible: int
    blocked: int
    unknown: int
    wave_count: int


class MigrationPlan(StatefluxBaseModel):
    """Top-level migration rollout plan."""
    migration_plan_id: str
    simulation_id: str
    objective: str = "Roll out verified policy change without service disruption"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    summary: MigrationPlanSummary
    waves: list[MigrationWave] = Field(default_factory=list)
    blocked_tunnels: list[BlockedTunnel] = Field(default_factory=list)
