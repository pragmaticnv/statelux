"""
STATEFLUX — Controlled Lab & Validation Data Models
===================================================
Phase 4 — Migration Planner + Real IPsec Lab + Prediction Validation

Defines data models for controlled strongSwan & Libreswan lab runs,
recording actual negotiation outcomes and evaluating model predictions.
"""

from typing import Optional, Any
from datetime import datetime, timezone
from pydantic import Field

from app.models.base import StatefluxBaseModel


class LabResult(StatefluxBaseModel):
    """Execution result from a controlled strongSwan / Libreswan test scenario."""
    lab_run_id: str
    scenario_id: str
    scenario_title: str
    platform_a: str = "strongSwan 5.9.8"
    platform_b: str = "strongSwan 5.9.8"
    initiator_platform: str = "strongSwan"
    responder_platform: str = "strongSwan"

    predicted_result: str  # "ESTABLISHED" | "FAILED" | "LATENT_FAILURE"
    actual_result: str     # "ESTABLISHED" | "FAILED" | "LATENT_FAILURE"
    prediction_match: bool

    predicted_details: dict[str, Any] = Field(default_factory=dict)
    actual_details: dict[str, Any] = Field(default_factory=dict)

    logs: list[str] = Field(default_factory=list)
    capture_reference: Optional[str] = None
    mismatch_reason: Optional[str] = None

    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_controlled_lab: bool = True


class LabValidationMetrics(StatefluxBaseModel):
    """Aggregate agreement metrics between STATEFLUX predictions and real lab outcomes."""
    total_scenarios: int = 0
    correct_predictions: int = 0
    mismatches: int = 0
    match_rate: float = 0.0
    runs: list[LabResult] = Field(default_factory=list)
