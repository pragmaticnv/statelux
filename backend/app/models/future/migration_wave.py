"""
STATEFLUX — Future Schema: MigrationWave
==========================================
PHASE STATUS: PLACEHOLDER — Phase 12/13 Implementation

A MigrationWave is one group of tunnels within an ordered migration plan.
Migration plans are generated after a simulation run and provide an
operational sequence for safely deploying a policy change without
creating unacceptable service disruption.

Wave ordering principles:
  Wave 1 — Canary (lowest criticality, isolated tunnels)
  Wave 2 — Non-critical regional tunnels
  Wave 3 — Dependent infrastructure tunnels
  Wave 4 — Critical gateways and hub tunnels

Each wave includes validation criteria and rollback procedures.
The migration goal is: IMPROVE SECURITY without OPERATIONAL DISRUPTION.
"""

from typing import Optional

from pydantic import BaseModel, ConfigDict


class MigrationWave(BaseModel):
    """One wave in a dependency-ordered migration plan (Phase 12/13 placeholder)."""

    model_config = ConfigDict(extra="forbid")

    wave_id:              str
    simulation_id:        str
    wave_number:          int
    label:                str              # e.g., "Wave 1 — Canary"
    tunnel_ids:           list[str]        = []
    prerequisite_wave_ids: list[str]       = []

    rationale:            str
    expected_impact:      str
    validation_criteria:  str
    rollback_procedure:   str
    estimated_risk_level: str              = "MEDIUM"   # CRITICAL|HIGH|MEDIUM|LOW

    # Set by Phase 14 lab verification
    lab_verified:         bool             = False
    verification_notes:   Optional[str]    = None
