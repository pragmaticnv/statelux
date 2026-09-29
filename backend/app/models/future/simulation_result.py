"""
STATEFLUX — Future Schema: SimulationResult
=============================================
PHASE STATUS: PLACEHOLDER — Phase 9/10 Implementation

A SimulationResult is an immutable snapshot of one simulation run.
It is created when an analyst requests to simulate a ChangeRequest
against the current fleet. Results are NEVER overwritten — multiple
runs are preserved for comparison.

Per-tunnel outcomes:
  HARDENED         — compatible proposals remain; new suite is stronger
  UNCHANGED        — compatible proposals remain; strength is equal
  DEGRADED         — compatible proposals remain; new suite is weaker
  INCOMPATIBLE     — no compatible proposals remain; tunnel breaks NOW
  LATENT_FAILURE   — no compatible proposals under new policy, BUT
                     the current SA is still alive; tunnel breaks at next rekey
  UNKNOWN          — insufficient data to determine outcome
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class SimulationTunnelOutcome(BaseModel):
    """Per-tunnel outcome within a simulation run (Phase 9/10 placeholder)."""

    model_config = ConfigDict(extra="forbid")

    tunnel_id:                    str
    outcome:                      str          # HARDENED|UNCHANGED|DEGRADED|INCOMPATIBLE|LATENT_FAILURE|UNKNOWN
    outcome_rationale:            str
    will_break_immediately:       bool         = False
    will_break_at_rekey:          bool         = False
    estimated_failure_at:         Optional[datetime] = None
    compatible_proposals_remaining: int        = 0
    failure_mode:                 Optional[str] = None


class SimulationResult(BaseModel):
    """Immutable snapshot of a simulation run (Phase 9/10 placeholder)."""

    model_config = ConfigDict(extra="forbid")

    simulation_id:        str
    dataset_id:           str
    change_request_id:    str
    policy_id:            str
    status:               str              = "PENDING"   # PENDING|RUNNING|COMPLETE|FAILED
    started_at:           Optional[datetime] = None
    completed_at:         Optional[datetime] = None

    total_tunnels:        int = 0
    count_hardened:       int = 0
    count_unchanged:      int = 0
    count_degraded:       int = 0
    count_incompatible:   int = 0
    count_latent_failure: int = 0
    count_unknown:        int = 0
    blast_radius_count:   int = 0         # degraded + incompatible + latent
    blast_radius_pct:     float = 0.0

    tunnel_outcomes: list[SimulationTunnelOutcome] = []
    created_at: Optional[datetime] = None
