"""
STATEFLUX — Future Schema: Policy
===================================
PHASE STATUS: PLACEHOLDER — Phase 7/8 Implementation

This stub establishes the data structure for a Policy object.
A Policy defines:
  - which encryption algorithms are permitted
  - which are explicitly forbidden
  - minimum DH group requirements
  - PFS requirements
  - lifetime bounds
  - replay protection requirements

The Policy object is the input to the Change-Impact Simulation Engine.
A proposed change (ChangeRequest) is applied to a base Policy to produce
a new Policy, which is then evaluated against every tunnel in the fleet.

DO NOT implement Policy enforcement logic in Phase 1.
DO NOT connect this to the simulation engine in Phase 1.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class Policy(BaseModel):
    """Versioned security policy (Phase 7/8 placeholder)."""

    model_config = ConfigDict(extra="forbid")

    policy_id:                  str
    name:                       str
    version:                    str
    description:                Optional[str]  = None

    # Cryptographic requirements (to be fully designed in Phase 7)
    allowed_encryption:         list[str]      = []
    forbidden_encryption:       list[str]      = []
    pfs_required:               bool           = False
    minimum_dh_group:           Optional[int]  = None
    replay_protection_required: bool           = True
    ike_version_minimum:        Optional[int]  = None

    # Lifetime constraints
    maximum_ike_lifetime_seconds:   Optional[int] = None
    maximum_ipsec_lifetime_seconds: Optional[int] = None

    # Provenance
    basis_standard:  Optional[str]      = None   # e.g., "NIST SP 800-77r1"
    created_at:      Optional[datetime] = None
    is_baseline:     bool               = False
    parent_policy_id: Optional[str]     = None
