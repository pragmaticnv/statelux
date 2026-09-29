"""
STATEFLUX — Future Schema: LabResult
========================================
PHASE STATUS: PLACEHOLDER — Phase 14/15 Implementation

A LabResult records the real outcome of running a specific IPsec
negotiation scenario in the strongSwan/Libreswan Docker lab environment.

Lab results serve one critical function:
  VERIFY whether simulation predictions match real VPN behavior.

Mismatches (predicted FAIL, actual SUCCESS) are NOT hidden.
They are displayed prominently in the Lab Verification screen
and used to improve the simulation model's accuracy.

Prediction quality (match rate) is a first-class metric of STATEFLUX.
A system that hides its own prediction errors is not trustworthy.

All lab results must have is_synthetic=True because they come from
a controlled lab, not from a real production VPN environment.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class LabResult(BaseModel):
    """Real outcome of a strongSwan/Libreswan lab test (Phase 14/15 placeholder)."""

    model_config = ConfigDict(extra="forbid")

    lab_result_id:            str
    scenario_id:              str

    # References
    simulation_tunnel_result_id: Optional[str] = None

    # Lab configuration
    initiator_platform:       str             # "strongSwan" | "Libreswan"
    responder_platform:       str
    initiator_config_snapshot: Optional[str] = None
    responder_config_snapshot: Optional[str] = None
    ike_version_tested:       Optional[int]  = None

    # Actual outcome
    negotiation_outcome:      str             # SUCCESS | FAIL | TIMEOUT | ERROR
    selected_ike_suite:       Optional[str]  = None
    selected_esp_suite:       Optional[str]  = None
    failure_reason:           Optional[str]  = None
    pcap_path:                Optional[str]  = None

    # Prediction validation
    predicted_outcome:        Optional[str]  = None
    prediction_match:         Optional[bool] = None
    mismatch_explanation:     Optional[str]  = None

    is_synthetic:             bool           = True   # Always True for lab results
    run_at:                   Optional[datetime] = None
