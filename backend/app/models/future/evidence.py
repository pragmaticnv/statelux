"""
STATEFLUX — Future Schema: Evidence
======================================
PHASE STATUS: PLACEHOLDER — Phase 13/14 Implementation

An Evidence record is the atomic element of the STATEFLUX provenance chain.

Every Finding must eventually be traceable through a chain of Evidence
records back to the raw source material (a PCAP packet, a config line,
or a lab result).

The provenance chain has the shape:
  Source (PCAP packet / config line)
      ↓
  Observation (parsed field value)
      ↓
  Rule (evaluated by Crypto Rules Engine)
      ↓
  Finding (specific security claim)
      ↓
  Simulation (if this finding led to a simulation outcome)
      ↓
  Recommendation

Evidence is different from Observation:
  - An Observation records a raw data point.
  - An Evidence record links an Observation (or other source) to a Finding.
  - Multiple Evidence records can support a single Finding.
  - A single Observation can appear in multiple Evidence records.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class Evidence(BaseModel):
    """An Evidence record linking a source to a finding (Phase 13/14 placeholder)."""

    model_config = ConfigDict(extra="forbid")

    evidence_id:       str
    evidence_type:     str              # PACKET | CONFIG_LINE | INFERRED | LAB_RESULT | SYNTHETIC

    # Source reference
    dataset_id:        Optional[str]   = None
    source_file:       Optional[str]   = None
    frame_number:      Optional[int]   = None   # PCAP frame number
    config_line:       Optional[int]   = None   # Config file line number

    # Observed value
    raw_value:         Optional[str]   = None
    field_path:        Optional[str]   = None

    # Inference metadata
    confidence:        float           = 1.0
    inference_method:  Optional[str]   = None

    # Linking
    finding_ids:       list[str]       = []    # Which findings this evidence supports

    is_synthetic:      bool            = False
    observation_time:  Optional[datetime] = None
    created_at:        Optional[datetime] = None
