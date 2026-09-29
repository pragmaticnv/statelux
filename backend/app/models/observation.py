"""
STATEFLUX — Observation Model
==============================
An Observation is the atomic unit of data provenance.

Every claim STATEFLUX makes about a tunnel, endpoint, or proposal
should eventually be traceable to one or more Observations. An
Observation records:
  - WHERE the data came from (source_type + source_id)
  - WHAT entity it describes (entity_type + entity_id)
  - WHICH specific field was observed (field)
  - WHAT value was seen (value — may be None if explicitly unknown)
  - HOW confident we are (confidence: 0.0–1.0)
  - WHEN it was observed (timestamp)

UNKNOWN VALUES:
  value=None does NOT mean "not observed yet".
  It means "observed, but the value could not be determined".
  This is an explicit epistemic state, not a missing data marker.
  Do not invent values. Represent incomplete knowledge explicitly.

CONFIDENCE:
  1.0 = directly read from a verified configuration
  0.9 = directly read from a PCAP with high parse confidence
  0.7 = inferred from indirect evidence
  0.5 = assumed based on endpoint profile defaults
  0.0 = completely unknown (value should also be None in this case)
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import field_validator

from app.models.base import (
    StatefluxBaseModel,
    SourceType,
    EntityType,
)


class Observation(StatefluxBaseModel):
    """A single observed data point about an IPsec entity.

    Attributes:
        observation_id:  Unique identifier (e.g., "obs-001").
        source_type:     The origin of this observation.
        source_id:       Reference to the specific source artifact
                         (e.g., a PCAP filename, a config file path,
                         a frame number, a lab run ID).
        entity_type:     What kind of entity this observation describes.
        entity_id:       The ID of the specific entity instance.
        field:           Dot-notation path to the observed field
                         (e.g., "selected.encryption", "capabilities.pfs_supported").
        value:           The observed value. May be None to explicitly indicate
                         that the field was observed but could not be determined.
        confidence:      Confidence in this observation: [0.0, 1.0].
        timestamp:       When this observation was made.
        notes:           Optional free-text analyst annotation.
    """

    observation_id: str
    source_type:    SourceType
    source_id:      str
    entity_type:    EntityType
    entity_id:      str
    field:          str
    value:          Optional[Any]   = None
    confidence:     float
    timestamp:      datetime
    notes:          Optional[str]   = None

    @field_validator("confidence")
    @classmethod
    def confidence_must_be_in_range(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError(
                f"confidence must be between 0.0 and 1.0, got {v}"
            )
        return v
