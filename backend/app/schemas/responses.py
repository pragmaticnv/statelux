"""
STATEFLUX — API Response Schemas
==================================
Pydantic models for API response bodies.
These are separate from the domain models to allow independent evolution
of the API surface without coupling it to internal data structures.
"""

from typing import Any, Optional
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status:           str
    version:          str
    dataset_loaded:   bool
    dataset_source:   Optional[str]
    load_timestamp:   Optional[datetime]
    entity_counts:    dict[str, int]
    is_synthetic:     bool
    disclaimer:       str


class FleetSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fleet_id:       str
    name:           str
    description:    str
    environment:    str
    created_at:     datetime
    endpoint_count: int
    tunnel_count:   int
    notes:          Optional[str] = None


class EndpointSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    endpoint_id:       str
    name:              str
    platform:          str
    platform_version:  str
    profile_type:      str
    validation_status: str
    proposal_count_ike: int
    proposal_count_esp: int
    pfs_supported:     bool
    ike_versions:      list[str]


class TunnelSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tunnel_id:         str
    endpoint_a:        str
    endpoint_b:        str
    mode:              str
    status:            str
    negotiation_id:    Optional[str]
    security_state_id: Optional[str]
    rekey_interval:    int
    scenario:          Optional[str]  # from annotations
    risk_level:        Optional[str]  # from security state
    risk_score:        Optional[float]


class FindingResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id:     str
    rule_id:        str
    severity:       str
    title:          str
    description:    str
    recommendation: str
    affected_field: str
    observed_value: Any


class TunnelAssessmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tunnel_id:          str
    ike_version:        Optional[str]
    mode:               str
    encryption:         Optional[str]
    key_size:           Optional[int]
    integrity:          Optional[str]
    dh_group:           Optional[int]
    pfs:                Optional[bool]
    replay_protection:  Optional[bool]
    rekey_interval:     int
    sa_status:          str
    findings:           list[FindingResponse]
    risk_score:         float
    risk_level:         str
    finding_count:      int
    assessment_version: str
    analysis_source:    str


class FleetAssessmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fleet_id:         str
    fleet_name:       str
    total_tunnels:    int
    tunnels_analyzed: int
    is_synthetic:     bool
    disclaimer:       str
    risk_distribution: dict[str, int]
    assessments:      list[TunnelAssessmentResponse]


class DatasetStatsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_loaded:       bool
    is_synthetic:    bool
    dataset_source:  Optional[str]
    load_timestamp:  Optional[datetime]
    entity_counts:   dict[str, int]
    disclaimer:      str
