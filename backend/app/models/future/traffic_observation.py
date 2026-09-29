"""
STATEFLUX — Future Schema: TrafficObservation
================================================
PHASE STATUS: PLACEHOLDER — Phase 15/17 Implementation

A TrafficObservation records metadata derived from analyzing traffic
flowing through an IPsec tunnel. Critically, this does NOT involve
decrypting the traffic. Only packet metadata is used:
  - Packet sizes and their distribution
  - Inter-arrival timing
  - Traffic direction ratios
  - Burst patterns

These features feed the ML Traffic Classifier (Phase 17) which
predicts the traffic type (WEB, VOIP, BULK_TRANSFER, etc.) from
the metadata alone.

IMPORTANT: The classifier can only INFER traffic type. It cannot
determine content. All classification results must carry a confidence
score and be labeled as inferences, not observations.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class TrafficObservation(BaseModel):
    """Metadata observation of traffic through a tunnel (Phase 15/17 placeholder)."""

    model_config = ConfigDict(extra="forbid")

    observation_id:            str
    tunnel_id:                 Optional[str]     = None
    dataset_id:                str

    window_start:              Optional[datetime] = None
    window_end:                Optional[datetime] = None
    packet_count:              int                = 0
    byte_count:                int                = 0

    # Statistical features for ML classifier
    avg_packet_size:           Optional[float]   = None
    stddev_packet_size:        Optional[float]   = None
    avg_inter_arrival_ms:      Optional[float]   = None
    stddev_inter_arrival_ms:   Optional[float]   = None
    direction_ratio:           Optional[float]   = None   # inbound/outbound bytes
    burst_count:               Optional[int]     = None

    # ML classifier output (Phase 17)
    predicted_traffic_type:    Optional[str]     = None   # WEB|VOIP|BULK_TRANSFER|INTERACTIVE|VIDEO|UNKNOWN
    classification_confidence: Optional[float]   = None

    is_synthetic: bool = True   # All Phase 1 observations are synthetic
