"""
STATEFLUX — PCAP & Traffic Observation Model
============================================
Phase 5 — AI + Evidence Engine + PCAP Analysis + Security Reporting

Represents structured observations derived from network packet captures.
Does NOT decrypt encrypted packet payloads. Extracts timing, outer headers,
IKE negotiation indicators, ESP/AH counters, and traffic metadata exposure.
"""

from enum import Enum
from typing import Optional, Any
from datetime import datetime, timezone
from pydantic import Field

from app.models.base import StatefluxBaseModel
from app.models.negotiation_space import ConfidenceLevel


class TrafficObservationType(str, Enum):
    """Categorical network packet observation type."""
    OUTER_ENDPOINT_OBSERVED = "OUTER_ENDPOINT_OBSERVED"
    INNER_ADDRESS_OBSERVED = "INNER_ADDRESS_OBSERVED"
    IKE_METADATA_OBSERVED = "IKE_METADATA_OBSERVED"
    ESP_METADATA_OBSERVED = "ESP_METADATA_OBSERVED"
    AH_METADATA_OBSERVED = "AH_METADATA_OBSERVED"
    TRAFFIC_TIMING_OBSERVED = "TRAFFIC_TIMING_OBSERVED"
    PACKET_SIZE_PATTERN_OBSERVED = "PACKET_SIZE_PATTERN_OBSERVED"
    NEGOTIATION_EXCHANGE_OBSERVED = "NEGOTIATION_EXCHANGE_OBSERVED"
    RETRANSMISSION_OBSERVED = "RETRANSMISSION_OBSERVED"


class TrafficObservation(StatefluxBaseModel):
    """A structured network traffic observation pointing back to Evidence."""
    observation_id: str
    evidence_id: str
    tunnel_id: Optional[str] = None
    protocol: str = "ESP"                      # "IKE" | "ESP" | "AH" | "UDP" | "TCP" | "OTHER"
    observation_type: TrafficObservationType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str                                # E.g. "192.168.100.10:500"
    destination: str                           # E.g. "192.168.100.20:500"
    packet_count: int = 1
    byte_count: int = 0
    duration_seconds: float = 0.0
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    observed: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)
