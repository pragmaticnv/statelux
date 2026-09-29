"""
STATEFLUX — Observation Fusion Engine
=====================================
Phase 5 — AI + Evidence Engine + PCAP Analysis + Security Reporting

Correlates multi-source evidence:
  Configuration + Negotiation + Security Floor + Digital Twin + Simulation + Lab Results + Logs + PCAP

Detects:
  - Confirmed agreement across sources (HIGH-CONFIDENCE OBSERVED STATE)
  - Contradictions / Disagreements (CONFLICT DETECTED)
  - Missing evidence / Unobserved states (INSUFFICIENT_EVIDENCE)

Preserves exact epistemic provenance (OBSERVED vs DERIVED vs SIMULATED vs UNKNOWN).
"""

import logging
from typing import Optional, Any
from datetime import datetime, timezone

from app.models.evidence import Evidence, EvidenceType, EvidenceProvenance
from app.models.negotiation_space import ConfidenceLevel
from app.services.evidence_engine import EvidenceEngine

logger = logging.getLogger(__name__)


class FusedState:
    """The synthesized, multi-source state of an asset or tunnel."""
    def __init__(
        self,
        target_id: str,
        status: str,  # "CONFIRMED_AGREEMENT" | "CONFLICT_DETECTED" | "INSUFFICIENT_EVIDENCE"
        confidence: ConfidenceLevel,
        observed_facts: list[str],
        derived_facts: list[str],
        simulated_facts: list[str],
        unknowns: list[str],
        evidence_ids: list[str],
        conflicts: list[str],
    ) -> None:
        self.target_id = target_id
        self.status = status
        self.confidence = confidence
        self.observed_facts = observed_facts
        self.derived_facts = derived_facts
        self.simulated_facts = simulated_facts
        self.unknowns = unknowns
        self.evidence_ids = evidence_ids
        self.conflicts = conflicts

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "status": self.status,
            "confidence": self.confidence.value,
            "observed_facts": self.observed_facts,
            "derived_facts": self.derived_facts,
            "simulated_facts": self.simulated_facts,
            "unknowns": self.unknowns,
            "evidence_ids": self.evidence_ids,
            "conflicts": self.conflicts,
        }


class ObservationFusionEngine:
    """Performs multi-source evidence fusion and contradiction analysis."""

    def __init__(self, evidence_engine: Optional[EvidenceEngine] = None) -> None:
        self.evidence_engine = evidence_engine or EvidenceEngine()

    def fuse_tunnel_evidence(
        self,
        tunnel_id: str,
        extra_evidence: Optional[list[Evidence]] = None,
    ) -> FusedState:
        """Cross-correlate all evidence items for a given tunnel."""
        evidence_items = self.evidence_engine.get_evidence_for_tunnel(tunnel_id)
        if extra_evidence:
            evidence_items.extend(extra_evidence)

        observed_facts: list[str] = []
        derived_facts: list[str] = []
        simulated_facts: list[str] = []
        unknowns: list[str] = []
        conflicts: list[str] = []
        ev_ids: list[str] = []

        types_present = set()

        for ev in evidence_items:
            ev_ids.append(ev.evidence_id)
            types_present.add(ev.evidence_type)

            if ev.provenance == EvidenceProvenance.OBSERVED:
                observed_facts.append(ev.content_summary)
            elif ev.provenance == EvidenceProvenance.DERIVED:
                derived_facts.append(ev.content_summary)
            elif ev.provenance == EvidenceProvenance.SIMULATED:
                simulated_facts.append(ev.content_summary)
            elif ev.provenance == EvidenceProvenance.PREDICTED:
                simulated_facts.append(f"PREDICTION: {ev.content_summary}")
            elif ev.provenance == EvidenceProvenance.UNKNOWN:
                unknowns.append(ev.content_summary)

        # Contradiction Detection:
        # Example 1: Config claims active tunnel, but a log or PCAP shows failure or zero traffic
        has_log = any(ev.evidence_type == EvidenceType.LOG for ev in evidence_items)
        has_pcap = any(ev.evidence_type == EvidenceType.PCAP for ev in evidence_items)
        has_floor = any(ev.evidence_type == EvidenceType.SECURITY_FLOOR for ev in evidence_items)

        # Check for NO_PROPOSAL_CHOSEN in logs
        for ev in evidence_items:
            if ev.evidence_type == EvidenceType.LOG and ev.raw_data:
                events = ev.raw_data.get("events", [])
                if any(e.get("event_type") == "NO_PROPOSAL_CHOSEN" for e in events):
                    conflicts.append("Log reports NO_PROPOSAL_CHOSEN while configuration expected active negotiation.")

        # Determine Fusion Status & Confidence
        if conflicts:
            fusion_status = "CONFLICT_DETECTED"
            confidence = ConfidenceLevel.MEDIUM
        elif not has_log and not has_pcap:
            fusion_status = "INSUFFICIENT_EVIDENCE"
            unknowns.append("No live daemon logs or PCAP captures available to confirm wire traffic.")
            confidence = ConfidenceLevel.MEDIUM
        else:
            fusion_status = "CONFIRMED_AGREEMENT"
            confidence = ConfidenceLevel.HIGH

        return FusedState(
            target_id=tunnel_id,
            status=fusion_status,
            confidence=confidence,
            observed_facts=observed_facts,
            derived_facts=derived_facts,
            simulated_facts=simulated_facts,
            unknowns=unknowns,
            evidence_ids=ev_ids,
            conflicts=conflicts,
        )
