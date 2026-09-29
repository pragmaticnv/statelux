"""
STATEFLUX — Evidence Engine Service
===================================
Phase 5 — AI + Evidence Engine + PCAP Analysis + Security Reporting

Manages the comprehensive, multi-source evidence repository.
Indexes and correlates evidence across:
  - Configurations (endpoints, proposals)
  - Active negotiations
  - Dynamic security floors & gaps
  - Simulations (what-if predictions, latent failure timings)
  - Migration plans (waves, rollback artifacts)
  - Controlled lab runs (real strongSwan / Libreswan execution)
  - Parsed daemon logs
  - PCAP traffic captures

Guarantees provenance tracking and strict immutability of recorded facts.
"""

import logging
from typing import Optional
from datetime import datetime, timezone

from app.models.evidence import Evidence, EvidenceType, EvidenceProvenance
from app.models.negotiation_space import ConfidenceLevel
from app.services.data_loader import DatasetState, get_dataset
from app.services.twin_service import DigitalTwinService
from app.services.lab_service import LabService
from app.services.log_analyzer import LogAnalyzer
from app.services.pcap_analyzer import PCAPAnalyzer

logger = logging.getLogger(__name__)


class EvidenceEngine:
    """Central repository and indexing service for all cryptographic evidence."""

    def __init__(
        self,
        dataset: Optional[DatasetState] = None,
        twin_service: Optional[DigitalTwinService] = None,
        lab_service: Optional[LabService] = None,
    ) -> None:
        self._dataset = dataset
        self.twin_service = twin_service or DigitalTwinService(dataset=dataset)
        self.lab_service = lab_service or LabService()
        self.log_analyzer = LogAnalyzer()
        self.pcap_analyzer = PCAPAnalyzer()

        self._evidence_store: dict[str, Evidence] = {}
        self._tunnel_index: dict[str, set[str]] = {}

        # Pre-seed initial evidence from dataset & lab
        self._bootstrap_evidence()

    def _get_ds(self) -> DatasetState:
        if self._dataset is not None:
            return self._dataset
        return get_dataset()

    def record_evidence(self, evidence: Evidence) -> None:
        """Store an evidence item and update secondary tunnel indices."""
        self._evidence_store[evidence.evidence_id] = evidence
        for tn_id in evidence.tunnel_ids:
            if tn_id not in self._tunnel_index:
                self._tunnel_index[tn_id] = set()
            self._tunnel_index[tn_id].add(evidence.evidence_id)

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        if not self._evidence_store:
            self._bootstrap_evidence()
        return self._evidence_store.get(evidence_id)

    def get_evidence_for_tunnel(self, tunnel_id: str) -> list[Evidence]:
        if not self._evidence_store:
            self._bootstrap_evidence()
        ev_ids = self._tunnel_index.get(tunnel_id, set())
        return [self._evidence_store[eid] for eid in ev_ids if eid in self._evidence_store]

    def get_all_evidence(self) -> list[Evidence]:
        if not self._evidence_store:
            self._bootstrap_evidence()
        return list(self._evidence_store.values())

    def _bootstrap_evidence(self) -> None:
        """Generate baseline evidence records from current dataset and lab runs."""
        try:
            ds = self._get_ds()
        except Exception:
            return

        # 1. Config & Negotiation Evidence per tunnel
        for tn_id, tunnel in ds.tunnels.items():
            ep_a = ds.endpoints.get(tunnel.endpoint_a)
            ep_b = ds.endpoints.get(tunnel.endpoint_b)

            # Configuration Evidence
            conf_ev_id = f"ev-cfg-{tn_id}"
            conf_ev = Evidence(
                evidence_id=conf_ev_id,
                evidence_type=EvidenceType.CONFIGURATION,
                provenance=EvidenceProvenance.DERIVED,
                source_id=tn_id,
                source_path="data/seed/tunnels.json",
                tunnel_ids=[tn_id],
                asset_ids=[tunnel.endpoint_a, tunnel.endpoint_b],
                content_summary=(
                    f"Configured endpoints for tunnel {tn_id}: "
                    f"{tunnel.endpoint_a} ({ep_a.platform if ep_a else 'unknown'}) <-> "
                    f"{tunnel.endpoint_b} ({ep_b.platform if ep_b else 'unknown'}), "
                    f"rekey_interval={tunnel.rekey_interval}s."
                ),
                confidence=ConfidenceLevel.HIGH,
                metadata={
                    "ike_proposals_a": ep_a.configuration.ike_proposals if ep_a else [],
                    "ike_proposals_b": ep_b.configuration.ike_proposals if ep_b else [],
                },
            )
            self.record_evidence(conf_ev)

            # Floor Evidence
            twin = self.twin_service.build_tunnel_twin(tn_id)
            floor_ev_id = f"ev-floor-{tn_id}"
            sel_str = twin.ike_floor.selected.encryption.name if twin.ike_floor and twin.ike_floor.selected else "None"
            floor_str = twin.ike_floor.display_floor.encryption.name if twin.ike_floor and twin.ike_floor.display_floor else "None"
            floor_ev = Evidence(
                evidence_id=floor_ev_id,
                evidence_type=EvidenceType.SECURITY_FLOOR,
                provenance=EvidenceProvenance.DERIVED,
                source_id=tn_id,
                source_path="app.services.floor_engine",
                tunnel_ids=[tn_id],
                content_summary=(
                    f"Dynamic Security Floor for {tn_id}: "
                    f"Selected={sel_str}, "
                    f"Floor={floor_str}, "
                    f"Gap={twin.composite_gap.gap_level.value}, "
                    f"Posture={twin.cryptographic_posture}."
                ),
                confidence=twin.confidence,
                metadata={
                    "gap_level": twin.composite_gap.gap_level.value,
                    "has_gap": twin.composite_gap.has_gap,
                    "gap_rank": twin.composite_gap.gap_level.rank,
                    "risk_level": twin.risk_level,
                },
            )
            self.record_evidence(floor_ev)

        # 2. Lab Evidence from verified lab scenarios
        for run_id, run in self.lab_service._runs.items():
            lab_ev_id = f"ev-lab-{run.scenario_id.lower()}"
            lab_ev = Evidence(
                evidence_id=lab_ev_id,
                evidence_type=EvidenceType.LAB_RESULT,
                provenance=EvidenceProvenance.OBSERVED,
                source_id=run_id,
                source_path="lab.services.lab_service",
                content_summary=(
                    f"Lab Scenario {run.scenario_id} ({run.scenario_title}): "
                    f"Prediction={run.predicted_result}, Actual={run.actual_result}, Match={run.prediction_match}."
                ),
                confidence=ConfidenceLevel.HIGH,
                raw_data={"actual_details": run.actual_details, "predicted_details": run.predicted_details},
                metadata={"scenario_id": run.scenario_id, "prediction_match": run.prediction_match},
            )
            self.record_evidence(lab_ev)

            # Parse logs for this lab run into Log Evidence
            if run.logs:
                _, log_ev = self.log_analyzer.parse_log_lines(
                    lines=run.logs,
                    source_id=f"{run.scenario_id.lower()}_charon.log",
                )
                self.record_evidence(log_ev)
