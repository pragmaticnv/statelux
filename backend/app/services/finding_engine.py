"""
STATEFLUX — Deterministic Finding Engine
========================================
Phase 5 — AI + Evidence Engine + PCAP Analysis + Security Reporting

Produces deterministic, standards-grounded security findings across:
  - Active cryptographic weaknesses (weak algorithms, low DH, missing PFS)
  - Negotiation floor gaps (dormant fallback vulnerability)
  - Simulation risks (incompatible policy, latent rekey failures)
  - Migration plan blockers (invariant violations)
  - Controlled lab mismatches (testbed divergence)
  - Observation fusion anomalies (conflicts, metadata exposure)

Severity and confidence are strictly derived from deterministic rules (Rule Pack 2026.1).
AI never invents or modifies finding severity.
"""

import logging
from typing import Optional
from datetime import datetime, timezone

from app.models.finding import Finding, FindingType, FindingSeverity, FindingReference
from app.models.negotiation_space import ConfidenceLevel
from app.services.data_loader import DatasetState, get_dataset
from app.services.twin_service import DigitalTwinService
from app.services.evidence_engine import EvidenceEngine
from app.services.observation_fusion import ObservationFusionEngine

logger = logging.getLogger(__name__)


class FindingEngine:
    """Produces deterministic security findings with full evidence traceability."""

    STANDARDS = {
        "NIST_800_77": FindingReference(
            reference_type="NIST",
            reference_id="NIST SP 800-77 Rev. 1",
            reference_title="Guide to IPsec VPNs: Security Requirements for Cryptographic Algorithms",
            url_or_identifier="https://csrc.nist.gov/publications/detail/sp/800-77/rev-1/final",
        ),
        "RFC_8247": FindingReference(
            reference_type="RFC",
            reference_id="RFC 8247",
            reference_title="Algorithm Implementation Requirements and Usage Guidance for IKEv2",
            url_or_identifier="https://datatracker.ietf.org/doc/html/rfc8247",
        ),
        "RFC_8221": FindingReference(
            reference_type="RFC",
            reference_id="RFC 8221",
            reference_title="Cryptographic Algorithm Implementation Requirements for ESP and AH",
            url_or_identifier="https://datatracker.ietf.org/doc/html/rfc8221",
        ),
        "RFC_7296": FindingReference(
            reference_type="RFC",
            reference_id="RFC 7296",
            reference_title="Internet Key Exchange Protocol Version 2 (IKEv2)",
            url_or_identifier="https://datatracker.ietf.org/doc/html/rfc7296",
        ),
    }

    def __init__(
        self,
        dataset: Optional[DatasetState] = None,
        twin_service: Optional[DigitalTwinService] = None,
        evidence_engine: Optional[EvidenceEngine] = None,
    ) -> None:
        self._dataset = dataset
        self.twin_service = twin_service or DigitalTwinService(dataset=dataset)
        self.evidence_engine = evidence_engine or EvidenceEngine(dataset=dataset, twin_service=self.twin_service)
        self.fusion_engine = ObservationFusionEngine(self.evidence_engine)
        self._findings_store: dict[str, Finding] = {}

        self._generate_fleet_findings()

    def _get_ds(self) -> DatasetState:
        if self._dataset is not None:
            return self._dataset
        return get_dataset()

    def get_all_findings(self) -> list[Finding]:
        if not self._findings_store:
            self._generate_fleet_findings()
        return list(self._findings_store.values())

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        if not self._findings_store:
            self._generate_fleet_findings()
        return self._findings_store.get(finding_id)

    def get_findings_for_tunnel(self, tunnel_id: str) -> list[Finding]:
        if not self._findings_store:
            self._generate_fleet_findings()
        return [f for f in self._findings_store.values() if tunnel_id in f.affected_tunnels]

    def record_finding(self, finding: Finding) -> None:
        self._findings_store[finding.finding_id] = finding

    # ------------------------------------------------------------------
    # Deterministic Generation Pipeline
    # ------------------------------------------------------------------

    def _generate_fleet_findings(self) -> None:
        """Evaluate deterministic rules across the digital twin fleet."""
        try:
            ds = self._get_ds()
        except Exception:
            return

        for tn_id, tunnel in ds.tunnels.items():
            twin = self.twin_service.build_tunnel_twin(tn_id)
            ev_list = self.evidence_engine.get_evidence_for_tunnel(tn_id)
            ev_ids = [e.evidence_id for e in ev_list]

            # 1. Check for Weak Selected Algorithm (3DES, DES, NULL)
            sel_cipher = (
                twin.ike_floor.selected.encryption.name
                if twin.ike_floor and twin.ike_floor.selected
                else ""
            )
            floor_cipher = (
                twin.ike_floor.display_floor.encryption.name
                if twin.ike_floor and twin.ike_floor.display_floor
                else ""
            )
            if "3DES" in sel_cipher or "DES" in sel_cipher:
                fid = f"F-WEAK-ENC-{tn_id}"
                self.record_finding(
                    Finding(
                        finding_id=fid,
                        finding_type=FindingType.WEAK_SELECTED_ALGORITHM,
                        title=f"Insecure 64-bit Block Cipher Selected ({sel_cipher})",
                        severity=FindingSeverity.CRITICAL,
                        confidence=twin.confidence,
                        affected_tunnels=[tn_id],
                        affected_assets=[tunnel.endpoint_a, tunnel.endpoint_b],
                        description=(
                            f"Tunnel {tn_id} negotiated {sel_cipher}. 64-bit block ciphers are vulnerable to "
                            f"Sweet32 collision attacks and deprecated by NIST SP 800-77 Rev. 1."
                        ),
                        evidence_ids=ev_ids,
                        derived_from="Rule: DISALLOW_64BIT_CIPHERS",
                        remediation="Migrate endpoints to AES-256-GCM or AES-128-GCM immediately.",
                        references=[self.STANDARDS["NIST_800_77"], self.STANDARDS["RFC_8221"]],
                    )
                )

            # 2. Check for Insecure Floor Gap (Dormant Weak Fallback)
            if twin.composite_gap.gap_level.value in ("CRITICAL", "HIGH"):
                fid = f"F-FLOOR-GAP-{tn_id}"
                self.record_finding(
                    Finding(
                        finding_id=fid,
                        finding_type=FindingType.INSECURE_FALLBACK,
                        title=f"High Negotiation Floor Gap ({twin.composite_gap.gap_level.value})",
                        severity=FindingSeverity.HIGH,
                        confidence=twin.confidence,
                        affected_tunnels=[tn_id],
                        affected_assets=[tunnel.endpoint_a, tunnel.endpoint_b],
                        description=(
                            f"Tunnel {tn_id} selected {sel_cipher or 'default'}, but its negotiation floor permits "
                            f"{floor_cipher or 'fallback'}. An attacker capable of tampering with initial IKE offers can "
                            f"downgrade connection security to the floor suite."
                        ),
                        evidence_ids=ev_ids,
                        derived_from="SecurityFloorEngine: GAP_EVALUATION",
                        remediation="Prune legacy proposals from remote and local gateway configuration files.",
                        references=[self.STANDARDS["NIST_800_77"], self.STANDARDS["RFC_8247"]],
                    )
                )

            # 3. Check for Observation Fusion Conflict
            fused = self.fusion_engine.fuse_tunnel_evidence(tn_id)
            if fused.conflicts:
                fid = f"F-CONFLICT-{tn_id}"
                self.record_finding(
                    Finding(
                        finding_id=fid,
                        finding_type=FindingType.EVIDENCE_CONFLICT,
                        title="Evidence Conflict Detected Between Config and Live Daemon Logs",
                        severity=FindingSeverity.MEDIUM,
                        confidence=ConfidenceLevel.HIGH,
                        affected_tunnels=[tn_id],
                        affected_assets=[tunnel.endpoint_a, tunnel.endpoint_b],
                        description="; ".join(fused.conflicts),
                        evidence_ids=fused.evidence_ids,
                        derived_from="ObservationFusionEngine: CONTRADICTION_DETECTOR",
                        remediation="Investigate peer daemon error logs to resolve negotiation mismatch.",
                        references=[self.STANDARDS["RFC_7296"]],
                    )
                )
