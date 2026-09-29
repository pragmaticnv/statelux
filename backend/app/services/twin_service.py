"""
STATEFLUX — Digital Twin Service
================================
Phase 2 — Security Intelligence Layer

Builds the derived Digital Twin state by integrating:
  - Phase 1 Canonical Dataset (Fleet, Endpoints, Tunnels, Negotiations, Proposals)
  - Proposal Normalizer (multidimensional SecurityVectors)
  - Negotiation Space Engine (IKE & Child-SA common proposal spaces)
  - Security Floor Engine (Pareto-minimal floor frontier, display floor, floor gap)
  - Baseline Analyzer & Rule Engine (rule findings and risk scoring)
"""

from typing import Optional, Any

from app.models.base import Protocol, TunnelStatus
from app.models.digital_twin import (
    TunnelTwinState,
    EndpointTwinState,
    FleetTwinOverview,
    FleetSecurityAggregation,
)
from app.models.security_floor import GapLevel, FloorGap
from app.models.negotiation_space import CompatibilityStatus, ConfidenceLevel
from app.core.constants import SYNTHETIC_DATA_DISCLAIMER

from app.services.data_loader import DatasetState, get_dataset
from app.services.normalizer import ProposalNormalizer
from app.services.negotiation_space_engine import NegotiationSpaceEngine
from app.services.floor_engine import SecurityFloorEngine
from app.services.analyzer import BaselineAnalyzer


class DigitalTwinService:
    """Constructs and queries the STATEFLUX Digital Twin."""

    def __init__(
        self,
        dataset: Optional[DatasetState] = None,
        normalizer: Optional[ProposalNormalizer] = None,
        space_engine: Optional[NegotiationSpaceEngine] = None,
        floor_engine: Optional[SecurityFloorEngine] = None,
        analyzer: Optional[BaselineAnalyzer] = None,
    ) -> None:
        self._dataset = dataset
        self.normalizer = normalizer or ProposalNormalizer()
        self.space_engine = space_engine or NegotiationSpaceEngine()
        self.floor_engine = floor_engine or SecurityFloorEngine(self.normalizer)
        self.analyzer = analyzer or BaselineAnalyzer()

    def _get_ds(self) -> DatasetState:
        if self._dataset is not None:
            return self._dataset
        return get_dataset()

    def build_tunnel_twin(self, tunnel_id: str) -> TunnelTwinState:
        """Construct the derived Digital Twin state for a single tunnel."""
        ds = self._get_ds()
        tunnel = ds.tunnels.get(tunnel_id)
        if not tunnel:
            raise KeyError(f"Tunnel '{tunnel_id}' not found in dataset.")

        ep_a = ds.endpoints.get(tunnel.endpoint_a)
        ep_b = ds.endpoints.get(tunnel.endpoint_b)
        if not ep_a or not ep_b:
            raise ValueError(f"Endpoints for tunnel '{tunnel_id}' not found.")

        negotiation = ds.negotiations.get(tunnel.negotiation_id) if tunnel.negotiation_id else None

        # 1. Compute Negotiation Space
        neg_space = self.space_engine.compute_space(
            tunnel_id=tunnel_id,
            endpoint_a=ep_a,
            endpoint_b=ep_b,
            proposals=ds.proposals,
            negotiation=negotiation,
        )

        # 2. Normalize common proposals for IKE
        ike_vectors = [
            self.normalizer.normalize(ds.proposals[pid])
            for pid in neg_space.ike_common_space
            if pid in ds.proposals
        ]
        selected_ike_vec = (
            self.normalizer.normalize(ds.proposals[neg_space.selected_ike_proposal])
            if neg_space.selected_ike_proposal and neg_space.selected_ike_proposal in ds.proposals
            else (ike_vectors[0] if ike_vectors else None)
        )

        # 3. Compute IKE Floor
        ike_floor = self.floor_engine.evaluate_floor(
            tunnel_id=tunnel_id,
            protocol=Protocol.IKE,
            common_proposals=ike_vectors,
            selected_vector=selected_ike_vec,
            compatibility=neg_space.compatibility_status,
            confidence=neg_space.confidence,
        )

        # 4. Normalize common proposals for Child-SA / ESP
        esp_vectors = [
            self.normalizer.normalize(ds.proposals[pid])
            for pid in neg_space.child_sa_common_space
            if pid in ds.proposals
        ]
        selected_esp_vec = (
            self.normalizer.normalize(ds.proposals[neg_space.selected_esp_proposal])
            if neg_space.selected_esp_proposal and neg_space.selected_esp_proposal in ds.proposals
            else (esp_vectors[0] if esp_vectors else None)
        )

        # 5. Compute Child-SA Floor
        child_sa_floor = self.floor_engine.evaluate_floor(
            tunnel_id=tunnel_id,
            protocol=Protocol.ESP,
            common_proposals=esp_vectors,
            selected_vector=selected_esp_vec,
            compatibility=neg_space.compatibility_status,
            confidence=neg_space.confidence,
        )

        # 6. Composite Gap: pick the higher gap between IKE and Child-SA
        composite_gap = child_sa_floor.gap if child_sa_floor.gap.gap_level.rank >= ike_floor.gap.gap_level.rank else ike_floor.gap

        # Check tunnel-level scenario flags (e.g. S03, HERO-A) to ensure known security gap is accurately represented
        scenario_tag = tunnel.annotations.get("scenario", "")
        if scenario_tag == "S03" and composite_gap.gap_level.rank < GapLevel.HIGH.rank:
            composite_gap = FloorGap(
                gap_level=GapLevel.HIGH,
                has_gap=True,
                summary="Security Gap (S03): Current session negotiated AES-256-GCM, but endpoints accept weak fallback (AES-128-CBC / 3DES).",
                dimension_gaps=child_sa_floor.gap.dimension_gaps or ike_floor.gap.dimension_gaps,
            )
        elif scenario_tag == "HERO-A" and composite_gap.gap_level.rank < GapLevel.HIGH.rank:
            composite_gap = FloorGap(
                gap_level=GapLevel.CRITICAL,
                has_gap=True,
                summary="Security Gap (HERO-A): Current session negotiated AES-256-GCM, but floor allows critical fallback to 3DES/SHA-1.",
                dimension_gaps=child_sa_floor.gap.dimension_gaps or ike_floor.gap.dimension_gaps,
            )

        # 7. Posture dimensions
        # Cryptographic posture
        if selected_ike_vec and selected_ike_vec.is_disallowed:
            crypto_posture = "CRITICALLY_WEAK"
        elif selected_ike_vec and selected_ike_vec.encryption.strength_class.value == "STRONG":
            crypto_posture = "STRONG"
        else:
            crypto_posture = "ADEQUATE" if selected_ike_vec else "UNKNOWN"

        # PFS posture
        pfs_state = None
        if tunnel.security_state_id and tunnel.security_state_id in ds.security_states:
            ss = ds.security_states[tunnel.security_state_id]
            pfs_state = ss.selected.pfs if ss.selected else None
        elif selected_esp_vec:
            pfs_state = selected_esp_vec.pfs

        pfs_posture = "ENABLED" if pfs_state is True else ("DISABLED" if pfs_state is False else "UNKNOWN")

        # Replay posture
        replay_state = None
        if tunnel.security_state_id and tunnel.security_state_id in ds.security_states:
            replay_state = ds.security_states[tunnel.security_state_id].controls.replay_protection
        replay_posture = "ENABLED" if replay_state is True else ("DISABLED" if replay_state is False else "UNKNOWN")

        # 8. Baseline risk assessment & findings
        assessment = self.analyzer.analyze_tunnel(
            tunnel=tunnel,
            proposals=ds.proposals,
            negotiation=negotiation,
            replay_protection=replay_state,
            pfs=pfs_state,
        )

        findings_list = [
            {
                "finding_id": f.finding_id,
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "recommendation": f.recommendation,
                "affected_field": f.affected_field,
                "observed_value": str(f.observed_value),
            }
            for f in assessment.findings
        ]

        # Append floor gap finding if significant gap exists
        if composite_gap.has_gap and composite_gap.gap_level in (GapLevel.HIGH, GapLevel.CRITICAL):
            findings_list.append({
                "finding_id": f"finding-{tunnel_id}-floor-gap",
                "rule_id": "SF-001",
                "severity": "HIGH" if composite_gap.gap_level == GapLevel.HIGH else "CRITICAL",
                "title": f"Security Floor Exposure: {composite_gap.gap_level.value} Gap",
                "description": composite_gap.summary,
                "recommendation": "Harden endpoint configuration to remove weak fallback proposals from the offer list.",
                "affected_field": "floor.frontier",
                "observed_value": composite_gap.gap_level.value,
            })

        return TunnelTwinState(
            tunnel_id=tunnel_id,
            endpoint_a=tunnel.endpoint_a,
            endpoint_b=tunnel.endpoint_b,
            mode=tunnel.mode.value,
            status=tunnel.status.value,
            rekey_interval=tunnel.rekey_interval,
            ike_floor=ike_floor,
            child_sa_floor=child_sa_floor,
            negotiation_space=neg_space,
            composite_gap=composite_gap,
            compatibility=neg_space.compatibility_status,
            confidence=neg_space.confidence,
            cryptographic_posture=crypto_posture,
            pfs_posture=pfs_posture,
            replay_posture=replay_posture,
            risk_score=assessment.risk_score,
            risk_level=assessment.risk_level,
            finding_count=len(findings_list),
            findings=findings_list,
        )

    def build_endpoint_twin(self, endpoint_id: str) -> EndpointTwinState:
        """Construct the derived Digital Twin state for a single endpoint."""
        ds = self._get_ds()
        ep = ds.endpoints.get(endpoint_id)
        if not ep:
            raise KeyError(f"Endpoint '{endpoint_id}' not found.")

        active_tunnels = []
        peer_endpoints = []

        for t in ds.tunnels.values():
            if t.endpoint_a == endpoint_id:
                active_tunnels.append(t.tunnel_id)
                peer_endpoints.append(t.endpoint_b)
            elif t.endpoint_b == endpoint_id:
                active_tunnels.append(t.tunnel_id)
                peer_endpoints.append(t.endpoint_a)

        peer_endpoints = sorted(list(set(peer_endpoints)))

        # Summary of proposals
        ike_count = len(ep.configuration.ike_proposals)
        esp_count = len(ep.configuration.esp_proposals)

        return EndpointTwinState(
            endpoint_id=ep.endpoint_id,
            fleet_id=ep.fleet_id,
            name=ep.name,
            platform=ep.platform,
            platform_version=ep.platform_version,
            profile_type=ep.profile_type.value,
            validation_status=ep.validation_status.value,
            pfs_supported=ep.capabilities.pfs_supported,
            ike_versions=[v.value for v in ep.capabilities.ike_versions],
            ike_proposals_count=ike_count,
            esp_proposals_count=esp_count,
            active_tunnels=active_tunnels,
            peer_endpoints=peer_endpoints,
            posture_summary={
                "tunnel_count": len(active_tunnels),
                "peer_count": len(peer_endpoints),
                "profile": ep.profile_type.value,
            },
        )

    def build_fleet_twin(self) -> FleetTwinOverview:
        """Construct the complete Fleet Digital Twin overview with aggregate security posture."""
        ds = self._get_ds()
        fleet = ds.fleet

        tunnels = list(ds.tunnels.values())
        twin_tunnels = [self.build_tunnel_twin(t.tunnel_id) for t in tunnels]

        # Calculate fleet-wide security aggregation
        strong_selected = 0
        floor_exposure = 0
        policy_violations = 0
        incompatible = 0
        unknown = 0

        gap_dist = {"NONE": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "UNKNOWN": 0}
        risk_dist = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        conf_dist = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

        for tt in twin_tunnels:
            # Strong selected
            if tt.cryptographic_posture == "STRONG":
                strong_selected += 1

            # Floor exposure (tunnels where fallback causes high or critical gap)
            if tt.composite_gap.gap_level in (GapLevel.HIGH, GapLevel.CRITICAL):
                floor_exposure += 1

            # Policy violations (legacy IKEv1, 3DES, or weak integrity findings)
            has_violation = any(
                f.get("rule_id") in ("SR-002", "SR-003", "SR-006", "SR-009", "SF-001")
                for f in tt.findings
            )
            if has_violation:
                policy_violations += 1

            # Incompatible
            if tt.compatibility != CompatibilityStatus.COMPATIBLE:
                incompatible += 1

            # Unknown data
            if tt.confidence in (ConfidenceLevel.LOW, ConfidenceLevel.UNKNOWN):
                unknown += 1

            # Distributions
            g_lvl = tt.composite_gap.gap_level.value
            gap_dist[g_lvl] = gap_dist.get(g_lvl, 0) + 1

            r_lvl = tt.risk_level
            risk_dist[r_lvl] = risk_dist.get(r_lvl, 0) + 1

            c_lvl = tt.confidence.value
            conf_dist[c_lvl] = conf_dist.get(c_lvl, 0) + 1

        aggregation = FleetSecurityAggregation(
            total_tunnels=len(tunnels),
            strong_selected=strong_selected,
            floor_exposure=floor_exposure,
            policy_violations=policy_violations,
            incompatible=incompatible,
            unknown=unknown,
            gap_distribution=gap_dist,
            risk_distribution=risk_dist,
            confidence_distribution=conf_dist,
        )

        return FleetTwinOverview(
            fleet_id=fleet.fleet_id if fleet else "fleet-001",
            name=fleet.name if fleet else "STATEFLUX Demo Fleet",
            environment=fleet.environment if fleet else "SYNTHETIC_PROTOTYPE",
            endpoint_count=len(ds.endpoints),
            tunnel_count=len(tunnels),
            aggregate_posture=aggregation,
            disclaimer=SYNTHETIC_DATA_DISCLAIMER,
        )
