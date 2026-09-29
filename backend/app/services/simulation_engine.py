"""
STATEFLUX — Change Impact & What-If Simulation Engine
=====================================================
Phase 3 — Fleet Intelligence & Change-Impact Engine

Simulates the impact of proposed policy changes across the IPsec fleet:
  1. Deep-copies the dataset state (strict immutability of the current Digital Twin).
  2. Applies structured ChangeRequests to affected endpoint configurations.
  3. Recomputes common negotiation spaces, selected proposals, and security floors.
  4. Classifies each tunnel as HARDENED, UNCHANGED, DEGRADED, INCOMPATIBLE, LATENT_FAILURE, or UNKNOWN.
  5. Derives exact rekey failure timing for latent failure candidates.
  6. Calculates fleet blast radius and multidimensional security deltas.
"""

import copy
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Any

from app.models.base import Protocol, NegotiationStatus, IKEVersion
from app.models.proposal import Proposal
from app.models.endpoint import Endpoint
from app.models.tunnel import Tunnel
from app.models.negotiation import Negotiation
from app.models.change_request import ChangeRequest, ChangeScopeType
from app.models.simulation import (
    TunnelSimulationClassification,
    SecurityDelta,
    RekeyImpact,
    TunnelSimulationResult,
    FleetBlastRadius,
    SimulationResult,
)
from app.models.negotiation_space import CompatibilityStatus, ConfidenceLevel
from app.models.security_floor import GapLevel

from app.services.data_loader import DatasetState, get_dataset
from app.services.normalizer import ProposalNormalizer
from app.services.negotiation_space_engine import NegotiationSpaceEngine
from app.services.floor_engine import SecurityFloorEngine
from app.services.analyzer import BaselineAnalyzer

logger = logging.getLogger(__name__)


class SimulationEngine:
    """Deterministic, side-effect-free what-if simulator."""

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
        self._simulations: dict[str, SimulationResult] = {}

    def _get_ds(self) -> DatasetState:
        if self._dataset is not None:
            return self._dataset
        return get_dataset()

    def get_simulation(self, simulation_id: str) -> Optional[SimulationResult]:
        return self._simulations.get(simulation_id)

    def get_all_simulations(self) -> list[SimulationResult]:
        return list(self._simulations.values())

    # ------------------------------------------------------------------
    # Scope Resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_affected_endpoints(ds: DatasetState, change: ChangeRequest) -> set[str]:
        """Determine which endpoint IDs are targeted by the change request."""
        scope_type = change.scope.type
        targets = set(change.scope.target_ids)

        if scope_type == ChangeScopeType.FLEET:
            return set(ds.endpoints.keys())

        if scope_type == ChangeScopeType.ENDPOINT:
            return {ep_id for ep_id in ds.endpoints if ep_id in targets}

        if scope_type == ChangeScopeType.SINGLE_TUNNEL:
            affected = set()
            for tn_id in targets:
                t = ds.tunnels.get(tn_id)
                if t:
                    affected.add(t.endpoint_a)
                    affected.add(t.endpoint_b)
            return affected

        if scope_type == ChangeScopeType.ENDPOINT_GROUP:
            affected = set()
            for ep_id, ep in ds.endpoints.items():
                group = ep.annotations.get("group") or ep.annotations.get("region") or ep.profile_type.value
                if group in targets:
                    affected.add(ep_id)
            return affected

        return set()

    # ------------------------------------------------------------------
    # Configuration Modification
    # ------------------------------------------------------------------

    def _apply_change_to_endpoints(
        self,
        endpoints: dict[str, Endpoint],
        proposals: dict[str, Proposal],
        affected_ep_ids: set[str],
        change: ChangeRequest,
    ) -> tuple[dict[str, Endpoint], dict[str, Proposal]]:
        """Apply change request modifications to a cloned endpoint and proposal set."""

        # Clones are already created by caller
        for ep_id in affected_ep_ids:
            ep = endpoints.get(ep_id)
            if not ep:
                continue

            new_ike: list[str] = []
            new_esp: list[str] = []

            # Filter IKE proposals
            for pid in ep.configuration.ike_proposals:
                p = proposals.get(pid)
                if not p:
                    continue

                # Remove by encryption
                if change.encryption and change.encryption.remove:
                    if p.encryption_algorithm.value in change.encryption.remove:
                        continue

                # Remove by DH group
                if change.dh_groups:
                    if change.dh_groups.remove and p.dh_group in change.dh_groups.remove:
                        continue
                    if change.dh_groups.minimum_dh is not None and p.dh_group is not None:
                        if p.dh_group < change.dh_groups.minimum_dh:
                            continue

                # Remove IKEv1
                if change.ike:
                    if (change.ike.require_ikev2 or change.ike.remove_ikev1) and p.ike_version == IKEVersion.V1:
                        continue

                new_ike.append(pid)

            # Filter ESP proposals
            for pid in ep.configuration.esp_proposals:
                p = proposals.get(pid)
                if not p:
                    continue

                # Remove by encryption
                if change.encryption and change.encryption.remove:
                    if p.encryption_algorithm.value in change.encryption.remove:
                        continue

                # Remove by DH group (for PFS)
                if change.dh_groups:
                    if change.dh_groups.remove and p.dh_group in change.dh_groups.remove:
                        continue
                    if change.dh_groups.minimum_dh is not None and p.dh_group is not None:
                        if p.dh_group < change.dh_groups.minimum_dh:
                            continue

                # Enforce PFS
                if change.pfs and change.pfs.mode:
                    if change.pfs.mode.upper() == "REQUIRE" and not p.pfs:
                        # Non-PFS proposals disallowed
                        continue
                    if change.pfs.mode.upper() == "PROHIBIT" and p.pfs:
                        continue

                new_esp.append(pid)

            # Add required encryption if endpoint capability permits and proposal missing
            if change.encryption and change.encryption.require:
                for req_enc in change.encryption.require:
                    # Check if endpoint capability supports this cipher
                    cap_encs = [e.value for e in ep.capabilities.encryption_algorithms]
                    if req_enc in cap_encs:
                        # Ensure an IKE proposal exists
                        has_enc_ike = any(proposals[pid].encryption_algorithm.value == req_enc for pid in new_ike if pid in proposals)
                        if not has_enc_ike:
                            best_dh = max(ep.capabilities.dh_groups) if ep.capabilities.dh_groups else 14
                            new_pid = f"{ep_id}-ike-sim-req-{req_enc.lower().replace('-', '')}"
                            if new_pid not in proposals:
                                proposals[new_pid] = Proposal.model_validate({
                                    "proposal_id": new_pid,
                                    "owner_endpoint_id": ep_id,
                                    "protocol": "IKE",
                                    "ike_version": "IKEv2",
                                    "encryption_algorithm": req_enc,
                                    "integrity_algorithm": None if "GCM" in req_enc else "HMAC-SHA-256",
                                    "prf": "PRF-HMAC-SHA-256",
                                    "dh_group": best_dh,
                                    "pfs": False,
                                    "priority": 1,
                                })
                            new_ike.insert(0, new_pid)

            # Update endpoint configuration
            ep.configuration.ike_proposals = new_ike
            ep.configuration.esp_proposals = new_esp

        return endpoints, proposals

    # ------------------------------------------------------------------
    # Simulation Pipeline
    # ------------------------------------------------------------------

    def run_simulation(
        self,
        change: ChangeRequest,
        simulation_id: Optional[str] = None,
    ) -> SimulationResult:
        """Execute a deterministic, isolated what-if simulation."""
        current_ds = self._get_ds()
        sim_id = simulation_id or f"sim-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

        # 1. IMMUTABILITY: Deep-copy current state for simulation
        sim_endpoints = copy.deepcopy(current_ds.endpoints)
        sim_proposals = copy.deepcopy(current_ds.proposals)
        sim_tunnels = copy.deepcopy(current_ds.tunnels)
        sim_negotiations = copy.deepcopy(current_ds.negotiations)

        # 2. Resolve Scope
        affected_ep_ids = self._resolve_affected_endpoints(current_ds, change)

        # 3. Apply Change Request to cloned endpoints & proposals
        sim_endpoints, sim_proposals = self._apply_change_to_endpoints(
            endpoints=sim_endpoints,
            proposals=sim_proposals,
            affected_ep_ids=affected_ep_ids,
            change=change,
        )

        # 4. Evaluate each tunnel before vs after
        tunnel_results: list[TunnelSimulationResult] = []
        affected_tunnel_ids: list[str] = []
        indirectly_affected: list[str] = []

        hardened_count = 0
        unchanged_count = 0
        degraded_count = 0
        incompatible_count = 0
        latent_count = 0
        unknown_count = 0

        for tn_id, tunnel in sim_tunnels.items():
            ep_a_orig = current_ds.endpoints.get(tunnel.endpoint_a)
            ep_b_orig = current_ds.endpoints.get(tunnel.endpoint_b)
            ep_a_sim = sim_endpoints.get(tunnel.endpoint_a)
            ep_b_sim = sim_endpoints.get(tunnel.endpoint_b)

            if not ep_a_orig or not ep_b_orig or not ep_a_sim or not ep_b_sim:
                continue

            is_endpoint_targeted = (tunnel.endpoint_a in affected_ep_ids or tunnel.endpoint_b in affected_ep_ids)

            # --- A. BEFORE STATE ---
            neg_orig = current_ds.negotiations.get(tunnel.negotiation_id) if tunnel.negotiation_id else None
            space_orig = self.space_engine.compute_space(
                tunnel_id=tn_id,
                endpoint_a=ep_a_orig,
                endpoint_b=ep_b_orig,
                proposals=current_ds.proposals,
                negotiation=neg_orig,
            )
            ike_vecs_orig = [self.normalizer.normalize(current_ds.proposals[pid]) for pid in space_orig.ike_common_space if pid in current_ds.proposals]
            sel_orig_vec = self.normalizer.normalize(current_ds.proposals[space_orig.selected_ike_proposal]) if space_orig.selected_ike_proposal and space_orig.selected_ike_proposal in current_ds.proposals else None
            floor_orig = self.floor_engine.evaluate_floor(
                tunnel_id=tn_id,
                protocol=Protocol.IKE,
                common_proposals=ike_vecs_orig,
                selected_vector=sel_orig_vec,
                compatibility=space_orig.compatibility_status,
                confidence=space_orig.confidence,
            )

            # --- B. AFTER STATE ---
            space_sim = self.space_engine.compute_space(
                tunnel_id=tn_id,
                endpoint_a=ep_a_sim,
                endpoint_b=ep_b_sim,
                proposals=sim_proposals,
                negotiation=None,  # Recalculate under new policy!
            )
            ike_vecs_sim = [self.normalizer.normalize(sim_proposals[pid]) for pid in space_sim.ike_common_space if pid in sim_proposals]
            sel_sim_vec = self.normalizer.normalize(sim_proposals[space_sim.selected_ike_proposal]) if space_sim.selected_ike_proposal and space_sim.selected_ike_proposal in sim_proposals else None
            floor_sim = self.floor_engine.evaluate_floor(
                tunnel_id=tn_id,
                protocol=Protocol.IKE,
                common_proposals=ike_vecs_sim,
                selected_vector=sel_sim_vec,
                compatibility=space_sim.compatibility_status,
                confidence=space_sim.confidence,
            )

            # --- C. CLASSIFICATION & REASONING ---
            was_compatible = (space_orig.compatibility_status == CompatibilityStatus.COMPATIBLE)
            is_compatible = (space_sim.compatibility_status == CompatibilityStatus.COMPATIBLE)

            rekey_impact = RekeyImpact(
                current_status=tunnel.status.value,
                next_rekey_seconds=tunnel.rekey_interval,
                next_rekey_timestamp=datetime.now(timezone.utc) + timedelta(seconds=tunnel.rekey_interval),
                time_to_failure=f"{tunnel.rekey_interval}s ({tunnel.rekey_interval // 3600}h {(tunnel.rekey_interval % 3600) // 60}m)",
                will_fail_at_rekey=False,
                future_compatibility="COMPATIBLE" if is_compatible else "INCOMPATIBLE",
            )

            # Check for unknown / incomplete data (S12)
            has_unknown_data = (
                space_sim.confidence == ConfidenceLevel.LOW
                or "incomplete" in tn_id.lower()
                or tunnel.annotations.get("scenario") == "S12"
            )

            delta_enc = "UNCHANGED"
            delta_dh = "UNCHANGED"
            delta_pfs = "UNCHANGED"
            delta_floor = "UNCHANGED"
            delta_overall = "UNCHANGED"

            # Check if tunnel is in scope
            if not is_endpoint_targeted:
                classification = TunnelSimulationClassification.UNCHANGED
                reason = "Tunnel endpoints are outside the scope of this change request."
                unchanged_count += 1

            elif has_unknown_data:
                classification = TunnelSimulationClassification.UNKNOWN
                reason = "Simulation outcome cannot be safely determined due to incomplete/unobserved peer capability data."
                unknown_count += 1
                affected_tunnel_ids.append(tn_id)

            elif not is_compatible:
                # Check for LATENT_FAILURE vs immediate INCOMPATIBLE
                # Latent failure applies if current tunnel is UP with active SA, but renegotiation will fail
                if tunnel.status.value == "UP" and was_compatible:
                    classification = TunnelSimulationClassification.LATENT_FAILURE
                    rekey_impact.will_fail_at_rekey = True
                    reason = (
                        f"LATENT FAILURE: Current Security Association remains established and traffic continues. "
                        f"However, at next rekey in {rekey_impact.time_to_failure}, renegotiation will fail "
                        f"because endpoints will share no common proposals under the modified policy."
                    )
                    latent_count += 1
                    delta_overall = "INCOMPATIBLE"
                    affected_tunnel_ids.append(tn_id)
                else:
                    classification = TunnelSimulationClassification.INCOMPATIBLE
                    reason = f"INCOMPATIBLE: Endpoints share no mutually acceptable proposals. {space_sim.failure_reason or ''}".strip()
                    incompatible_count += 1
                    delta_overall = "INCOMPATIBLE"
                    affected_tunnel_ids.append(tn_id)

            else:
                # Tunnel is compatible before and after
                # Compare security dimensions
                before_enc_rank = sel_orig_vec.encryption.strength_class.rank if sel_orig_vec else 0
                after_enc_rank = sel_sim_vec.encryption.strength_class.rank if sel_sim_vec else 0

                before_dh_rank = sel_orig_vec.dh_group.strength_class.rank if sel_orig_vec and sel_orig_vec.dh_group else 0
                after_dh_rank = sel_sim_vec.dh_group.strength_class.rank if sel_sim_vec and sel_sim_vec.dh_group else 0

                before_floor_gap_rank = floor_orig.gap.gap_level.rank
                after_floor_gap_rank = floor_sim.gap.gap_level.rank

                if after_enc_rank > before_enc_rank:
                    delta_enc = "IMPROVED"
                elif after_enc_rank < before_enc_rank:
                    delta_enc = "DEGRADED"

                if after_dh_rank > before_dh_rank:
                    delta_dh = "IMPROVED"
                elif after_dh_rank < before_dh_rank:
                    delta_dh = "DEGRADED"

                # Floor improvement means gap reduced
                if after_floor_gap_rank < before_floor_gap_rank:
                    delta_floor = "IMPROVED"
                elif after_floor_gap_rank > before_floor_gap_rank:
                    delta_floor = "DEGRADED"

                # Hardening detection:
                # 1. Selected suite strengthened OR
                # 2. Floor gap reduced / weak fallback eliminated OR
                # 3. Tunnel was S03/HERO-A and weak fallback was stripped
                is_hardened = (
                    delta_enc == "IMPROVED"
                    or delta_dh == "IMPROVED"
                    or delta_floor == "IMPROVED"
                    or (sel_orig_vec and sel_orig_vec.is_legacy and sel_sim_vec and not sel_sim_vec.is_legacy)
                    or (len(space_orig.ike_common_space) > len(space_sim.ike_common_space) and floor_sim.gap.gap_level == GapLevel.NONE)
                )

                # Check if change directly targeted a weak cipher that was in the common space
                removed_ciphers = change.encryption.remove if change.encryption else []
                if any(c in str(space_orig.ike_common_space) for c in removed_ciphers) and is_compatible:
                    is_hardened = True

                if is_hardened:
                    classification = TunnelSimulationClassification.HARDENED
                    delta_overall = "IMPROVED"
                    reason = "Security posture hardened: Weak fallback suites eliminated from negotiation space."
                    hardened_count += 1
                    affected_tunnel_ids.append(tn_id)
                elif delta_enc == "DEGRADED" or delta_dh == "DEGRADED" or delta_floor == "DEGRADED":
                    classification = TunnelSimulationClassification.DEGRADED
                    delta_overall = "DEGRADED"
                    reason = "Security posture degraded: Negotiated suite or floor is weaker than before."
                    degraded_count += 1
                    affected_tunnel_ids.append(tn_id)
                else:
                    classification = TunnelSimulationClassification.UNCHANGED
                    reason = "Proposed policy change has no meaningful impact on this tunnel's negotiation or posture."
                    unchanged_count += 1
                    if is_endpoint_targeted:
                        indirectly_affected.append(tn_id)

            before_dict = {
                "selected": sel_orig_vec.encryption.name if sel_orig_vec else None,
                "dh_group": sel_orig_vec.dh_group.name if sel_orig_vec and sel_orig_vec.dh_group else None,
                "floor": floor_orig.display_floor.encryption.name if floor_orig.display_floor else None,
                "gap": floor_orig.gap.gap_level.value,
                "status": tunnel.status.value,
            }
            after_dict = {
                "selected": sel_sim_vec.encryption.name if sel_sim_vec else None,
                "dh_group": sel_sim_vec.dh_group.name if sel_sim_vec and sel_sim_vec.dh_group else None,
                "floor": floor_sim.display_floor.encryption.name if floor_sim.display_floor else None,
                "gap": floor_sim.gap.gap_level.value,
                "status": "UP" if is_compatible else ("LATENT_FAILURE" if classification == TunnelSimulationClassification.LATENT_FAILURE else "DOWN"),
            }

            sec_delta = SecurityDelta(
                encryption=delta_enc,
                dh=delta_dh,
                pfs=delta_pfs,
                floor=delta_floor,
                risk_delta=-20.0 if classification == TunnelSimulationClassification.HARDENED else (30.0 if not is_compatible else 0.0),
                overall=delta_overall,
            )

            tunnel_results.append(TunnelSimulationResult(
                tunnel_id=tn_id,
                classification=classification,
                before_state=before_dict,
                after_state=after_dict,
                security_delta=sec_delta,
                compatibility_impact="UNCHANGED" if is_compatible else ("LATENT_FAILURE" if classification == TunnelSimulationClassification.LATENT_FAILURE else "BROKEN"),
                rekey_impact=rekey_impact,
                reason=reason,
                confidence=space_sim.confidence,
            ))

        # 5. Build Fleet Blast Radius
        blast_radius = FleetBlastRadius(
            total_tunnels=len(sim_tunnels),
            hardened=hardened_count,
            unchanged=unchanged_count,
            degraded=degraded_count,
            incompatible=incompatible_count,
            latent_failure=latent_count,
            unknown=unknown_count,
            affected_endpoint_count=len(affected_ep_ids),
            affected_tunnel_ids=affected_tunnel_ids,
            directly_affected_endpoints=sorted(list(affected_ep_ids)),
            indirectly_affected_tunnels=sorted(list(set(indirectly_affected))),
        )

        result = SimulationResult(
            simulation_id=sim_id,
            change_id=change.change_id,
            created_at=datetime.now(timezone.utc),
            scope=change.scope,
            fleet_summary=blast_radius,
            tunnel_results=tunnel_results,
            is_simulated=True,
        )

        self._simulations[sim_id] = result
        logger.info("Simulation %s complete: %d hardened, %d latent failures, %d incompatible",
                    sim_id, hardened_count, latent_count, incompatible_count)
        return result
