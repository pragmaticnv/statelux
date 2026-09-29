"""
STATEFLUX — Migration Planner Service
=====================================
Phase 4 — Migration Planner + Real IPsec Lab + Prediction Validation

Consumes:
  - SimulationResult (from Phase 3)
  - FleetNegotiationGraph (from Phase 3)
  - Current Digital Twin / Dataset (from Phase 2)
  - ChangeRequest (from Phase 3)

Generates:
  - Dependency-ordered migration waves (CANARY, LOW_RISK_BATCH, DEPENDENCY_ORDERED, FINAL_HIGH_RISK)
  - Preconditions, validation checks, and structured rollback artifacts
  - Strict enforcement of the Migration Invariant (blocking INCOMPATIBLE and LATENT_FAILURE tunnels)
"""

import logging
from typing import Optional
from datetime import datetime, timezone

from app.models.change_request import ChangeRequest
from app.models.graph import FleetNegotiationGraph
from app.models.simulation import SimulationResult, TunnelSimulationClassification
from app.models.migration import (
    MigrationPlan,
    MigrationPlanSummary,
    MigrationWave,
    MigrationStrategy,
    WaveRiskLevel,
    RollbackPlan,
    BlockedTunnel,
)
from app.services.data_loader import DatasetState, get_dataset
from app.services.graph_service import FleetGraphService

logger = logging.getLogger(__name__)


class MigrationPlannerService:
    """Deterministic, dependency-aware migration wave planner."""

    def __init__(self, dataset: Optional[DatasetState] = None) -> None:
        self._dataset = dataset
        self._plans: dict[str, MigrationPlan] = {}

    def _get_ds(self) -> DatasetState:
        if self._dataset is not None:
            return self._dataset
        return get_dataset()

    def get_plan(self, plan_id: str) -> Optional[MigrationPlan]:
        return self._plans.get(plan_id)

    # ------------------------------------------------------------------
    # Rollback Synthesis
    # ------------------------------------------------------------------

    @staticmethod
    def _synthesize_rollback(change: Optional[ChangeRequest]) -> RollbackPlan:
        """Invert the forward policy change into explicit rollback actions."""
        if not change:
            return RollbackPlan(
                forward_actions=["Apply security policy update"],
                rollback_actions=["Restore previous endpoint configurations from backup"],
            )

        forward = []
        rollback = []

        if change.encryption:
            if change.encryption.remove:
                ciphers = ", ".join(change.encryption.remove)
                forward.append(f"Remove legacy ciphers: {ciphers}")
                rollback.append(f"Restore legacy ciphers to proposal list: {ciphers}")
            if change.encryption.require:
                ciphers = ", ".join(change.encryption.require)
                forward.append(f"Enforce mandatory cipher requirement: {ciphers}")
                rollback.append(f"Remove mandatory cipher requirement for: {ciphers}")

        if change.dh_groups:
            if change.dh_groups.remove:
                groups = ", ".join(str(g) for g in change.dh_groups.remove)
                forward.append(f"Remove DH groups: {groups}")
                rollback.append(f"Restore DH groups to peer configuration: {groups}")
            if change.dh_groups.minimum_dh is not None:
                forward.append(f"Require minimum DH group {change.dh_groups.minimum_dh}")
                rollback.append(f"Lower minimum DH group threshold back to 14 (or legacy standard)")

        if change.pfs and change.pfs.mode:
            forward.append(f"Set PFS requirement mode to {change.pfs.mode}")
            rollback.append("Restore previous PFS configuration (allow negotiation without DH in Child SA)")

        if change.ike:
            if change.ike.require_ikev2:
                forward.append("Enforce IKEv2 only (disallow IKEv1)")
                rollback.append("Re-allow IKEv1 fallback negotiation")
            if change.ike.remove_ikev1:
                forward.append("Remove IKEv1 proposal definitions")
                rollback.append("Restore IKEv1 proposals in swanctl.conf / ipsec.conf")

        if not forward:
            forward = ["Apply configuration changes"]
            rollback = ["Revert configuration to pre-change snapshot"]

        return RollbackPlan(
            available=True,
            forward_actions=forward,
            rollback_actions=rollback,
            estimated_rollback_seconds=300,
            pre_rollback_validation=[
                "VERIFY_SSH_ACCESS_TO_ENDPOINTS",
                "CAPTURE_CURRENT_IKE_SA_LOGS",
                "NOTIFY_NOC_ROLLBACK_INITIATED",
            ],
        )

    # ------------------------------------------------------------------
    # Plan Generation Pipeline
    # ------------------------------------------------------------------

    def generate_plan(
        self,
        simulation_result: SimulationResult,
        graph: Optional[FleetNegotiationGraph] = None,
        change_request: Optional[ChangeRequest] = None,
        objective: str = "Roll out verified policy change without service disruption",
    ) -> MigrationPlan:
        """Partition simulated tunnels into safe, ordered rollout waves."""
        ds = self._get_ds()
        if not graph:
            graph = FleetGraphService(dataset=ds).build_graph()

        # Build endpoint centrality lookup (node degree)
        centrality_map: dict[str, int] = {node.id: node.degree for node in graph.nodes}

        # 1. Enforce Migration Invariant: Identify Eligible vs Blocked Tunnels
        eligible_tunnels: list[tuple[str, float]] = []  # (tunnel_id, centrality)
        blocked_tunnels: list[BlockedTunnel] = []
        unknown_count = 0

        # Build tunnel lookup for endpoints
        for tn_res in simulation_result.tunnel_results:
            tn_id = tn_res.tunnel_id
            tunnel = ds.tunnels.get(tn_id)
            ep_a = tunnel.endpoint_a if tunnel else "unknown"
            ep_b = tunnel.endpoint_b if tunnel else "unknown"

            deg_a = centrality_map.get(ep_a, 0)
            deg_b = centrality_map.get(ep_b, 0)
            max_centrality = max(deg_a, deg_b)

            cls = tn_res.classification

            if cls == TunnelSimulationClassification.UNKNOWN:
                unknown_count += 1
                blocked_tunnels.append(
                    BlockedTunnel(
                        tunnel_id=tn_id,
                        classification=cls,
                        blocked_reason="BLOCKED: Peer capabilities are unobserved or incomplete. Cannot guarantee safe negotiation.",
                        required_remediation="Verify peer cryptographic support via configuration inspection or lab testing before scheduling.",
                        endpoint_a=ep_a,
                        endpoint_b=ep_b,
                    )
                )

            elif cls == TunnelSimulationClassification.INCOMPATIBLE:
                blocked_tunnels.append(
                    BlockedTunnel(
                        tunnel_id=tn_id,
                        classification=cls,
                        blocked_reason=f"BLOCKED: Negotiation failure predicted under target policy. {tn_res.reason}",
                        required_remediation="Upgrade legacy endpoint or add compatible cryptographic proposals to peer before policy rollout.",
                        endpoint_a=ep_a,
                        endpoint_b=ep_b,
                    )
                )

            elif cls == TunnelSimulationClassification.LATENT_FAILURE:
                rekey_str = tn_res.rekey_impact.time_to_failure or "next rekey"
                blocked_tunnels.append(
                    BlockedTunnel(
                        tunnel_id=tn_id,
                        classification=cls,
                        blocked_reason=f"BLOCKED: Latent failure predicted at {rekey_str}. Current SA remains up, but future rekey will break.",
                        required_remediation=f"Update remote peer configuration to support modern proposals prior to rekey deadline ({rekey_str}).",
                        endpoint_a=ep_a,
                        endpoint_b=ep_b,
                    )
                )

            else:
                # HARDENED, UNCHANGED, or DEGRADED (if compatible)
                # Only include tunnels that are affected or hardened if desired, or all eligible
                eligible_tunnels.append((tn_id, float(max_centrality)))

        # 2. Sort eligible tunnels by centrality (ascending: least connected first)
        eligible_tunnels.sort(key=lambda x: x[1])

        # 3. Partition into Waves:
        #    Wave 1: CANARY (1-3 tunnels, lowest centrality)
        #    Wave 2: LOW_RISK_BATCH (centrality <= 3)
        #    Wave 3: DEPENDENCY_ORDERED (3 < centrality <= 6)
        #    Wave 4: FINAL_HIGH_RISK (centrality > 6)
        waves: list[MigrationWave] = []
        rollback_plan = self._synthesize_rollback(change_request)

        canary_tns: list[str] = []
        batch_tns: list[str] = []
        dep_tns: list[str] = []
        high_risk_tns: list[str] = []

        # Tunnels targeted by change (prefer hardened for canary)
        hardened_set = {
            t.tunnel_id
            for t in simulation_result.tunnel_results
            if t.classification == TunnelSimulationClassification.HARDENED
        }

        # Select up to 3 canary tunnels
        remaining = list(eligible_tunnels)
        # Prioritize hardened tunnels with lowest centrality for canary
        hardened_candidates = [t for t in remaining if t[0] in hardened_set]
        canary_picks = hardened_candidates[:3] if hardened_candidates else remaining[:3]
        for c in canary_picks:
            canary_tns.append(c[0])
            remaining.remove(c)

        for tn_id, cent in remaining:
            if cent <= 3.0:
                batch_tns.append(tn_id)
            elif cent <= 6.0:
                dep_tns.append(tn_id)
            else:
                high_risk_tns.append(tn_id)

        wave_num = 1

        # Wave 1: CANARY
        if canary_tns:
            w1_id = f"WAVE-0{wave_num}"
            waves.append(
                MigrationWave(
                    wave_id=w1_id,
                    order=wave_num,
                    strategy=MigrationStrategy.CANARY,
                    tunnel_ids=canary_tns,
                    risk=WaveRiskLevel.LOW,
                    modeled_centrality_score=1.0,
                    prerequisites=[
                        "VERIFY_CANARY_HEALTH_BASELINE",
                        "OBTAIN_CHANGE_MANAGEMENT_APPROVAL",
                        "DEPLOY_SYNTHETIC_HEARTBEAT_PROBES",
                    ],
                    validation_checks=[
                        "IKE_SA_ESTABLISHED",
                        "CHILD_SA_ESTABLISHED",
                        "TRAFFIC_FLOW_VERIFIED",
                        "OBSERVE_24H_STABILITY_PERIOD",
                    ],
                    rollback=rollback_plan,
                    depends_on_wave=[],
                )
            )
            wave_num += 1

        # Wave 2: LOW_RISK_BATCH
        if batch_tns:
            w_id = f"WAVE-0{wave_num}"
            dep_wave = [waves[-1].wave_id] if waves else []
            waves.append(
                MigrationWave(
                    wave_id=w_id,
                    order=wave_num,
                    strategy=MigrationStrategy.LOW_RISK_BATCH,
                    tunnel_ids=batch_tns,
                    risk=WaveRiskLevel.LOW,
                    modeled_centrality_score=2.5,
                    prerequisites=[f"{dep_wave[0]}_CANARY_SUCCESSFULLY_COMPLETED"] if dep_wave else [],
                    validation_checks=[
                        "IKE_SA_ESTABLISHED",
                        "CHILD_SA_ESTABLISHED",
                        "PING_SWEEP_VERIFICATION",
                    ],
                    rollback=rollback_plan,
                    depends_on_wave=dep_wave,
                )
            )
            wave_num += 1

        # Wave 3: DEPENDENCY_ORDERED
        if dep_tns:
            w_id = f"WAVE-0{wave_num}"
            dep_wave = [waves[-1].wave_id] if waves else []
            waves.append(
                MigrationWave(
                    wave_id=w_id,
                    order=wave_num,
                    strategy=MigrationStrategy.DEPENDENCY_ORDERED,
                    tunnel_ids=dep_tns,
                    risk=WaveRiskLevel.MEDIUM,
                    modeled_centrality_score=5.0,
                    prerequisites=[
                        f"{dep_wave[0]}_SUCCESSFULLY_COMPLETED",
                        "COORDINATE_REGIONAL_BRANCH_TEAMS",
                    ],
                    validation_checks=[
                        "IKE_SA_ESTABLISHED",
                        "CHILD_SA_ESTABLISHED",
                        "ROUTE_TABLE_CONVERGENCE_CHECK",
                    ],
                    rollback=rollback_plan,
                    depends_on_wave=dep_wave,
                )
            )
            wave_num += 1

        # Wave 4: FINAL_HIGH_RISK
        if high_risk_tns:
            w_id = f"WAVE-0{wave_num}"
            dep_wave = [waves[-1].wave_id] if waves else []
            waves.append(
                MigrationWave(
                    wave_id=w_id,
                    order=wave_num,
                    strategy=MigrationStrategy.FINAL_HIGH_RISK,
                    tunnel_ids=high_risk_tns,
                    risk=WaveRiskLevel.HIGH,
                    modeled_centrality_score=8.0,
                    prerequisites=[
                        f"{dep_wave[0]}_SUCCESSFULLY_COMPLETED",
                        "OPEN_EXECUTIVE_MAINTENANCE_WINDOW",
                        "DEDICATED_ON_CALL_ESCALATION_ACTIVE",
                    ],
                    validation_checks=[
                        "CORE_HUB_BGP_SESSION_ESTABLISHED",
                        "END_TO_END_LATENCY_WITHIN_SLA",
                        "NO_CRYPTO_ERRORS_IN_CORE_GATEWAY_LOGS",
                    ],
                    rollback=rollback_plan,
                    depends_on_wave=dep_wave,
                )
            )

        summary = MigrationPlanSummary(
            total_tunnels=len(simulation_result.tunnel_results),
            eligible=len(eligible_tunnels),
            blocked=len(blocked_tunnels),
            unknown=unknown_count,
            wave_count=len(waves),
        )

        plan_id = f"plan-{simulation_result.simulation_id}"
        plan = MigrationPlan(
            migration_plan_id=plan_id,
            simulation_id=simulation_result.simulation_id,
            objective=objective,
            created_at=datetime.now(timezone.utc),
            summary=summary,
            waves=waves,
            blocked_tunnels=blocked_tunnels,
        )

        self._plans[plan_id] = plan
        logger.info("Generated migration plan %s: %d waves, %d eligible, %d blocked",
                    plan_id, len(waves), len(eligible_tunnels), len(blocked_tunnels))
        return plan
