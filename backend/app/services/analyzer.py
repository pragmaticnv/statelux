"""
STATEFLUX — Baseline Structured-Data Analyzer
===============================================
Phase 1A implementation of the IPsec baseline analyzer.

This analyzer operates on STRUCTURED DATA only — it reads the
Pydantic objects loaded from the seed dataset. It does NOT parse
PCAP files (that is Phase 3).

What it does:
  For each tunnel in the dataset:
    1. Resolve the negotiation → selected proposal
    2. Extract normalized assessment fields (IKE version, encryption, etc.)
    3. Run the Rule Engine against the selected proposal
    4. Compute the risk score and level
    5. Return a TunnelAssessment

This analysis pipeline is intentionally minimal for Phase 1.
Future phases will extend it with PCAP parsing, evidence linkage,
security floor comparison, and policy-aware rule evaluation.

NOTE: The analyzer evaluates the SELECTED proposal (the currently
negotiated suite). The Security Floor comparison (selected vs
weakest-permitted) is a Phase 6 function.
"""

from typing import Optional

from app.models.tunnel import Tunnel
from app.models.proposal import Proposal
from app.models.negotiation import Negotiation
from app.models.base import NegotiationStatus, Protocol
from app.services.rule_engine import RuleEngine, TunnelAssessment, SecurityFinding


class BaselineAnalyzer:
    """Analyzes structured IPsec data to produce per-tunnel assessments.

    Stateless between calls. Create once and reuse.
    """

    def __init__(self) -> None:
        self._engine = RuleEngine()

    def analyze_tunnel(
        self,
        tunnel: Tunnel,
        proposals: dict[str, Proposal],
        negotiation: Optional[Negotiation],
        replay_protection: Optional[bool] = None,
        pfs: Optional[bool] = None,
    ) -> TunnelAssessment:
        """Produce a TunnelAssessment for a single tunnel.

        Args:
            tunnel:             The Tunnel to analyze.
            proposals:          Dict of all proposals keyed by proposal_id.
                                Must include all proposals referenced by the tunnel.
            negotiation:        The Negotiation record for this tunnel (may be None).
            replay_protection:  Observed replay protection state (from SecurityState
                                or observations). May be None if unknown.
            pfs:                Observed or configured PFS state for the tunnel.
                                If None, defaults to selected ESP proposal's PFS flag.

        Returns:
            A TunnelAssessment with extracted fields, findings, and risk score.
        """
        self._engine.reset()

        # Determine effective PFS
        effective_pfs = pfs

        # Base fields from tunnel
        assessment = TunnelAssessment(
            tunnel_id=tunnel.tunnel_id,
            ike_version=None,
            mode=tunnel.mode.value,
            encryption=None,
            key_size=None,
            integrity=None,
            dh_group=None,
            pfs=effective_pfs,
            replay_protection=replay_protection,
            rekey_interval=tunnel.rekey_interval,
            sa_status=tunnel.status.value,
        )

        # If no negotiation, or negotiation failed/unknown, return minimal assessment
        if negotiation is None or negotiation.status != NegotiationStatus.SUCCESS:
            assessment.findings = []
            if negotiation and negotiation.status == NegotiationStatus.FAILED:
                # For failed tunnels, note the failure mode
                assessment.sa_status = "DOWN"
            assessment.risk_score, assessment.risk_level = 0.0, "INFO"
            return assessment

        # Extract IKE version from negotiation
        assessment.ike_version = negotiation.ike_version.value

        # Resolve the selected proposal
        selected_id = negotiation.selected_proposal
        selected_proposal: Optional[Proposal] = proposals.get(selected_id) if selected_id else None

        if selected_proposal is None:
            assessment.findings = []
            assessment.risk_score, assessment.risk_level = 0.0, "UNKNOWN"
            return assessment

        # Populate normalized fields
        assessment.encryption = selected_proposal.encryption_algorithm.value
        assessment.key_size   = selected_proposal.key_size
        assessment.integrity  = (
            selected_proposal.integrity_algorithm.value
            if selected_proposal.integrity_algorithm else None
        )
        assessment.dh_group = selected_proposal.dh_group

        if effective_pfs is None and selected_proposal.protocol == Protocol.ESP:
            effective_pfs = selected_proposal.pfs
        assessment.pfs = effective_pfs

        # Run rule engine
        findings = self._engine.evaluate_proposal(
            proposal=selected_proposal,
            tunnel_id=tunnel.tunnel_id,
            ike_version=negotiation.ike_version.value,
            pfs=effective_pfs,
            replay_protection=replay_protection,
        )

        assessment.findings = findings
        assessment.risk_score, assessment.risk_level = self._engine.compute_risk(findings)
        return assessment

    def analyze_fleet(
        self,
        tunnels: list[Tunnel],
        proposals: dict[str, Proposal],
        negotiations: dict[str, Negotiation],
        replay_states: Optional[dict[str, bool]] = None,
        pfs_states: Optional[dict[str, bool]] = None,
    ) -> list[TunnelAssessment]:
        """Analyze all tunnels in a fleet.

        Args:
            tunnels:        All tunnels to analyze.
            proposals:      All proposals indexed by proposal_id.
            negotiations:   All negotiations indexed by negotiation_id.
            replay_states:  Optional dict of tunnel_id → replay_protection state.
            pfs_states:     Optional dict of tunnel_id → pfs state.

        Returns:
            List of TunnelAssessment, one per tunnel.
        """
        results: list[TunnelAssessment] = []
        replay_states = replay_states or {}
        pfs_states = pfs_states or {}

        for tunnel in tunnels:
            negotiation: Optional[Negotiation] = None
            if tunnel.negotiation_id:
                negotiation = negotiations.get(tunnel.negotiation_id)

            replay = replay_states.get(tunnel.tunnel_id)
            pfs = pfs_states.get(tunnel.tunnel_id)

            assessment = self.analyze_tunnel(
                tunnel=tunnel,
                proposals=proposals,
                negotiation=negotiation,
                replay_protection=replay,
                pfs=pfs,
            )
            results.append(assessment)

        return results
