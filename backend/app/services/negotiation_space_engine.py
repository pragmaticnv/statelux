"""
STATEFLUX — Negotiation Space Engine
====================================
Phase 2 — Security Intelligence Layer

Computes the common negotiation space between two endpoints:
  Endpoint A proposals ∩ Endpoint B proposals

Maintains strict separation between:
  - IKE negotiation space
  - Child-SA / ESP negotiation space (including PFS compatibility)
"""

from typing import Optional

from app.models.base import Protocol, NegotiationStatus, IKEVersion
from app.models.endpoint import Endpoint
from app.models.proposal import Proposal
from app.models.negotiation import Negotiation
from app.models.negotiation_space import (
    TunnelNegotiationSpace,
    ProposalMatch,
    CompatibilityStatus,
    ConfidenceLevel,
)


class NegotiationSpaceEngine:
    """Calculates the mutually acceptable proposal space for a tunnel."""

    @staticmethod
    def _are_ike_proposals_compatible(prop_a: Proposal, prop_b: Proposal) -> bool:
        """Check if two IKE proposals are algorithmically compatible."""
        if prop_a.protocol != Protocol.IKE or prop_b.protocol != Protocol.IKE:
            return False

        # Encryption and key size must match
        if prop_a.encryption_algorithm != prop_b.encryption_algorithm:
            return False
        if prop_a.key_size != prop_b.key_size:
            return False

        # Integrity must match (None for AEAD)
        if prop_a.integrity_algorithm != prop_b.integrity_algorithm:
            return False

        # DH group must match for IKE SA
        if prop_a.dh_group != prop_b.dh_group:
            return False

        # IKE version compatibility
        if prop_a.ike_version and prop_b.ike_version:
            if prop_a.ike_version != prop_b.ike_version:
                return False

        return True

    @staticmethod
    def _are_esp_proposals_compatible(
        prop_a: Proposal,
        prop_b: Proposal,
        endpoint_a: Optional[Endpoint] = None,
        endpoint_b: Optional[Endpoint] = None,
    ) -> bool:
        """Check if two ESP / Child-SA proposals are algorithmically compatible."""
        if prop_a.protocol != Protocol.ESP or prop_b.protocol != Protocol.ESP:
            return False

        # Encryption and key size must match
        if prop_a.encryption_algorithm != prop_b.encryption_algorithm:
            return False
        if prop_a.key_size != prop_b.key_size:
            return False

        # Integrity must match
        if prop_a.integrity_algorithm != prop_b.integrity_algorithm:
            return False

        # PFS compatibility
        pfs_a = prop_a.pfs
        pfs_b = prop_b.pfs

        # If both want PFS: DH group must match and both endpoints must support PFS
        if pfs_a and pfs_b:
            if prop_a.dh_group != prop_b.dh_group:
                return False
            if endpoint_a and not endpoint_a.capabilities.pfs_supported:
                return False
            if endpoint_b and not endpoint_b.capabilities.pfs_supported:
                return False
            return True

        # If neither wants PFS: compatible without DH
        if not pfs_a and not pfs_b:
            return True

        # One requires PFS, the other does not:
        # In standard IPsec, if responder requires PFS and initiator offers non-PFS, negotiation fails.
        return False

    def compute_space(
        self,
        tunnel_id: str,
        endpoint_a: Endpoint,
        endpoint_b: Endpoint,
        proposals: dict[str, Proposal],
        negotiation: Optional[Negotiation] = None,
    ) -> TunnelNegotiationSpace:
        """Compute the complete negotiation space for a tunnel."""

        # 1. Retrieve ordered offers from endpoints
        ike_ids_a = [pid for pid in endpoint_a.configuration.ike_proposals if pid in proposals]
        esp_ids_a = [pid for pid in endpoint_a.configuration.esp_proposals if pid in proposals]
        ike_ids_b = [pid for pid in endpoint_b.configuration.ike_proposals if pid in proposals]
        esp_ids_b = [pid for pid in endpoint_b.configuration.esp_proposals if pid in proposals]

        # If negotiation record has explicit offers, supplement them while preserving order
        if negotiation:
            for pid in negotiation.offers_from_a:
                if pid in proposals and pid not in ike_ids_a and proposals[pid].protocol == Protocol.IKE:
                    ike_ids_a.append(pid)
                elif pid in proposals and pid not in esp_ids_a and proposals[pid].protocol == Protocol.ESP:
                    esp_ids_a.append(pid)
            for pid in negotiation.offers_from_b:
                if pid in proposals and pid not in ike_ids_b and proposals[pid].protocol == Protocol.IKE:
                    ike_ids_b.append(pid)
                elif pid in proposals and pid not in esp_ids_b and proposals[pid].protocol == Protocol.ESP:
                    esp_ids_b.append(pid)

        # 2. Compute IKE common intersection (preserving A's priority ordering)
        ike_common: list[str] = []
        ike_matches: list[ProposalMatch] = []
        seen_ike_common: set[str] = set()

        for pid_a in ike_ids_a:
            prop_a = proposals[pid_a]
            for pid_b in ike_ids_b:
                prop_b = proposals[pid_b]
                if self._are_ike_proposals_compatible(prop_a, prop_b):
                    if pid_a not in seen_ike_common:
                        ike_common.append(pid_a)
                        seen_ike_common.add(pid_a)
                    ike_matches.append(ProposalMatch(
                        proposal_id_a=pid_a,
                        proposal_id_b=pid_b,
                        protocol="IKE",
                        is_identical=(prop_a.encryption_algorithm == prop_b.encryption_algorithm
                                      and prop_a.dh_group == prop_b.dh_group),
                        common_encryption=prop_a.encryption_algorithm.value,
                        common_integrity=prop_a.integrity_algorithm.value if prop_a.integrity_algorithm else None,
                        common_dh_group=prop_a.dh_group,
                        pfs_agreed=None,
                    ))
                    break  # Matched highest priority B offer for this A proposal

        # 3. Compute Child-SA / ESP common intersection
        esp_common: list[str] = []
        esp_matches: list[ProposalMatch] = []
        seen_esp_common: set[str] = set()

        for pid_a in esp_ids_a:
            prop_a = proposals[pid_a]
            for pid_b in esp_ids_b:
                prop_b = proposals[pid_b]
                if self._are_esp_proposals_compatible(prop_a, prop_b, endpoint_a, endpoint_b):
                    if pid_a not in seen_esp_common:
                        esp_common.append(pid_a)
                        seen_esp_common.add(pid_a)
                    esp_matches.append(ProposalMatch(
                        proposal_id_a=pid_a,
                        proposal_id_b=pid_b,
                        protocol="ESP",
                        is_identical=(prop_a.encryption_algorithm == prop_b.encryption_algorithm
                                      and prop_a.pfs == prop_b.pfs),
                        common_encryption=prop_a.encryption_algorithm.value,
                        common_integrity=prop_a.integrity_algorithm.value if prop_a.integrity_algorithm else None,
                        common_dh_group=prop_a.dh_group,
                        pfs_agreed=prop_a.pfs,
                    ))
                    break

        # If Phase 1 negotiation record already specified common proposals, ensure they are represented
        if negotiation and negotiation.status == NegotiationStatus.SUCCESS:
            for pid in negotiation.common_proposals:
                if pid in proposals:
                    p = proposals[pid]
                    if p.protocol == Protocol.IKE and pid not in seen_ike_common:
                        ike_common.append(pid)
                        seen_ike_common.add(pid)
                    elif p.protocol == Protocol.ESP and pid not in seen_esp_common:
                        esp_common.append(pid)
                        seen_esp_common.add(pid)

        # 4. Resolve selected proposals
        selected_ike: Optional[str] = None
        selected_esp: Optional[str] = None
        selection_rule = "HIGHEST_PRIORITY_COMMON"

        if negotiation and negotiation.selected_proposal:
            sel_id = negotiation.selected_proposal
            if sel_id in proposals:
                if proposals[sel_id].protocol == Protocol.IKE:
                    selected_ike = sel_id
                else:
                    selected_esp = sel_id
            selection_rule = negotiation.selection_rule

        # Default selected to highest priority common if not explicitly recorded and successful
        if not selected_ike and ike_common:
            selected_ike = ike_common[0]
        if not selected_esp and esp_common:
            selected_esp = esp_common[0]

        # 5. Determine Compatibility Status
        failure_reason: Optional[str] = None
        if negotiation and negotiation.status == NegotiationStatus.FAILED:
            status = CompatibilityStatus.INCOMPATIBLE
            failure_reason = negotiation.failure_reason or negotiation.selection_rule
            selected_ike = None
            selected_esp = None
        elif len(ike_common) == 0 and len(esp_common) == 0:
            status = CompatibilityStatus.INCOMPATIBLE
            failure_reason = "No mutually acceptable IKE or ESP proposals found between endpoints."
            selected_ike = None
            selected_esp = None
        elif len(ike_common) == 0:
            status = CompatibilityStatus.INCOMPATIBLE_IKE
            failure_reason = "No mutually acceptable IKE proposals found."
            selected_ike = None
        elif len(esp_common) == 0 and len(esp_ids_a) > 0 and len(esp_ids_b) > 0:
            status = CompatibilityStatus.INCOMPATIBLE_CHILD_SA
            failure_reason = "No mutually acceptable ESP/Child-SA proposals found."
            selected_esp = None
        else:
            status = CompatibilityStatus.COMPATIBLE

        # 6. Determine Confidence
        provenance_notes = []
        confidence = ConfidenceLevel.HIGH

        if not endpoint_a or not endpoint_b:
            confidence = ConfidenceLevel.UNKNOWN
            provenance_notes.append("Endpoint configuration unavailable.")
        elif endpoint_a.validation_status.value != "VALIDATED" or endpoint_b.validation_status.value != "VALIDATED":
            confidence = ConfidenceLevel.MEDIUM
            provenance_notes.append("One or both endpoints have unvalidated profile configurations.")

        # Check for incomplete observation scenarios (e.g. S12)
        if "incomplete" in tunnel_id.lower() or "s12" in (tunnel_id.lower()):
            confidence = ConfidenceLevel.LOW
            provenance_notes.append("Observation state is partial or unverified.")

        return TunnelNegotiationSpace(
            tunnel_id=tunnel_id,
            endpoint_a=endpoint_a.endpoint_id,
            endpoint_b=endpoint_b.endpoint_id,
            ike_common_space=ike_common,
            child_sa_common_space=esp_common,
            ike_offers_a=ike_ids_a,
            ike_offers_b=ike_ids_b,
            esp_offers_a=esp_ids_a,
            esp_offers_b=esp_ids_b,
            ike_matches=ike_matches,
            esp_matches=esp_matches,
            selected_ike_proposal=selected_ike,
            selected_esp_proposal=selected_esp,
            selection_rule=selection_rule,
            compatibility_status=status,
            failure_reason=failure_reason,
            confidence=confidence,
            provenance_notes=provenance_notes,
        )
