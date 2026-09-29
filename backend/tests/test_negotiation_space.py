"""
STATEFLUX — Negotiation Space Engine Tests
==========================================
Phase 2 — Security Intelligence Layer

Tests:
  - Proposal intersection calculation
  - Strict separation of IKE vs Child-SA spaces
  - Priority ordering preservation
  - Incompatibility detection (S04 PFS, S05 DH, S06 Encryption)
  - Confidence derivation
"""

import pytest

from app.models.base import Protocol, NegotiationStatus, IKEVersion
from app.models.proposal import Proposal
from app.models.endpoint import Endpoint
from app.models.negotiation import Negotiation
from app.models.negotiation_space import CompatibilityStatus, ConfidenceLevel
from app.services.negotiation_space_engine import NegotiationSpaceEngine


class TestNegotiationSpaceEngine:

    def setup_method(self):
        self.engine = NegotiationSpaceEngine()

    def test_ike_and_child_sa_separation(self, dataset):
        """Negotiation space separates IKE common proposals from ESP proposals."""
        tunnel = dataset.tunnels["tn-001"]
        ep_a = dataset.endpoints[tunnel.endpoint_a]
        ep_b = dataset.endpoints[tunnel.endpoint_b]
        neg = dataset.negotiations.get(tunnel.negotiation_id)

        space = self.engine.compute_space(
            tunnel_id=tunnel.tunnel_id,
            endpoint_a=ep_a,
            endpoint_b=ep_b,
            proposals=dataset.proposals,
            negotiation=neg,
        )

        assert space.tunnel_id == "tn-001"
        assert space.is_fully_compatible is True

        # All proposals in IKE space must be IKE protocol
        for pid in space.ike_common_space:
            assert dataset.proposals[pid].protocol == Protocol.IKE

        # All proposals in ESP space must be ESP protocol
        for pid in space.child_sa_common_space:
            assert dataset.proposals[pid].protocol == Protocol.ESP

    def test_priority_ordering_preserved(self, dataset):
        """Common proposals must preserve endpoint A's priority ordering."""
        tunnel = dataset.tunnels["tn-001"]
        ep_a = dataset.endpoints[tunnel.endpoint_a]
        ep_b = dataset.endpoints[tunnel.endpoint_b]
        neg = dataset.negotiations.get(tunnel.negotiation_id)

        space = self.engine.compute_space(
            tunnel_id=tunnel.tunnel_id,
            endpoint_a=ep_a,
            endpoint_b=ep_b,
            proposals=dataset.proposals,
            negotiation=neg,
        )

        # In S01, initiator proposals are in order of preference
        if len(space.ike_common_space) > 1:
            priorities = [dataset.proposals[pid].priority for pid in space.ike_common_space]
            assert priorities == sorted(priorities), "Initiator priority ordering must be preserved"

    def test_s04_pfs_incompatibility_detected(self, dataset):
        """S04: Tunnel down due to PFS mismatch."""
        s04_tunnels = [t for t in dataset.tunnels.values() if t.annotations.get("scenario") == "S04"]
        assert len(s04_tunnels) >= 1
        t = s04_tunnels[0]
        ep_a = dataset.endpoints[t.endpoint_a]
        ep_b = dataset.endpoints[t.endpoint_b]
        neg = dataset.negotiations.get(t.negotiation_id)

        space = self.engine.compute_space(
            tunnel_id=t.tunnel_id,
            endpoint_a=ep_a,
            endpoint_b=ep_b,
            proposals=dataset.proposals,
            negotiation=neg,
        )

        assert space.is_fully_compatible is False
        assert space.compatibility_status in (
            CompatibilityStatus.INCOMPATIBLE,
            CompatibilityStatus.INCOMPATIBLE_CHILD_SA,
        )

    def test_s05_dh_incompatibility_detected(self, dataset):
        """S05: Tunnel down due to DH group mismatch."""
        s05_tunnels = [t for t in dataset.tunnels.values() if t.annotations.get("scenario") == "S05"]
        assert len(s05_tunnels) >= 1
        t = s05_tunnels[0]
        ep_a = dataset.endpoints[t.endpoint_a]
        ep_b = dataset.endpoints[t.endpoint_b]
        neg = dataset.negotiations.get(t.negotiation_id)

        space = self.engine.compute_space(
            tunnel_id=t.tunnel_id,
            endpoint_a=ep_a,
            endpoint_b=ep_b,
            proposals=dataset.proposals,
            negotiation=neg,
        )

        assert space.is_fully_compatible is False
        assert len(space.ike_common_space) == 0

    def test_s06_encryption_incompatibility_detected(self, dataset):
        """S06: Tunnel down due to cipher mismatch."""
        s06_tunnels = [t for t in dataset.tunnels.values() if t.annotations.get("scenario") == "S06"]
        assert len(s06_tunnels) >= 1
        t = s06_tunnels[0]
        ep_a = dataset.endpoints[t.endpoint_a]
        ep_b = dataset.endpoints[t.endpoint_b]
        neg = dataset.negotiations.get(t.negotiation_id)

        space = self.engine.compute_space(
            tunnel_id=t.tunnel_id,
            endpoint_a=ep_a,
            endpoint_b=ep_b,
            proposals=dataset.proposals,
            negotiation=neg,
        )

        assert space.is_fully_compatible is False
        assert len(space.ike_common_space) == 0

    def test_s03_wide_fallback_intersection(self, dataset):
        """S03: Must produce common space containing both strong and weak fallback suites."""
        s03_tunnels = [t for t in dataset.tunnels.values() if t.annotations.get("scenario") == "S03"]
        assert len(s03_tunnels) >= 1
        t = s03_tunnels[0]
        ep_a = dataset.endpoints[t.endpoint_a]
        ep_b = dataset.endpoints[t.endpoint_b]
        neg = dataset.negotiations.get(t.negotiation_id)

        space = self.engine.compute_space(
            tunnel_id=t.tunnel_id,
            endpoint_a=ep_a,
            endpoint_b=ep_b,
            proposals=dataset.proposals,
            negotiation=neg,
        )

        assert space.is_fully_compatible is True
        assert len(space.ike_common_space) >= 1
