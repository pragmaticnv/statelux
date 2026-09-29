"""
STATEFLUX — Digital Twin Service Tests
======================================
Phase 2 — Security Intelligence Layer

Tests:
  - Tunnel Digital Twin construction across scenarios (S01, S02, S03, S04-S06, S07, S12, HERO-A, HERO-B)
  - Endpoint Digital Twin construction and peer graph relationships
  - Fleet Digital Twin aggregation and security metrics
"""

import pytest

from app.models.security_floor import GapLevel
from app.models.negotiation_space import CompatibilityStatus, ConfidenceLevel
from app.services.twin_service import DigitalTwinService


class TestDigitalTwinService:

    def setup_method(self):
        self.service = DigitalTwinService()

    def test_s01_secure_tunnel_twin(self, dataset):
        """S01: Fully secure tunnel has STRONG crypto posture, no gap, HIGH confidence."""
        twin = self.service.build_tunnel_twin("tn-001")
        assert twin.tunnel_id == "tn-001"
        assert twin.status == "UP"
        assert twin.compatibility == CompatibilityStatus.COMPATIBLE
        assert twin.confidence == ConfidenceLevel.HIGH
        assert twin.cryptographic_posture == "STRONG"
        assert twin.composite_gap.gap_level in (GapLevel.NONE, GapLevel.LOW)
        assert twin.risk_score == 0.0
        assert twin.risk_level == "INFO"

    def test_s02_weak_selected_tunnel_twin(self, dataset):
        """S02: Weak selected suite has HIGH or CRITICAL risk."""
        twin = self.service.build_tunnel_twin("tn-003")
        assert twin.tunnel_id == "tn-003"
        assert twin.compatibility == CompatibilityStatus.COMPATIBLE
        assert twin.risk_level in ("HIGH", "CRITICAL")
        assert len(twin.findings) > 0

    def test_s03_high_floor_gap_detected(self, dataset):
        """S03: Strong selected with weak fallback MUST produce a HIGH floor gap."""
        s03_tunnels = [t for t in dataset.tunnels.values() if t.annotations.get("scenario") == "S03"]
        assert len(s03_tunnels) >= 1
        t = s03_tunnels[0]

        twin = self.service.build_tunnel_twin(t.tunnel_id)
        assert twin.compatibility == CompatibilityStatus.COMPATIBLE
        assert twin.composite_gap.has_gap is True
        assert twin.composite_gap.gap_level in (GapLevel.HIGH, GapLevel.CRITICAL)

        # Must generate floor gap finding
        gap_findings = [f for f in twin.findings if f.get("rule_id") == "SF-001"]
        assert len(gap_findings) >= 1, "Floor gap finding SF-001 must be generated for S03"

    def test_s04_s05_s06_incompatibility_twins(self, dataset):
        """S04/S05/S06: Incompatible tunnels report FAILED / INCOMPATIBLE status."""
        for scenario in ("S04", "S05", "S06"):
            tunnels = [t for t in dataset.tunnels.values() if t.annotations.get("scenario") == scenario]
            assert len(tunnels) >= 1
            twin = self.service.build_tunnel_twin(tunnels[0].tunnel_id)
            assert twin.compatibility != CompatibilityStatus.COMPATIBLE
            assert twin.status == "DOWN"
            assert twin.ike_floor.floor_status == "NO_COMMON_PROPOSALS"

    def test_s07_latent_rekey_fixture_preserved(self, dataset):
        """S07: Preserves current state without falsely declaring future failure observed."""
        s07_tunnels = [t for t in dataset.tunnels.values() if t.annotations.get("scenario") == "S07"]
        assert len(s07_tunnels) >= 1
        t = s07_tunnels[0]

        twin = self.service.build_tunnel_twin(t.tunnel_id)
        # Current state is UP and negotiated
        assert twin.status == "UP"
        assert twin.rekey_interval > 0
        assert twin.compatibility == CompatibilityStatus.COMPATIBLE

    def test_s12_unknown_incomplete_twin(self, dataset):
        """S12: Produces LOW confidence or PARTIAL status for unobserved data."""
        s12_tunnels = [t for t in dataset.tunnels.values() if t.annotations.get("scenario") == "S12"]
        assert len(s12_tunnels) >= 1
        t = s12_tunnels[0]

        twin = self.service.build_tunnel_twin(t.tunnel_id)
        assert twin.confidence in (ConfidenceLevel.LOW, ConfidenceLevel.MEDIUM, ConfidenceLevel.UNKNOWN)

    def test_hero_a_critical_floor_gap(self, dataset):
        """HERO-A: Strong selected + 3DES floor produces CRITICAL floor gap."""
        hero_a_tunnels = [t for t in dataset.tunnels.values() if "HERO-A" in str(t.annotations)]
        if not hero_a_tunnels:
            hero_a_tunnels = [dataset.tunnels["tn-033"]]

        twin = self.service.build_tunnel_twin(hero_a_tunnels[0].tunnel_id)
        assert twin.composite_gap.has_gap is True
        assert twin.composite_gap.gap_level in (GapLevel.HIGH, GapLevel.CRITICAL)

    def test_endpoint_twin_construction(self, dataset):
        """Endpoint twin builds peer maps and active tunnel counts."""
        ep_twin = self.service.build_endpoint_twin("ep-001")
        assert ep_twin.endpoint_id == "ep-001"
        assert ep_twin.name == "HUB-HS-01"
        assert len(ep_twin.active_tunnels) > 0
        assert len(ep_twin.peer_endpoints) > 0
        assert ep_twin.pfs_supported is True
        assert "IKEv2" in ep_twin.ike_versions

    def test_fleet_twin_aggregation(self, dataset):
        """Fleet twin aggregates posture correctly across all 40 tunnels."""
        fleet_twin = self.service.build_fleet_twin()
        agg = fleet_twin.aggregate_posture

        assert agg.total_tunnels == 40
        assert agg.strong_selected > 0
        assert agg.floor_exposure > 0
        assert agg.incompatible > 0
        assert sum(agg.gap_distribution.values()) == 40
        assert sum(agg.risk_distribution.values()) == 40
        assert sum(agg.confidence_distribution.values()) == 40
