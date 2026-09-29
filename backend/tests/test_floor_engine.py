"""
STATEFLUX — Security Floor Engine Tests
=======================================
Phase 2 — Security Intelligence Layer

Tests:
  - Pareto-minimal floor frontier calculation
  - One-dimensional dominance (dominated proposal eliminated from floor)
  - Multi-dimensional non-dominance (trade-off proposals both preserved on frontier)
  - Display floor derivation
  - Floor gap calculation across scenarios (S01, S02, S03, HERO-A, S12)
  - Safe handling of unknown/incomplete data
"""

import pytest

from app.models.base import Protocol, IKEVersion
from app.models.proposal import Proposal
from app.models.security_vector import SecurityVector, StrengthClass
from app.models.security_floor import GapLevel
from app.services.normalizer import ProposalNormalizer
from app.services.floor_engine import SecurityFloorEngine


class TestSecurityFloorEngine:

    def setup_method(self):
        self.normalizer = ProposalNormalizer()
        self.engine = SecurityFloorEngine(self.normalizer)

    def _make_vec(self, pid: str, enc: str, dh: int, protocol: str = "ESP", pfs: bool = True, integ=None) -> SecurityVector:
        data = {
            "proposal_id": pid, "owner_endpoint_id": "ep-1",
            "protocol": protocol, "encryption_algorithm": enc,
            "dh_group": dh, "pfs": pfs if protocol == "ESP" else False,
            "priority": 1,
        }
        if "GCM" not in enc:
            data["integrity_algorithm"] = integ or "HMAC-SHA-256"
        if protocol == "IKE":
            data["prf"] = "PRF-HMAC-SHA-256"
            data["ike_version"] = "IKEv2"
        prop = Proposal.model_validate(data)
        return self.normalizer.normalize(prop)

    def test_single_proposal_frontier(self):
        """Single proposal common space has a frontier of 1, identical to display floor."""
        v = self._make_vec("p1", "AES-256-GCM", 20)
        frontier = self.engine.calculate_floor_frontier([v])
        assert len(frontier) == 1
        assert frontier[0].proposal_id == "p1"

        disp = self.engine.derive_display_floor(frontier)
        assert disp is not None
        assert disp.proposal_id == "p1"

    def test_one_dimensional_dominance(self):
        """Strong proposal dominates weak proposal; weak proposal is the sole floor element."""
        v_strong = self._make_vec("p-strong", "AES-256-GCM", 20)
        v_weak = self._make_vec("p-weak", "AES-128-CBC", 14)

        frontier = self.engine.calculate_floor_frontier([v_strong, v_weak])
        # v_strong strictly dominates v_weak in strength.
        # Therefore v_strong is NOT on the floor frontier (it dominates another permitted element).
        # v_weak is the Pareto-minimal element (nothing is weaker than it).
        assert len(frontier) == 1
        assert frontier[0].proposal_id == "p-weak"

    def test_multidimensional_non_dominance_frontier(self):
        """Two proposals with non-dominated trade-offs are BOTH preserved on the frontier."""
        # v1: AES-256-CBC (stronger enc 256-bit), DH-14 (weaker DH 2048-bit)
        # v2: AES-128-CBC (weaker enc 128-bit), DH-20 (stronger DH 384-bit)
        v1 = self._make_vec("v1", "AES-256-CBC", 14)
        v2 = self._make_vec("v2", "AES-128-CBC", 20)

        frontier = self.engine.calculate_floor_frontier([v1, v2])
        assert len(frontier) == 2, "Both non-dominated proposals must be in the floor frontier"
        frontier_ids = {p.proposal_id for p in frontier}
        assert frontier_ids == {"v1", "v2"}

    def test_s01_floor_gap_is_none(self):
        """S01: When selected matches floor, gap is NONE."""
        v_strong = self._make_vec("p1", "AES-256-GCM", 20)
        gap = self.engine.calculate_floor_gap(selected=v_strong, floor=v_strong)
        assert gap.has_gap is False
        assert gap.gap_level == GapLevel.NONE

    def test_s02_weak_selected_matches_floor_gap(self):
        """S02: When selected is weak and floor is weak, there is no fallback gap."""
        v_weak = self._make_vec("p1", "AES-128-CBC", 14, integ="HMAC-SHA-1")
        gap = self.engine.calculate_floor_gap(selected=v_weak, floor=v_weak)
        assert gap.has_gap is False
        assert gap.gap_level == GapLevel.NONE

    def test_s03_high_floor_gap(self):
        """S03: Selected is strong (AES-256-GCM / DH-20) but floor is weak (AES-128-CBC / DH-14)."""
        v_selected = self._make_vec("p-sel", "AES-256-GCM", 20)
        v_floor = self._make_vec("p-flr", "AES-128-CBC", 14)

        gap = self.engine.calculate_floor_gap(selected=v_selected, floor=v_floor)
        assert gap.has_gap is True
        assert gap.gap_level in (GapLevel.HIGH, GapLevel.CRITICAL)

        # Check dimension degradation
        dims = {d.dimension: d for d in gap.dimension_gaps}
        assert "encryption" in dims
        assert dims["encryption"].selected_class == StrengthClass.STRONG
        assert dims["encryption"].floor_class == StrengthClass.WEAK

    def test_hero_a_critical_floor_gap(self):
        """HERO-A: Selected is AES-256-GCM / DH-20, floor falls back to 3DES / DH-2."""
        v_selected = self._make_vec("p-sel", "AES-256-GCM", 20)
        v_floor = self._make_vec("p-3des", "3DES", 2, integ="HMAC-SHA-1")

        gap = self.engine.calculate_floor_gap(selected=v_selected, floor=v_floor)
        assert gap.has_gap is True
        assert gap.gap_level == GapLevel.CRITICAL

        dims = {d.dimension: d for d in gap.dimension_gaps}
        assert "encryption" in dims
        assert dims["encryption"].floor_class == StrengthClass.DISALLOWED

    def test_unknown_values_handled_safely(self):
        """Incomplete values produce PARTIAL status without inventing facts."""
        v_unknown = self.normalizer.normalize_dict({
            "encryption": "UNKNOWN",
            "dh_group": None,
            "pfs": None,
        })
        res = self.engine.evaluate_floor(
            tunnel_id="tn-unknown",
            protocol=Protocol.ESP,
            common_proposals=[v_unknown],
        )
        assert res.floor_status == "PARTIAL"
        assert res.confidence in (StrengthClass.UNKNOWN, StrengthClass.WEAK, "LOW", "UNKNOWN")
