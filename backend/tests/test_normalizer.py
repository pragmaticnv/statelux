"""
STATEFLUX — Cryptographic Normalizer Tests
==========================================
Phase 2 — Security Intelligence Layer

Tests:
  - Cryptographic transform classification (NIST / RFC 9395 rules)
  - Strict separation of IKE vs ESP / Child-SA (PFS not applied to IKE)
  - Multidimensional SecurityVector comparisons
  - Pareto dominance and non-dominance (incomparable vectors)
"""

import pytest

from app.models.base import Protocol, IKEVersion
from app.models.proposal import Proposal
from app.models.security_vector import StrengthClass, DimensionComparison
from app.services.normalizer import ProposalNormalizer


class TestProposalNormalizer:

    def setup_method(self):
        self.normalizer = ProposalNormalizer()

    def test_normalize_strong_ike_proposal(self):
        prop = Proposal.model_validate({
            "proposal_id": "ep-001-ike-01",
            "owner_endpoint_id": "ep-001",
            "protocol": "IKE",
            "ike_version": "IKEv2",
            "encryption_algorithm": "AES-256-GCM",
            "integrity_algorithm": None,
            "prf": "PRF-HMAC-SHA-384",
            "dh_group": 20,
            "pfs": False,
            "priority": 1,
        })
        vec = self.normalizer.normalize(prop)
        assert vec.encryption.strength_class == StrengthClass.STRONG
        assert vec.encryption.key_size == 256
        assert vec.dh_group.strength_class == StrengthClass.STRONG
        # PFS is NOT an IKE dimension — must remain None / UNKNOWN
        assert vec.pfs is None
        assert vec.pfs_strength == StrengthClass.UNKNOWN
        assert vec.is_aead is True
        assert vec.is_disallowed is False
        assert vec.is_legacy is False

    def test_normalize_weak_proposal(self):
        prop = Proposal.model_validate({
            "proposal_id": "ep-012-ike-01",
            "owner_endpoint_id": "ep-012",
            "protocol": "IKE",
            "ike_version": "IKEv2",
            "encryption_algorithm": "AES-128-CBC",
            "integrity_algorithm": "HMAC-SHA-1",
            "prf": "PRF-HMAC-SHA-1",
            "dh_group": 14,
            "pfs": False,
            "priority": 1,
        })
        vec = self.normalizer.normalize(prop)
        assert vec.encryption.strength_class == StrengthClass.WEAK
        assert vec.integrity.strength_class == StrengthClass.WEAK
        assert vec.dh_group.strength_class == StrengthClass.ACCEPTABLE
        assert vec.is_legacy is True

    def test_normalize_disallowed_3des_proposal(self):
        prop = Proposal.model_validate({
            "proposal_id": "ep-012-ike-02",
            "owner_endpoint_id": "ep-012",
            "protocol": "IKE",
            "ike_version": "IKEv1",
            "encryption_algorithm": "3DES",
            "integrity_algorithm": "HMAC-SHA-1",
            "prf": "PRF-HMAC-SHA-1",
            "dh_group": 2,
            "pfs": False,
            "priority": 2,
        })
        vec = self.normalizer.normalize(prop)
        assert vec.encryption.strength_class == StrengthClass.DISALLOWED
        assert vec.dh_group.strength_class == StrengthClass.DISALLOWED
        assert vec.is_disallowed is True
        assert vec.is_legacy is True

    def test_pfs_separation_on_esp_proposals(self):
        prop_pfs = Proposal.model_validate({
            "proposal_id": "ep-001-esp-01",
            "owner_endpoint_id": "ep-001",
            "protocol": "ESP",
            "encryption_algorithm": "AES-256-GCM",
            "integrity_algorithm": None,
            "dh_group": 20,
            "pfs": True,
            "priority": 1,
        })
        vec_pfs = self.normalizer.normalize(prop_pfs)
        assert vec_pfs.pfs is True
        assert vec_pfs.pfs_strength == StrengthClass.STRONG

        prop_no_pfs = Proposal.model_validate({
            "proposal_id": "ep-001-esp-02",
            "owner_endpoint_id": "ep-001",
            "protocol": "ESP",
            "encryption_algorithm": "AES-256-GCM",
            "integrity_algorithm": None,
            "dh_group": None,
            "pfs": False,
            "priority": 2,
        })
        vec_no_pfs = self.normalizer.normalize(prop_no_pfs)
        assert vec_no_pfs.pfs is False
        assert vec_no_pfs.pfs_strength == StrengthClass.WEAK

    def test_vector_one_dimensional_dominance(self):
        """AES-256-GCM / DH-20 strictly dominates AES-128-CBC / DH-14."""
        prop_strong = Proposal.model_validate({
            "proposal_id": "p-strong", "owner_endpoint_id": "ep-1",
            "protocol": "IKE", "ike_version": "IKEv2",
            "encryption_algorithm": "AES-256-GCM", "integrity_algorithm": None,
            "prf": "PRF-HMAC-SHA-256", "dh_group": 20, "pfs": False, "priority": 1,
        })
        prop_weak = Proposal.model_validate({
            "proposal_id": "p-weak", "owner_endpoint_id": "ep-1",
            "protocol": "IKE", "ike_version": "IKEv2",
            "encryption_algorithm": "AES-128-CBC", "integrity_algorithm": "HMAC-SHA-1",
            "prf": "PRF-HMAC-SHA-256", "dh_group": 14, "pfs": False, "priority": 2,
        })
        v_strong = self.normalizer.normalize(prop_strong)
        v_weak = self.normalizer.normalize(prop_weak)

        assert v_strong.dominates(v_weak)
        assert v_weak.is_dominated_by(v_strong)
        assert v_strong.compare_to(v_weak) == DimensionComparison.STRONGER
        assert v_weak.compare_to(v_strong) == DimensionComparison.WEAKER

    def test_vector_multidimensional_non_dominance(self):
        """Proposal 1 has stronger cipher; Proposal 2 has stronger DH -> INCOMPARABLE."""
        # P1: AES-256-CBC (ACCEPTABLE enc), DH-14 (ACCEPTABLE dh)
        prop_1 = Proposal.model_validate({
            "proposal_id": "p1", "owner_endpoint_id": "ep-1",
            "protocol": "IKE", "ike_version": "IKEv2",
            "encryption_algorithm": "AES-256-CBC", "integrity_algorithm": "HMAC-SHA-256",
            "prf": "PRF-HMAC-SHA-256", "dh_group": 14, "pfs": False, "priority": 1,
        })
        # P2: AES-128-CBC (WEAK enc), DH-20 (STRONG dh)
        prop_2 = Proposal.model_validate({
            "proposal_id": "p2", "owner_endpoint_id": "ep-1",
            "protocol": "IKE", "ike_version": "IKEv2",
            "encryption_algorithm": "AES-128-CBC", "integrity_algorithm": "HMAC-SHA-256",
            "prf": "PRF-HMAC-SHA-256", "dh_group": 20, "pfs": False, "priority": 2,
        })
        v1 = self.normalizer.normalize(prop_1)
        v2 = self.normalizer.normalize(prop_2)

        # Neither dominates the other!
        assert not v1.dominates(v2)
        assert not v2.dominates(v1)
        assert v1.compare_to(v2) == DimensionComparison.INCOMPARABLE
        assert v2.compare_to(v1) == DimensionComparison.INCOMPARABLE
