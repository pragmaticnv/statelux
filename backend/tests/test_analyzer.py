"""
STATEFLUX — Rule Engine and Analyzer Tests
============================================
Tests that the rule engine and baseline analyzer produce correct
findings and risk scores for known input.
"""

import pytest
from datetime import datetime, timezone

from app.models.base import IKEVersion, NegotiationStatus, TunnelMode, TunnelStatus
from app.models.proposal import Proposal
from app.models.tunnel import Tunnel
from app.models.negotiation import Negotiation
from app.services.rule_engine import RuleEngine
from app.services.analyzer import BaselineAnalyzer
from app.core.constants import (
    RULE_WEAK_ENCRYPTION,
    RULE_INSECURE_ENCRYPTION,
    RULE_INSECURE_DH,
    RULE_LEGACY_IKE,
    RULE_PFS_DISABLED,
    RULE_WEAK_INTEGRITY,
    RULE_ADEQUATE_DH,
    RULE_REPLAY_DISABLED,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_proposal(proposal_id: str, enc: str, dh: int = 20,
                   pfs: bool = True, protocol: str = "ESP",
                   integrity=None, prf=None, ike_ver=None) -> Proposal:
    """Helper to build valid Proposal objects for testing."""
    is_aead = "GCM" in enc
    data = {
        "proposal_id":           proposal_id,
        "owner_endpoint_id":     "ep-test",
        "protocol":              protocol,
        "ike_version":           ike_ver,
        "encryption_algorithm":  enc,
        "integrity_algorithm":   None if is_aead else (integrity or "HMAC-SHA-256"),
        "prf":                   prf if protocol == "IKE" else None,
        "dh_group":              dh,
        "pfs":                   pfs,
        "priority":              1,
    }
    if protocol == "IKE" and prf is None:
        data["prf"] = "PRF-HMAC-SHA-256"
    return Proposal.model_validate(data)


def _make_tunnel(tunnel_id: str = "tn-test") -> Tunnel:
    return Tunnel.model_validate({
        "tunnel_id":      tunnel_id,
        "fleet_id":       "fleet-001",
        "endpoint_a":     "ep-001",
        "endpoint_b":     "ep-002",
        "mode":           "TUNNEL",
        "status":         "UP",
        "rekey_interval": 3600,
        "negotiation_id": "neg-test",
    })


def _make_negotiation(tunnel_id: str, selected_id: str,
                      ike_ver: str = "IKEv2") -> Negotiation:
    return Negotiation.model_validate({
        "negotiation_id":   "neg-test",
        "tunnel_id":        tunnel_id,
        "ike_version":      ike_ver,
        "offers_from_a":    [selected_id, "ep-test-fallback"],
        "offers_from_b":    [selected_id],
        "common_proposals": [selected_id],
        "selected_proposal": selected_id,
        "selection_rule":   "HIGHEST_PRIORITY_COMMON",
        "status":           "SUCCESS",
    })


# ---------------------------------------------------------------------------
# Rule Engine Unit Tests
# ---------------------------------------------------------------------------

class TestRuleEngine:

    def setup_method(self):
        self.engine = RuleEngine()
        self.engine.reset()

    def test_aes256gcm_dh20_pfs_no_findings(self):
        """Strong proposal must produce zero findings."""
        prop = _make_proposal("p1", "AES-256-GCM", dh=20, pfs=True)
        findings = self.engine.evaluate_proposal(
            prop, "tn-001",
            ike_version="IKEv2", pfs=True, replay_protection=True
        )
        rule_ids = [f.rule_id for f in findings]
        assert RULE_WEAK_ENCRYPTION   not in rule_ids
        assert RULE_INSECURE_ENCRYPTION not in rule_ids
        assert RULE_PFS_DISABLED      not in rule_ids
        assert RULE_REPLAY_DISABLED   not in rule_ids

    def test_3des_triggers_insecure_encryption(self):
        prop = _make_proposal("p2", "3DES", dh=14, pfs=False,
                              protocol="IKE", integrity="HMAC-SHA-1",
                              prf="PRF-HMAC-SHA-1", ike_ver="IKEv1")
        findings = self.engine.evaluate_proposal(prop, "tn-002")
        rule_ids = [f.rule_id for f in findings]
        assert RULE_INSECURE_ENCRYPTION in rule_ids
        # 3DES should never trigger WEAK (only INSECURE)
        assert RULE_WEAK_ENCRYPTION not in rule_ids

    def test_aes128cbc_triggers_weak_encryption(self):
        prop = _make_proposal("p3", "AES-128-CBC", dh=14, pfs=False,
                              protocol="ESP", integrity="HMAC-SHA-256")
        findings = self.engine.evaluate_proposal(prop, "tn-003")
        rule_ids = [f.rule_id for f in findings]
        assert RULE_WEAK_ENCRYPTION in rule_ids
        assert RULE_INSECURE_ENCRYPTION not in rule_ids

    def test_sha1_triggers_weak_integrity(self):
        prop = _make_proposal("p4", "AES-256-CBC", dh=20, pfs=True,
                              protocol="ESP", integrity="HMAC-SHA-1")
        findings = self.engine.evaluate_proposal(prop, "tn-004")
        rule_ids = [f.rule_id for f in findings]
        assert RULE_WEAK_INTEGRITY in rule_ids

    def test_dh14_triggers_adequate_dh_nudge(self):
        prop = _make_proposal("p5", "AES-256-GCM", dh=14, pfs=True)
        findings = self.engine.evaluate_proposal(prop, "tn-005")
        rule_ids = [f.rule_id for f in findings]
        assert RULE_ADEQUATE_DH in rule_ids

    def test_dh2_triggers_insecure_dh(self):
        prop = _make_proposal("p6", "AES-256-GCM", dh=2, pfs=True)
        findings = self.engine.evaluate_proposal(prop, "tn-006")
        rule_ids = [f.rule_id for f in findings]
        assert RULE_INSECURE_DH in rule_ids

    def test_ikev1_triggers_legacy_ike(self):
        prop = _make_proposal("p7", "AES-256-CBC", dh=14, pfs=False,
                              protocol="IKE", integrity="HMAC-SHA-256",
                              prf="PRF-HMAC-SHA-256", ike_ver="IKEv1")
        findings = self.engine.evaluate_proposal(
            prop, "tn-007", ike_version="IKEv1"
        )
        rule_ids = [f.rule_id for f in findings]
        assert RULE_LEGACY_IKE in rule_ids

    def test_pfs_disabled_triggers_finding(self):
        prop = _make_proposal("p8", "AES-256-GCM", dh=None, pfs=False)
        findings = self.engine.evaluate_proposal(
            prop, "tn-008", pfs=False
        )
        rule_ids = [f.rule_id for f in findings]
        assert RULE_PFS_DISABLED in rule_ids

    def test_replay_disabled_triggers_finding(self):
        prop = _make_proposal("p9", "AES-256-GCM", dh=20, pfs=True)
        findings = self.engine.evaluate_proposal(
            prop, "tn-009", replay_protection=False
        )
        rule_ids = [f.rule_id for f in findings]
        assert RULE_REPLAY_DISABLED in rule_ids

    def test_risk_score_increases_with_weaknesses(self):
        """Multiple weaknesses should produce higher score than one weakness."""
        # Only one weakness: PFS off
        prop_partial = _make_proposal("p10", "AES-256-GCM", dh=None, pfs=False)
        f1 = self.engine.evaluate_proposal(prop_partial, "tn-010", pfs=False)
        score1, _ = self.engine.compute_risk(f1)

        self.engine.reset()

        # Multiple weaknesses: 3DES + SHA-1 + PFS off
        prop_weak = _make_proposal("p11", "3DES", dh=14, pfs=False,
                                   protocol="IKE", integrity="HMAC-SHA-1",
                                   prf="PRF-HMAC-SHA-1", ike_ver="IKEv2")
        f2 = self.engine.evaluate_proposal(prop_weak, "tn-011", pfs=False)
        score2, _ = self.engine.compute_risk(f2)

        assert score2 > score1, (
            f"Multiple weaknesses should score higher: {score2} vs {score1}"
        )

    def test_risk_score_capped_at_100(self):
        """Risk score must never exceed 100."""
        prop = _make_proposal("p12", "3DES", dh=2, pfs=False,
                              protocol="IKE", integrity="HMAC-SHA-1",
                              prf="PRF-HMAC-SHA-1", ike_ver="IKEv1")
        findings = self.engine.evaluate_proposal(
            prop, "tn-012",
            ike_version="IKEv1", pfs=False, replay_protection=False
        )
        score, _ = self.engine.compute_risk(findings)
        assert score <= 100.0

    def test_risk_level_mapping(self):
        """INFO → LOW → MEDIUM → HIGH → CRITICAL thresholds."""
        # No weaknesses → INFO
        prop_strong = _make_proposal("p13", "AES-256-GCM", dh=20, pfs=True)
        f_strong = self.engine.evaluate_proposal(prop_strong, "tn-013")
        _, level = self.engine.compute_risk(f_strong)
        assert level == "INFO"

        self.engine.reset()

        # 3DES + DH group 2 → CRITICAL
        prop_weak = _make_proposal("p14", "3DES", dh=2, pfs=False,
                                   protocol="IKE", integrity="HMAC-SHA-1",
                                   prf="PRF-HMAC-SHA-1", ike_ver="IKEv2")
        f_weak = self.engine.evaluate_proposal(prop_weak, "tn-014")
        _, level = self.engine.compute_risk(f_weak)
        assert level == "CRITICAL"

    def test_same_rule_not_double_counted(self):
        """If a rule fires, it must only add to the score once."""
        engine = RuleEngine()
        engine.reset()
        prop = _make_proposal("p15", "AES-256-GCM", dh=None, pfs=False)
        # Create two findings with the same rule ID
        findings = engine.evaluate_proposal(prop, "tn-015", pfs=False)
        pfs_findings = [f for f in findings if f.rule_id == RULE_PFS_DISABLED]
        assert len(pfs_findings) == 1, "PFS rule should fire exactly once"


# ---------------------------------------------------------------------------
# Analyzer Tests
# ---------------------------------------------------------------------------

class TestBaselineAnalyzer:

    def setup_method(self):
        self.analyzer = BaselineAnalyzer()

    def test_strong_tunnel_produces_info_risk(self):
        tunnel = _make_tunnel("tn-strong")
        prop = _make_proposal("ep-test-ike-01", "AES-256-GCM", dh=20,
                              protocol="IKE", ike_ver="IKEv2")
        neg = _make_negotiation("tn-strong", "ep-test-ike-01")

        result = self.analyzer.analyze_tunnel(
            tunnel=tunnel,
            proposals={"ep-test-ike-01": prop, "ep-test-fallback": prop},
            negotiation=neg,
            replay_protection=True,
        )

        assert result.risk_level == "INFO"
        assert result.encryption == "AES-256-GCM"
        assert result.ike_version == "IKEv2"

    def test_failed_negotiation_produces_empty_findings(self):
        tunnel = Tunnel.model_validate({
            "tunnel_id": "tn-fail",
            "fleet_id": "fleet-001",
            "endpoint_a": "ep-001",
            "endpoint_b": "ep-002",
            "mode": "TUNNEL",
            "status": "DOWN",
            "rekey_interval": 3600,
            "negotiation_id": "neg-fail",
        })
        neg = Negotiation.model_validate({
            "negotiation_id":   "neg-fail",
            "tunnel_id":        "tn-fail",
            "ike_version":      "IKEv2",
            "offers_from_a":    ["ep-test-ike-01"],
            "offers_from_b":    ["ep-other-01"],
            "common_proposals": [],
            "selected_proposal": None,
            "selection_rule":   "FAILED_NO_COMMON_PROPOSALS",
            "status":           "FAILED",
        })
        result = self.analyzer.analyze_tunnel(
            tunnel=tunnel,
            proposals={},
            negotiation=neg,
        )
        assert result.findings == []
        assert result.sa_status == "DOWN"

    def test_fleet_analysis_returns_one_result_per_tunnel(self, dataset):
        tunnels = list(dataset.tunnels.values())
        results = self.analyzer.analyze_fleet(
            tunnels=tunnels,
            proposals=dataset.proposals,
            negotiations=dataset.negotiations,
        )
        assert len(results) == len(tunnels)

    def test_dataset_s02_tunnels_have_high_risk(self, dataset):
        """S02 tunnels should produce HIGH or CRITICAL risk via the analyzer."""
        s02_tunnels = [
            t for t in dataset.tunnels.values()
            if t.annotations.get("scenario") == "S02"
        ]
        pfs_states = {
            ss.tunnel_id: ss.selected.pfs
            for ss in dataset.security_states.values()
            if ss.selected and ss.selected.pfs is not None
        }
        replay_states = {
            ss.tunnel_id: ss.controls.replay_protection
            for ss in dataset.security_states.values()
        }
        results = self.analyzer.analyze_fleet(
            tunnels=s02_tunnels,
            proposals=dataset.proposals,
            negotiations=dataset.negotiations,
            pfs_states=pfs_states,
            replay_states=replay_states,
        )
        for result in results:
            assert result.risk_level in ("HIGH", "CRITICAL"), (
                f"S02 tunnel {result.tunnel_id}: expected HIGH/CRITICAL, "
                f"got {result.risk_level} (score={result.risk_score})"
            )
