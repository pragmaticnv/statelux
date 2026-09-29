"""
STATEFLUX — Schema Validation Tests
======================================
Tests that Pydantic models accept valid data and reject invalid data.
These are the most fundamental tests in the suite — if the schemas
are wrong, everything downstream is wrong.
"""

import pytest
from datetime import datetime, timezone
from pydantic import ValidationError

from app.models.base import (
    Protocol, IKEVersion, EncryptionAlgorithm, IntegrityAlgorithm,
    PRFAlgorithm, TunnelMode, TunnelStatus, NegotiationStatus, RiskLevel,
    ProfileType, ValidationStatus, SourceType, EntityType,
)
from app.models.fleet import Fleet
from app.models.endpoint import Endpoint, EndpointCapabilities, EndpointConfiguration, EndpointNetwork, EndpointRekey
from app.models.proposal import Proposal
from app.models.tunnel import Tunnel
from app.models.negotiation import Negotiation
from app.models.observation import Observation
from app.models.security_state import SecurityState, CryptoSuite, SecurityControls, RiskAssessment


# ---------------------------------------------------------------------------
# Proposal validation
# ---------------------------------------------------------------------------

class TestProposalValidation:

    def _base_ike_gcm(self, **overrides) -> dict:
        base = {
            "proposal_id": "test-ike-001",
            "owner_endpoint_id": "ep-001",
            "protocol": "IKE",
            "ike_version": "IKEv2",
            "encryption_algorithm": "AES-256-GCM",
            "integrity_algorithm": None,      # AEAD: no separate integrity
            "prf": "PRF-HMAC-SHA-256",
            "dh_group": 20,
            "pfs": False,
            "priority": 1,
        }
        base.update(overrides)
        return base

    def _base_ike_cbc(self, **overrides) -> dict:
        base = {
            "proposal_id": "test-ike-002",
            "owner_endpoint_id": "ep-001",
            "protocol": "IKE",
            "ike_version": "IKEv2",
            "encryption_algorithm": "AES-256-CBC",
            "integrity_algorithm": "HMAC-SHA-256",
            "prf": "PRF-HMAC-SHA-256",
            "dh_group": 14,
            "pfs": False,
            "priority": 2,
        }
        base.update(overrides)
        return base

    def _base_esp_gcm(self, **overrides) -> dict:
        base = {
            "proposal_id": "test-esp-001",
            "owner_endpoint_id": "ep-001",
            "protocol": "ESP",
            "ike_version": None,
            "encryption_algorithm": "AES-256-GCM",
            "integrity_algorithm": None,
            "prf": None,
            "dh_group": 20,
            "pfs": True,
            "priority": 1,
        }
        base.update(overrides)
        return base

    def test_valid_ike_gcm_proposal(self):
        p = Proposal.model_validate(self._base_ike_gcm())
        assert p.is_aead is True
        assert p.key_size == 256

    def test_valid_ike_cbc_proposal(self):
        p = Proposal.model_validate(self._base_ike_cbc())
        assert p.is_aead is False
        assert p.key_size == 256

    def test_valid_esp_gcm_with_pfs(self):
        p = Proposal.model_validate(self._base_esp_gcm())
        assert p.pfs is True
        assert p.prf is None  # PRF not used in ESP

    def test_valid_esp_gcm_no_pfs(self):
        p = Proposal.model_validate(self._base_esp_gcm(dh_group=None, pfs=False))
        assert p.pfs is False

    def test_key_size_derived_automatically(self):
        data = self._base_ike_gcm()
        del data["proposal_id"]
        data["proposal_id"] = "test-keysize"
        # Don't provide key_size — should be derived
        p = Proposal.model_validate(data)
        assert p.key_size == 256

    def test_key_size_mismatch_rejected(self):
        with pytest.raises(ValidationError, match="key_size"):
            Proposal.model_validate(self._base_ike_gcm(key_size=128))

    def test_esp_with_prf_rejected(self):
        with pytest.raises(ValidationError, match="PRF"):
            Proposal.model_validate(self._base_esp_gcm(prf="PRF-HMAC-SHA-256"))

    def test_non_aead_esp_without_integrity_rejected(self):
        with pytest.raises(ValidationError, match="integrity_algorithm"):
            Proposal.model_validate({
                "proposal_id": "test-bad-esp",
                "owner_endpoint_id": "ep-001",
                "protocol": "ESP",
                "ike_version": None,
                "encryption_algorithm": "AES-256-CBC",
                "integrity_algorithm": None,   # MISSING — required for non-AEAD
                "prf": None,
                "dh_group": 14,
                "pfs": True,
                "priority": 1,
            })

    def test_esp_pfs_true_requires_dh_group(self):
        with pytest.raises(ValidationError, match="ESP proposal with pfs=True must specify dh_group"):
            Proposal.model_validate(self._base_esp_gcm(dh_group=None, pfs=True))

    def test_ike_requires_dh_group(self):
        with pytest.raises(ValidationError, match="IKE proposals must specify dh_group"):
            Proposal.model_validate(self._base_ike_gcm(dh_group=None))

    def test_non_aead_ike_without_integrity_rejected(self):
        with pytest.raises(ValidationError, match="integrity_algorithm"):
            Proposal.model_validate(self._base_ike_cbc(integrity_algorithm=None))

    def test_priority_must_be_positive(self):
        with pytest.raises(ValidationError, match="priority must be >= 1"):
            Proposal.model_validate(self._base_ike_gcm(priority=0))

    def test_unknown_dh_group_rejected(self):
        with pytest.raises(ValidationError, match="recognised IANA group"):
            Proposal.model_validate(self._base_ike_gcm(dh_group=999))

    def test_3des_key_size_is_168(self):
        p = Proposal.model_validate({
            "proposal_id": "test-3des",
            "owner_endpoint_id": "ep-012",
            "protocol": "IKE",
            "ike_version": "IKEv1",
            "encryption_algorithm": "3DES",
            "integrity_algorithm": "HMAC-SHA-1",
            "prf": "PRF-HMAC-SHA-1",
            "dh_group": 14,
            "pfs": False,
            "priority": 1,
        })
        assert p.key_size == 168
        assert p.is_aead is False


# ---------------------------------------------------------------------------
# Tunnel validation
# ---------------------------------------------------------------------------

class TestTunnelValidation:

    def test_self_tunnel_rejected(self):
        with pytest.raises(ValidationError, match="cannot connect an endpoint to itself"):
            Tunnel.model_validate({
                "tunnel_id": "tn-bad",
                "fleet_id": "fleet-001",
                "endpoint_a": "ep-001",
                "endpoint_b": "ep-001",   # SAME as A
                "mode": "TUNNEL",
                "status": "UP",
                "rekey_interval": 3600,
            })

    def test_valid_tunnel(self):
        t = Tunnel.model_validate({
            "tunnel_id": "tn-001",
            "fleet_id": "fleet-001",
            "endpoint_a": "ep-001",
            "endpoint_b": "ep-002",
            "mode": "TUNNEL",
            "status": "UP",
            "rekey_interval": 3600,
        })
        assert t.tunnel_id == "tn-001"

    def test_negative_rekey_interval_rejected(self):
        with pytest.raises(ValidationError, match="positive"):
            Tunnel.model_validate({
                "tunnel_id": "tn-bad",
                "fleet_id": "fleet-001",
                "endpoint_a": "ep-001",
                "endpoint_b": "ep-002",
                "mode": "TUNNEL",
                "status": "UP",
                "rekey_interval": -1,
            })


# ---------------------------------------------------------------------------
# Negotiation validation
# ---------------------------------------------------------------------------

class TestNegotiationValidation:

    def test_success_without_selected_rejected(self):
        with pytest.raises(ValidationError, match="must have selected_proposal"):
            Negotiation.model_validate({
                "negotiation_id": "neg-bad",
                "tunnel_id": "tn-001",
                "ike_version": "IKEv2",
                "offers_from_a": ["prop-a-1"],
                "offers_from_b": ["prop-b-1"],
                "common_proposals": ["prop-a-1"],
                "selected_proposal": None,     # MISSING for SUCCESS
                "selection_rule": "HIGHEST_PRIORITY_COMMON",
                "status": "SUCCESS",
            })

    def test_failed_with_selected_rejected(self):
        with pytest.raises(ValidationError, match="must not have selected_proposal"):
            Negotiation.model_validate({
                "negotiation_id": "neg-bad",
                "tunnel_id": "tn-001",
                "ike_version": "IKEv2",
                "offers_from_a": ["prop-a-1"],
                "offers_from_b": ["prop-b-1"],
                "common_proposals": [],
                "selected_proposal": "prop-a-1",   # INVALID for FAILED
                "selection_rule": "FAILED_NO_COMMON",
                "status": "FAILED",
            })

    def test_selected_not_in_common_rejected(self):
        with pytest.raises(ValidationError, match="not in common_proposals"):
            Negotiation.model_validate({
                "negotiation_id": "neg-bad",
                "tunnel_id": "tn-001",
                "ike_version": "IKEv2",
                "offers_from_a": ["prop-a-1", "prop-a-2"],
                "offers_from_b": ["prop-b-1"],
                "common_proposals": ["prop-a-2"],
                "selected_proposal": "prop-a-1",   # not in common
                "selection_rule": "HIGHEST_PRIORITY_COMMON",
                "status": "SUCCESS",
            })

    def test_common_not_in_offers_a_rejected(self):
        with pytest.raises(ValidationError, match="not present in offers_from_a"):
            Negotiation.model_validate({
                "negotiation_id": "neg-bad",
                "tunnel_id": "tn-001",
                "ike_version": "IKEv2",
                "offers_from_a": ["prop-a-1"],
                "offers_from_b": ["prop-b-1"],
                "common_proposals": ["prop-b-1"],   # from B, not A
                "selected_proposal": "prop-b-1",
                "selection_rule": "HIGHEST_PRIORITY_COMMON",
                "status": "SUCCESS",
            })

    def test_valid_success_negotiation(self):
        n = Negotiation.model_validate({
            "negotiation_id": "neg-001",
            "tunnel_id": "tn-001",
            "ike_version": "IKEv2",
            "offers_from_a": ["prop-a-1", "prop-a-2"],
            "offers_from_b": ["prop-b-1"],
            "common_proposals": ["prop-a-1"],
            "selected_proposal": "prop-a-1",
            "selection_rule": "HIGHEST_PRIORITY_COMMON",
            "status": "SUCCESS",
        })
        assert n.status == NegotiationStatus.SUCCESS
        assert n.selected_proposal == "prop-a-1"

    def test_valid_failed_negotiation(self):
        n = Negotiation.model_validate({
            "negotiation_id": "neg-fail",
            "tunnel_id": "tn-001",
            "ike_version": "IKEv2",
            "offers_from_a": ["prop-a-1"],
            "offers_from_b": ["prop-b-1"],
            "common_proposals": [],
            "selected_proposal": None,
            "selection_rule": "FAILED_NO_COMMON_PROPOSALS",
            "status": "FAILED",
            "failure_reason": "No common DH group",
        })
        assert n.status == NegotiationStatus.FAILED
        assert n.selected_proposal is None


# ---------------------------------------------------------------------------
# Observation validation
# ---------------------------------------------------------------------------

class TestObservationValidation:

    def test_confidence_out_of_range_rejected(self):
        with pytest.raises(ValidationError, match="confidence"):
            Observation.model_validate({
                "observation_id": "obs-bad",
                "source_type": "CONFIG",
                "source_id": "seed-001",
                "entity_type": "tunnel",
                "entity_id": "tn-001",
                "field": "status",
                "value": "UP",
                "confidence": 1.5,   # > 1.0 — invalid
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    def test_none_value_is_valid_explicit_unknown(self):
        obs = Observation.model_validate({
            "observation_id": "obs-001",
            "source_type": "CONFIG",
            "source_id": "seed-001",
            "entity_type": "tunnel",
            "entity_id": "tn-001",
            "field": "pfs",
            "value": None,     # Explicit unknown — this is valid
            "confidence": 0.5,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        assert obs.value is None
        assert obs.confidence == 0.5


# ---------------------------------------------------------------------------
# SecurityState validation
# ---------------------------------------------------------------------------

class TestSecurityStateValidation:

    def test_risk_score_out_of_range_rejected(self):
        with pytest.raises(ValidationError, match="risk score"):
            from app.models.security_state import RiskAssessment
            RiskAssessment.model_validate({
                "score": 150.0,   # > 100
                "level": "CRITICAL",
            })

    def test_valid_security_state(self):
        ss = SecurityState.model_validate({
            "security_state_id": "ss-001",
            "tunnel_id": "tn-001",
            "selected": {
                "encryption": "AES-256-GCM",
                "integrity": None,
                "dh_group": 20,
                "pfs": True,
            },
            "floor": None,
            "controls": {"replay_protection": True},
            "risk": {"score": 5.0, "level": "INFO"},
            "floor_gap_exists": False,
        })
        assert ss.risk.score == 5.0
        assert ss.selected.encryption.value == "AES-256-GCM"
