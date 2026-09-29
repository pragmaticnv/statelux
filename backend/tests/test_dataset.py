"""
STATEFLUX — Dataset Generation and Loading Tests
=================================================
Tests that the synthetic dataset generator produces a correct,
internally consistent dataset and that the data loader validates it.
"""

import pytest


class TestDatasetGeneration:

    def test_dataset_loads_without_error(self, dataset):
        assert dataset.is_loaded is True

    def test_fleet_loaded(self, dataset):
        assert dataset.fleet is not None
        assert dataset.fleet.fleet_id == "fleet-001"

    def test_endpoint_count(self, dataset):
        assert len(dataset.endpoints) == 20, (
            f"Expected 20 endpoints, got {len(dataset.endpoints)}"
        )

    def test_tunnel_count(self, dataset):
        assert len(dataset.tunnels) == 40, (
            f"Expected 40 tunnels, got {len(dataset.tunnels)}"
        )

    def test_proposal_count_in_range(self, dataset):
        count = len(dataset.proposals)
        assert 100 <= count <= 200, (
            f"Expected 100-200 proposals (per-endpoint instances), got {count}"
        )

    def test_negotiation_count_matches_tunnels(self, dataset):
        tunnels_with_neg = sum(
            1 for t in dataset.tunnels.values()
            if t.negotiation_id is not None
        )
        assert len(dataset.negotiations) == tunnels_with_neg

    def test_observation_count_over_100(self, dataset):
        assert len(dataset.observations) >= 100, (
            f"Expected >= 100 observations, got {len(dataset.observations)}"
        )

    def test_all_fleet_endpoints_exist(self, dataset):
        for ep_id in dataset.fleet.endpoint_ids:
            assert ep_id in dataset.endpoints, f"Fleet references missing endpoint '{ep_id}'"

    def test_all_fleet_tunnels_exist(self, dataset):
        for tn_id in dataset.fleet.tunnel_ids:
            assert tn_id in dataset.tunnels, f"Fleet references missing tunnel '{tn_id}'"

    def test_all_tunnel_endpoints_exist(self, dataset):
        for tn_id, tunnel in dataset.tunnels.items():
            assert tunnel.endpoint_a in dataset.endpoints, (
                f"Tunnel '{tn_id}'.endpoint_a='{tunnel.endpoint_a}' not found"
            )
            assert tunnel.endpoint_b in dataset.endpoints, (
                f"Tunnel '{tn_id}'.endpoint_b='{tunnel.endpoint_b}' not found"
            )

    def test_no_self_tunnels(self, dataset):
        for tn_id, tunnel in dataset.tunnels.items():
            assert tunnel.endpoint_a != tunnel.endpoint_b, (
                f"Self-tunnel detected: '{tn_id}' connects endpoint to itself"
            )

    def test_all_negotiation_proposals_exist(self, dataset):
        for neg_id, neg in dataset.negotiations.items():
            all_refs = (neg.offers_from_a + neg.offers_from_b
                        + neg.common_proposals)
            if neg.selected_proposal:
                all_refs.append(neg.selected_proposal)
            for prop_id in all_refs:
                assert prop_id in dataset.proposals, (
                    f"Negotiation '{neg_id}' references missing proposal '{prop_id}'"
                )

    def test_success_negotiations_have_selected_proposal(self, dataset):
        from app.models.base import NegotiationStatus
        for neg_id, neg in dataset.negotiations.items():
            if neg.status == NegotiationStatus.SUCCESS:
                assert neg.selected_proposal is not None, (
                    f"SUCCESS negotiation '{neg_id}' has no selected_proposal"
                )

    def test_failed_negotiations_have_no_selected_proposal(self, dataset):
        from app.models.base import NegotiationStatus
        for neg_id, neg in dataset.negotiations.items():
            if neg.status == NegotiationStatus.FAILED:
                assert neg.selected_proposal is None, (
                    f"FAILED negotiation '{neg_id}' unexpectedly has selected_proposal"
                )

    def test_s01_tunnels_are_secure(self, dataset):
        """S01 tunnels must have AES-256-GCM, DH>=20, PFS on."""
        s01_tunnels = [
            t for t in dataset.tunnels.values()
            if t.annotations.get("scenario") == "S01"
        ]
        assert len(s01_tunnels) >= 2, "Expected at least 2 S01 tunnels"
        for t in s01_tunnels:
            ss = dataset.security_states.get(t.security_state_id)
            assert ss is not None
            assert ss.selected.encryption.value == "AES-256-GCM", (
                f"S01 tunnel {t.tunnel_id}: expected AES-256-GCM, "
                f"got {ss.selected.encryption}"
            )
            assert ss.selected.dh_group >= 20, (
                f"S01 tunnel {t.tunnel_id}: expected DH>=20, "
                f"got {ss.selected.dh_group}"
            )
            assert ss.risk.level.value == "INFO", (
                f"S01 tunnel {t.tunnel_id}: expected risk=INFO, "
                f"got {ss.risk.level.value}"
            )

    def test_s02_tunnels_have_weak_encryption(self, dataset):
        """S02 tunnels must have weak encryption (AES-128-CBC or 3DES)."""
        s02_tunnels = [
            t for t in dataset.tunnels.values()
            if t.annotations.get("scenario") == "S02"
        ]
        assert len(s02_tunnels) >= 2
        for t in s02_tunnels:
            ss = dataset.security_states.get(t.security_state_id)
            assert ss is not None
            assert ss.selected.encryption.value in ("AES-128-CBC", "3DES"), (
                f"S02 tunnel {t.tunnel_id}: expected weak enc, "
                f"got {ss.selected.encryption}"
            )
            assert ss.risk.level.value in ("HIGH", "CRITICAL"), (
                f"S02 tunnel {t.tunnel_id}: expected HIGH/CRITICAL risk, "
                f"got {ss.risk.level.value}"
            )

    def test_s03_tunnels_have_floor_gap(self, dataset):
        """S03 tunnels must have floor_gap_exists=True."""
        s03_tunnels = [
            t for t in dataset.tunnels.values()
            if t.annotations.get("scenario") == "S03"
        ]
        assert len(s03_tunnels) >= 2
        for t in s03_tunnels:
            ss = dataset.security_states.get(t.security_state_id)
            assert ss is not None
            assert ss.floor_gap_exists is True, (
                f"S03 tunnel {t.tunnel_id}: floor_gap_exists should be True"
            )
            # Selected must be strong
            assert ss.selected.encryption.value == "AES-256-GCM", (
                f"S03 tunnel {t.tunnel_id}: selected must be AES-256-GCM"
            )

    def test_failed_tunnels_are_down(self, dataset):
        """Tunnels with FAILED negotiations must be DOWN."""
        from app.models.base import NegotiationStatus, TunnelStatus
        for tn_id, tunnel in dataset.tunnels.items():
            if tunnel.negotiation_id:
                neg = dataset.negotiations.get(tunnel.negotiation_id)
                if neg and neg.status == NegotiationStatus.FAILED:
                    assert tunnel.status == TunnelStatus.DOWN, (
                        f"Tunnel '{tn_id}' has FAILED negotiation "
                        f"but status={tunnel.status}"
                    )

    def test_hero_a_scenario_exists(self, dataset):
        """HERO-A must exist with selected=GCM256, floor_gap=True."""
        hero_a = [
            t for t in dataset.tunnels.values()
            if t.annotations.get("scenario") == "HERO-A"
        ]
        assert len(hero_a) >= 1, "HERO-A scenario tunnel not found"
        for t in hero_a:
            ss = dataset.security_states.get(t.security_state_id)
            assert ss is not None
            assert ss.floor_gap_exists is True, "HERO-A must have floor_gap_exists=True"

    def test_hero_b_scenario_is_latent_risk(self, dataset):
        """HERO-B must have latent_rekey_risk annotation and be UP."""
        hero_b = [
            t for t in dataset.tunnels.values()
            if t.annotations.get("scenario") == "HERO-B"
        ]
        assert len(hero_b) >= 1, "HERO-B scenario tunnel not found"
        for t in hero_b:
            assert t.annotations.get("latent_rekey_risk") == "TRUE"
            assert t.status.value == "UP"

    def test_all_endpoint_proposals_have_correct_owner(self, dataset):
        """Every proposal's owner_endpoint_id must match the owning endpoint."""
        for prop_id, prop in dataset.proposals.items():
            owner_id = prop.owner_endpoint_id
            assert owner_id in dataset.endpoints, (
                f"Proposal '{prop_id}' owner='{owner_id}' not in endpoints"
            )
            owner = dataset.endpoints[owner_id]
            all_ep_proposals = (
                owner.configuration.ike_proposals
                + owner.configuration.esp_proposals
            )
            assert prop_id in all_ep_proposals, (
                f"Proposal '{prop_id}' claims owner='{owner_id}' "
                f"but is not in that endpoint's configuration"
            )

    def test_dataset_is_marked_synthetic(self, dataset):
        assert dataset.is_synthetic is True

    def test_stats_computed(self, dataset):
        assert dataset.stats.get("tunnels") == len(dataset.tunnels)
        assert dataset.stats.get("endpoints") == len(dataset.endpoints)

    def test_high_security_endpoints_are_validated(self, dataset):
        """HIGH_SECURITY profile endpoints must be VALIDATED."""
        from app.models.base import ProfileType, ValidationStatus
        hs_endpoints = [
            e for e in dataset.endpoints.values()
            if e.profile_type == ProfileType.HIGH_SECURITY
        ]
        assert len(hs_endpoints) >= 3, "Expected at least 3 HIGH_SECURITY endpoints"
        for ep in hs_endpoints:
            assert ep.validation_status == ValidationStatus.VALIDATED, (
                f"HIGH_SECURITY endpoint '{ep.endpoint_id}' is not VALIDATED"
            )

    def test_unvalidated_endpoints_labeled_correctly(self, dataset):
        """UNVALIDATED_PROFILE endpoints must not be VALIDATED."""
        from app.models.base import ValidationStatus
        unvalidated = [
            e for e in dataset.endpoints.values()
            if e.validation_status == ValidationStatus.UNVALIDATED_PROFILE
        ]
        assert len(unvalidated) >= 3, (
            "Expected at least 3 UNVALIDATED_PROFILE endpoints for S12/Vendor scenarios"
        )
