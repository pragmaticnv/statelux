"""
STATEFLUX — Synthetic Dataset Generator
=========================================
Generates a deterministic, internally consistent synthetic dataset
for Phase 1A development and testing.

DESIGN PRINCIPLES:
  - Fixed random seed (42) → same data every run.
  - All data is labeled SYNTHETIC throughout.
  - All scenarios have documented, intentional properties.
  - No emergent / accidental scenario correctness.
  - No fabricated real-world vendor claims.

TARGET:
  1 fleet, 20 endpoints, ~145 proposals, 40 tunnels,
  40 negotiations, 40 security states, 120+ observations.

SCENARIOS GENERATED:
  S01 — Fully secure tunnel
  S02 — Weak selected suite
  S03 — Strong selected suite with weak floor (security gap)
  S04 — PFS mismatch (one side requires, other cannot do it)
  S05 — DH group incompatibility → negotiation failure
  S06 — Encryption incompatibility → negotiation failure
  S07 — Latent rekey failure candidate
  S08 — Policy compliant tunnel
  S09 — Policy violation (legacy, SHA-1, IKEv1)
  S10 — Mixed enterprise fleet (10 tunnels)
  S11 — Transport mode tunnel
  S12 — Incomplete/unknown observation
  HERO-A — Hero scenario: selected=strong, floor=weak, gap visible
  HERO-B — Hero scenario: latent rekey failure after proposed hardening
"""

import json
import logging
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Ephemeral random instance with fixed seed
_rng = random.Random(42)

# ---------------------------------------------------------------------------
# Algorithm shorthand constants
# ---------------------------------------------------------------------------

ENC = {
    "gcm256": "AES-256-GCM",
    "cbc256": "AES-256-CBC",
    "gcm128": "AES-128-GCM",
    "cbc128": "AES-128-CBC",
    "3des":   "3DES",
}
INT = {
    "sha512": "HMAC-SHA-512",
    "sha384": "HMAC-SHA-384",
    "sha256": "HMAC-SHA-256",
    "sha1":   "HMAC-SHA-1",
}
PRF = {
    "sha512": "PRF-HMAC-SHA-512",
    "sha384": "PRF-HMAC-SHA-384",
    "sha256": "PRF-HMAC-SHA-256",
    "sha1":   "PRF-HMAC-SHA-1",
}
KEY = {"AES-256-GCM": 256, "AES-256-CBC": 256,
       "AES-128-GCM": 128, "AES-128-CBC": 128, "3DES": 168}


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Proposal builder helpers
# ---------------------------------------------------------------------------

def _ike_prop(ep_id: str, n: int, enc: str, prf_key: str,
              dh: int, priority: int,
              integ: Optional[str] = None,
              ike_ver: str = "IKEv2") -> dict:
    """Build an IKE proposal dict."""
    prop: dict[str, Any] = {
        "proposal_id":           f"{ep_id}-ike-{n:02d}",
        "owner_endpoint_id":     ep_id,
        "protocol":              "IKE",
        "ike_version":           ike_ver,
        "encryption_algorithm":  enc,
        "integrity_algorithm":   integ,
        "prf":                   PRF[prf_key],
        "dh_group":              dh,
        "pfs":                   False,    # PFS field has no meaning for IKE proposals
        "priority":              priority,
    }
    return prop


def _esp_prop(ep_id: str, n: int, enc: str,
              dh: Optional[int], pfs: bool, priority: int,
              integ: Optional[str] = None) -> dict:
    """Build an ESP proposal dict."""
    prop: dict[str, Any] = {
        "proposal_id":           f"{ep_id}-esp-{n:02d}",
        "owner_endpoint_id":     ep_id,
        "protocol":              "ESP",
        "ike_version":           None,
        "encryption_algorithm":  enc,
        "integrity_algorithm":   integ,
        "prf":                   None,
        "dh_group":              dh,
        "pfs":                   pfs,
        "priority":              priority,
    }
    return prop


# ---------------------------------------------------------------------------
# Proposal sets per endpoint profile
# ---------------------------------------------------------------------------

def _proposals_high_security(ep_id: str) -> tuple[list[dict], list[str], list[str]]:
    """High-Security: AES-256-GCM only, DH20/21, IKEv2, PFS required."""
    ike = [
        _ike_prop(ep_id, 1, ENC["gcm256"], "sha384", 21, 1),
        _ike_prop(ep_id, 2, ENC["gcm256"], "sha256", 20, 2),
    ]
    esp = [
        _esp_prop(ep_id, 1, ENC["gcm256"], 21, True,  1),
        _esp_prop(ep_id, 2, ENC["gcm256"], 20, True,  2),
    ]
    ike_ids = [p["proposal_id"] for p in ike]
    esp_ids = [p["proposal_id"] for p in esp]
    return ike + esp, ike_ids, esp_ids


def _proposals_modern_strong(ep_id: str) -> tuple[list[dict], list[str], list[str]]:
    """Modern Strong: GCM-256/256-CBC, DH19/20, IKEv2."""
    ike = [
        _ike_prop(ep_id, 1, ENC["gcm256"], "sha256", 20, 1),
        _ike_prop(ep_id, 2, ENC["gcm256"], "sha256", 19, 2),
        _ike_prop(ep_id, 3, ENC["cbc256"], "sha256", 20, 3, INT["sha256"]),
        _ike_prop(ep_id, 4, ENC["cbc256"], "sha256", 14, 4, INT["sha256"]),
    ]
    esp = [
        _esp_prop(ep_id, 1, ENC["gcm256"], 20, True,  1),
        _esp_prop(ep_id, 2, ENC["gcm256"], 19, True,  2),
        _esp_prop(ep_id, 3, ENC["cbc256"], 20, True,  3, INT["sha256"]),
        _esp_prop(ep_id, 4, ENC["cbc256"], 14, True,  4, INT["sha256"]),
    ]
    ike_ids = [p["proposal_id"] for p in ike]
    esp_ids = [p["proposal_id"] for p in esp]
    return ike + esp, ike_ids, esp_ids


def _proposals_enterprise(ep_id: str) -> tuple[list[dict], list[str], list[str]]:
    """Enterprise: Wide support range, DH14/19/20, IKEv2."""
    ike = [
        _ike_prop(ep_id, 1, ENC["gcm256"], "sha256", 20, 1),
        _ike_prop(ep_id, 2, ENC["gcm256"], "sha256", 19, 2),
        _ike_prop(ep_id, 3, ENC["gcm256"], "sha256", 14, 3),
        _ike_prop(ep_id, 4, ENC["cbc256"], "sha256", 14, 4, INT["sha256"]),
        _ike_prop(ep_id, 5, ENC["gcm128"], "sha256", 14, 5),
        _ike_prop(ep_id, 6, ENC["cbc128"], "sha256", 14, 6, INT["sha256"]),
    ]
    esp = [
        _esp_prop(ep_id, 1, ENC["gcm256"], 20, True,  1),
        _esp_prop(ep_id, 2, ENC["gcm256"], 14, True,  2),
        _esp_prop(ep_id, 3, ENC["cbc256"], 14, True,  3, INT["sha256"]),
        _esp_prop(ep_id, 4, ENC["gcm128"], 14, True,  4),
        _esp_prop(ep_id, 5, ENC["cbc128"], 14, True,  5, INT["sha256"]),
        _esp_prop(ep_id, 6, ENC["cbc128"], None, False, 6, INT["sha256"]),
    ]
    ike_ids = [p["proposal_id"] for p in ike]
    esp_ids = [p["proposal_id"] for p in esp]
    return ike + esp, ike_ids, esp_ids


def _proposals_legacy(ep_id: str) -> tuple[list[dict], list[str], list[str]]:
    """Legacy: AES-128-CBC + 3DES, DH14, IKEv1/v2, PFS mostly off."""
    ike = [
        _ike_prop(ep_id, 1, ENC["cbc128"], "sha1", 14, 1, INT["sha1"]),
        _ike_prop(ep_id, 2, ENC["3des"],   "sha1", 14, 2, INT["sha1"]),
        _ike_prop(ep_id, 3, ENC["cbc128"], "sha1", 14, 3, INT["sha1"], "IKEv1"),
        _ike_prop(ep_id, 4, ENC["3des"],   "sha1", 14, 4, INT["sha1"], "IKEv1"),
    ]
    esp = [
        _esp_prop(ep_id, 1, ENC["cbc128"], None, False, 1, INT["sha1"]),
        _esp_prop(ep_id, 2, ENC["3des"],   None, False, 2, INT["sha1"]),
        _esp_prop(ep_id, 3, ENC["cbc128"], 14,   True,  3, INT["sha1"]),
    ]
    ike_ids = [p["proposal_id"] for p in ike]
    esp_ids = [p["proposal_id"] for p in esp]
    return ike + esp, ike_ids, esp_ids


def _proposals_restricted(ep_id: str) -> tuple[list[dict], list[str], list[str]]:
    """Restricted / Synthetic-Vendor: Limited proposal set (UNVALIDATED)."""
    ike = [
        _ike_prop(ep_id, 1, ENC["gcm256"], "sha256", 20, 1),
        _ike_prop(ep_id, 2, ENC["cbc256"], "sha256", 14, 2, INT["sha256"]),
        _ike_prop(ep_id, 3, ENC["gcm128"], "sha256", 14, 3),
    ]
    esp = [
        _esp_prop(ep_id, 1, ENC["gcm256"], 20, True,  1),
        _esp_prop(ep_id, 2, ENC["cbc256"], 14, True,  2, INT["sha256"]),
        _esp_prop(ep_id, 3, ENC["cbc256"], None, False, 3, INT["sha256"]),
    ]
    ike_ids = [p["proposal_id"] for p in ike]
    esp_ids = [p["proposal_id"] for p in esp]
    return ike + esp, ike_ids, esp_ids


def _proposals_wide_fallback(ep_id: str) -> tuple[list[dict], list[str], list[str]]:
    """Enterprise with wide fallback (for S03/S10): includes weak proposals."""
    ike = [
        _ike_prop(ep_id, 1, ENC["gcm256"], "sha256", 20, 1),
        _ike_prop(ep_id, 2, ENC["gcm256"], "sha256", 14, 2),
        _ike_prop(ep_id, 3, ENC["cbc256"], "sha256", 14, 3, INT["sha256"]),
        _ike_prop(ep_id, 4, ENC["cbc128"], "sha1",   14, 4, INT["sha1"]),
        _ike_prop(ep_id, 5, ENC["3des"],   "sha1",   14, 5, INT["sha1"]),
    ]
    esp = [
        _esp_prop(ep_id, 1, ENC["gcm256"], 20, True,  1),
        _esp_prop(ep_id, 2, ENC["gcm256"], 14, True,  2),
        _esp_prop(ep_id, 3, ENC["cbc256"], 14, True,  3, INT["sha256"]),
        _esp_prop(ep_id, 4, ENC["cbc128"], 14, True,  4, INT["sha1"]),
        _esp_prop(ep_id, 5, ENC["3des"],   None, False, 5, INT["sha1"]),
    ]
    ike_ids = [p["proposal_id"] for p in ike]
    esp_ids = [p["proposal_id"] for p in esp]
    return ike + esp, ike_ids, esp_ids


# ---------------------------------------------------------------------------
# Endpoint builder
# ---------------------------------------------------------------------------

def _endpoint(ep_id: str, fleet_id: str, name: str, platform: str, version: str,
              profile: str, val_status: str, ike_ids: list[str], esp_ids: list[str],
              ike_versions: list[str], enc_algs: list[str], integ_algs: list[str],
              dh_groups: list[int], pfs_supported: bool,
              ike_lifetime: int = 86400, child_lifetime: int = 3600,
              mtu: int = 1500, annotations: Optional[dict] = None) -> dict:
    return {
        "endpoint_id":       ep_id,
        "fleet_id":          fleet_id,
        "name":              name,
        "platform":          platform,
        "platform_version":  version,
        "profile_type":      profile,
        "validation_status": val_status,
        "capabilities": {
            "ike_versions":                ike_versions,
            "encryption_algorithms":       enc_algs,
            "integrity_algorithms":        integ_algs,
            "dh_groups":                   dh_groups,
            "pfs_supported":               pfs_supported,
            "replay_protection_supported": True,
        },
        "configuration": {
            "ike_proposals":        ike_ids,
            "esp_proposals":        esp_ids,
            "selection_preference": "ORDERED_PRIORITY",
        },
        "network": {
            "ip_versions": ["IPv4"],
            "mtu":         mtu,
        },
        "rekey": {
            "ike_lifetime":      ike_lifetime,
            "child_sa_lifetime": child_lifetime,
        },
        "annotations": annotations or {},
    }


# ---------------------------------------------------------------------------
# Negotiation / SecurityState / Observation builders
# ---------------------------------------------------------------------------

def _negotiation(neg_id: str, tunnel_id: str, ike_ver: str,
                 offers_a: list[str], offers_b: list[str],
                 common: list[str], selected: Optional[str],
                 rule: str, status: str,
                 failure_reason: Optional[str] = None) -> dict:
    return {
        "negotiation_id":   neg_id,
        "tunnel_id":        tunnel_id,
        "ike_version":      ike_ver,
        "offers_from_a":    offers_a,
        "offers_from_b":    offers_b,
        "common_proposals": common,
        "selected_proposal": selected,
        "selection_rule":   rule,
        "status":           status,
        "failure_reason":   failure_reason,
    }


def _security_state(ss_id: str, tunnel_id: str,
                    sel_enc: Optional[str], sel_int: Optional[str],
                    sel_dh: Optional[int], sel_pfs: Optional[bool],
                    floor_enc: Optional[str], floor_int: Optional[str],
                    floor_dh: Optional[int], floor_pfs: Optional[bool],
                    replay: Optional[bool],
                    score: float, level: str, basis: str,
                    floor_gap: bool) -> dict:
    return {
        "security_state_id": ss_id,
        "tunnel_id":         tunnel_id,
        "selected": {
            "encryption":  sel_enc,
            "integrity":   sel_int,
            "dh_group":    sel_dh,
            "pfs":         sel_pfs,
        },
        "floor": {
            "encryption":  floor_enc,
            "integrity":   floor_int,
            "dh_group":    floor_dh,
            "pfs":         floor_pfs,
        } if floor_enc is not None else None,
        "controls": {"replay_protection": replay},
        "risk": {"score": score, "level": level, "basis": basis},
        "floor_gap_exists": floor_gap,
        "assessment_version": "1.0-phase1a",
    }


def _obs(obs_id: str, src_type: str, src_id: str, ent_type: str, ent_id: str,
         field: str, value: Any, confidence: float, notes: Optional[str] = None) -> dict:
    return {
        "observation_id": obs_id,
        "source_type":    src_type,
        "source_id":      src_id,
        "entity_type":    ent_type,
        "entity_id":      ent_id,
        "field":          field,
        "value":          value,
        "confidence":     confidence,
        "timestamp":      _ts(),
        "notes":          notes,
    }


def _tunnel(tn_id: str, fleet_id: str, ep_a: str, ep_b: str,
            mode: str, status: str, neg_id: Optional[str],
            ss_id: Optional[str], rekey: int,
            annotations: Optional[dict] = None) -> dict:
    return {
        "tunnel_id":          tn_id,
        "fleet_id":           fleet_id,
        "endpoint_a":         ep_a,
        "endpoint_b":         ep_b,
        "mode":               mode,
        "status":             status,
        "negotiation_id":     neg_id,
        "security_state_id":  ss_id,
        "rekey_interval":     rekey,
        "annotations":        annotations or {},
    }


# ---------------------------------------------------------------------------
# Main Generator
# ---------------------------------------------------------------------------

class StatefluxDatasetGenerator:
    """Deterministic synthetic dataset generator.

    Usage:
        gen = StatefluxDatasetGenerator()
        gen.generate(output_dir=Path("data/seed"))
    """

    FLEET_ID = "fleet-001"
    SEED     = 42

    def __init__(self) -> None:
        self._rng = random.Random(self.SEED)
        self._obs_counter   = 0
        self._fleet:        dict = {}
        self._endpoints:    list[dict] = []
        self._proposals:    list[dict] = []
        self._tunnels:      list[dict] = []
        self._negotiations: list[dict] = []
        self._security_states: list[dict] = []
        self._observations: list[dict] = []
        # Index: proposal_id → proposal dict
        self._prop_index:   dict[str, dict] = {}
        # ep_id → {ike: [ids], esp: [ids]}
        self._ep_proposals: dict[str, dict[str, list[str]]] = {}

    def _obs_id(self) -> str:
        self._obs_counter += 1
        return f"obs-{self._obs_counter:04d}"

    def _add_obs(self, src_type: str, src_id: str, ent_type: str, ent_id: str,
                 field: str, value: Any, confidence: float,
                 notes: Optional[str] = None) -> None:
        self._observations.append(_obs(
            self._obs_id(), src_type, src_id, ent_type, ent_id,
            field, value, confidence, notes,
        ))

    def _register_proposals(self, props: list[dict], ike_ids: list[str],
                            esp_ids: list[str], ep_id: str) -> None:
        for p in props:
            self._proposals.append(p)
            self._prop_index[p["proposal_id"]] = p
        self._ep_proposals[ep_id] = {"ike": ike_ids, "esp": esp_ids}

    # ------------------------------------------------------------------
    # Endpoints
    # ------------------------------------------------------------------

    def _build_endpoints(self) -> None:
        fid = self.FLEET_ID

        # --- High-Security (strongSwan) ep-001 to ep-003 ---
        for i in range(1, 4):
            ep_id = f"ep-{i:03d}"
            props, ike_ids, esp_ids = _proposals_high_security(ep_id)
            self._register_proposals(props, ike_ids, esp_ids, ep_id)
            self._endpoints.append(_endpoint(
                ep_id, fid, f"HUB-HS-{i:02d}", "strongSwan", "5.9.14",
                "HIGH_SECURITY", "VALIDATED",
                ike_ids, esp_ids,
                ["IKEv2"], [ENC["gcm256"]], [INT["sha512"], INT["sha384"], INT["sha256"]],
                [20, 21], True, 86400, 3600,
                annotations={"region": "HQ", "role": "hub"},
            ))

        # --- Modern Strong (Libreswan) ep-004 to ep-006 ---
        for i in range(4, 7):
            ep_id = f"ep-{i:03d}"
            props, ike_ids, esp_ids = _proposals_modern_strong(ep_id)
            self._register_proposals(props, ike_ids, esp_ids, ep_id)
            self._endpoints.append(_endpoint(
                ep_id, fid, f"REGIONAL-GW-{i-3:02d}", "Libreswan", "4.12",
                "MODERN_STRONG", "VALIDATED",
                ike_ids, esp_ids,
                ["IKEv2"], [ENC["gcm256"], ENC["cbc256"]],
                [INT["sha512"], INT["sha384"], INT["sha256"]],
                [19, 20], True, 86400, 3600,
                annotations={"region": f"REGION-{i-3}", "role": "spoke"},
            ))

        # --- Enterprise (strongSwan) ep-007 to ep-009 ---
        for i in range(7, 10):
            ep_id = f"ep-{i:03d}"
            props, ike_ids, esp_ids = _proposals_enterprise(ep_id)
            self._register_proposals(props, ike_ids, esp_ids, ep_id)
            self._endpoints.append(_endpoint(
                ep_id, fid, f"SITE-ENT-{i-6:02d}", "strongSwan", "5.9.14",
                "ENTERPRISE", "VALIDATED",
                ike_ids, esp_ids,
                ["IKEv2"],
                [ENC["gcm256"], ENC["cbc256"], ENC["gcm128"], ENC["cbc128"]],
                [INT["sha512"], INT["sha256"], INT["sha1"]],
                [14, 19, 20], True, 86400, 3600,
                annotations={"region": f"SITE-{i-6}", "role": "spoke"},
            ))

        # --- Enterprise with wide fallback ep-010 to ep-011 (for S03/hero) ---
        for i in range(10, 12):
            ep_id = f"ep-{i:03d}"
            props, ike_ids, esp_ids = _proposals_wide_fallback(ep_id)
            self._register_proposals(props, ike_ids, esp_ids, ep_id)
            self._endpoints.append(_endpoint(
                ep_id, fid, f"SITE-WIDE-{i-9:02d}", "strongSwan", "5.9.6",
                "ENTERPRISE", "VALIDATED",
                ike_ids, esp_ids,
                ["IKEv2"],
                [ENC["gcm256"], ENC["cbc256"], ENC["cbc128"], ENC["3des"]],
                [INT["sha256"], INT["sha1"]],
                [14, 19, 20], True, 86400, 3600,
                annotations={"region": f"LEGACY-SITE-{i-9}", "role": "spoke",
                             "scenario": "S03/HERO", "has_weak_fallback": "true"},
            ))

        # --- Legacy (Legacy-Gateway) ep-012 to ep-014 ---
        for i in range(12, 15):
            ep_id = f"ep-{i:03d}"
            props, ike_ids, esp_ids = _proposals_legacy(ep_id)
            self._register_proposals(props, ike_ids, esp_ids, ep_id)
            self._endpoints.append(_endpoint(
                ep_id, fid, f"LEGACY-GW-{i-11:02d}", "Legacy-Gateway", "2.6.37",
                "LEGACY", "VALIDATED",
                ike_ids, esp_ids,
                ["IKEv1", "IKEv2"], [ENC["cbc128"], ENC["3des"]],
                [INT["sha256"], INT["sha1"]],
                [14], False, 28800, 3600,
                annotations={"region": f"LEGACY-{i-11}", "role": "spoke",
                             "upgrade_priority": "HIGH"},
            ))

        # --- Restricted / Synthetic-Vendor-A ep-015 to ep-017 ---
        for i in range(15, 18):
            ep_id = f"ep-{i:03d}"
            props, ike_ids, esp_ids = _proposals_restricted(ep_id)
            self._register_proposals(props, ike_ids, esp_ids, ep_id)
            # ep-017: incomplete data (S12)
            pfs_cap = True if i < 17 else None
            self._endpoints.append(_endpoint(
                ep_id, fid, f"VENDOR-A-GW-{i-14:02d}",
                "Synthetic-Vendor-A", "UNKNOWN",
                "RESTRICTED", "UNVALIDATED_PROFILE",
                ike_ids, esp_ids,
                ["IKEv2"], [ENC["gcm256"], ENC["cbc256"]],
                [INT["sha256"]], [14, 20],
                pfs_cap if pfs_cap is not None else False, 86400, 3600,
                annotations={"scenario": "S12" if i == 17 else "RESTRICTED",
                             "data_completeness": "PARTIAL" if i == 17 else "FULL"},
            ))

        # --- Synthetic-Vendor-B ep-018 to ep-020 ---
        for i in range(18, 21):
            ep_id = f"ep-{i:03d}"
            props, ike_ids, esp_ids = _proposals_modern_strong(ep_id)
            self._register_proposals(props, ike_ids, esp_ids, ep_id)
            self._endpoints.append(_endpoint(
                ep_id, fid, f"VENDOR-B-GW-{i-17:02d}",
                "Synthetic-Vendor-B", "3.1.0",
                "ENTERPRISE", "UNVALIDATED_PROFILE",
                ike_ids, esp_ids,
                ["IKEv2"], [ENC["gcm256"], ENC["cbc256"]],
                [INT["sha512"], INT["sha256"]], [14, 19, 20], True, 86400, 3600,
                annotations={"region": f"VENDOR-B-REGION-{i-17}"},
            ))

    # ------------------------------------------------------------------
    # Tunnel + Negotiation + SecurityState factories
    # ------------------------------------------------------------------

    def _add_tunnel_scenario(
        self, tn_id: str, ep_a: str, ep_b: str,
        mode: str, status: str, neg_id: str,
        ss_id: str, rekey: int,
        # Negotiation parameters
        ike_ver: str, offers_a: list[str], offers_b: list[str],
        common: list[str], selected: Optional[str],
        neg_rule: str, neg_status: str, failure_reason: Optional[str],
        # SecurityState parameters
        sel_enc: Optional[str], sel_int: Optional[str],
        sel_dh: Optional[int], sel_pfs: Optional[bool],
        floor_enc: Optional[str], floor_int: Optional[str],
        floor_dh: Optional[int], floor_pfs: Optional[bool],
        replay: Optional[bool], risk_score: float, risk_level: str,
        risk_basis: str, floor_gap: bool,
        # Metadata
        annotations: Optional[dict] = None,
    ) -> None:
        self._tunnels.append(_tunnel(
            tn_id, self.FLEET_ID, ep_a, ep_b,
            mode, status, neg_id, ss_id, rekey, annotations,
        ))
        self._negotiations.append(_negotiation(
            neg_id, tn_id, ike_ver,
            offers_a, offers_b, common, selected,
            neg_rule, neg_status, failure_reason,
        ))
        self._security_states.append(_security_state(
            ss_id, tn_id,
            sel_enc, sel_int, sel_dh, sel_pfs,
            floor_enc, floor_int, floor_dh, floor_pfs,
            replay, risk_score, risk_level, risk_basis, floor_gap,
        ))

    # ------------------------------------------------------------------
    # Build all tunnels
    # ------------------------------------------------------------------

    def _build_tunnels(self) -> None:
        ep = self._ep_proposals

        # ==============================================================
        # S01 — Fully Secure
        # ep-001 (HS) ↔ ep-004 (Modern Strong)
        # Common: AES-256-GCM/DH20 (ep-001's prop, matched by ep-004)
        # ==============================================================
        self._add_tunnel_scenario(
            "tn-001", "ep-001", "ep-004",
            "TUNNEL", "UP", "neg-001", "ss-001", 3600,
            "IKEv2",
            ep["ep-001"]["ike"], ep["ep-004"]["ike"],
            ["ep-001-ike-02"],   # common: AES-256-GCM/DH20
            "ep-001-ike-02",     # selected
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["gcm256"], None, 20, True,
            ENC["gcm256"], None, 20, True,  # floor = same as selected (both strong)
            True, 0.0, "INFO", "AES-256-GCM+DH20+PFS", False,
            {"scenario": "S01", "label": "Fully Secure"},
        )
        # S01 — second tunnel
        self._add_tunnel_scenario(
            "tn-002", "ep-002", "ep-003",
            "TUNNEL", "UP", "neg-002", "ss-002", 3600,
            "IKEv2",
            ep["ep-002"]["ike"], ep["ep-003"]["ike"],
            ["ep-002-ike-01"],   # AES-256-GCM/DH21
            "ep-002-ike-01",
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["gcm256"], None, 21, True,
            ENC["gcm256"], None, 21, True,
            True, 0.0, "INFO", "AES-256-GCM+DH21+PFS", False,
            {"scenario": "S01", "label": "Fully Secure (High-Sec Hub)"},
        )

        # ==============================================================
        # S02 — Weak Selected Suite
        # ep-012 (Legacy) ↔ ep-013 (Legacy)
        # Both legacy → 3DES/SHA-1 selected
        # ==============================================================
        self._add_tunnel_scenario(
            "tn-003", "ep-012", "ep-013",
            "TUNNEL", "UP", "neg-003", "ss-003", 3600,
            "IKEv1",
            ep["ep-012"]["ike"], ep["ep-013"]["ike"],
            ["ep-012-ike-04"],   # 3DES/SHA-1/IKEv1 — common
            "ep-012-ike-04",     # selected = 3DES
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["3des"], INT["sha1"], 14, False,
            ENC["3des"], INT["sha1"], 14, False,
            True, 85.0, "CRITICAL",
            "3DES+SHA-1+IKEv1+PFS_DISABLED", False,
            {"scenario": "S02", "label": "Weak Selected Suite",
             "upgrade_required": "IMMEDIATE"},
        )
        # S02 — second tunnel (AES-128-CBC)
        self._add_tunnel_scenario(
            "tn-004", "ep-013", "ep-014",
            "TUNNEL", "UP", "neg-004", "ss-004", 3600,
            "IKEv2",
            ep["ep-013"]["ike"], ep["ep-014"]["ike"],
            ["ep-013-ike-01"],   # AES-128-CBC/SHA-1/IKEv2 common
            "ep-013-ike-01",
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["cbc128"], INT["sha1"], 14, False,
            ENC["cbc128"], INT["sha1"], 14, False,
            True, 64.0, "HIGH",
            "AES-128-CBC+SHA-1+PFS_DISABLED", False,
            {"scenario": "S02", "label": "Weak Selected Suite (AES-128)"},
        )

        # ==============================================================
        # S03 — Strong Selected + Weak Floor (Security Gap)
        # ep-001 (HS, GCM-256 only) ↔ ep-010 (Wide, includes 3DES)
        # Selected: AES-256-GCM (highest common priority)
        # Floor: 3DES (weakest ep-010 still offers) — BUT ep-001 only has GCM
        # Actually: floor = weakest that BOTH could negotiate
        # Since ep-001 only has GCM, the floor = GCM (no true weak fallback via ep-001)
        #
        # BETTER for S03: ep-010 ↔ ep-011 (both wide fallback)
        # Both offer AES-256-GCM and 3DES → Selected=GCM, Floor=3DES → GAP
        # ==============================================================
        self._add_tunnel_scenario(
            "tn-005", "ep-010", "ep-011",
            "TUNNEL", "UP", "neg-005", "ss-005", 3600,
            "IKEv2",
            ep["ep-010"]["ike"], ep["ep-011"]["ike"],
            ["ep-010-ike-01", "ep-010-ike-02", "ep-010-ike-03",
             "ep-010-ike-04", "ep-010-ike-05"],   # all 5 common
            "ep-010-ike-01",     # selected = AES-256-GCM/DH20 (priority 1)
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["gcm256"], None, 20, True,
            ENC["3des"],   INT["sha1"], 14, False,  # floor = 3DES (weakest common)
            True, 5.0, "INFO",
            "SELECTED=AES-256-GCM+DH20 | FLOOR=3DES+SHA-1",
            True,   # floor_gap_exists = True (key STATEFLUX finding)
            {"scenario": "S03", "label": "Strong Selected + Weak Floor",
             "floor_gap": "SEVERE", "stateflux_highlight": "SECURITY_FLOOR_GAP"},
        )
        # S03 — second (enterprise peer with weak fallbacks)
        self._add_tunnel_scenario(
            "tn-006", "ep-007", "ep-011",
            "TUNNEL", "UP", "neg-006", "ss-006", 3600,
            "IKEv2",
            ep["ep-007"]["ike"], ep["ep-011"]["ike"],
            ["ep-007-ike-01", "ep-007-ike-02", "ep-007-ike-03"],
            "ep-007-ike-01",     # selected = AES-256-GCM/DH20
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["gcm256"], None, 20, True,
            ENC["cbc128"], INT["sha1"], 14, False,
            True, 5.0, "INFO",
            "SELECTED=AES-256-GCM | FLOOR=AES-128-CBC+SHA-1", True,
            {"scenario": "S03", "label": "Enterprise Strong + Weak Floor"},
        )

        # ==============================================================
        # S04 — PFS Mismatch (tunnel DOWN)
        # ep-001 (PFS required, only PFS proposals) ↔ ep-012 (PFS off)
        # ep-001 only has DH20/21 GCM proposals (all have PFS via DH)
        # ep-012 only has no-PFS proposals → no common → FAIL
        # ==============================================================
        self._add_tunnel_scenario(
            "tn-007", "ep-001", "ep-012",
            "TUNNEL", "DOWN", "neg-007", "ss-007", 3600,
            "IKEv2",
            ep["ep-001"]["ike"], ep["ep-012"]["ike"],
            [],              # no common proposals
            None,            # no selected proposal
            "FAILED_PFS_MISMATCH", "FAILED",
            "Endpoint ep-001 requires PFS (DH20/21); ep-012 has no PFS capability",
            None, None, None, None,
            None, None, None, None,
            None, 0.0, "INFO", "NEGOTIATION_FAILED", False,
            {"scenario": "S04", "label": "PFS Mismatch — Tunnel DOWN",
             "failure_mode": "PFS_MISMATCH"},
        )
        # S04 — second (degraded PFS)
        self._add_tunnel_scenario(
            "tn-008", "ep-004", "ep-014",
            "TUNNEL", "UP", "neg-008", "ss-008", 3600,
            "IKEv2",
            ep["ep-004"]["ike"], ep["ep-014"]["ike"],
            ["ep-004-ike-04"],   # AES-256-CBC/DH14/SHA-256 — no PFS in esp
            "ep-004-ike-04",
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["cbc256"], INT["sha256"], 14, False,
            ENC["cbc256"], INT["sha256"], 14, False,
            True, 28.0, "LOW",
            "AES-256-CBC+DH14+PFS_DISABLED", False,
            {"scenario": "S04", "label": "PFS Degraded (no PFS on remote)"},
        )

        # ==============================================================
        # S05 — DH Incompatibility (tunnel DOWN)
        # ep-001 (DH20/21 only) ↔ ep-015 (DH20 only, different enc)
        # ep-001: AES-256-GCM/DH20, AES-256-GCM/DH21
        # ep-015: AES-256-GCM/DH20, AES-256-CBC/DH14 — DH14 not in ep-001
        # Common = AES-256-GCM/DH20 → actually SUCCESS here
        #
        # TRUE DH INCOMPAT: ep-001 (DH20/21) ↔ restricted ep-016 only DH14
        # ep-016 has: AES-256-GCM/DH20, AES-256-CBC/DH14, AES-128-GCM/DH14
        # ep-001 has: AES-256-GCM/DH21, AES-256-GCM/DH20
        # Common: AES-256-GCM/DH20 → SUCCESS → not an incompat
        #
        # REAL INCOMPAT: need ep with DH14 only and ep with DH20 only for SAME enc
        # Use ep-003 (DH20/21 only) ↔ ep-012 (DH14 only)
        # ep-003: gcm256/DH21, gcm256/DH20
        # ep-012: cbc128/DH14, 3des/DH14 → different ENC → enc incompat too
        #
        # For pure DH incompat: construct a specific scenario
        # ep-007 has gcm256/DH20, gcm256/DH14 (but ep-007 also has cbc128)
        # For S05 clarity: ep-003 ↔ ep-012 captures the incompatibility clearly
        # ==============================================================
        self._add_tunnel_scenario(
            "tn-009", "ep-003", "ep-012",
            "TUNNEL", "DOWN", "neg-009", "ss-009", 3600,
            "IKEv2",
            ep["ep-003"]["ike"], ep["ep-012"]["ike"],
            [],      # No common: ep-003 only has GCM256/DH20-21, ep-012 only CBC128/3DES/DH14
            None,
            "FAILED_NO_COMMON_PROPOSALS", "FAILED",
            "No compatible proposal: ep-003 offers only AES-256-GCM with DH20/21; "
            "ep-012 offers only AES-128-CBC/3DES with DH14",
            None, None, None, None, None, None, None, None,
            None, 0.0, "INFO", "NEGOTIATION_FAILED", False,
            {"scenario": "S05", "label": "DH Incompatibility → Failure",
             "failure_mode": "DH_AND_ENCRYPTION_MISMATCH"},
        )
        # S05 — second: DH mismatch with partial overlap (DEGRADED)
        self._add_tunnel_scenario(
            "tn-010", "ep-005", "ep-014",
            "TUNNEL", "UP", "neg-010", "ss-010", 3600,
            "IKEv2",
            ep["ep-005"]["ike"], ep["ep-014"]["ike"],
            ["ep-005-ike-04"],   # AES-256-CBC/DH14 — lowest common denominator
            "ep-005-ike-04",
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["cbc256"], INT["sha256"], 14, False,
            ENC["cbc256"], INT["sha256"], 14, False,
            True, 23.0, "LOW",
            "AES-256-CBC+DH14+PFS_DISABLED (DH degraded)", False,
            {"scenario": "S05", "label": "DH Degraded (forced to DH14)"},
        )

        # ==============================================================
        # S06 — Encryption Incompatibility (tunnel DOWN)
        # ep-001 (GCM256 only) ↔ ep-013 (CBC128/3DES only)
        # ==============================================================
        self._add_tunnel_scenario(
            "tn-011", "ep-001", "ep-013",
            "TUNNEL", "DOWN", "neg-011", "ss-011", 3600,
            "IKEv2",
            ep["ep-001"]["ike"], ep["ep-013"]["ike"],
            [], None,
            "FAILED_NO_COMMON_PROPOSALS", "FAILED",
            "No compatible proposal: ep-001 requires AES-256-GCM; "
            "ep-013 only supports AES-128-CBC and 3DES",
            None, None, None, None, None, None, None, None,
            None, 0.0, "INFO", "NEGOTIATION_FAILED", False,
            {"scenario": "S06", "label": "Encryption Incompatibility → Failure",
             "failure_mode": "ENCRYPTION_MISMATCH"},
        )
        # S06 — second (partial enc incompat, downgrade succeeded)
        self._add_tunnel_scenario(
            "tn-012", "ep-006", "ep-014",
            "TUNNEL", "UP", "neg-012", "ss-012", 3600,
            "IKEv2",
            ep["ep-006"]["ike"], ep["ep-014"]["ike"],
            ["ep-006-ike-04"],
            "ep-006-ike-04",
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["cbc256"], INT["sha256"], 14, False,
            ENC["cbc256"], INT["sha256"], 14, False,
            True, 23.0, "LOW",
            "AES-256-CBC+DH14 (downgraded due to peer enc support)", False,
            {"scenario": "S06", "label": "Encryption Downgraded (partial compat)"},
        )

        # ==============================================================
        # S07 — Latent Rekey Failure Candidate
        # Currently UP, but if a hardening policy is applied, the next
        # rekey will fail because only weak proposals remain.
        # ep-010 (wide fallback including 3DES) ↔ ep-012 (legacy, 3DES only)
        # Current selected: AES-128-CBC (best common between wide and legacy)
        # After hardening (remove AES-128): no compatible proposal at rekey
        # ==============================================================
        self._add_tunnel_scenario(
            "tn-013", "ep-010", "ep-012",
            "TUNNEL", "UP", "neg-013", "ss-013", 3600,
            "IKEv2",
            ep["ep-010"]["ike"], ep["ep-012"]["ike"],
            ["ep-010-ike-04", "ep-010-ike-05"],  # AES-128-CBC and 3DES are common
            "ep-010-ike-04",     # selected = AES-128-CBC (best of weak commons)
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["cbc128"], INT["sha1"], 14, False,
            ENC["3des"],   INT["sha1"], 14, False,  # floor = 3DES
            True, 64.0, "HIGH",
            "SELECTED=AES-128-CBC+SHA-1 | LATENT_REKEY_RISK",
            True,
            {"scenario": "S07", "label": "Latent Rekey Failure",
             "latent_rekey_risk": "TRUE",
             "stateflux_highlight": "LATENT_REKEY_FAILURE_CANDIDATE",
             "will_fail_after_hardening": "TRUE"},
        )
        # S07 — second latent failure case
        self._add_tunnel_scenario(
            "tn-014", "ep-011", "ep-013",
            "TUNNEL", "UP", "neg-014", "ss-014", 3600,
            "IKEv2",
            ep["ep-011"]["ike"], ep["ep-013"]["ike"],
            ["ep-011-ike-04", "ep-011-ike-05"],
            "ep-011-ike-04",     # selected = AES-128-CBC
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["cbc128"], INT["sha1"], 14, False,
            ENC["3des"],   INT["sha1"], 14, False,
            True, 64.0, "HIGH",
            "SELECTED=AES-128-CBC+SHA-1 | LATENT_REKEY_RISK", True,
            {"scenario": "S07", "label": "Latent Rekey Failure (site-to-legacy)",
             "latent_rekey_risk": "TRUE"},
        )

        # ==============================================================
        # S08 — Policy Compliant (GCM256, DH20, PFS, replay on)
        # ep-007 ↔ ep-008 (both enterprise with GCM256/DH20)
        # ==============================================================
        self._add_tunnel_scenario(
            "tn-015", "ep-007", "ep-008",
            "TUNNEL", "UP", "neg-015", "ss-015", 3600,
            "IKEv2",
            ep["ep-007"]["ike"], ep["ep-008"]["ike"],
            ["ep-007-ike-01", "ep-007-ike-02"],
            "ep-007-ike-01",     # AES-256-GCM/DH20
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["gcm256"], None, 20, True,
            ENC["gcm256"], None, 14, True,
            True, 5.0, "INFO",
            "AES-256-GCM+DH20+PFS | POLICY_COMPLIANT", False,
            {"scenario": "S08", "label": "Policy Compliant"},
        )
        self._add_tunnel_scenario(
            "tn-016", "ep-018", "ep-019",
            "TUNNEL", "UP", "neg-016", "ss-016", 3600,
            "IKEv2",
            ep["ep-018"]["ike"], ep["ep-019"]["ike"],
            ["ep-018-ike-01"],
            "ep-018-ike-01",
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["gcm256"], None, 20, True,
            ENC["gcm256"], None, 20, True,
            True, 0.0, "INFO",
            "AES-256-GCM+DH20+PFS | POLICY_COMPLIANT", False,
            {"scenario": "S08", "label": "Policy Compliant (Vendor-B pair)"},
        )

        # ==============================================================
        # S09 — Policy Violation (IKEv1, SHA-1, AES-128)
        # ep-012 (legacy) ↔ ep-013 (legacy)
        # ==============================================================
        self._add_tunnel_scenario(
            "tn-017", "ep-012", "ep-014",
            "TUNNEL", "UP", "neg-017", "ss-017", 3600,
            "IKEv1",
            ep["ep-012"]["ike"], ep["ep-014"]["ike"],
            ["ep-012-ike-03"],   # AES-128-CBC/SHA-1/IKEv1
            "ep-012-ike-03",
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["cbc128"], INT["sha1"], 14, False,
            ENC["cbc128"], INT["sha1"], 14, False,
            True, 71.0, "HIGH",
            "IKEv1+AES-128-CBC+SHA-1+PFS_DISABLED | POLICY_VIOLATION", False,
            {"scenario": "S09", "label": "Policy Violation — IKEv1+SHA-1",
             "policy_violations": "IKEv1,AES-128,SHA-1,PFS_OFF"},
        )
        self._add_tunnel_scenario(
            "tn-018", "ep-013", "ep-012",
            "TUNNEL", "UP", "neg-018", "ss-018", 3600,
            "IKEv1",
            ep["ep-013"]["ike"], ep["ep-012"]["ike"],
            ["ep-013-ike-03"],
            "ep-013-ike-03",
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["3des"], INT["sha1"], 14, False,
            ENC["3des"], INT["sha1"], 14, False,
            True, 85.0, "CRITICAL",
            "IKEv1+3DES+SHA-1+PFS_DISABLED | CRITICAL_POLICY_VIOLATION", False,
            {"scenario": "S09", "label": "Policy Violation — IKEv1+3DES (CRITICAL)",
             "policy_violations": "IKEv1,3DES,SHA-1,PFS_OFF"},
        )

        # ==============================================================
        # S10 — Mixed Enterprise Fleet (10 tunnels)
        # ep-007 to ep-011 ↔ various endpoints
        # A realistic mix of outcomes for demo
        # ==============================================================
        mixed = [
            # (ep_a, ep_b, selected_ike, sel_enc, sel_dh, pfs, score, level, note)
            ("ep-007", "ep-018", "ep-007-ike-01", ENC["gcm256"], 20, True,  5.0,  "INFO",   "Strong"),
            ("ep-008", "ep-019", "ep-008-ike-01", ENC["gcm256"], 20, True,  5.0,  "INFO",   "Strong"),
            ("ep-008", "ep-020", "ep-008-ike-03", ENC["gcm256"], 14, True,  5.0,  "INFO",   "Adequate-DH14"),
            ("ep-009", "ep-015", "ep-009-ike-01", ENC["gcm256"], 20, True,  5.0,  "INFO",   "Strong"),
            ("ep-009", "ep-016", "ep-009-ike-03", ENC["gcm256"], 14, True,  10.0, "LOW",    "DH14-nudge"),
            ("ep-010", "ep-018", "ep-010-ike-01", ENC["gcm256"], 20, True,  5.0,  "INFO",   "Strong"),
            ("ep-010", "ep-020", "ep-010-ike-03", ENC["cbc256"], 14, True,  10.0, "LOW",    "CBC-DH14"),
            ("ep-011", "ep-015", "ep-011-ike-01", ENC["gcm256"], 20, True,  5.0,  "INFO",   "Strong"),
            ("ep-011", "ep-016", "ep-011-ike-05", ENC["cbc128"], 14, False, 50.0, "MEDIUM", "Weak+NoPFS"),
            ("ep-009", "ep-017", "ep-009-ike-04", ENC["cbc256"], 14, False, 23.0, "LOW",    "CBC+NoPFS"),
        ]
        for idx, (ep_a, ep_b, sel_id, sel_enc, sel_dh, sel_pfs, score, level, note) in enumerate(mixed):
            i = idx + 19  # tn-019 through tn-028
            tn_id  = f"tn-{i:03d}"
            neg_id = f"neg-{i:03d}"
            ss_id  = f"ss-{i:03d}"
            self._add_tunnel_scenario(
                tn_id, ep_a, ep_b,
                "TUNNEL", "UP", neg_id, ss_id, 3600,
                "IKEv2",
                ep[ep_a]["ike"], ep[ep_b]["ike"],
                [sel_id], sel_id,
                "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
                sel_enc, None if "GCM" in sel_enc else INT["sha256"],
                sel_dh, sel_pfs,
                sel_enc, None if "GCM" in sel_enc else INT["sha256"],
                sel_dh, sel_pfs,
                True, score, level,
                f"{sel_enc}+DH{sel_dh}+PFS={'ON' if sel_pfs else 'OFF'}", False,
                {"scenario": "S10", "label": f"Mixed Enterprise — {note}"},
            )

        # ==============================================================
        # S11 — Transport Mode
        # ep-007 ↔ ep-008 in TRANSPORT mode (for host-to-host IPsec)
        # ==============================================================
        self._add_tunnel_scenario(
            "tn-029", "ep-007", "ep-009",
            "TRANSPORT", "UP", "neg-029", "ss-029", 3600,
            "IKEv2",
            ep["ep-007"]["ike"], ep["ep-009"]["ike"],
            ["ep-007-ike-01"],
            "ep-007-ike-01",
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["gcm256"], None, 20, True,
            ENC["gcm256"], None, 20, True,
            True, 0.0, "INFO",
            "AES-256-GCM+DH20+PFS | TRANSPORT_MODE", False,
            {"scenario": "S11", "label": "Transport Mode",
             "mode_note": "Host-to-host transport mode IPsec"},
        )
        self._add_tunnel_scenario(
            "tn-030", "ep-008", "ep-009",
            "TRANSPORT", "UP", "neg-030", "ss-030", 3600,
            "IKEv2",
            ep["ep-008"]["ike"], ep["ep-009"]["ike"],
            ["ep-008-ike-01"],
            "ep-008-ike-01",
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["gcm256"], None, 20, True,
            ENC["gcm256"], None, 20, True,
            True, 0.0, "INFO",
            "AES-256-GCM+DH20+PFS | TRANSPORT_MODE", False,
            {"scenario": "S11", "label": "Transport Mode (second)"},
        )

        # ==============================================================
        # S12 — Unknown / Incomplete Observation
        # ep-017 (Synthetic-Vendor-A, PARTIAL data)
        # Some fields are unknown — represented explicitly as None
        # ==============================================================
        self._add_tunnel_scenario(
            "tn-031", "ep-015", "ep-017",
            "TUNNEL", "UNKNOWN", "neg-031", "ss-031", 3600,
            "IKEv2",
            ep["ep-015"]["ike"], ep["ep-017"]["ike"],
            ["ep-015-ike-01"],
            "ep-015-ike-01",
            "ASSUMED_FROM_PROFILE", "SUCCESS", None,
            ENC["gcm256"], None, 20, None,   # pfs unknown
            None, None, None, None,           # floor unknown
            None, 10.0, "LOW",               # replay unknown
            "INCOMPLETE_DATA | PFS_UNKNOWN | FLOOR_UNKNOWN", False,
            {"scenario": "S12", "label": "Incomplete Observation",
             "data_quality": "PARTIAL",
             "unknown_fields": "pfs,floor,replay_protection"},
        )
        self._add_tunnel_scenario(
            "tn-032", "ep-016", "ep-017",
            "TUNNEL", "UNKNOWN", "neg-032", "ss-032", 3600,
            "IKEv2",
            ep["ep-016"]["ike"], ep["ep-017"]["ike"],
            ["ep-016-ike-01"],
            "ep-016-ike-01",
            "ASSUMED_FROM_PROFILE", "SUCCESS", None,
            ENC["gcm256"], None, 20, None,
            None, None, None, None,
            None, 10.0, "LOW",
            "INCOMPLETE_DATA | VENDOR_PROFILE_UNVALIDATED", False,
            {"scenario": "S12", "label": "Unvalidated Vendor Profile"},
        )

        # ==============================================================
        # HERO-A — Primary demo: strong selected, weak floor (gap visible)
        # ep-001 (HS, GCM256/DH21 only) ↔ ep-010 (wide, includes 3DES)
        # We want: selected=GCM256, floor=weakest both could negotiate
        # ep-001 can ONLY do GCM256/DH20-21 → floor = GCM256/DH20 (no real gap via ep-001)
        #
        # For HERO gap demo: ep-010 ↔ ep-011 with scenario S03 is the right pair
        # hero-01 reuses the S03 data concept — use ep-010 ↔ ep-011
        # Let's use ep-010 ↔ ep-012 for the hero (GCM256 selected but 3DES floor via ep-010)
        # Wait: ep-010 has 3DES in its list, but ep-012 also has 3DES → common includes 3DES
        # BUT: selected = GCM256 (ep-010's priority 1 if compatible)
        # ep-012 has no GCM256 → common between ep-010 and ep-012 would be AES-128-CBC and 3DES
        # selected = AES-128-CBC (best of common)
        # For the HERO we need: selected=STRONG, floor=WEAK
        # ep-010 ↔ ep-011 is the best hero pair (already done as tn-005/S03)
        # Create dedicated hero tunnels with unique IDs
        # ==============================================================
        self._add_tunnel_scenario(
            "tn-033", "ep-010", "ep-011",
            "TUNNEL", "UP", "neg-033", "ss-033", 3600,
            "IKEv2",
            ep["ep-010"]["ike"], ep["ep-011"]["ike"],
            ["ep-010-ike-01", "ep-010-ike-02", "ep-010-ike-03",
             "ep-010-ike-04", "ep-010-ike-05"],
            "ep-010-ike-01",     # STRONG selected: AES-256-GCM/DH20
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["gcm256"], None, 20, True,
            ENC["3des"],   INT["sha1"], 14, False,  # WEAK floor
            True, 5.0, "INFO",
            "HERO: SELECTED=AES-256-GCM+DH20 | FLOOR=3DES+SHA-1+NO-PFS",
            True,   # floor_gap_exists — KEY DEMO FINDING
            {"scenario": "HERO-A",
             "label": "HERO: Strong Selected + Severe Floor Gap",
             "stateflux_highlight": "PRIMARY_DEMO_FLOOR_GAP",
             "hero_note": (
                 "This tunnel currently negotiates AES-256-GCM with DH-20 and PFS. "
                 "However both endpoints still permit 3DES with DH-14 and no PFS as a fallback. "
                 "If an attacker forces a proposal downgrade, or if a policy change "
                 "removes AES-256-GCM, this tunnel will fall back to 3DES."
             )},
        )

        # ==============================================================
        # HERO-B — Latent rekey failure after proposed hardening
        # ep-010 (wide, allows AES-256-GCM down to 3DES) ↔ ep-012 (legacy)
        # Current: UP with AES-128-CBC (best common)
        # After hardening (remove AES-128, AES-128-CBC, 3DES):
        #   ep-012 would have NO compatible proposals left → LATENT FAIL at rekey
        # ==============================================================
        self._add_tunnel_scenario(
            "tn-034", "ep-010", "ep-012",
            "TUNNEL", "UP", "neg-034", "ss-034", 3600,
            "IKEv2",
            ep["ep-010"]["ike"], ep["ep-012"]["ike"],
            ["ep-010-ike-04", "ep-010-ike-05"],  # AES-128-CBC, 3DES (only commons)
            "ep-010-ike-04",     # AES-128-CBC (current selected — UP now)
            "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
            ENC["cbc128"], INT["sha1"], 14, False,
            ENC["3des"],   INT["sha1"], 14, False,
            True, 64.0, "HIGH",
            "HERO: CURRENT=AES-128-CBC | WILL_FAIL_AFTER_HARDENING",
            True,
            {"scenario": "HERO-B",
             "label": "HERO: Latent Rekey Failure After Hardening",
             "stateflux_highlight": "LATENT_REKEY_FAILURE",
             "latent_rekey_risk": "TRUE",
             "will_fail_after_hardening": "TRUE",
             "hero_note": (
                 "This tunnel is currently UP with AES-128-CBC. "
                 "If the proposed hardening policy (remove AES-128, require AES-256-GCM) "
                 "is applied, ep-012 will have NO compatible proposals at the next rekey. "
                 "The tunnel will not break immediately (current SA is alive) "
                 "but WILL break silently at the next rekey event."
             )},
        )

        # ==============================================================
        # Filler tunnels tn-035 to tn-040 (fleet realism)
        # ==============================================================
        filler = [
            ("ep-004", "ep-018", "ep-004-ike-01", ENC["gcm256"], 20, True,  5.0,  "INFO"),
            ("ep-005", "ep-020", "ep-005-ike-01", ENC["gcm256"], 20, True,  5.0,  "INFO"),
            ("ep-006", "ep-019", "ep-006-ike-01", ENC["gcm256"], 20, True,  5.0,  "INFO"),
            ("ep-004", "ep-007", "ep-004-ike-01", ENC["gcm256"], 20, True,  5.0,  "INFO"),
            ("ep-005", "ep-008", "ep-005-ike-01", ENC["gcm256"], 20, True,  5.0,  "INFO"),
            ("ep-006", "ep-009", "ep-006-ike-03", ENC["cbc256"], 14, True, 10.0,  "LOW"),
        ]
        for idx, (ep_a, ep_b, sel_id, sel_enc, sel_dh, sel_pfs, score, level) in enumerate(filler):
            i = idx + 35  # tn-035 to tn-040
            tn_id  = f"tn-{i:03d}"
            neg_id = f"neg-{i:03d}"
            ss_id  = f"ss-{i:03d}"
            self._add_tunnel_scenario(
                tn_id, ep_a, ep_b,
                "TUNNEL", "UP", neg_id, ss_id, 3600,
                "IKEv2",
                ep[ep_a]["ike"], ep[ep_b]["ike"],
                [sel_id], sel_id,
                "HIGHEST_PRIORITY_COMMON", "SUCCESS", None,
                sel_enc, None if "GCM" in sel_enc else INT["sha256"],
                sel_dh, sel_pfs,
                sel_enc, None if "GCM" in sel_enc else INT["sha256"],
                sel_dh, sel_pfs,
                True, score, level,
                f"{sel_enc}+DH{sel_dh}", False,
                {"scenario": "FLEET", "label": f"Fleet Tunnel {i}"},
            )

    # ------------------------------------------------------------------
    # Build Observations
    # ------------------------------------------------------------------

    def _build_observations(self) -> None:
        """Generate structured observations for all tunnels and endpoints."""
        obs_src = "STATEFLUX-SYNTHETIC-SEED-v1"

        # Observations for each tunnel (from negotiation/config data)
        for tunnel in self._tunnels:
            tn_id = tunnel["tunnel_id"]
            neg   = next((n for n in self._negotiations
                          if n["negotiation_id"] == tunnel.get("negotiation_id")), None)
            ss    = next((s for s in self._security_states
                          if s["security_state_id"] == tunnel.get("security_state_id")), None)

            # Basic tunnel observations
            self._add_obs("CONFIG", obs_src, "tunnel", tn_id,
                          "mode", tunnel["mode"], 1.0)
            self._add_obs("CONFIG", obs_src, "tunnel", tn_id,
                          "status", tunnel["status"], 0.9)
            self._add_obs("CONFIG", obs_src, "tunnel", tn_id,
                          "rekey_interval", tunnel["rekey_interval"], 1.0)

            if neg:
                self._add_obs("CONFIG", obs_src, "tunnel", tn_id,
                              "ike_version", neg["ike_version"], 1.0)
                self._add_obs("CONFIG", obs_src, "negotiation", neg["negotiation_id"],
                              "status", neg["status"], 1.0)
                if neg.get("selected_proposal"):
                    # Find the proposal to extract encryption
                    prop = self._prop_index.get(neg["selected_proposal"])
                    if prop:
                        self._add_obs("CONFIG", obs_src, "tunnel", tn_id,
                                      "selected.encryption",
                                      prop["encryption_algorithm"], 1.0)
                        self._add_obs("CONFIG", obs_src, "tunnel", tn_id,
                                      "selected.dh_group", prop["dh_group"], 1.0)
                        self._add_obs("CONFIG", obs_src, "tunnel", tn_id,
                                      "selected.pfs", prop["pfs"], 1.0)

            if ss:
                replay_val = ss["controls"].get("replay_protection")
                conf = 0.5 if replay_val is None else 1.0  # S12 incomplete
                self._add_obs("CONFIG", obs_src, "tunnel", tn_id,
                              "controls.replay_protection", replay_val, conf,
                              notes="NULL indicates unknown value" if replay_val is None else None)

        # Endpoint profile observations
        for ep in self._endpoints:
            ep_id = ep["endpoint_id"]
            self._add_obs("CONFIG", obs_src, "endpoint", ep_id,
                          "platform", ep["platform"], 1.0)
            self._add_obs("CONFIG", obs_src, "endpoint", ep_id,
                          "platform_version", ep["platform_version"],
                          0.5 if ep["platform_version"] == "UNKNOWN" else 1.0)
            self._add_obs("CONFIG", obs_src, "endpoint", ep_id,
                          "capabilities.pfs_supported",
                          ep["capabilities"]["pfs_supported"], 1.0)
            self._add_obs("CONFIG", obs_src, "endpoint", ep_id,
                          "validation_status", ep["validation_status"], 1.0)

    # ------------------------------------------------------------------
    # Build Fleet
    # ------------------------------------------------------------------

    def _build_fleet(self) -> None:
        ep_ids = [e["endpoint_id"] for e in self._endpoints]
        tn_ids = [t["tunnel_id"] for t in self._tunnels]
        self._fleet = {
            "fleet_id":    self.FLEET_ID,
            "name":        "STATEFLUX Demo Fleet",
            "description": (
                "Synthetic IPsec VPN fleet for STATEFLUX Phase 1A demonstration. "
                "Includes 12 controlled scenarios covering the full spectrum of "
                "IPsec security postures from fully secure to critically weak. "
                "⚠ SYNTHETIC DATA — not representative of any real deployment."
            ),
            "environment": "SYNTHETIC_PROTOTYPE",
            "created_at":  _ts(),
            "endpoint_ids": ep_ids,
            "tunnel_ids":   tn_ids,
            "notes": (
                "Generated by StatefluxDatasetGenerator with seed=42. "
                "All data is synthetic and must be labeled as such."
            ),
        }

    # ------------------------------------------------------------------
    # Generate + Write
    # ------------------------------------------------------------------

    def generate(self, output_dir: Path) -> dict[str, int]:
        """Generate the complete dataset and write to output_dir.

        Args:
            output_dir: Directory to write JSON files to (will be created).

        Returns:
            Dict of entity name → count.
        """
        logger.info("Generating STATEFLUX synthetic dataset (seed=%d)...", self.SEED)
        output_dir.mkdir(parents=True, exist_ok=True)

        self._build_endpoints()
        self._build_tunnels()
        self._build_observations()
        self._build_fleet()

        files = {
            "fleet.json":         self._fleet,        # single object
            "endpoints.json":     self._endpoints,
            "proposals.json":     self._proposals,
            "tunnels.json":       self._tunnels,
            "negotiations.json":  self._negotiations,
            "observations.json":  self._observations,
            "security_states.json": self._security_states,
        }

        for filename, data in files.items():
            path = output_dir / filename
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, default=str, ensure_ascii=False)
            logger.info("Wrote %s (%d records)",
                        filename,
                        1 if isinstance(data, dict) else len(data))

        stats = {
            "fleet":           1,
            "endpoints":       len(self._endpoints),
            "proposals":       len(self._proposals),
            "tunnels":         len(self._tunnels),
            "negotiations":    len(self._negotiations),
            "observations":    len(self._observations),
            "security_states": len(self._security_states),
        }
        logger.info("Dataset generation complete: %s", stats)
        return stats
