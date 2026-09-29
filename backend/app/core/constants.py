"""
STATEFLUX — Core Constants
============================
Domain-specific constants used by the security rule engine and analyzer.

PHILOSOPHY:
  All security judgements are backed by explicit, named constants.
  No magic numbers. Every threshold is documented with its rationale.
  When standards change, only this file (and tests) need updating.
"""

# ---------------------------------------------------------------------------
# DH Group Strength Classification
# ---------------------------------------------------------------------------
# IANA group number → strength label
# Based on NIST SP 800-77r1 and BSI TR-02102-3 (2023) recommendations.

DH_GROUP_STRENGTH: dict[int, str] = {
    1:  "INSECURE",   # 768-bit MODP — should not be used
    2:  "INSECURE",   # 1024-bit MODP — deprecated, vulnerable
    5:  "WEAK",       # 1536-bit MODP — below modern minimum
    14: "ADEQUATE",   # 2048-bit MODP — minimum acceptable per NIST SP 800-77r1
    15: "ADEQUATE",   # 3072-bit MODP — adequate
    16: "ADEQUATE",   # 4096-bit MODP — adequate
    17: "ADEQUATE",   # 6144-bit MODP — adequate but unusual
    18: "ADEQUATE",   # 8192-bit MODP — adequate but unusual
    19: "STRONG",     # 256-bit ECP (NIST P-256) — strong
    20: "STRONG",     # 384-bit ECP (NIST P-384) — strong, recommended
    21: "STRONG",     # 521-bit ECP (NIST P-521) — strong, high-security
    31: "STRONG",     # Curve25519 — strong, modern
    32: "STRONG",     # Curve448 — strong, high-security
}

# Minimum DH group number considered "adequate" for modern deployments
DH_GROUP_MINIMUM_ADEQUATE = 14

# Minimum DH group number for a "strong" deployment
DH_GROUP_MINIMUM_STRONG = 19

# ---------------------------------------------------------------------------
# Algorithm Strength Classification
# ---------------------------------------------------------------------------

ENCRYPTION_STRENGTH: dict[str, str] = {
    "AES-256-GCM": "STRONG",
    "AES-256-CBC": "ADEQUATE",
    "AES-128-GCM": "ADEQUATE",
    "AES-128-CBC": "WEAK",
    "3DES":        "INSECURE",
}

INTEGRITY_STRENGTH: dict[str, str] = {
    "HMAC-SHA-512": "STRONG",
    "HMAC-SHA-384": "STRONG",
    "HMAC-SHA-256": "ADEQUATE",
    "HMAC-SHA-1":   "WEAK",
}

# ---------------------------------------------------------------------------
# Risk Scoring Weights
# ---------------------------------------------------------------------------
# Each weakness adds to the risk score (0–100 scale).
# Multiple weaknesses accumulate additively, capped at 100.

RISK_WEIGHT: dict[str, float] = {
    "INSECURE_ENCRYPTION":      45.0,  # 3DES
    "WEAK_ENCRYPTION":          22.0,  # AES-128-CBC
    "INSECURE_DH_GROUP":        35.0,  # DH group 1 or 2
    "WEAK_DH_GROUP":            15.0,  # DH group 5
    "ADEQUATE_DH_GROUP":         5.0,  # DH group 14 — slight risk nudge
    "LEGACY_IKE_VERSION":       12.0,  # IKEv1
    "PFS_DISABLED":             18.0,
    "REPLAY_PROTECTION_OFF":    10.0,
    "WEAK_INTEGRITY":           14.0,  # SHA-1
}

# Risk level thresholds (score → level)
RISK_THRESHOLDS: list[tuple[float, str]] = [
    (0,   "INFO"),
    (10,  "LOW"),
    (30,  "MEDIUM"),
    (55,  "HIGH"),
    (75,  "CRITICAL"),
]

# ---------------------------------------------------------------------------
# Security Rule IDs
# ---------------------------------------------------------------------------
# Each rule has a stable ID used in findings and test assertions.

RULE_WEAK_ENCRYPTION      = "SR-001"
RULE_INSECURE_ENCRYPTION  = "SR-002"
RULE_INSECURE_DH          = "SR-003"
RULE_WEAK_DH              = "SR-004"
RULE_ADEQUATE_DH          = "SR-005"
RULE_LEGACY_IKE           = "SR-006"
RULE_PFS_DISABLED         = "SR-007"
RULE_REPLAY_DISABLED      = "SR-008"
RULE_WEAK_INTEGRITY       = "SR-009"
RULE_POLICY_VIOLATION     = "SR-010"   # Placeholder for Phase 7

# ---------------------------------------------------------------------------
# Data Constants
# ---------------------------------------------------------------------------

SYNTHETIC_DATA_DISCLAIMER = (
    "⚠ SYNTHETIC / PROTOTYPE DATA — "
    "All fleet data in this report was generated synthetically "
    "for demonstration and testing purposes. "
    "It does NOT represent any real-world VPN deployment."
)

ASSESSMENT_VERSION = "1.0-phase1a"
