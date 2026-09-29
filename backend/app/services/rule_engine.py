"""
STATEFLUX — Basic Security Rule Engine
========================================
Phase 1A implementation of deterministic security rules.

DESIGN PRINCIPLES:
  1. STATELESS — The engine receives data and returns findings.
     It has no internal state and no I/O side effects.

  2. DETERMINISTIC — Identical input always produces identical output.
     No randomness, no external dependencies, no caching.

  3. RULES ARE EXPLICIT — Every rule has an ID, a name, severity,
     description, and recommendation. Nothing is a magic number.

  4. AI DOES NOT OVERRIDE THIS ENGINE — The rule engine's conclusions
     are authoritative. AI may explain them, but not change them.

  5. TRACEABLE — Every finding references the rule that produced it.

PHASE 1 SCOPE:
  This implements basic structural rules against a Proposal object.
  Future phases will add:
    - Policy-aware rules (SR-010 and beyond)
    - Fleet-level rules (e.g., topology vulnerabilities)
    - Evidence chain linkage
    - Confidence scoring based on data provenance
"""

from dataclasses import dataclass, field
from typing import Any, Optional

from app.models.base import IKEVersion, RiskLevel
from app.models.proposal import Proposal
from app.models.negotiation import Negotiation
from app.core.constants import (
    DH_GROUP_STRENGTH,
    DH_GROUP_MINIMUM_ADEQUATE,
    ENCRYPTION_STRENGTH,
    INTEGRITY_STRENGTH,
    RISK_WEIGHT,
    RISK_THRESHOLDS,
    RULE_WEAK_ENCRYPTION,
    RULE_INSECURE_ENCRYPTION,
    RULE_INSECURE_DH,
    RULE_WEAK_DH,
    RULE_ADEQUATE_DH,
    RULE_LEGACY_IKE,
    RULE_PFS_DISABLED,
    RULE_REPLAY_DISABLED,
    RULE_WEAK_INTEGRITY,
    ASSESSMENT_VERSION,
)


# ---------------------------------------------------------------------------
# Finding — output of the rule engine
# ---------------------------------------------------------------------------

@dataclass
class SecurityFinding:
    """A single security finding produced by the rule engine.

    Attributes:
        finding_id:    Unique within a single assessment run.
        tunnel_id:     Which tunnel this finding pertains to.
        rule_id:       Which rule produced this finding (e.g., "SR-001").
        severity:      Categorical severity level.
        title:         Short, human-readable summary.
        description:   Full explanation of the issue.
        recommendation: Suggested remediation action.
        affected_field: Which field on the entity triggered this rule.
        observed_value: The actual value that triggered the rule.
    """
    finding_id:      str
    tunnel_id:       str
    rule_id:         str
    severity:        RiskLevel
    title:           str
    description:     str
    recommendation:  str
    affected_field:  str
    observed_value:  Any


# ---------------------------------------------------------------------------
# Assessment Result — full output per tunnel
# ---------------------------------------------------------------------------

@dataclass
class TunnelAssessment:
    """Complete assessment result for one tunnel."""
    tunnel_id:          str
    ike_version:        Optional[str]
    mode:               str
    encryption:         Optional[str]
    key_size:           Optional[int]
    integrity:          Optional[str]
    dh_group:           Optional[int]
    pfs:                Optional[bool]
    replay_protection:  Optional[bool]
    rekey_interval:     int
    sa_status:          str
    findings:           list[SecurityFinding]  = field(default_factory=list)
    risk_score:         float                  = 0.0
    risk_level:         str                    = "INFO"
    assessment_version: str                    = ASSESSMENT_VERSION
    analysis_source:    str                    = "STRUCTURED_DATA"


# ---------------------------------------------------------------------------
# Rule Engine
# ---------------------------------------------------------------------------

class RuleEngine:
    """Stateless, deterministic security rule evaluator.

    Evaluates a Proposal + Negotiation context and returns a list of
    SecurityFindings. The caller is responsible for aggregating findings
    from multiple proposals into a tunnel-level assessment.

    Usage:
        engine = RuleEngine()
        findings = engine.evaluate_proposal(proposal, tunnel_id, negotiation)
        risk_score, risk_level = engine.compute_risk(findings)
    """

    def __init__(self) -> None:
        self._finding_counter: int = 0

    def _next_id(self, tunnel_id: str) -> str:
        self._finding_counter += 1
        return f"finding-{tunnel_id}-{self._finding_counter:04d}"

    def reset(self) -> None:
        """Reset counter — call between assessment runs to keep IDs clean."""
        self._finding_counter = 0

    # ------------------------------------------------------------------
    # Core rule evaluators
    # ------------------------------------------------------------------

    def _check_encryption(
        self, proposal: Proposal, tunnel_id: str
    ) -> list[SecurityFinding]:
        findings = []
        enc = proposal.encryption_algorithm.value
        strength = ENCRYPTION_STRENGTH.get(enc, "UNKNOWN")

        if strength == "INSECURE":
            findings.append(SecurityFinding(
                finding_id=self._next_id(tunnel_id),
                tunnel_id=tunnel_id,
                rule_id=RULE_INSECURE_ENCRYPTION,
                severity=RiskLevel.CRITICAL,
                title=f"Insecure encryption algorithm: {enc}",
                description=(
                    f"The negotiated encryption algorithm '{enc}' is considered "
                    f"cryptographically insecure. 3DES is vulnerable to the "
                    f"Sweet32 birthday attack and should not be used in any "
                    f"new deployment."
                ),
                recommendation=(
                    "Replace with AES-256-GCM immediately. "
                    "If peer compatibility is required, AES-256-CBC is an "
                    "acceptable intermediate step."
                ),
                affected_field="selected.encryption",
                observed_value=enc,
            ))
        elif strength == "WEAK":
            findings.append(SecurityFinding(
                finding_id=self._next_id(tunnel_id),
                tunnel_id=tunnel_id,
                rule_id=RULE_WEAK_ENCRYPTION,
                severity=RiskLevel.HIGH,
                title=f"Weak encryption algorithm: {enc}",
                description=(
                    f"The negotiated encryption algorithm '{enc}' uses a "
                    f"128-bit key, which is below the recommended 256-bit "
                    f"minimum for high-assurance environments. "
                    f"AES-128-CBC also lacks authenticated encryption."
                ),
                recommendation=(
                    "Upgrade to AES-256-GCM. If CBC mode is required, "
                    "use AES-256-CBC with HMAC-SHA-256 or stronger."
                ),
                affected_field="selected.encryption",
                observed_value=enc,
            ))
        return findings

    def _check_dh_group(
        self, dh_group: Optional[int], tunnel_id: str, context: str = "selected"
    ) -> list[SecurityFinding]:
        findings = []
        if dh_group is None:
            return findings

        strength = DH_GROUP_STRENGTH.get(dh_group, "UNKNOWN")

        if strength == "INSECURE":
            findings.append(SecurityFinding(
                finding_id=self._next_id(tunnel_id),
                tunnel_id=tunnel_id,
                rule_id=RULE_INSECURE_DH,
                severity=RiskLevel.CRITICAL,
                title=f"Insecure DH group: Group {dh_group}",
                description=(
                    f"DH group {dh_group} provides insufficient key exchange "
                    f"security. Groups 1 (768-bit) and 2 (1024-bit) are "
                    f"considered broken and susceptible to passive decryption "
                    f"attacks with current computing resources."
                ),
                recommendation=(
                    "Replace with DH group 20 (384-bit ECP / NIST P-384) "
                    "or group 19 (256-bit ECP / NIST P-256) minimum. "
                    "Do not use any MODP group below group 14."
                ),
                affected_field=f"{context}.dh_group",
                observed_value=dh_group,
            ))
        elif strength == "WEAK":
            findings.append(SecurityFinding(
                finding_id=self._next_id(tunnel_id),
                tunnel_id=tunnel_id,
                rule_id=RULE_WEAK_DH,
                severity=RiskLevel.HIGH,
                title=f"Weak DH group: Group {dh_group}",
                description=(
                    f"DH group {dh_group} (1536-bit MODP) is below the "
                    f"current recommended minimum of group 14 (2048-bit MODP)."
                ),
                recommendation=(
                    "Upgrade to DH group 19 (ECP-256) or higher."
                ),
                affected_field=f"{context}.dh_group",
                observed_value=dh_group,
            ))
        elif strength == "ADEQUATE" and dh_group == DH_GROUP_MINIMUM_ADEQUATE:
            # DH-14 is technically adequate but worth flagging for planning
            findings.append(SecurityFinding(
                finding_id=self._next_id(tunnel_id),
                tunnel_id=tunnel_id,
                rule_id=RULE_ADEQUATE_DH,
                severity=RiskLevel.LOW,
                title=f"Minimum-adequate DH group: Group {dh_group}",
                description=(
                    f"DH group {dh_group} (2048-bit MODP) meets the minimum "
                    f"threshold per NIST SP 800-77r1 but is the weakest "
                    f"acceptable option. Consider upgrading."
                ),
                recommendation=(
                    "Plan to upgrade to DH group 19 (ECP-256) or group 20 "
                    "(ECP-384) during the next maintenance window."
                ),
                affected_field=f"{context}.dh_group",
                observed_value=dh_group,
            ))
        return findings

    def _check_ike_version(
        self, ike_version: Optional[str], tunnel_id: str
    ) -> list[SecurityFinding]:
        findings = []
        if ike_version == IKEVersion.V1.value:
            findings.append(SecurityFinding(
                finding_id=self._next_id(tunnel_id),
                tunnel_id=tunnel_id,
                rule_id=RULE_LEGACY_IKE,
                severity=RiskLevel.MEDIUM,
                title="Legacy IKE version: IKEv1",
                description=(
                    "IKEv1 has known vulnerabilities including susceptibility "
                    "to main-mode identity protection bypass in aggressive mode "
                    "and weaker authentication mechanisms compared to IKEv2. "
                    "RFC 9395 recommends deprecating IKEv1."
                ),
                recommendation=(
                    "Migrate to IKEv2. IKEv2 provides stronger authentication, "
                    "built-in mobility support (MOBIKE), and cleaner semantics. "
                    "Most modern VPN implementations support IKEv2."
                ),
                affected_field="ike_version",
                observed_value=ike_version,
            ))
        return findings

    def _check_pfs(
        self, pfs: Optional[bool], tunnel_id: str
    ) -> list[SecurityFinding]:
        findings = []
        if pfs is False:
            findings.append(SecurityFinding(
                finding_id=self._next_id(tunnel_id),
                tunnel_id=tunnel_id,
                rule_id=RULE_PFS_DISABLED,
                severity=RiskLevel.MEDIUM,
                title="PFS (Perfect Forward Secrecy) disabled",
                description=(
                    "PFS is not enabled for this tunnel. Without PFS, "
                    "compromise of the long-term IKE key material could "
                    "allow decryption of historical ESP traffic. "
                    "PFS ensures that each session key is ephemeral."
                ),
                recommendation=(
                    "Enable PFS with DH group 19 or 20. "
                    "For IKEv2, set a DH group in the ESP/CHILD_SA proposal."
                ),
                affected_field="selected.pfs",
                observed_value=pfs,
            ))
        return findings

    def _check_replay_protection(
        self, replay_protection: Optional[bool], tunnel_id: str
    ) -> list[SecurityFinding]:
        findings = []
        if replay_protection is False:
            findings.append(SecurityFinding(
                finding_id=self._next_id(tunnel_id),
                tunnel_id=tunnel_id,
                rule_id=RULE_REPLAY_DISABLED,
                severity=RiskLevel.MEDIUM,
                title="Anti-replay protection disabled",
                description=(
                    "Anti-replay protection (sequence number validation) is "
                    "disabled for this tunnel. This leaves the tunnel vulnerable "
                    "to replay attacks where captured ESP packets are retransmitted."
                ),
                recommendation=(
                    "Enable anti-replay protection. "
                    "Consider enabling Extended Sequence Numbers (ESN) "
                    "for high-throughput tunnels."
                ),
                affected_field="controls.replay_protection",
                observed_value=replay_protection,
            ))
        return findings

    def _check_integrity(
        self, proposal: Proposal, tunnel_id: str
    ) -> list[SecurityFinding]:
        findings = []
        if proposal.integrity_algorithm is None:
            # AEAD — no separate integrity needed; not a finding
            return findings

        integ = proposal.integrity_algorithm.value
        strength = INTEGRITY_STRENGTH.get(integ, "UNKNOWN")

        if strength == "WEAK":
            findings.append(SecurityFinding(
                finding_id=self._next_id(tunnel_id),
                tunnel_id=tunnel_id,
                rule_id=RULE_WEAK_INTEGRITY,
                severity=RiskLevel.HIGH,
                title=f"Weak integrity algorithm: {integ}",
                description=(
                    f"HMAC-SHA-1 provides only 80-bit collision resistance "
                    f"(due to SHA-1's 160-bit output and birthday-bound), "
                    f"which is below the 128-bit minimum recommended for "
                    f"modern deployments. NIST formally deprecated SHA-1 "
                    f"for most uses in 2011."
                ),
                recommendation=(
                    "Replace HMAC-SHA-1 with HMAC-SHA-256 minimum. "
                    "Prefer HMAC-SHA-384 or HMAC-SHA-512 for high-assurance "
                    "environments."
                ),
                affected_field="selected.integrity",
                observed_value=integ,
            ))
        return findings

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate_proposal(
        self,
        proposal: Proposal,
        tunnel_id: str,
        ike_version: Optional[str] = None,
        pfs: Optional[bool] = None,
        replay_protection: Optional[bool] = None,
    ) -> list[SecurityFinding]:
        """Evaluate a single proposal and return all triggered findings.

        Args:
            proposal:           The Proposal to evaluate.
            tunnel_id:          ID of the tunnel this proposal belongs to.
            ike_version:        IKE version string (checked separately).
            pfs:                PFS state to evaluate.
            replay_protection:  Replay protection state to evaluate.
        """
        findings: list[SecurityFinding] = []

        findings.extend(self._check_encryption(proposal, tunnel_id))
        findings.extend(self._check_integrity(proposal, tunnel_id))

        if proposal.dh_group is not None:
            findings.extend(self._check_dh_group(proposal.dh_group, tunnel_id))

        if ike_version is not None:
            findings.extend(self._check_ike_version(ike_version, tunnel_id))

        if pfs is not None:
            findings.extend(self._check_pfs(pfs, tunnel_id))

        if replay_protection is not None:
            findings.extend(self._check_replay_protection(replay_protection, tunnel_id))

        return findings

    @staticmethod
    def compute_risk(findings: list[SecurityFinding]) -> tuple[float, str]:
        """Compute aggregate risk score and level from a list of findings.

        Returns:
            (score, level) where score ∈ [0.0, 100.0] and level is a
            RiskLevel string value.
        """
        rule_to_weight = {
            RULE_INSECURE_ENCRYPTION: RISK_WEIGHT["INSECURE_ENCRYPTION"],
            RULE_WEAK_ENCRYPTION:     RISK_WEIGHT["WEAK_ENCRYPTION"],
            RULE_INSECURE_DH:         RISK_WEIGHT["INSECURE_DH_GROUP"],
            RULE_WEAK_DH:             RISK_WEIGHT["WEAK_DH_GROUP"],
            RULE_ADEQUATE_DH:         RISK_WEIGHT["ADEQUATE_DH_GROUP"],
            RULE_LEGACY_IKE:          RISK_WEIGHT["LEGACY_IKE_VERSION"],
            RULE_PFS_DISABLED:        RISK_WEIGHT["PFS_DISABLED"],
            RULE_REPLAY_DISABLED:     RISK_WEIGHT["REPLAY_PROTECTION_OFF"],
            RULE_WEAK_INTEGRITY:      RISK_WEIGHT["WEAK_INTEGRITY"],
        }

        # Accumulate; avoid double-counting same rule
        seen_rules: set[str] = set()
        score: float = 0.0
        for finding in findings:
            if finding.rule_id not in seen_rules:
                score += rule_to_weight.get(finding.rule_id, 0.0)
                seen_rules.add(finding.rule_id)

        score = min(score, 100.0)

        # Determine level
        level = "INFO"
        for threshold, lv in RISK_THRESHOLDS:
            if score >= threshold:
                level = lv

        return round(score, 2), level
