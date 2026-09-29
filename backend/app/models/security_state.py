"""
STATEFLUX — SecurityState Model
=================================
The SecurityState captures the assessed cryptographic posture of a
single tunnel at a specific point in time.

SELECTED vs FLOOR:
  This is the core STATEFLUX concept:

  selected:
    The cryptographic suite that is currently in use for this tunnel.
    This is what was negotiated and agreed upon by both endpoints.

  floor:
    The weakest cryptographic suite that both endpoints would ACCEPT,
    i.e., the fallback they would fall back to if the stronger suite
    became unavailable.

  A tunnel may appear secure because its SELECTED suite is strong
  (e.g., AES-256-GCM). But if the FLOOR allows 3DES, the real
  security posture of the tunnel is bounded by 3DES.

  In Phase 1, the floor is computed by the dataset generator from
  the common proposal intersection, ordered by strength. The
  Security Floor Engine (Phase 6/7) will compute this more
  rigorously with full policy context.

RISK SCORE:
  risk.score is in the range [0, 100]:
    0   = no identified risk
    100 = maximum possible risk

  In Phase 1, the score is computed by the basic rule engine.
  It is intentionally simple. Future phases will refine it with
  a weighted, evidence-backed scoring model.

  Do not treat Phase 1 risk scores as accurate risk assessments.
  They are structural placeholders with basic signal value.
"""

from typing import Optional

from pydantic import field_validator

from app.models.base import (
    StatefluxBaseModel,
    EncryptionAlgorithm,
    IntegrityAlgorithm,
    RiskLevel,
)


class CryptoSuite(StatefluxBaseModel):
    """A snapshot of one cryptographic suite (selected or floor).

    All fields are Optional because the suite may be partially known
    (e.g., encryption is observed but DH group is not).
    Use None to represent 'unknown', not 'not applicable'.
    """
    encryption:  Optional[EncryptionAlgorithm]  = None
    integrity:   Optional[IntegrityAlgorithm]   = None
    dh_group:    Optional[int]                  = None
    pfs:         Optional[bool]                 = None


class SecurityControls(StatefluxBaseModel):
    """Additional security control assessments beyond the core crypto suite."""
    replay_protection: Optional[bool] = None


class RiskAssessment(StatefluxBaseModel):
    """Composite risk score for this tunnel's security posture.

    score:  0 (no risk identified) → 100 (maximum risk).
    level:  Categorical label derived from the score.
    basis:  Short description of what drove the score (e.g., "3DES + SHA-1 + PFS_OFF").
    """
    score: float
    level: RiskLevel
    basis: Optional[str] = None

    @field_validator("score")
    @classmethod
    def score_must_be_in_range(cls, v: float) -> float:
        if not (0.0 <= v <= 100.0):
            raise ValueError(
                f"risk score must be between 0.0 and 100.0, got {v}"
            )
        return v


class SecurityState(StatefluxBaseModel):
    """The assessed security posture of a single tunnel.

    Attributes:
        security_state_id:  Unique identifier (e.g., "ss-001").
        tunnel_id:          The tunnel this state describes.
        selected:           The currently negotiated cryptographic suite.
        floor:              The weakest suite both endpoints would accept.
                            None if the tunnel is DOWN or the floor cannot
                            be computed from available data.
        controls:           Supplemental security controls (replay protection).
        risk:               Composite risk assessment.
        floor_gap_exists:   Computed flag: True if selected != floor,
                            indicating a gap between current and worst-case security.
        assessment_version: Version string for the rule set used to produce
                            this assessment. Allows re-assessment when rules change.
    """

    security_state_id:   str
    tunnel_id:           str
    selected:            CryptoSuite
    floor:               Optional[CryptoSuite]    = None
    controls:            SecurityControls
    risk:                RiskAssessment
    floor_gap_exists:    bool                     = False
    assessment_version:  str                      = "1.0-phase1a"
