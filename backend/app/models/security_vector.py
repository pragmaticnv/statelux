"""
STATEFLUX — Security Vector & Cryptographic Normalization Models
================================================================
Phase 2 — Security Intelligence Layer

Represents multidimensional security vectors for cryptographic proposals.
Enforces separation between:
  - IKE security dimensions
  - Child-SA / ESP security dimensions (including PFS)

Provides Pareto dominance comparison across security dimensions:
  STRONG > ACCEPTABLE > WEAK > LEGACY > DISALLOWED
"""

from enum import Enum
from typing import Optional, Any
from pydantic import Field

from app.models.base import StatefluxBaseModel, Protocol, IKEVersion


class StrengthClass(str, Enum):
    """Categorical classification of cryptographic strength.

    Ordered from strongest (STRONG) to weakest (DISALLOWED).
    UNKNOWN represents missing or unobserved data.
    """
    STRONG = "STRONG"
    ACCEPTABLE = "ACCEPTABLE"
    WEAK = "WEAK"
    LEGACY = "LEGACY"
    DISALLOWED = "DISALLOWED"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        """Numerical rank for order comparison.

        Higher = stronger. UNKNOWN has rank -1 (incomparable in standard order).
        """
        mapping = {
            StrengthClass.DISALLOWED: 0,
            StrengthClass.LEGACY: 1,
            StrengthClass.WEAK: 2,
            StrengthClass.ACCEPTABLE: 3,
            StrengthClass.STRONG: 4,
            StrengthClass.UNKNOWN: -1,
        }
        return mapping[self]

    def is_known(self) -> bool:
        return self != StrengthClass.UNKNOWN

    def is_stronger_than(self, other: "StrengthClass") -> bool:
        if not self.is_known() or not other.is_known():
            return False
        return self.rank > other.rank

    def is_weaker_than(self, other: "StrengthClass") -> bool:
        if not self.is_known() or not other.is_known():
            return False
        return self.rank < other.rank

    def is_at_least(self, other: "StrengthClass") -> bool:
        if not self.is_known() or not other.is_known():
            return False
        return self.rank >= other.rank


class DimensionComparison(str, Enum):
    """Result of comparing two proposals along a single or composite dimension."""
    STRONGER = "STRONGER"
    EQUAL = "EQUAL"
    WEAKER = "WEAKER"
    INCOMPARABLE = "INCOMPARABLE"


class NormalizedTransform(StatefluxBaseModel):
    """Normalized evaluation of a single cryptographic transform."""
    name: str
    strength_class: StrengthClass
    key_size: Optional[int] = None
    notes: Optional[str] = None


class SecurityVector(StatefluxBaseModel):
    """Multidimensional security vector for a single proposal.

    Maintains separate semantic dimensions rather than collapsing to a single scalar score.
    """
    proposal_id: str
    owner_endpoint_id: str
    protocol: Protocol
    priority: int
    ike_version: Optional[IKEVersion] = None

    # Cryptographic dimensions
    encryption: NormalizedTransform
    integrity: Optional[NormalizedTransform] = None
    dh_group: Optional[NormalizedTransform] = None
    prf: Optional[NormalizedTransform] = None

    # PFS — strictly an ESP/Child-SA dimension; None for IKE
    pfs: Optional[bool] = None
    pfs_strength: StrengthClass = StrengthClass.UNKNOWN

    # Properties
    is_aead: bool = False
    is_legacy: bool = False
    is_disallowed: bool = False

    def compare_to(self, other: "SecurityVector") -> DimensionComparison:
        """Compare this vector to another along all shared dimensions.

        Returns:
            STRONGER if self >= other in all dimensions and > in at least one.
            WEAKER if self <= other in all dimensions and < in at least one.
            EQUAL if self == other in all dimensions.
            INCOMPARABLE if self is stronger in some dimension and weaker in another,
                         or if either has UNKNOWN values in a differentiating dimension.
        """
        if self.protocol != other.protocol:
            return DimensionComparison.INCOMPARABLE

        # Compare dimensions
        dims: list[tuple[StrengthClass, StrengthClass]] = []

        # 1. Encryption
        dims.append((self.encryption.strength_class, other.encryption.strength_class))

        # 2. Integrity (compare if applicable to either)
        if self.integrity is not None or other.integrity is not None:
            c1 = self.integrity.strength_class if self.integrity else StrengthClass.STRONG  # AEAD implicit
            c2 = other.integrity.strength_class if other.integrity else StrengthClass.STRONG
            dims.append((c1, c2))

        # 3. DH Group (for IKE, or ESP when DH is configured)
        if self.dh_group is not None or other.dh_group is not None:
            c1 = self.dh_group.strength_class if self.dh_group else StrengthClass.DISALLOWED
            c2 = other.dh_group.strength_class if other.dh_group else StrengthClass.DISALLOWED
            dims.append((c1, c2))

        # 4. PFS (only for ESP / Child-SA)
        if self.protocol == Protocol.ESP:
            dims.append((self.pfs_strength, other.pfs_strength))

        # Check for UNKNOWN
        for c1, c2 in dims:
            if not c1.is_known() or not c2.is_known():
                # If values differ and one is unknown, they are incomparable
                if c1 != c2:
                    return DimensionComparison.INCOMPARABLE

        has_greater = False
        has_lesser = False

        for c1, c2 in dims:
            if c1.rank > c2.rank:
                has_greater = True
            elif c1.rank < c2.rank:
                has_lesser = True

        if has_greater and has_lesser:
            return DimensionComparison.INCOMPARABLE
        if has_greater:
            return DimensionComparison.STRONGER
        if has_lesser:
            return DimensionComparison.WEAKER
        return DimensionComparison.EQUAL

    def dominates(self, other: "SecurityVector") -> bool:
        """True if self is strictly stronger than other in the Pareto sense."""
        return self.compare_to(other) == DimensionComparison.STRONGER

    def is_dominated_by(self, other: "SecurityVector") -> bool:
        """True if other is strictly stronger than self (i.e. self is strictly weaker)."""
        return self.compare_to(other) == DimensionComparison.WEAKER
