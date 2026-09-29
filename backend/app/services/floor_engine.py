"""
STATEFLUX — Security Floor & Pareto Frontier Engine
===================================================
Phase 2 — Security Intelligence Layer

Calculates the Security Floor Frontier and Display Floor for a tunnel:
  1. Transforms common proposal space into normalized SecurityVectors.
  2. Identifies Pareto-minimal (weakest non-dominated permitted) proposals.
  3. Derives a representative Display Floor.
  4. Computes multidimensional Floor Gap between selected and floor posture.
  5. Preserves uncertainty without converting unknown values into false facts.
"""

from typing import Optional, Sequence

from app.models.base import Protocol
from app.models.security_vector import SecurityVector, StrengthClass, DimensionComparison
from app.models.negotiation_space import CompatibilityStatus, ConfidenceLevel
from app.models.security_floor import (
    SecurityFloorResult,
    FloorGap,
    FloorGapDimension,
    GapLevel,
)
from app.services.normalizer import ProposalNormalizer


class SecurityFloorEngine:
    """Calculates the Security Floor Frontier, Display Floor, and Floor Gap."""

    def __init__(self, normalizer: Optional[ProposalNormalizer] = None) -> None:
        self.normalizer = normalizer or ProposalNormalizer()

    # ------------------------------------------------------------------
    # Pareto Frontier Calculation
    # ------------------------------------------------------------------

    @staticmethod
    def calculate_floor_frontier(vectors: Sequence[SecurityVector]) -> list[SecurityVector]:
        """Compute the Pareto-minimal (weakest non-dominated) permitted proposals.

        A proposal A is on the floor frontier if there is NO proposal B in vectors
        such that A strictly dominates B in strength (A >_strength B).

        In other words, no proposal in the permitted set is strictly weaker than A
        across all dimensions.
        """
        if not vectors:
            return []

        # Deduplicate vectors with identical transforms
        unique_vectors: list[SecurityVector] = []
        seen_keys: set[str] = set()

        for v in vectors:
            key = (
                v.protocol.value,
                v.encryption.name,
                v.integrity.name if v.integrity else None,
                v.dh_group.name if v.dh_group else None,
                v.pfs,
            )
            if key not in seen_keys:
                unique_vectors.append(v)
                seen_keys.add(key)

        if len(unique_vectors) <= 1:
            return list(unique_vectors)

        frontier: list[SecurityVector] = []

        for candidate in unique_vectors:
            # Candidate is in the floor frontier if it does NOT strictly dominate
            # any other proposal in the set.
            strictly_dominates_other = False
            for other in unique_vectors:
                if candidate is not other and candidate.dominates(other):
                    strictly_dominates_other = True
                    break

            if not strictly_dominates_other:
                frontier.append(candidate)

        return frontier

    # ------------------------------------------------------------------
    # Display Floor Derivation
    # ------------------------------------------------------------------

    @staticmethod
    def derive_display_floor(frontier: list[SecurityVector]) -> Optional[SecurityVector]:
        """Derive the single representative display floor from the frontier.

        If multiple non-dominated proposals exist, select the one with the lowest
        primary encryption strength, then lowest DH group, then lowest integrity.
        """
        if not frontier:
            return None
        if len(frontier) == 1:
            return frontier[0]

        def _sort_key(v: SecurityVector) -> tuple[int, int, int]:
            enc_rank = v.encryption.strength_class.rank
            dh_rank = v.dh_group.strength_class.rank if v.dh_group else 0
            int_rank = v.integrity.strength_class.rank if v.integrity else 4  # AEAD is 4
            pfs_rank = v.pfs_strength.rank if v.protocol == Protocol.ESP else 4
            return (enc_rank, dh_rank, int_rank, pfs_rank)

        # Sort ascending by strength ranks so the weakest comes first
        sorted_frontier = sorted(frontier, key=_sort_key)
        return sorted_frontier[0]

    # ------------------------------------------------------------------
    # Multidimensional Gap Analysis
    # ------------------------------------------------------------------

    @staticmethod
    def calculate_floor_gap(
        selected: Optional[SecurityVector],
        floor: Optional[SecurityVector],
    ) -> FloorGap:
        """Compute the structured degradation between selected and floor posture."""
        if not selected or not floor:
            return FloorGap(
                gap_level=GapLevel.UNKNOWN,
                has_gap=False,
                summary="Insufficient data to compute security floor gap.",
                dimension_gaps=[],
            )

        dimension_gaps: list[FloorGapDimension] = []

        # 1. Encryption degradation
        s_enc = selected.encryption.strength_class
        f_enc = floor.encryption.strength_class

        if s_enc.is_known() and f_enc.is_known():
            if s_enc.rank > f_enc.rank:
                delta = s_enc.rank - f_enc.rank
                if f_enc in (StrengthClass.DISALLOWED, StrengthClass.LEGACY):
                    enc_gap = GapLevel.CRITICAL
                    desc = f"Encryption degrades from {selected.encryption.name} ({s_enc.value}) to deprecated/insecure {floor.encryption.name} ({f_enc.value})."
                elif delta >= 2 or f_enc == StrengthClass.WEAK:
                    enc_gap = GapLevel.HIGH
                    desc = f"Encryption degrades from {selected.encryption.name} ({s_enc.value}) to weak {floor.encryption.name} ({f_enc.value})."
                else:
                    enc_gap = GapLevel.LOW
                    desc = f"Encryption degrades slightly from {selected.encryption.name} to {floor.encryption.name}."

                dimension_gaps.append(FloorGapDimension(
                    dimension="encryption",
                    selected_value=selected.encryption.name,
                    selected_class=s_enc,
                    floor_value=floor.encryption.name,
                    floor_class=f_enc,
                    degradation_level=enc_gap,
                    description=desc,
                ))

        # 2. Diffie-Hellman degradation
        s_dh = selected.dh_group.strength_class if selected.dh_group else StrengthClass.UNKNOWN
        f_dh = floor.dh_group.strength_class if floor.dh_group else StrengthClass.UNKNOWN

        if s_dh.is_known() and f_dh.is_known() and selected.dh_group and floor.dh_group:
            if s_dh.rank > f_dh.rank:
                if f_dh in (StrengthClass.DISALLOWED, StrengthClass.LEGACY):
                    dh_gap = GapLevel.CRITICAL
                    desc = f"Key exchange degrades to broken/insecure {floor.dh_group.name}."
                elif f_dh == StrengthClass.WEAK:
                    dh_gap = GapLevel.HIGH
                    desc = f"Key exchange degrades from {selected.dh_group.name} to weak {floor.dh_group.name}."
                else:
                    dh_gap = GapLevel.LOW
                    desc = f"Key exchange degrades from {selected.dh_group.name} to adequate {floor.dh_group.name}."

                dimension_gaps.append(FloorGapDimension(
                    dimension="dh_group",
                    selected_value=selected.dh_group.name,
                    selected_class=s_dh,
                    floor_value=floor.dh_group.name,
                    floor_class=f_dh,
                    degradation_level=dh_gap,
                    description=desc,
                ))

        # 3. PFS degradation (ESP only)
        if selected.protocol == Protocol.ESP and floor.protocol == Protocol.ESP:
            if selected.pfs is True and floor.pfs is False:
                dimension_gaps.append(FloorGapDimension(
                    dimension="pfs",
                    selected_value="Enabled (PFS)",
                    selected_class=StrengthClass.STRONG,
                    floor_value="Disabled (No PFS)",
                    floor_class=StrengthClass.WEAK,
                    degradation_level=GapLevel.MEDIUM,
                    description="PFS is active on the current SA, but fallback configuration permits child SAs without ephemeral DH.",
                ))
            elif selected.pfs is False and floor.pfs is False:
                pass  # Both off, no gap in this dimension

        # 4. Integrity degradation
        if selected.integrity and floor.integrity:
            s_int = selected.integrity.strength_class
            f_int = floor.integrity.strength_class
            if s_int.is_known() and f_int.is_known() and s_int.rank > f_int.rank:
                int_gap = GapLevel.HIGH if f_int in (StrengthClass.WEAK, StrengthClass.LEGACY) else GapLevel.LOW
                dimension_gaps.append(FloorGapDimension(
                    dimension="integrity",
                    selected_value=selected.integrity.name,
                    selected_class=s_int,
                    floor_value=floor.integrity.name,
                    floor_class=f_int,
                    degradation_level=int_gap,
                    description=f"Integrity degrades from {selected.integrity.name} to {floor.integrity.name}.",
                ))

        # Compute overall gap level
        if not dimension_gaps:
            return FloorGap(
                gap_level=GapLevel.NONE,
                has_gap=False,
                summary="Selected cryptographic suite matches the security floor. No fallback degradation exists.",
                dimension_gaps=[],
            )

        highest_rank = max(dg.degradation_level.rank for dg in dimension_gaps)
        overall_gap = GapLevel.NONE
        for gl in GapLevel:
            if gl.rank == highest_rank:
                overall_gap = gl
                break

        summary_parts = [dg.description for dg in dimension_gaps]
        summary = "Security Gap: " + " ".join(summary_parts)

        return FloorGap(
            gap_level=overall_gap,
            has_gap=True,
            summary=summary,
            dimension_gaps=dimension_gaps,
        )

    # ------------------------------------------------------------------
    # Full Result Calculation
    # ------------------------------------------------------------------

    def evaluate_floor(
        self,
        tunnel_id: str,
        protocol: Protocol,
        common_proposals: Sequence[SecurityVector],
        selected_vector: Optional[SecurityVector] = None,
        compatibility: CompatibilityStatus = CompatibilityStatus.COMPATIBLE,
        confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
    ) -> SecurityFloorResult:
        """Calculate the complete Security Floor Result for a tunnel context."""

        if compatibility in (CompatibilityStatus.INCOMPATIBLE, CompatibilityStatus.INCOMPATIBLE_IKE, CompatibilityStatus.INCOMPATIBLE_CHILD_SA):
            return SecurityFloorResult(
                tunnel_id=tunnel_id,
                protocol=protocol,
                selected=None,
                common_space=[],
                floor_frontier=[],
                display_floor=None,
                compatibility=compatibility,
                confidence=confidence,
                floor_status="NO_COMMON_PROPOSALS",
                gap=FloorGap(
                    gap_level=GapLevel.NONE,
                    has_gap=False,
                    summary="No security floor exists because endpoints have no mutually acceptable proposal space.",
                    dimension_gaps=[],
                ),
            )

        if not common_proposals:
            return SecurityFloorResult(
                tunnel_id=tunnel_id,
                protocol=protocol,
                selected=selected_vector,
                common_space=[],
                floor_frontier=[],
                display_floor=None,
                compatibility=CompatibilityStatus.INCOMPATIBLE,
                confidence=confidence,
                floor_status="NO_COMMON_PROPOSALS",
                gap=FloorGap(
                    gap_level=GapLevel.NONE,
                    has_gap=False,
                    summary="Common proposal space is empty.",
                    dimension_gaps=[],
                ),
            )

        # Check for unknown values (S12)
        has_unknown = any(
            v.encryption.strength_class == StrengthClass.UNKNOWN
            or (v.dh_group and v.dh_group.strength_class == StrengthClass.UNKNOWN)
            for v in common_proposals
        )
        if has_unknown and confidence == ConfidenceLevel.HIGH:
            confidence = ConfidenceLevel.LOW

        floor_status = "PARTIAL" if has_unknown else "COMPUTED"

        # Calculate Pareto frontier
        frontier = self.calculate_floor_frontier(common_proposals)

        # Derive representative display floor
        display_floor = self.derive_display_floor(frontier)

        # Default selected to first common proposal if not provided
        effective_selected = selected_vector or (common_proposals[0] if common_proposals else None)

        # Compute gap
        gap = self.calculate_floor_gap(effective_selected, display_floor)

        return SecurityFloorResult(
            tunnel_id=tunnel_id,
            protocol=protocol,
            selected=effective_selected,
            common_space=list(common_proposals),
            floor_frontier=frontier,
            display_floor=display_floor,
            compatibility=compatibility,
            confidence=confidence,
            floor_status=floor_status,
            gap=gap,
        )
