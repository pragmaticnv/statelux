"""
STATEFLUX — Negotiation Model
==============================
A Negotiation records the IKE proposal exchange for a specific tunnel.
It captures what each endpoint offered, what both could agree on,
and what was ultimately selected.

This is the computational core for Phase 4's change-impact simulation:
the simulation engine will re-run the proposal intersection logic
under a modified policy to determine the simulated outcome.

VALIDATION RULES (invariants that must always hold):
  1. A SUCCESSFUL negotiation MUST have a selected_proposal.
     It is invalid to claim success without a chosen suite.

  2. A FAILED negotiation MUST NOT have a selected_proposal.
     If negotiation failed, no suite was agreed upon.

  3. A SUCCESSFUL negotiation's selected_proposal MUST appear in
     common_proposals (it must have been a mutually acceptable suite).

  4. common_proposals must be a subset of offers_from_a ∪ offers_from_b.
     You cannot have a "common" proposal that neither side offered.
"""

from typing import Optional

from pydantic import model_validator

from app.models.base import (
    StatefluxBaseModel,
    IKEVersion,
    NegotiationStatus,
)


class Negotiation(StatefluxBaseModel):
    """The complete record of an IKE proposal exchange.

    Attributes:
        negotiation_id:    Unique identifier (e.g., "neg-001").
        tunnel_id:         The tunnel this negotiation belongs to.
        ike_version:       Which IKE version was used in this negotiation.
        offers_from_a:     Ordered list of Proposal IDs offered by endpoint A.
                           Order reflects A's priority preference.
        offers_from_b:     Ordered list of Proposal IDs offered by endpoint B.
                           Order reflects B's priority preference.
        common_proposals:  Proposal IDs from A's offers that are algorithmically
                           compatible with at least one of B's offers.
                           Ordered by A's preference (highest priority first).
        selected_proposal: The Proposal ID of the suite that was actually chosen.
                           - Must be set if status=SUCCESS.
                           - Must be None if status=FAILED.
                           References a proposal from endpoint A's offer list
                           (in IKEv2, the responder selects from the initiator's
                           proposals and echoes back the chosen one).
        selection_rule:    Human-readable description of how the proposal was
                           selected (e.g., "HIGHEST_PRIORITY_COMMON",
                           "FAILED_NO_COMMON_PROPOSALS",
                           "FAILED_PFS_MISMATCH").
        status:            The outcome of the negotiation attempt.
        failure_reason:    Free-text explanation when status=FAILED.
    """

    negotiation_id:   str
    tunnel_id:        str
    ike_version:      IKEVersion
    offers_from_a:    list[str]
    offers_from_b:    list[str]
    common_proposals: list[str]
    selected_proposal: Optional[str]    = None
    selection_rule:    str
    status:            NegotiationStatus
    failure_reason:    Optional[str]    = None

    @model_validator(mode="after")
    def validate_negotiation_consistency(self) -> "Negotiation":
        # Rule 1: SUCCESS requires a selected proposal
        if self.status == NegotiationStatus.SUCCESS:
            if self.selected_proposal is None:
                raise ValueError(
                    "A SUCCESSFUL negotiation must have selected_proposal set"
                )

        # Rule 2: FAILED must not have a selected proposal
        if self.status == NegotiationStatus.FAILED:
            if self.selected_proposal is not None:
                raise ValueError(
                    "A FAILED negotiation must not have selected_proposal set. "
                    f"Got: '{self.selected_proposal}'"
                )

        # Rule 3: selected_proposal must appear in common_proposals
        if (
            self.status == NegotiationStatus.SUCCESS
            and self.selected_proposal is not None
            and self.common_proposals
        ):
            if self.selected_proposal not in self.common_proposals:
                raise ValueError(
                    f"selected_proposal '{self.selected_proposal}' is not in "
                    f"common_proposals {self.common_proposals}"
                )

        # Rule 4: common_proposals must be a subset of A's offers
        # (they are A's proposals that B accepted — they come from A's list)
        for prop_id in self.common_proposals:
            if prop_id not in self.offers_from_a:
                raise ValueError(
                    f"common_proposal '{prop_id}' is not present in "
                    f"offers_from_a. Common proposals must reference proposals "
                    f"from the initiator (endpoint A) offer list."
                )

        return self
