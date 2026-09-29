"""
STATEFLUX — Tunnel Model
=========================
A Tunnel represents a single IPsec tunnel between exactly two endpoints.
It is the primary edge in the Fleet Negotiation Graph and the primary
unit of security analysis, simulation, and migration planning.

VALIDATION:
  - endpoint_a and endpoint_b must be different entities.
    A self-tunnel (device tunneling to itself) is structurally invalid.
  - rekey_interval must be a positive number of seconds.
"""

from typing import Optional

from pydantic import model_validator, field_validator

from app.models.base import (
    StatefluxBaseModel,
    TunnelMode,
    TunnelStatus,
)


class Tunnel(StatefluxBaseModel):
    """A single IPsec tunnel between two endpoints.

    Attributes:
        tunnel_id:         Stable unique identifier (e.g., "tn-001").
        fleet_id:          The fleet this tunnel belongs to.
        endpoint_a:        Endpoint ID of the initiating/local side.
        endpoint_b:        Endpoint ID of the remote side.
        mode:              TUNNEL (default) or TRANSPORT encapsulation.
        status:            Current observed operational state.
        negotiation_id:    Reference to the Negotiation record for this tunnel.
                           May be None if no negotiation has been observed yet.
        security_state_id: Reference to the SecurityState record computed for
                           this tunnel. May be None if not yet assessed.
        rekey_interval:    How often the IPsec SA is rekeyed (seconds).
                           This is typically the child-SA / Phase-2 lifetime.
        annotations:       Scenario tags, analyst notes, or any future metadata
                           that does not yet have a dedicated field.
    """

    tunnel_id:         str
    fleet_id:          str
    endpoint_a:        str
    endpoint_b:        str
    mode:              TunnelMode   = TunnelMode.TUNNEL
    status:            TunnelStatus = TunnelStatus.UNKNOWN
    negotiation_id:    Optional[str] = None
    security_state_id: Optional[str] = None
    rekey_interval:    int

    annotations: dict[str, str] = {}
    notes:       Optional[str]  = None

    @field_validator("rekey_interval")
    @classmethod
    def rekey_must_be_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("rekey_interval must be a positive number of seconds")
        return v

    @model_validator(mode="after")
    def endpoints_must_differ(self) -> "Tunnel":
        if self.endpoint_a == self.endpoint_b:
            raise ValueError(
                f"A tunnel cannot connect an endpoint to itself: "
                f"endpoint_a and endpoint_b both reference '{self.endpoint_a}'"
            )
        return self
