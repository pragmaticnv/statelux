"""
STATEFLUX — Fleet Model
=======================
A Fleet is the top-level organizational container for a set of IPsec
endpoints and tunnels belonging to a single managed security domain.

In Phase 1, a Fleet is loaded from a seed JSON file.
In future phases, multiple Fleets may exist (e.g., different security zones
or organizational units), each with independent analysis and simulation runs.
"""

from datetime import datetime
from typing import Optional

from app.models.base import StatefluxBaseModel


class Fleet(StatefluxBaseModel):
    """Top-level container for an IPsec VPN environment.

    Attributes:
        fleet_id:     Stable unique identifier (e.g., "fleet-001").
        name:         Human-readable name for the fleet.
        description:  Free-text description of the fleet's purpose/scope.
        environment:  Deployment context (e.g., "GOVERNMENT_WAN", "ENTERPRISE_DC").
        created_at:   ISO 8601 timestamp of when this fleet record was created.
        endpoint_ids: Ordered list of endpoint IDs belonging to this fleet.
        tunnel_ids:   Ordered list of tunnel IDs belonging to this fleet.
    """

    fleet_id:     str
    name:         str
    description:  str
    environment:  str
    created_at:   datetime
    endpoint_ids: list[str]
    tunnel_ids:   list[str]

    # Optional analyst notes — free text, not evaluated by the engine
    notes: Optional[str] = None
