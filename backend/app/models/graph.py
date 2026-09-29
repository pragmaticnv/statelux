"""
STATEFLUX — Fleet Negotiation Graph Model
=========================================
Phase 3 — Fleet Intelligence & Change-Impact Engine

Provides a computational graph abstraction:
  - Nodes: VPN Endpoints (gateways, clients, hubs)
  - Edges: IPsec Tunnels linking endpoints

Enables graph topological lookups, adjacency queries, and blast-radius tracing.
"""

from typing import Optional, Any
from pydantic import Field

from app.models.base import StatefluxBaseModel


class GraphNode(StatefluxBaseModel):
    """An endpoint node in the fleet negotiation graph."""
    id: str  # endpoint_id
    label: str  # endpoint name
    platform: str
    profile: str
    capabilities: dict[str, Any] = Field(default_factory=dict)
    configured_proposals: dict[str, Any] = Field(default_factory=dict)
    current_posture: str = "UNKNOWN"
    degree: int = 0


class GraphEdge(StatefluxBaseModel):
    """An IPsec tunnel edge connecting two endpoint nodes."""
    id: str  # tunnel_id
    source: str  # endpoint_a
    target: str  # endpoint_b
    selected_security: Optional[str] = None
    security_floor: Optional[str] = None
    compatibility: str = "UNKNOWN"
    rekey_interval: int = 3600
    status: str = "UP"
    current_risk: str = "INFO"
    floor_gap: str = "NONE"


class FleetNegotiationGraph(StatefluxBaseModel):
    """Machine-readable fleet negotiation graph."""
    fleet_id: str
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)

    # ------------------------------------------------------------------
    # Graph traversal & helper utilities
    # ------------------------------------------------------------------

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        for n in self.nodes:
            if n.id == node_id:
                return n
        return None

    def get_edge(self, edge_id: str) -> Optional[GraphEdge]:
        for e in self.edges:
            if e.id == edge_id:
                return e
        return None

    def neighbors(self, node_id: str) -> list[str]:
        """Return IDs of all endpoints connected to node_id."""
        res = set()
        for e in self.edges:
            if e.source == node_id:
                res.add(e.target)
            elif e.target == node_id:
                res.add(e.source)
        return sorted(list(res))

    def incident_edges(self, node_id: str) -> list[GraphEdge]:
        """Return all tunnel edges connected to node_id."""
        return [e for e in self.edges if e.source == node_id or e.target == node_id]

    def find_affected_tunnels(self, endpoint_ids: list[str]) -> list[str]:
        """Return all tunnel IDs incident to any of the specified endpoint IDs."""
        ep_set = set(endpoint_ids)
        res = []
        for e in self.edges:
            if e.source in ep_set or e.target in ep_set:
                res.append(e.id)
        return res
