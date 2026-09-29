"""
STATEFLUX — Fleet Graph Service
===============================
Phase 3 — Fleet Intelligence & Change-Impact Engine

Constructs and queries the machine-readable Fleet Negotiation Graph:
  - Nodes: VPN Endpoints (gateways, clients, hubs)
  - Edges: IPsec Tunnels linking endpoints
"""

from typing import Optional

from app.models.graph import GraphNode, GraphEdge, FleetNegotiationGraph
from app.services.data_loader import DatasetState, get_dataset
from app.services.twin_service import DigitalTwinService


class FleetGraphService:
    """Constructs and queries the Fleet Negotiation Graph."""

    def __init__(
        self,
        dataset: Optional[DatasetState] = None,
        twin_service: Optional[DigitalTwinService] = None,
    ) -> None:
        self._dataset = dataset
        self.twin_service = twin_service or DigitalTwinService(dataset=dataset)

    def _get_ds(self) -> DatasetState:
        if self._dataset is not None:
            return self._dataset
        return get_dataset()

    def build_graph(self) -> FleetNegotiationGraph:
        """Construct the complete Fleet Negotiation Graph."""
        ds = self._get_ds()
        fleet_id = ds.fleet.fleet_id if ds.fleet else "fleet-001"

        # Build tunnel twin states to get accurate posture on edges
        tunnels = list(ds.tunnels.values())
        twin_tunnels = {t.tunnel_id: self.twin_service.build_tunnel_twin(t.tunnel_id) for t in tunnels}

        # Calculate endpoint degrees
        endpoint_degrees: dict[str, int] = {ep_id: 0 for ep_id in ds.endpoints}
        for t in tunnels:
            if t.endpoint_a in endpoint_degrees:
                endpoint_degrees[t.endpoint_a] += 1
            if t.endpoint_b in endpoint_degrees:
                endpoint_degrees[t.endpoint_b] += 1

        # Build Nodes
        nodes: list[GraphNode] = []
        for ep_id, ep in ds.endpoints.items():
            # Derive posture of endpoint from its connected tunnels
            connected_twins = [tt for tt in twin_tunnels.values() if tt.endpoint_a == ep_id or tt.endpoint_b == ep_id]
            if any(tt.risk_level in ("HIGH", "CRITICAL") for tt in connected_twins):
                ep_posture = "HIGH_RISK"
            elif any(tt.composite_gap.gap_level.value in ("HIGH", "CRITICAL") for tt in connected_twins):
                ep_posture = "FLOOR_EXPOSURE"
            elif all(tt.cryptographic_posture == "STRONG" for tt in connected_twins) and connected_twins:
                ep_posture = "STRONG"
            else:
                ep_posture = "ADEQUATE" if connected_twins else "ISOLATED"

            nodes.append(GraphNode(
                id=ep.endpoint_id,
                label=ep.name,
                platform=f"{ep.platform} {ep.platform_version or ''}".strip(),
                profile=ep.profile_type.value,
                capabilities={
                    "pfs_supported": ep.capabilities.pfs_supported,
                    "ike_versions": [v.value for v in ep.capabilities.ike_versions],
                    "encryption_count": len(ep.capabilities.encryption_algorithms),
                    "dh_groups": ep.capabilities.dh_groups,
                },
                configured_proposals={
                    "ike_proposals": ep.configuration.ike_proposals,
                    "esp_proposals": ep.configuration.esp_proposals,
                },
                current_posture=ep_posture,
                degree=endpoint_degrees.get(ep_id, 0),
            ))

        # Build Edges
        edges: list[GraphEdge] = []
        for t in tunnels:
            tt = twin_tunnels.get(t.tunnel_id)
            selected_sec = None
            floor_sec = None
            gap_lvl = "NONE"
            compat = "UNKNOWN"
            risk = "INFO"

            if tt:
                gap_lvl = tt.composite_gap.gap_level.value
                compat = tt.compatibility.value
                risk = tt.risk_level
                if tt.ike_floor and tt.ike_floor.selected:
                    selected_sec = f"{tt.ike_floor.selected.encryption.name}/{tt.ike_floor.selected.dh_group.name if tt.ike_floor.selected.dh_group else ''}"
                if tt.ike_floor and tt.ike_floor.display_floor:
                    floor_sec = f"{tt.ike_floor.display_floor.encryption.name}/{tt.ike_floor.display_floor.dh_group.name if tt.ike_floor.display_floor.dh_group else ''}"

            edges.append(GraphEdge(
                id=t.tunnel_id,
                source=t.endpoint_a,
                target=t.endpoint_b,
                selected_security=selected_sec,
                security_floor=floor_sec,
                compatibility=compat,
                rekey_interval=t.rekey_interval,
                status=t.status.value,
                current_risk=risk,
                floor_gap=gap_lvl,
            ))

        return FleetNegotiationGraph(
            fleet_id=fleet_id,
            nodes=nodes,
            edges=edges,
        )
