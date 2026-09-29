"""
STATEFLUX — Phase 3 Fleet Negotiation Graph Tests
==================================================
Tests the Fleet Negotiation Graph model, service, and API endpoint:
  - Graph construction and node/edge mapping
  - Endpoint degree calculations
  - Graph traversal helpers (neighbors, incident_edges, find_affected_tunnels)
  - GET /api/v1/graph/fleet API endpoint
"""

import pytest

from app.models.graph import FleetNegotiationGraph, GraphNode, GraphEdge
from app.services.graph_service import FleetGraphService


def test_fleet_graph_service(dataset):
    """Test FleetGraphService builds a valid graph with nodes and edges."""
    service = FleetGraphService(dataset=dataset)
    graph = service.build_graph()

    assert isinstance(graph, FleetNegotiationGraph)
    assert len(graph.nodes) == len(dataset.endpoints)
    assert len(graph.edges) == len(dataset.tunnels)

    # Check node properties
    for node in graph.nodes:
        assert node.id in dataset.endpoints
        assert node.label is not None
        assert node.platform is not None
        assert node.profile is not None
        assert "pfs_supported" in node.capabilities
        assert "ike_proposals" in node.configured_proposals
        assert node.degree >= 0

    # Check edge properties
    for edge in graph.edges:
        assert edge.id in dataset.tunnels
        assert edge.source in dataset.endpoints
        assert edge.target in dataset.endpoints
        assert edge.rekey_interval > 0
        assert edge.status in ("UP", "DOWN", "DEGRADED", "ESTABLISHING", "UNKNOWN")


def test_graph_traversal_methods():
    """Test FleetNegotiationGraph traversal helpers."""
    nodes = [
        GraphNode(id="ep-1", label="EP 1", platform="Linux", profile="HUB"),
        GraphNode(id="ep-2", label="EP 2", platform="Cisco", profile="BRANCH"),
        GraphNode(id="ep-3", label="EP 3", platform="Fortinet", profile="BRANCH"),
    ]
    edges = [
        GraphEdge(id="tn-1", source="ep-1", target="ep-2"),
        GraphEdge(id="tn-2", source="ep-1", target="ep-3"),
    ]
    graph = FleetNegotiationGraph(fleet_id="test-fleet", nodes=nodes, edges=edges)

    assert graph.get_node("ep-1") is not None
    assert graph.get_node("ep-999") is None

    assert graph.get_edge("tn-1") is not None
    assert graph.get_edge("tn-999") is None

    # Neighbors
    neighbors = graph.neighbors("ep-1")
    assert neighbors == ["ep-2", "ep-3"]
    assert graph.neighbors("ep-2") == ["ep-1"]

    # Incident edges
    incident = graph.incident_edges("ep-1")
    assert len(incident) == 2
    assert [e.id for e in incident] == ["tn-1", "tn-2"]

    # Find affected tunnels
    affected = graph.find_affected_tunnels(["ep-2"])
    assert affected == ["tn-1"]

    affected_multi = graph.find_affected_tunnels(["ep-1"])
    assert len(affected_multi) == 2


def test_graph_api_endpoint(client):
    """Test GET /api/v1/graph/fleet API."""
    res = client.get("/api/v1/graph/fleet")
    assert res.status_code == 200
    data = res.json()
    assert "fleet_id" in data
    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) > 0
    assert len(data["edges"]) > 0

    sample_node = data["nodes"][0]
    assert "id" in sample_node
    assert "platform" in sample_node
    assert "degree" in sample_node

    sample_edge = data["edges"][0]
    assert "id" in sample_edge
    assert "source" in sample_edge
    assert "target" in sample_edge
    assert "rekey_interval" in sample_edge
