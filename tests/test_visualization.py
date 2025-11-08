"""Tests for graph visualization components."""

import pytest
from pathlib import Path
import networkx as nx

from threat_radar.graph import NetworkXClient, GraphBuilder
from threat_radar.graph.models import (
    GraphNode,
    GraphEdge,
    NodeType,
    EdgeType,
    AttackPath,
    AttackStep,
    AttackStepType,
    ThreatLevel,
)

# Skip tests if plotly is not installed
pytest.importorskip("plotly")

from threat_radar.visualization import (
    NetworkGraphVisualizer,
    AttackPathVisualizer,
    NetworkTopologyVisualizer,
    GraphFilter,
    GraphExporter,
)


@pytest.fixture
def sample_graph_client():
    """Create a sample graph for testing."""
    client = NetworkXClient()

    # Add nodes
    container = GraphNode(
        node_id="container:alpine",
        node_type=NodeType.CONTAINER,
        properties={"name": "alpine:3.18", "zone": "dmz"}
    )
    package = GraphNode(
        node_id="pkg:openssl@1.1.1",
        node_type=NodeType.PACKAGE,
        properties={"name": "openssl", "version": "1.1.1"}
    )
    vuln = GraphNode(
        node_id="cve:CVE-2023-1234",
        node_type=NodeType.VULNERABILITY,
        properties={
            "cve_id": "CVE-2023-1234",
            "severity": "high",
            "cvss_score": 7.5
        }
    )

    client.add_node(container)
    client.add_node(package)
    client.add_node(vuln)

    # Add edges
    client.add_edge(GraphEdge(
        source_id="container:alpine",
        target_id="pkg:openssl@1.1.1",
        edge_type=EdgeType.CONTAINS
    ))
    client.add_edge(GraphEdge(
        source_id="pkg:openssl@1.1.1",
        target_id="cve:CVE-2023-1234",
        edge_type=EdgeType.HAS_VULNERABILITY
    ))

    return client


@pytest.fixture
def sample_attack_path():
    """Create a sample attack path for testing."""
    steps = [
        AttackStep(
            node_id="container:dmz-web",
            step_type=AttackStepType.ENTRY_POINT,
            description="Initial access via DMZ web server",
            vulnerabilities=["CVE-2023-1111"],
            cvss_score=7.5,
        ),
        AttackStep(
            node_id="pkg:openssl@1.1.1",
            step_type=AttackStepType.EXPLOIT_VULNERABILITY,
            description="Exploit OpenSSL vulnerability",
            vulnerabilities=["CVE-2023-1234"],
            cvss_score=7.5,
        ),
        AttackStep(
            node_id="container:internal-db",
            step_type=AttackStepType.TARGET_ACCESS,
            description="Access internal database",
            vulnerabilities=[],
            cvss_score=None,
        ),
    ]

    return AttackPath(
        path_id="path_1",
        entry_point="container:dmz-web",
        target="container:internal-db",
        steps=steps,
        total_cvss=15.0,
        threat_level=ThreatLevel.HIGH,
        exploitability=0.75,
        path_length=3,
    )


class TestNetworkGraphVisualizer:
    """Tests for NetworkGraphVisualizer."""

    def test_initialization(self, sample_graph_client):
        """Test visualizer initialization."""
        visualizer = NetworkGraphVisualizer(sample_graph_client)
        assert visualizer.client == sample_graph_client
        assert visualizer.graph == sample_graph_client.graph

    def test_calculate_layout(self, sample_graph_client):
        """Test layout calculation."""
        visualizer = NetworkGraphVisualizer(sample_graph_client)

        # Test different layouts
        for layout in ["spring", "kamada_kawai", "circular", "spectral", "hierarchical"]:
            pos = visualizer._calculate_layout(layout)
            assert len(pos) == 3  # 3 nodes in sample graph
            assert all(isinstance(p, tuple) and len(p) == 2 for p in pos.values())

    def test_visualize(self, sample_graph_client):
        """Test basic visualization creation."""
        visualizer = NetworkGraphVisualizer(sample_graph_client)

        fig = visualizer.visualize(
            layout="spring",
            title="Test Graph",
            width=800,
            height=600,
        )

        assert fig is not None
        assert fig.layout.title.text == "Test Graph"
        assert fig.layout.width == 800
        assert fig.layout.height == 600

    def test_get_statistics(self, sample_graph_client):
        """Test statistics gathering."""
        visualizer = NetworkGraphVisualizer(sample_graph_client)

        stats = visualizer.get_statistics()

        assert stats["total_nodes"] == 3
        assert stats["total_edges"] == 2
        assert "node_types" in stats
        assert "edge_types" in stats


class TestAttackPathVisualizer:
    """Tests for AttackPathVisualizer."""

    def test_initialization(self, sample_graph_client):
        """Test attack path visualizer initialization."""
        visualizer = AttackPathVisualizer(sample_graph_client)
        assert visualizer.client == sample_graph_client

    def test_visualize_single_path(self, sample_graph_client, sample_attack_path):
        """Test single attack path visualization."""
        # Add nodes for attack path to graph
        for step in sample_attack_path.steps:
            if step.node_id not in sample_graph_client.graph:
                sample_graph_client.add_node(GraphNode(
                    node_id=step.node_id,
                    node_type=NodeType.CONTAINER,
                    properties={"name": step.node_id}
                ))

        visualizer = AttackPathVisualizer(sample_graph_client)

        fig = visualizer.visualize_single_path(
            attack_path=sample_attack_path,
            layout="hierarchical",
        )

        assert fig is not None
        assert "Attack Path" in fig.layout.title.text

    def test_visualize_multiple_paths(self, sample_graph_client, sample_attack_path):
        """Test multiple attack paths visualization."""
        # Add nodes to graph
        for step in sample_attack_path.steps:
            if step.node_id not in sample_graph_client.graph:
                sample_graph_client.add_node(GraphNode(
                    node_id=step.node_id,
                    node_type=NodeType.CONTAINER,
                    properties={"name": step.node_id}
                ))

        visualizer = AttackPathVisualizer(sample_graph_client)

        fig = visualizer.visualize_attack_paths(
            attack_paths=[sample_attack_path],
            layout="hierarchical",
        )

        assert fig is not None


class TestNetworkTopologyVisualizer:
    """Tests for NetworkTopologyVisualizer."""

    def test_initialization(self, sample_graph_client):
        """Test topology visualizer initialization."""
        visualizer = NetworkTopologyVisualizer(sample_graph_client)
        assert visualizer.client == sample_graph_client

    def test_group_nodes_by_zone(self, sample_graph_client):
        """Test node grouping by zone."""
        visualizer = NetworkTopologyVisualizer(sample_graph_client)

        zones = visualizer._group_nodes_by_zone()

        assert "dmz" in zones
        assert "container:alpine" in zones["dmz"]

    def test_visualize_topology(self, sample_graph_client):
        """Test topology visualization."""
        visualizer = NetworkTopologyVisualizer(sample_graph_client)

        fig = visualizer.visualize_topology(
            layout="hierarchical",
            color_by="zone",
        )

        assert fig is not None

    def test_visualize_security_zones(self, sample_graph_client):
        """Test security zones visualization."""
        visualizer = NetworkTopologyVisualizer(sample_graph_client)

        fig = visualizer.visualize_security_zones()

        assert fig is not None


class TestGraphFilter:
    """Tests for GraphFilter."""

    def test_initialization(self, sample_graph_client):
        """Test filter initialization."""
        graph_filter = GraphFilter(sample_graph_client)
        assert graph_filter.client == sample_graph_client

    def test_filter_by_severity(self, sample_graph_client):
        """Test severity filtering."""
        graph_filter = GraphFilter(sample_graph_client)

        filtered = graph_filter.filter_by_severity("high")

        assert filtered is not None
        assert filtered.graph.number_of_nodes() > 0

    def test_filter_by_node_type(self, sample_graph_client):
        """Test node type filtering."""
        graph_filter = GraphFilter(sample_graph_client)

        filtered = graph_filter.filter_by_node_type(
            node_types=[NodeType.VULNERABILITY.value]
        )

        assert filtered is not None
        # Should have at least the vulnerability node
        assert filtered.graph.number_of_nodes() >= 1

    def test_get_filter_statistics(self, sample_graph_client):
        """Test filter statistics."""
        graph_filter = GraphFilter(sample_graph_client)

        stats = graph_filter.get_filter_statistics()

        assert stats["total_nodes"] == 3
        assert stats["total_edges"] == 2
        assert "node_types" in stats
        assert "severities" in stats


class TestGraphExporter:
    """Tests for GraphExporter."""

    def test_initialization(self, sample_graph_client):
        """Test exporter initialization."""
        exporter = GraphExporter(sample_graph_client)
        assert exporter.client == sample_graph_client

    def test_export_json(self, sample_graph_client, tmp_path):
        """Test JSON export."""
        exporter = GraphExporter(sample_graph_client)

        output_file = tmp_path / "graph.json"
        exporter.export_json(output_file)

        assert output_file.exists()
        assert output_file.stat().st_size > 0

    def test_export_visualization_data(self, sample_graph_client, tmp_path):
        """Test visualization data export."""
        exporter = GraphExporter(sample_graph_client)

        output_file = tmp_path / "viz_data.json"
        exporter.export_visualization_data(output_file)

        assert output_file.exists()

        import json
        with open(output_file) as f:
            data = json.load(f)

        assert "graph" in data
        assert "metadata" in data
        assert data["metadata"]["total_nodes"] == 3

    def test_export_attack_paths(self, sample_attack_path, sample_graph_client, tmp_path):
        """Test attack paths export."""
        exporter = GraphExporter(sample_graph_client)

        output_file = tmp_path / "attack_paths.json"
        exporter.export_attack_paths([sample_attack_path], output_file)

        assert output_file.exists()

        import json
        with open(output_file) as f:
            data = json.load(f)

        assert "attack_paths" in data
        assert data["total_paths"] == 1
        assert data["attack_paths"][0]["path_id"] == "path_1"


def test_visualization_integration(sample_graph_client, tmp_path):
    """Test complete visualization workflow."""
    # Create visualizer
    visualizer = NetworkGraphVisualizer(sample_graph_client)

    # Create visualization
    fig = visualizer.visualize(layout="spring")

    # Export
    exporter = GraphExporter(sample_graph_client)
    output_file = tmp_path / "test_graph.html"

    exporter.export_html(fig, output_file)

    assert output_file.exists()
    assert output_file.stat().st_size > 0
