"""Tests for graph database integration."""

import pytest
from pathlib import Path
import tempfile
import json

from threat_radar.graph import (
    NetworkXClient,
    GraphBuilder,
    GraphAnalyzer,
    GraphNode,
    GraphEdge,
    NodeType,
    EdgeType,
)
from threat_radar.core.grype_integration import GrypeScanResult, GrypeVulnerability
from threat_radar.core.container_analyzer import ContainerAnalysis
from threat_radar.core.package_extractors import Package
from threat_radar.utils.graph_storage import GraphStorageManager


@pytest.fixture
def graph_client():
    """Create a fresh NetworkX graph client."""
    return NetworkXClient()


@pytest.fixture
def sample_vulnerabilities():
    """Create sample vulnerabilities for testing."""
    return [
        GrypeVulnerability(
            id="CVE-2023-0001",
            severity="critical",
            package_name="openssl",
            package_version="1.1.1",
            package_type="apk",
            fixed_in_version="1.1.1k",
            description="Critical vulnerability in OpenSSL",
            cvss_score=9.8,
            urls=["https://nvd.nist.gov/vuln/detail/CVE-2023-0001"],
        ),
        GrypeVulnerability(
            id="CVE-2023-0002",
            severity="high",
            package_name="curl",
            package_version="7.79.0",
            package_type="apk",
            fixed_in_version="7.79.1",
            description="High severity vulnerability in curl",
            cvss_score=7.5,
        ),
        GrypeVulnerability(
            id="CVE-2023-0003",
            severity="medium",
            package_name="openssl",
            package_version="1.1.1",
            package_type="apk",
            fixed_in_version="1.1.1k",
            description="Medium severity vulnerability in OpenSSL",
            cvss_score=5.3,
        ),
    ]


@pytest.fixture
def sample_scan_result(sample_vulnerabilities):
    """Create a sample scan result."""
    return GrypeScanResult(
        target="alpine:3.18",
        vulnerabilities=sample_vulnerabilities,
    )


@pytest.fixture
def sample_container():
    """Create a sample container analysis."""
    return ContainerAnalysis(
        image_name="alpine:3.18",
        image_id="sha256:abc123",
        distro="alpine",
        distro_version="3.18",
        architecture="amd64",
        os="linux",
        packages=[
            Package(name="openssl", version="1.1.1", architecture="x86_64"),
            Package(name="curl", version="7.79.0", architecture="x86_64"),
            Package(name="busybox", version="1.35.0", architecture="x86_64"),
        ],
    )


class TestGraphNode:
    """Test GraphNode data model."""

    def test_create_node(self):
        """Test creating a graph node."""
        node = GraphNode(
            node_id="test:node",
            node_type=NodeType.CONTAINER,
            properties={"name": "test-container", "version": "1.0"}
        )

        assert node.node_id == "test:node"
        assert node.node_type == NodeType.CONTAINER
        assert node.properties["name"] == "test-container"

    def test_node_type_conversion(self):
        """Test automatic string to enum conversion."""
        node = GraphNode(
            node_id="test:node",
            node_type="package",  # String, should convert to enum
            properties={}
        )

        assert node.node_type == NodeType.PACKAGE


class TestGraphEdge:
    """Test GraphEdge data model."""

    def test_create_edge(self):
        """Test creating a graph edge."""
        edge = GraphEdge(
            source_id="container:1",
            target_id="package:2",
            edge_type=EdgeType.CONTAINS,
            properties={"weight": 1.0}
        )

        assert edge.source_id == "container:1"
        assert edge.target_id == "package:2"
        assert edge.edge_type == EdgeType.CONTAINS
        assert edge.properties["weight"] == 1.0

    def test_edge_type_conversion(self):
        """Test automatic string to enum conversion."""
        edge = GraphEdge(
            source_id="a",
            target_id="b",
            edge_type="DEPENDS_ON",  # String, should convert to enum
        )

        assert edge.edge_type == EdgeType.DEPENDS_ON


class TestNetworkXClient:
    """Test NetworkX graph client."""

    def test_add_node(self, graph_client):
        """Test adding nodes to graph."""
        node = GraphNode(
            node_id="container:test",
            node_type=NodeType.CONTAINER,
            properties={"name": "test"}
        )

        graph_client.add_node(node)

        assert "container:test" in graph_client.graph
        assert graph_client.graph.nodes["container:test"]["name"] == "test"

    def test_add_edge(self, graph_client):
        """Test adding edges to graph."""
        # Add nodes first
        node1 = GraphNode("container:1", NodeType.CONTAINER, {})
        node2 = GraphNode("package:2", NodeType.PACKAGE, {})
        graph_client.add_node(node1)
        graph_client.add_node(node2)

        # Add edge
        edge = GraphEdge("container:1", "package:2", EdgeType.CONTAINS)
        graph_client.add_edge(edge)

        assert graph_client.graph.has_edge("container:1", "package:2")
        edge_data = graph_client.graph.get_edge_data("container:1", "package:2")
        assert edge_data["edge_type"] == EdgeType.CONTAINS.value

    def test_get_node(self, graph_client):
        """Test retrieving a node."""
        original_node = GraphNode(
            node_id="test:1",
            node_type=NodeType.PACKAGE,
            properties={"version": "1.0"}
        )
        graph_client.add_node(original_node)

        retrieved_node = graph_client.get_node("test:1")

        assert retrieved_node is not None
        assert retrieved_node.node_id == "test:1"
        assert retrieved_node.node_type == NodeType.PACKAGE
        assert retrieved_node.properties["version"] == "1.0"

    def test_get_neighbors(self, graph_client):
        """Test getting neighboring nodes."""
        # Build a small graph
        container = GraphNode("container:1", NodeType.CONTAINER, {})
        pkg1 = GraphNode("package:1", NodeType.PACKAGE, {})
        pkg2 = GraphNode("package:2", NodeType.PACKAGE, {})

        graph_client.add_node(container)
        graph_client.add_node(pkg1)
        graph_client.add_node(pkg2)

        graph_client.add_edge(GraphEdge("container:1", "package:1", EdgeType.CONTAINS))
        graph_client.add_edge(GraphEdge("container:1", "package:2", EdgeType.CONTAINS))

        neighbors = graph_client.get_neighbors("container:1")

        assert len(neighbors) == 2
        assert "package:1" in neighbors
        assert "package:2" in neighbors

    def test_find_nodes_by_type(self, graph_client):
        """Test finding nodes by type."""
        graph_client.add_node(GraphNode("container:1", NodeType.CONTAINER, {}))
        graph_client.add_node(GraphNode("container:2", NodeType.CONTAINER, {}))
        graph_client.add_node(GraphNode("package:1", NodeType.PACKAGE, {}))

        containers = graph_client.find_nodes_by_type(NodeType.CONTAINER)

        assert len(containers) == 2
        assert "container:1" in containers
        assert "container:2" in containers

    def test_get_metadata(self, graph_client):
        """Test graph metadata retrieval."""
        graph_client.add_node(GraphNode("container:1", NodeType.CONTAINER, {}))
        graph_client.add_node(GraphNode("package:1", NodeType.PACKAGE, {}))
        graph_client.add_edge(GraphEdge("container:1", "package:1", EdgeType.CONTAINS))

        metadata = graph_client.get_metadata()

        assert metadata.node_count == 2
        assert metadata.edge_count == 1
        assert metadata.node_type_counts["container"] == 1
        assert metadata.node_type_counts["package"] == 1

    def test_save_and_load(self, graph_client):
        """Test saving and loading graphs."""
        # Build graph
        graph_client.add_node(GraphNode("test:1", NodeType.CONTAINER, {"name": "test"}))
        graph_client.add_node(GraphNode("test:2", NodeType.PACKAGE, {"version": "1.0"}))
        graph_client.add_edge(GraphEdge("test:1", "test:2", EdgeType.CONTAINS))

        # Save to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".graphml", delete=False) as f:
            temp_path = f.name

        try:
            graph_client.save(temp_path)

            # Load in new client
            new_client = NetworkXClient()
            new_client.load(temp_path)

            # Verify loaded correctly
            assert new_client.graph.number_of_nodes() == 2
            assert new_client.graph.number_of_edges() == 1
            assert "test:1" in new_client.graph
            assert "test:2" in new_client.graph

        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestGraphBuilder:
    """Test graph builder."""

    def test_build_from_scan(self, graph_client, sample_scan_result, sample_container):
        """Test building graph from scan results."""
        builder = GraphBuilder(graph_client)
        builder.build_from_scan(sample_scan_result, sample_container)

        metadata = graph_client.get_metadata()

        # Should have container, packages, vulnerabilities, scan result nodes
        assert metadata.node_count > 0
        assert metadata.edge_count > 0

        # Check specific nodes exist
        container_nodes = graph_client.find_nodes_by_type(NodeType.CONTAINER)
        assert len(container_nodes) == 1

        vuln_nodes = graph_client.find_nodes_by_type(NodeType.VULNERABILITY)
        assert len(vuln_nodes) == 3  # CVE-2023-0001, 0002, 0003

    def test_build_scan_only(self, graph_client, sample_scan_result):
        """Test building graph from scan without container analysis."""
        builder = GraphBuilder(graph_client)
        builder.build_from_scan(sample_scan_result)

        metadata = graph_client.get_metadata()

        # Should still have vulnerabilities and packages
        assert metadata.node_count > 0
        vuln_nodes = graph_client.find_nodes_by_type(NodeType.VULNERABILITY)
        assert len(vuln_nodes) == 3

    def test_vulnerability_edges(self, graph_client, sample_scan_result):
        """Test that HAS_VULNERABILITY edges are created correctly."""
        builder = GraphBuilder(graph_client)
        builder.build_from_scan(sample_scan_result)

        # Check openssl package has vulnerability edges
        openssl_neighbors = graph_client.get_neighbors(
            "package:openssl@1.1.1",
            edge_type=EdgeType.HAS_VULNERABILITY
        )

        assert len(openssl_neighbors) >= 2  # CVE-2023-0001 and CVE-2023-0003

    def test_fixed_by_edges(self, graph_client, sample_scan_result):
        """Test that FIXED_BY edges are created for vulnerabilities with fixes."""
        builder = GraphBuilder(graph_client)
        builder.build_from_scan(sample_scan_result)

        # Check CVE-2023-0001 has FIXED_BY edge
        cve_neighbors = graph_client.get_neighbors(
            "cve:CVE-2023-0001",
            edge_type=EdgeType.FIXED_BY
        )

        assert len(cve_neighbors) > 0
        assert "package:openssl@1.1.1k" in cve_neighbors


class TestGraphAnalyzer:
    """Test graph analyzer."""

    def test_blast_radius(self, graph_client, sample_scan_result, sample_container):
        """Test calculating vulnerability blast radius."""
        builder = GraphBuilder(graph_client)
        builder.build_from_scan(sample_scan_result, sample_container)

        analyzer = GraphAnalyzer(graph_client)
        blast_radius = analyzer.blast_radius("CVE-2023-0001")

        # Should find affected packages and containers
        assert len(blast_radius["packages"]) > 0
        assert len(blast_radius["containers"]) > 0

    def test_most_vulnerable_packages(self, graph_client, sample_scan_result):
        """Test finding most vulnerable packages."""
        builder = GraphBuilder(graph_client)
        builder.build_from_scan(sample_scan_result)

        analyzer = GraphAnalyzer(graph_client)
        vulnerable_pkgs = analyzer.most_vulnerable_packages(top_n=5)

        # Should find vulnerable packages
        assert len(vulnerable_pkgs) > 0

        # Verify results have correct structure
        for pkg_id, vuln_count, avg_cvss in vulnerable_pkgs:
            assert isinstance(pkg_id, str)
            assert isinstance(vuln_count, int)
            assert vuln_count > 0
            assert isinstance(avg_cvss, float)
            assert avg_cvss >= 0.0

    def test_vulnerability_statistics(self, graph_client, sample_scan_result):
        """Test vulnerability statistics calculation."""
        builder = GraphBuilder(graph_client)
        builder.build_from_scan(sample_scan_result)

        analyzer = GraphAnalyzer(graph_client)
        stats = analyzer.vulnerability_statistics()

        assert stats["total_vulnerabilities"] == 3
        assert stats["by_severity"]["critical"] == 1
        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["medium"] == 1
        assert stats["with_fixes"] == 3  # All have fixes

    def test_find_fix_candidates(self, graph_client, sample_scan_result):
        """Test finding vulnerabilities with fixes."""
        builder = GraphBuilder(graph_client)
        builder.build_from_scan(sample_scan_result)

        analyzer = GraphAnalyzer(graph_client)
        fix_candidates = analyzer.find_fix_candidates()

        assert len(fix_candidates) == 3  # All 3 CVEs have fixes

        # Test severity filtering
        critical_fixes = analyzer.find_fix_candidates(severity="critical")
        assert len(critical_fixes) == 1
        assert critical_fixes[0]["cve_id"] == "CVE-2023-0001"


class TestGraphStorage:
    """Test graph storage manager."""

    def test_save_graph(self, graph_client):
        """Test saving graph to storage."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = GraphStorageManager(storage_dir=tmpdir)

            # Add some data
            graph_client.add_node(GraphNode("test:1", NodeType.CONTAINER, {}))

            # Save
            saved_path = storage.save_graph(graph_client, "test-graph")

            assert saved_path.exists()
            assert saved_path.suffix == ".graphml"
            assert "test-graph" in saved_path.name

    def test_load_graph(self, graph_client):
        """Test loading graph from storage."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = GraphStorageManager(storage_dir=tmpdir)

            # Save graph
            graph_client.add_node(GraphNode("test:1", NodeType.CONTAINER, {"name": "test"}))
            saved_path = storage.save_graph(graph_client, "test-graph")

            # Load graph
            loaded_client = storage.load_graph(str(saved_path))

            assert loaded_client.graph.number_of_nodes() == 1
            assert "test:1" in loaded_client.graph

    def test_list_graphs(self, graph_client):
        """Test listing stored graphs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = GraphStorageManager(storage_dir=tmpdir)

            # Save multiple graphs
            storage.save_graph(graph_client, "graph1")
            storage.save_graph(graph_client, "graph2")
            storage.save_graph(graph_client, "graph3")

            # List
            graphs = storage.list_graphs()

            assert len(graphs) == 3

    def test_get_storage_stats(self):
        """Test storage statistics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = GraphStorageManager(storage_dir=tmpdir)
            stats = storage.get_storage_stats()

            assert stats["total_graphs"] == 0
            assert stats["total_size_bytes"] == 0
            assert "storage_dir" in stats


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
