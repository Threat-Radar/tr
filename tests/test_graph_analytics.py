"""Comprehensive tests for graph analytics engine."""

import pytest
from unittest.mock import Mock, patch, MagicMock
import networkx as nx

from threat_radar.graph import NetworkXClient, GraphNode, GraphEdge, NodeType, EdgeType
from threat_radar.graph.analytics import GraphAnalytics
from threat_radar.graph.analytics_models import (
    CentralityMetric,
    CentralityResult,
    CommunityAlgorithm,
    PropagationReport,
    GraphMetrics,
)


@pytest.fixture
def simple_graph_client():
    """Create a simple graph client for testing."""
    client = NetworkXClient()

    # Create a simple graph: Container -> Package -> Vulnerability
    client.add_node(GraphNode("container:1", NodeType.CONTAINER, {"name": "alpine"}))
    client.add_node(GraphNode("package:1", NodeType.PACKAGE, {"name": "openssl"}))
    client.add_node(GraphNode("package:2", NodeType.PACKAGE, {"name": "curl"}))
    client.add_node(
        GraphNode("cve:1", NodeType.VULNERABILITY, {"severity": "critical"})
    )
    client.add_node(GraphNode("cve:2", NodeType.VULNERABILITY, {"severity": "high"}))

    # Add edges
    client.add_edge(GraphEdge("container:1", "package:1", EdgeType.CONTAINS))
    client.add_edge(GraphEdge("container:1", "package:2", EdgeType.CONTAINS))
    client.add_edge(GraphEdge("package:1", "cve:1", EdgeType.HAS_VULNERABILITY))
    client.add_edge(GraphEdge("package:2", "cve:2", EdgeType.HAS_VULNERABILITY))

    return client


@pytest.fixture
def complex_graph_client():
    """Create a more complex graph for advanced testing."""
    client = NetworkXClient()

    # Create multiple containers
    for i in range(3):
        client.add_node(
            GraphNode(f"container:{i}", NodeType.CONTAINER, {"name": f"container-{i}"})
        )

    # Create packages
    for i in range(5):
        client.add_node(
            GraphNode(f"package:{i}", NodeType.PACKAGE, {"name": f"package-{i}"})
        )

    # Create vulnerabilities
    for i in range(4):
        severity = ["critical", "high", "medium", "low"][i % 4]
        client.add_node(
            GraphNode(f"cve:{i}", NodeType.VULNERABILITY, {"severity": severity})
        )

    # Add edges to create a network
    # Container 0 -> Package 0, 1
    client.add_edge(GraphEdge("container:0", "package:0", EdgeType.CONTAINS))
    client.add_edge(GraphEdge("container:0", "package:1", EdgeType.CONTAINS))

    # Container 1 -> Package 2, 3
    client.add_edge(GraphEdge("container:1", "package:2", EdgeType.CONTAINS))
    client.add_edge(GraphEdge("container:1", "package:3", EdgeType.CONTAINS))

    # Container 2 -> Package 4
    client.add_edge(GraphEdge("container:2", "package:4", EdgeType.CONTAINS))

    # Packages -> CVEs
    client.add_edge(GraphEdge("package:0", "cve:0", EdgeType.HAS_VULNERABILITY))
    client.add_edge(GraphEdge("package:1", "cve:0", EdgeType.HAS_VULNERABILITY))
    client.add_edge(GraphEdge("package:2", "cve:1", EdgeType.HAS_VULNERABILITY))
    client.add_edge(GraphEdge("package:3", "cve:2", EdgeType.HAS_VULNERABILITY))
    client.add_edge(GraphEdge("package:4", "cve:3", EdgeType.HAS_VULNERABILITY))

    return client


class TestGraphAnalyticsInitialization:
    """Test GraphAnalytics initialization."""

    def test_init_success(self, simple_graph_client):
        """Test successful initialization."""
        analytics = GraphAnalytics(simple_graph_client)

        assert analytics.client == simple_graph_client
        assert analytics.graph == simple_graph_client.graph

    def test_init_invalid_client(self):
        """Test initialization with invalid client type."""
        mock_client = Mock()

        with pytest.raises(ValueError, match="only supports NetworkXClient"):
            GraphAnalytics(mock_client)


class TestCentralityAnalysis:
    """Test centrality analysis methods."""

    def test_calculate_degree_centrality(self, simple_graph_client):
        """Test degree centrality calculation."""
        analytics = GraphAnalytics(simple_graph_client)

        result = analytics.calculate_centrality(CentralityMetric.DEGREE)

        assert isinstance(result, CentralityResult)
        assert result.metric == CentralityMetric.DEGREE
        assert len(result.nodes) == 5  # All nodes
        assert result.total_nodes == 5

        # Container should have high degree (connects to 2 packages)
        container_node = next(n for n in result.nodes if n.node_id == "container:1")
        assert container_node.score > 0

    def test_calculate_betweenness_centrality(self, simple_graph_client):
        """Test betweenness centrality calculation."""
        analytics = GraphAnalytics(simple_graph_client)

        result = analytics.calculate_centrality(CentralityMetric.BETWEENNESS)

        assert result.metric == CentralityMetric.BETWEENNESS
        assert len(result.nodes) == 5

    def test_calculate_closeness_centrality(self, simple_graph_client):
        """Test closeness centrality calculation."""
        analytics = GraphAnalytics(simple_graph_client)

        result = analytics.calculate_centrality(CentralityMetric.CLOSENESS)

        assert result.metric == CentralityMetric.CLOSENESS
        assert len(result.nodes) == 5

    def test_calculate_pagerank(self, simple_graph_client):
        """Test PageRank calculation."""
        analytics = GraphAnalytics(simple_graph_client)

        result = analytics.calculate_centrality(CentralityMetric.PAGERANK)

        assert result.metric == CentralityMetric.PAGERANK
        assert len(result.nodes) == 5
        # PageRank scores should sum to approximately 1
        total_score = sum(n.score for n in result.nodes)
        assert 0.9 < total_score < 1.1

    def test_calculate_eigenvector_centrality(self, simple_graph_client):
        """Test eigenvector centrality calculation."""
        analytics = GraphAnalytics(simple_graph_client)

        result = analytics.calculate_centrality(CentralityMetric.EIGENVECTOR)

        assert result.metric == CentralityMetric.EIGENVECTOR
        assert len(result.nodes) == 5

    def test_centrality_with_top_n(self, complex_graph_client):
        """Test centrality with top_n limit."""
        analytics = GraphAnalytics(complex_graph_client)

        result = analytics.calculate_centrality(CentralityMetric.DEGREE, top_n=3)

        assert len(result.nodes) == 3
        assert result.total_nodes > 3

        # Results should be sorted by score
        scores = [n.score for n in result.nodes]
        assert scores == sorted(scores, reverse=True)

    def test_centrality_with_node_type_filter(self, complex_graph_client):
        """Test centrality with node type filter."""
        analytics = GraphAnalytics(complex_graph_client)

        result = analytics.calculate_centrality(
            CentralityMetric.DEGREE, node_type_filter="package"
        )

        # Should only include package nodes
        for node in result.nodes:
            assert node.node_type == "package"

    def test_centrality_ranks_assigned(self, simple_graph_client):
        """Test that ranks are properly assigned."""
        analytics = GraphAnalytics(simple_graph_client)

        result = analytics.calculate_centrality(CentralityMetric.DEGREE)

        # Ranks should be sequential starting from 1
        ranks = [n.rank for n in result.nodes]
        assert ranks == list(range(1, len(result.nodes) + 1))

    def test_centrality_statistics(self, simple_graph_client):
        """Test that centrality statistics are calculated correctly."""
        analytics = GraphAnalytics(simple_graph_client)

        result = analytics.calculate_centrality(CentralityMetric.DEGREE)

        scores = [n.score for n in result.nodes]

        assert result.avg_score == sum(scores) / len(scores)
        assert result.max_score == max(scores)
        assert result.min_score == min(scores)

    def test_centrality_unsupported_metric(self, simple_graph_client):
        """Test that unsupported metric raises error."""
        analytics = GraphAnalytics(simple_graph_client)

        # Create a mock unsupported metric
        invalid_metric = "invalid_metric"

        with pytest.raises(Exception):
            # This should fail because invalid_metric is not a valid CentralityMetric
            analytics.calculate_centrality(invalid_metric)


class TestCommunityDetection:
    """Test community detection methods."""

    def test_detect_communities_greedy_modularity(self, complex_graph_client):
        """Test community detection with greedy modularity."""
        analytics = GraphAnalytics(complex_graph_client)

        result = analytics.detect_communities(CommunityAlgorithm.GREEDY_MODULARITY)

        assert result.algorithm == CommunityAlgorithm.GREEDY_MODULARITY
        assert len(result.communities) > 0
        assert result.total_communities > 0
        assert result.modularity is not None

    def test_detect_communities_label_propagation(self, complex_graph_client):
        """Test community detection with label propagation."""
        analytics = GraphAnalytics(complex_graph_client)

        result = analytics.detect_communities(CommunityAlgorithm.LABEL_PROPAGATION)

        assert result.algorithm == CommunityAlgorithm.LABEL_PROPAGATION
        assert len(result.communities) > 0

    def test_detect_communities_louvain(self, complex_graph_client):
        """Test community detection with Louvain method."""
        analytics = GraphAnalytics(complex_graph_client)

        result = analytics.detect_communities(CommunityAlgorithm.LOUVAIN)

        assert result.algorithm == CommunityAlgorithm.LOUVAIN
        assert len(result.communities) > 0

    def test_community_node_assignment(self, complex_graph_client):
        """Test that all nodes are assigned to communities."""
        analytics = GraphAnalytics(complex_graph_client)

        result = analytics.detect_communities(CommunityAlgorithm.GREEDY_MODULARITY)

        # Count total nodes in communities
        total_nodes_in_communities = sum(c.size for c in result.communities)

        # Should match total nodes in graph
        assert (
            total_nodes_in_communities == complex_graph_client.graph.number_of_nodes()
        )

    def test_community_sizes(self, complex_graph_client):
        """Test that community sizes are correct."""
        analytics = GraphAnalytics(complex_graph_client)

        result = analytics.detect_communities(CommunityAlgorithm.GREEDY_MODULARITY)

        for community in result.communities:
            assert community.size == len(community.nodes)
            assert community.size > 0


class TestPropagationModeling:
    """Test vulnerability propagation modeling."""

    def test_simulate_propagation(self, complex_graph_client):
        """Test simulating vulnerability propagation."""
        analytics = GraphAnalytics(complex_graph_client)

        # Start from a vulnerability node
        result = analytics.simulate_propagation(start_node="cve:0", max_steps=5)

        assert isinstance(result, PropagationReport)
        assert result.start_node == "cve:0"
        assert len(result.steps) > 0
        assert len(result.affected_nodes) > 0

    def test_propagation_max_steps(self, complex_graph_client):
        """Test that propagation respects max_steps."""
        analytics = GraphAnalytics(complex_graph_client)

        result = analytics.simulate_propagation(start_node="cve:0", max_steps=2)

        assert len(result.steps) <= 2

    def test_propagation_affected_nodes(self, simple_graph_client):
        """Test that affected nodes are correctly identified."""
        analytics = GraphAnalytics(simple_graph_client)

        result = analytics.simulate_propagation(start_node="cve:1", max_steps=10)

        # Should trace back through package to container
        assert "package:1" in result.affected_nodes
        assert "container:1" in result.affected_nodes

    def test_propagation_nonexistent_node(self, simple_graph_client):
        """Test propagation from nonexistent node."""
        analytics = GraphAnalytics(simple_graph_client)

        with pytest.raises(Exception):
            analytics.simulate_propagation(start_node="nonexistent:node", max_steps=5)


class TestGraphMetrics:
    """Test comprehensive graph metrics calculation."""

    def test_calculate_metrics(self, complex_graph_client):
        """Test calculating comprehensive graph metrics."""
        analytics = GraphAnalytics(complex_graph_client)

        metrics = analytics.calculate_metrics()

        assert isinstance(metrics, GraphMetrics)
        assert metrics.total_nodes > 0
        assert metrics.total_edges > 0
        assert metrics.density >= 0.0
        assert metrics.average_degree > 0

    def test_metrics_node_type_distribution(self, complex_graph_client):
        """Test node type distribution in metrics."""
        analytics = GraphAnalytics(complex_graph_client)

        metrics = analytics.calculate_metrics()

        assert "container" in metrics.node_type_distribution
        assert "package" in metrics.node_type_distribution
        assert "vulnerability" in metrics.node_type_distribution

        # Sum should equal total nodes
        total = sum(metrics.node_type_distribution.values())
        assert total == metrics.total_nodes

    def test_metrics_connected_components(self, complex_graph_client):
        """Test connected components calculation."""
        analytics = GraphAnalytics(complex_graph_client)

        metrics = analytics.calculate_metrics()

        assert metrics.connected_components > 0
        assert metrics.largest_component_size > 0
        assert metrics.largest_component_size <= metrics.total_nodes

    def test_metrics_average_path_length(self, simple_graph_client):
        """Test average path length calculation."""
        analytics = GraphAnalytics(simple_graph_client)

        metrics = analytics.calculate_metrics()

        # Should have a valid average path length
        if metrics.average_path_length is not None:
            assert metrics.average_path_length > 0

    def test_metrics_clustering_coefficient(self, complex_graph_client):
        """Test clustering coefficient calculation."""
        analytics = GraphAnalytics(complex_graph_client)

        metrics = analytics.calculate_metrics()

        assert 0.0 <= metrics.clustering_coefficient <= 1.0


class TestAnalyticsSummary:
    """Test analytics summary generation."""

    def test_generate_summary(self, complex_graph_client):
        """Test generating analytics summary."""
        analytics = GraphAnalytics(complex_graph_client)

        summary = analytics.generate_summary()

        assert summary.total_nodes > 0
        assert summary.total_edges > 0
        assert summary.top_central_nodes is not None
        assert summary.communities is not None
        assert summary.metrics is not None

    def test_summary_top_central_nodes(self, complex_graph_client):
        """Test that summary includes top central nodes."""
        analytics = GraphAnalytics(complex_graph_client)

        summary = analytics.generate_summary(top_n=5)

        assert len(summary.top_central_nodes) <= 5

    def test_summary_completeness(self, simple_graph_client):
        """Test that summary contains all required information."""
        analytics = GraphAnalytics(simple_graph_client)

        summary = analytics.generate_summary()

        # Check all required fields are present
        assert hasattr(summary, "total_nodes")
        assert hasattr(summary, "total_edges")
        assert hasattr(summary, "top_central_nodes")
        assert hasattr(summary, "communities")
        assert hasattr(summary, "metrics")


class TestGraphAnalyticsEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_graph(self):
        """Test analytics on empty graph."""
        client = NetworkXClient()
        analytics = GraphAnalytics(client)

        # Centrality on empty graph
        result = analytics.calculate_centrality(CentralityMetric.DEGREE)
        assert len(result.nodes) == 0

        # Metrics on empty graph
        metrics = analytics.calculate_metrics()
        assert metrics.total_nodes == 0
        assert metrics.total_edges == 0

    def test_single_node_graph(self):
        """Test analytics on graph with single node."""
        client = NetworkXClient()
        client.add_node(GraphNode("node:1", NodeType.PACKAGE, {}))

        analytics = GraphAnalytics(client)

        result = analytics.calculate_centrality(CentralityMetric.DEGREE)
        assert len(result.nodes) == 1
        assert result.nodes[0].score == 0.0  # No edges

    def test_disconnected_graph(self):
        """Test analytics on disconnected graph."""
        client = NetworkXClient()

        # Create two separate components
        client.add_node(GraphNode("a:1", NodeType.CONTAINER, {}))
        client.add_node(GraphNode("a:2", NodeType.PACKAGE, {}))
        client.add_edge(GraphEdge("a:1", "a:2", EdgeType.CONTAINS))

        client.add_node(GraphNode("b:1", NodeType.CONTAINER, {}))
        client.add_node(GraphNode("b:2", NodeType.PACKAGE, {}))
        client.add_edge(GraphEdge("b:1", "b:2", EdgeType.CONTAINS))

        analytics = GraphAnalytics(client)

        metrics = analytics.calculate_metrics()
        assert metrics.connected_components == 2

    def test_large_graph_performance(self):
        """Test analytics on larger graph (performance check)."""
        client = NetworkXClient()

        # Create a larger graph
        for i in range(100):
            client.add_node(GraphNode(f"node:{i}", NodeType.PACKAGE, {}))

        # Add random edges
        for i in range(200):
            source = f"node:{i % 100}"
            target = f"node:{(i * 2) % 100}"
            if source != target:
                try:
                    client.add_edge(GraphEdge(source, target, EdgeType.DEPENDS_ON))
                except:
                    pass

        analytics = GraphAnalytics(client)

        # Should complete without timeout
        result = analytics.calculate_centrality(CentralityMetric.DEGREE, top_n=10)
        assert len(result.nodes) == 10


class TestGraphAnalyticsIntegration:
    """Integration tests for graph analytics."""

    def test_complete_analytics_workflow(self, complex_graph_client):
        """Test complete analytics workflow."""
        analytics = GraphAnalytics(complex_graph_client)

        # Calculate centrality
        centrality = analytics.calculate_centrality(CentralityMetric.PAGERANK, top_n=5)
        assert len(centrality.nodes) == 5

        # Detect communities
        communities = analytics.detect_communities(CommunityAlgorithm.GREEDY_MODULARITY)
        assert len(communities.communities) > 0

        # Calculate metrics
        metrics = analytics.calculate_metrics()
        assert metrics.total_nodes > 0

        # Generate summary
        summary = analytics.generate_summary(top_n=5)
        assert summary.total_nodes == complex_graph_client.graph.number_of_nodes()

    def test_vulnerability_focused_analysis(self, complex_graph_client):
        """Test analysis focused on vulnerabilities."""
        analytics = GraphAnalytics(complex_graph_client)

        # Get most central vulnerabilities
        vuln_centrality = analytics.calculate_centrality(
            CentralityMetric.DEGREE, node_type_filter="vulnerability"
        )

        # All results should be vulnerabilities
        for node in vuln_centrality.nodes:
            assert node.node_type == "vulnerability"

    def test_package_risk_analysis(self, complex_graph_client):
        """Test analysis focused on packages."""
        analytics = GraphAnalytics(complex_graph_client)

        # Get most central packages (highest risk)
        package_centrality = analytics.calculate_centrality(
            CentralityMetric.BETWEENNESS, node_type_filter="package"
        )

        # All results should be packages
        for node in package_centrality.nodes:
            assert node.node_type == "package"

        # Top package should have connections to vulnerabilities
        if package_centrality.nodes:
            top_package = package_centrality.nodes[0]
            assert top_package.score >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
