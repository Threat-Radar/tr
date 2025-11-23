"""Graph analytics engine for vulnerability analysis."""

import logging
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict, deque
import networkx as nx
from networkx.algorithms import community

from .graph_client import GraphClient, NetworkXClient
from .models import NodeType, EdgeType
from .analytics_models import (
    CentralityMetric,
    CentralityResult,
    NodeCentrality,
    CommunityAlgorithm,
    CommunityDetectionResult,
    Community,
    PropagationReport,
    PropagationStep,
    GraphMetrics,
    AnalyticsSummary,
)

logger = logging.getLogger(__name__)


class GraphAnalytics:
    """
    Advanced graph analytics engine for security vulnerability analysis.

    Provides centrality analysis, community detection, propagation modeling,
    and comprehensive graph metrics for vulnerability management.
    """

    def __init__(self, client: GraphClient):
        """
        Initialize analytics engine.

        Args:
            client: Graph client containing the vulnerability graph
        """
        self.client = client
        if not isinstance(client, NetworkXClient):
            raise ValueError("GraphAnalytics currently only supports NetworkXClient")
        self.graph = client.graph
        logger.info("Initialized GraphAnalytics engine")

    def calculate_centrality(
        self,
        metric: CentralityMetric,
        top_n: Optional[int] = None,
        node_type_filter: Optional[str] = None,
    ) -> CentralityResult:
        """
        Calculate centrality scores for all nodes in the graph.

        Args:
            metric: Type of centrality metric to calculate
            top_n: Return only top N nodes (None for all)
            node_type_filter: Filter by node type (e.g., "package", "vulnerability")

        Returns:
            CentralityResult with ranked nodes
        """
        logger.info(f"Calculating {metric.value} centrality")

        # Calculate centrality based on metric type
        if metric == CentralityMetric.DEGREE:
            centrality_scores = nx.degree_centrality(self.graph)
            # Fix edge case: single node with no edges should have centrality 0.0
            if self.graph.number_of_nodes() == 1:
                for node in centrality_scores:
                    if self.graph.degree(node) == 0:
                        centrality_scores[node] = 0.0
        elif metric == CentralityMetric.BETWEENNESS:
            centrality_scores = nx.betweenness_centrality(self.graph)
        elif metric == CentralityMetric.CLOSENESS:
            # Only calculate for largest connected component
            if nx.is_strongly_connected(self.graph):
                centrality_scores = nx.closeness_centrality(self.graph)
            else:
                # For weakly connected graphs, calculate on largest component
                largest_cc = max(nx.weakly_connected_components(self.graph), key=len)
                subgraph = self.graph.subgraph(largest_cc)
                centrality_scores = nx.closeness_centrality(subgraph)
                # Fill in zeros for nodes not in largest component
                for node in self.graph.nodes():
                    if node not in centrality_scores:
                        centrality_scores[node] = 0.0
        elif metric == CentralityMetric.PAGERANK:
            centrality_scores = nx.pagerank(self.graph)
        elif metric == CentralityMetric.EIGENVECTOR:
            try:
                centrality_scores = nx.eigenvector_centrality(self.graph, max_iter=1000)
            except nx.PowerIterationFailedConvergence:
                logger.warning("Eigenvector centrality failed to converge, using degree centrality")
                centrality_scores = nx.degree_centrality(self.graph)
        else:
            raise ValueError(f"Unsupported centrality metric: {metric}")

        # Convert to NodeCentrality objects
        nodes = []
        for node_id, score in centrality_scores.items():
            node_data = self.graph.nodes[node_id]
            node_type = node_data.get("node_type", "unknown")

            # Apply node type filter if specified
            if node_type_filter and node_type != node_type_filter:
                continue

            nodes.append(
                NodeCentrality(
                    node_id=node_id,
                    score=score,
                    rank=0,  # Will be set after sorting
                    node_type=node_type,
                    properties={
                        k: v
                        for k, v in node_data.items()
                        if k not in ["node_type"]
                    },
                )
            )

        # Sort by score descending and assign ranks
        nodes.sort(key=lambda x: x.score, reverse=True)
        for rank, node in enumerate(nodes, start=1):
            node.rank = rank

        # Limit to top N if specified
        if top_n:
            nodes = nodes[:top_n]

        # Calculate statistics
        all_scores = [n.score for n in nodes]
        result = CentralityResult(
            metric=metric,
            nodes=nodes,
            total_nodes=len(centrality_scores),
            avg_score=sum(all_scores) / len(all_scores) if all_scores else 0.0,
            max_score=max(all_scores) if all_scores else 0.0,
            min_score=min(all_scores) if all_scores else 0.0,
        )

        logger.info(f"Calculated centrality for {len(nodes)} nodes")
        return result

    def detect_communities(
        self,
        algorithm: CommunityAlgorithm = CommunityAlgorithm.GREEDY_MODULARITY,
    ) -> CommunityDetectionResult:
        """
        Detect communities (clusters) in the vulnerability graph.

        Args:
            algorithm: Community detection algorithm to use

        Returns:
            CommunityDetectionResult with detected communities
        """
        logger.info(f"Detecting communities using {algorithm.value}")

        # Convert to undirected graph for community detection
        undirected_graph = self.graph.to_undirected()

        # Detect communities based on algorithm
        if algorithm == CommunityAlgorithm.GREEDY_MODULARITY:
            communities_generator = community.greedy_modularity_communities(undirected_graph)
            detected_communities = list(communities_generator)
        elif algorithm == CommunityAlgorithm.LABEL_PROPAGATION:
            communities_generator = community.label_propagation_communities(undirected_graph)
            detected_communities = list(communities_generator)
        elif algorithm == CommunityAlgorithm.LOUVAIN:
            # Try to use python-louvain if available, else fall back to greedy
            try:
                import community as louvain_community
                partition = louvain_community.best_partition(undirected_graph)
                # Convert partition dict to list of sets
                community_dict = defaultdict(set)
                for node, comm_id in partition.items():
                    community_dict[comm_id].add(node)
                detected_communities = list(community_dict.values())
            except ImportError:
                logger.warning("python-louvain not installed, using greedy_modularity instead")
                communities_generator = community.greedy_modularity_communities(undirected_graph)
                detected_communities = list(communities_generator)
        else:
            raise ValueError(f"Unsupported community algorithm: {algorithm}")

        # Calculate modularity
        modularity_score = community.modularity(undirected_graph, detected_communities)

        # Build Community objects
        communities = []
        for comm_id, node_set in enumerate(detected_communities):
            # Calculate community density
            subgraph = undirected_graph.subgraph(node_set)
            density = nx.density(subgraph)

            # Count node types
            node_types = defaultdict(int)
            vulns_cvss_scores = []
            for node in node_set:
                node_data = self.graph.nodes[node]
                node_type = node_data.get("node_type", "unknown")
                node_types[node_type] += 1

                # Collect CVSS scores for vulnerabilities
                if node_type == "vulnerability":
                    cvss = node_data.get("cvss_score")
                    if cvss is not None:
                        vulns_cvss_scores.append(cvss)

            # Calculate average CVSS
            avg_cvss = (
                sum(vulns_cvss_scores) / len(vulns_cvss_scores)
                if vulns_cvss_scores
                else None
            )

            # Generate description
            description = self._generate_community_description(node_set, node_types)

            communities.append(
                Community(
                    community_id=comm_id,
                    nodes=node_set,
                    size=len(node_set),
                    density=density,
                    description=description,
                    node_types=dict(node_types),
                    avg_cvss=avg_cvss,
                )
            )

        # Sort by size descending
        communities.sort(key=lambda c: c.size, reverse=True)

        # Calculate coverage (fraction of nodes in communities)
        total_nodes = self.graph.number_of_nodes()
        coverage = sum(c.size for c in communities) / total_nodes if total_nodes > 0 else 0.0

        result = CommunityDetectionResult(
            algorithm=algorithm,
            communities=communities,
            total_communities=len(communities),
            modularity=modularity_score,
            coverage=coverage,
        )

        logger.info(f"Detected {len(communities)} communities")
        return result

    def simulate_propagation(
        self, start_node: str, max_steps: int = 10
    ) -> PropagationReport:
        """
        Simulate propagation from any starting node in the graph.

        This is a general-purpose propagation simulator that can start from
        any node type (vulnerability, package, container, etc.).

        Args:
            start_node: Node ID to start propagation from
            max_steps: Maximum propagation steps to simulate

        Returns:
            PropagationReport with propagation analysis
        """
        logger.info(f"Simulating propagation from {start_node}")

        if start_node not in self.graph:
            raise ValueError(f"Node {start_node} not found in graph")

        # BFS to find all reachable nodes
        queue = deque([(start_node, 0, [start_node])])
        visited = {start_node}
        all_paths = []
        affected_packages = []
        affected_containers = []
        max_observed_depth = 0

        while queue:
            current_node, depth, path = queue.popleft()

            if depth >= max_steps:
                continue

            max_observed_depth = max(max_observed_depth, depth)

            # Get incoming neighbors (propagation goes backwards: CVE -> package -> container)
            neighbors = list(self.graph.predecessors(current_node))

            for neighbor in neighbors:
                if neighbor not in visited:
                    visited.add(neighbor)
                    new_path = path + [neighbor]

                    # Record node by type
                    node_data = self.graph.nodes[neighbor]
                    node_type = node_data.get("node_type", "unknown")

                    if node_type == "package":
                        affected_packages.append(neighbor)
                    elif node_type == "container":
                        affected_containers.append(neighbor)

                    # Save this path (at least 2 nodes)
                    all_paths.append(new_path)

                    # Continue propagation
                    if depth + 1 < max_steps:
                        queue.append((neighbor, depth + 1, new_path))

        # Convert all paths to PropagationStep format
        propagation_paths = [self._path_to_steps(path) for path in all_paths if len(path) > 1]

        # Calculate infection score
        total_nodes = self.graph.number_of_nodes()
        affected_ratio = len(visited) / total_nodes if total_nodes > 0 else 0.0
        infection_score = min(100.0, affected_ratio * 100 * (1 + max_observed_depth / 10))

        # Find critical path
        critical_path = self._find_critical_path(propagation_paths)

        report = PropagationReport(
            cve_id=start_node,  # Use start_node as cve_id for general propagation
            total_affected_nodes=len(visited),
            affected_packages=affected_packages,
            affected_containers=affected_containers,
            max_depth=max_observed_depth,
            propagation_paths=propagation_paths,
            infection_score=infection_score,
            critical_path=critical_path,
        )

        logger.info(
            f"Propagation simulation: {len(visited)} nodes affected, "
            f"depth={max_observed_depth}, score={infection_score:.1f}"
        )
        return report

    def analyze_vulnerability_propagation(
        self, cve_id: str, max_depth: int = 10
    ) -> PropagationReport:
        """
        Analyze how a vulnerability propagates through dependencies.

        Args:
            cve_id: CVE identifier to analyze
            max_depth: Maximum propagation depth to trace

        Returns:
            PropagationReport with propagation analysis
        """
        logger.info(f"Analyzing propagation for {cve_id}")

        vuln_node_id = f"cve:{cve_id}"
        if vuln_node_id not in self.graph:
            raise ValueError(f"Vulnerability {cve_id} not found in graph")

        # BFS to find all reachable nodes and paths
        queue = deque([(vuln_node_id, 0, [vuln_node_id])])
        visited = {vuln_node_id}
        propagation_paths = []
        affected_packages = []
        affected_containers = []
        max_observed_depth = 0

        while queue:
            current_node, depth, path = queue.popleft()

            if depth > max_depth:
                continue

            max_observed_depth = max(max_observed_depth, depth)

            # Get outgoing neighbors (propagation direction)
            for neighbor in self.graph.successors(current_node):
                if neighbor not in visited:
                    visited.add(neighbor)
                    new_path = path + [neighbor]

                    # Record path as propagation step
                    node_data = self.graph.nodes[neighbor]
                    node_type = node_data.get("node_type", "unknown")

                    step = PropagationStep(
                        node_id=neighbor,
                        node_type=node_type,
                        depth=depth + 1,
                        path_from_source=new_path,
                        cvss_score=node_data.get("cvss_score"),
                        package_name=node_data.get("name"),
                    )

                    # Track affected assets
                    if node_type == "package":
                        affected_packages.append(neighbor)
                    elif node_type == "container":
                        affected_containers.append(neighbor)

                    # Build path for this propagation chain
                    if depth + 1 <= max_depth:
                        queue.append((neighbor, depth + 1, new_path))

            # Save completed path
            if len(path) > 1:  # At least source + one hop
                path_steps = self._path_to_steps(path)
                propagation_paths.append(path_steps)

        # Calculate infection score (0-100) based on affected nodes
        total_nodes = self.graph.number_of_nodes()
        affected_ratio = len(visited) / total_nodes if total_nodes > 0 else 0.0
        infection_score = min(100.0, affected_ratio * 100 * (1 + max_observed_depth / 10))

        # Find critical path (highest CVSS scores)
        critical_path = self._find_critical_path(propagation_paths)

        report = PropagationReport(
            cve_id=cve_id,
            total_affected_nodes=len(visited),
            affected_packages=affected_packages,
            affected_containers=affected_containers,
            max_depth=max_observed_depth,
            propagation_paths=propagation_paths,
            infection_score=infection_score,
            critical_path=critical_path,
        )

        logger.info(
            f"Propagation analysis: {len(visited)} nodes affected, "
            f"depth={max_observed_depth}, score={infection_score:.1f}"
        )
        return report

    def calculate_graph_metrics(self) -> GraphMetrics:
        """
        Calculate comprehensive graph topology and health metrics.

        Returns:
            GraphMetrics with various graph statistics
        """
        logger.info("Calculating graph metrics")

        total_nodes = self.graph.number_of_nodes()
        total_edges = self.graph.number_of_edges()

        # Handle empty graph edge case
        if total_nodes == 0:
            return GraphMetrics(
                total_nodes=0,
                total_edges=0,
                density=0.0,
                avg_degree=0.0,
                avg_clustering=0.0,
                avg_path_length=0.0,
                diameter=0,
                connected_components=0,
                largest_component_size=0,
                vulnerability_concentration=0.0,
                critical_node_count=0,
                security_score=100.0,  # Empty graph is technically "secure"
                node_type_distribution={},
            )

        # Basic metrics
        density = nx.density(self.graph)
        degrees = [d for n, d in self.graph.degree()]
        avg_degree = sum(degrees) / len(degrees) if degrees else 0.0

        # Clustering coefficient (handle empty graph)
        undirected = self.graph.to_undirected()
        if total_nodes > 0:
            try:
                avg_clustering = nx.average_clustering(undirected)
            except ZeroDivisionError:
                avg_clustering = 0.0
        else:
            avg_clustering = 0.0

        # Path length and diameter (on largest weakly connected component)
        weakly_connected_components = list(nx.weakly_connected_components(self.graph))
        connected_components_count = len(weakly_connected_components) if weakly_connected_components else 0

        if weakly_connected_components:
            largest_cc = max(weakly_connected_components, key=len)
            largest_component_size = len(largest_cc)
        else:
            largest_cc = set()
            largest_component_size = 0

        if len(largest_cc) > 1:
            # Convert to undirected for path length and diameter calculations
            # since directed graphs require strong connectivity
            largest_subgraph = self.graph.subgraph(largest_cc).to_undirected()
            try:
                avg_path_length = nx.average_shortest_path_length(largest_subgraph)
                diameter = nx.diameter(largest_subgraph)
            except nx.NetworkXError:
                # Graph is not connected even as undirected (shouldn't happen in weakly connected component)
                avg_path_length = 0.0
                diameter = 0
        else:
            avg_path_length = 0.0
            diameter = 0

        # Vulnerability concentration (Gini coefficient)
        vulnerability_counts = self._calculate_vulnerability_distribution()
        vulnerability_concentration = self._calculate_gini_coefficient(vulnerability_counts)

        # Count critical nodes (high betweenness centrality)
        betweenness = nx.betweenness_centrality(self.graph)
        critical_threshold = 0.1  # Nodes with betweenness > 0.1
        critical_node_count = sum(1 for score in betweenness.values() if score > critical_threshold)

        # Calculate security score (0-100, higher is better)
        security_score = self._calculate_security_score(
            density=density,
            avg_clustering=avg_clustering,
            vulnerability_concentration=vulnerability_concentration,
            critical_node_ratio=critical_node_count / total_nodes if total_nodes > 0 else 0,
        )

        # Calculate node type distribution
        node_type_distribution = defaultdict(int)
        for node, data in self.graph.nodes(data=True):
            node_type = data.get("node_type", "unknown")
            node_type_distribution[node_type] += 1

        metrics = GraphMetrics(
            total_nodes=total_nodes,
            total_edges=total_edges,
            density=density,
            avg_degree=avg_degree,
            avg_clustering=avg_clustering,
            avg_path_length=avg_path_length,
            diameter=diameter,
            connected_components=connected_components_count,
            largest_component_size=largest_component_size,
            vulnerability_concentration=vulnerability_concentration,
            critical_node_count=critical_node_count,
            security_score=security_score,
            node_type_distribution=dict(node_type_distribution),
        )

        logger.info(f"Graph metrics calculated: security_score={security_score:.1f}")
        return metrics

    # Helper methods

    def _generate_community_description(
        self, nodes: Set[str], node_types: Dict[str, int]
    ) -> str:
        """Generate human-readable description of a community."""
        primary_type = max(node_types.items(), key=lambda x: x[1])[0] if node_types else "unknown"
        size = len(nodes)

        if primary_type == "package":
            return f"Package cluster ({size} packages)"
        elif primary_type == "vulnerability":
            return f"Vulnerability cluster ({size} CVEs)"
        elif primary_type == "container":
            return f"Container cluster ({size} containers)"
        else:
            return f"Mixed cluster ({size} nodes, {len(node_types)} types)"

    def _path_to_steps(self, path: List[str]) -> List[PropagationStep]:
        """Convert node path to propagation steps."""
        steps = []
        for depth, node_id in enumerate(path):
            node_data = self.graph.nodes[node_id]
            steps.append(
                PropagationStep(
                    node_id=node_id,
                    node_type=node_data.get("node_type", "unknown"),
                    depth=depth,
                    path_from_source=path[: depth + 1],
                    cvss_score=node_data.get("cvss_score"),
                    package_name=node_data.get("name"),
                )
            )
        return steps

    def _find_critical_path(
        self, paths: List[List[PropagationStep]]
    ) -> Optional[List[PropagationStep]]:
        """Find the most critical propagation path based on CVSS scores."""
        if not paths:
            return None

        def path_criticality(path: List[PropagationStep]) -> float:
            cvss_scores = [step.cvss_score for step in path if step.cvss_score]
            return sum(cvss_scores) if cvss_scores else 0.0

        return max(paths, key=path_criticality)

    def _calculate_vulnerability_distribution(self) -> List[int]:
        """Calculate distribution of vulnerabilities across packages."""
        vuln_counts = defaultdict(int)
        for node, data in self.graph.nodes(data=True):
            if data.get("node_type") == "package":
                # Count vulnerabilities connected to this package
                vuln_count = sum(
                    1
                    for neighbor in self.graph.successors(node)
                    if self.graph.nodes[neighbor].get("node_type") == "vulnerability"
                )
                vuln_counts[node] = vuln_count

        return list(vuln_counts.values()) if vuln_counts else [0]

    def _calculate_gini_coefficient(self, values: List[int]) -> float:
        """Calculate Gini coefficient (measure of inequality)."""
        if not values or len(values) == 0:
            return 0.0

        sorted_values = sorted(values)
        n = len(sorted_values)
        cumsum = sum((i + 1) * val for i, val in enumerate(sorted_values))
        total = sum(sorted_values)

        if total == 0:
            return 0.0

        return (2 * cumsum) / (n * total) - (n + 1) / n

    def _calculate_security_score(
        self,
        density: float,
        avg_clustering: float,
        vulnerability_concentration: float,
        critical_node_ratio: float,
    ) -> float:
        """
        Calculate overall security score (0-100, higher is better).

        Lower density and clustering = better (less interconnected vulnerabilities)
        Lower concentration = better (vulnerabilities spread evenly)
        Lower critical node ratio = better (fewer bottleneck nodes)
        """
        # Invert metrics (lower is better becomes higher score)
        density_score = (1 - density) * 100
        clustering_score = (1 - avg_clustering) * 100
        concentration_score = (1 - vulnerability_concentration) * 100
        critical_score = (1 - critical_node_ratio) * 100

        # Weighted average
        security_score = (
            density_score * 0.3 +
            clustering_score * 0.2 +
            concentration_score * 0.3 +
            critical_score * 0.2
        )

        return max(0.0, min(100.0, security_score))

    def calculate_metrics(self) -> GraphMetrics:
        """
        Alias for calculate_graph_metrics() for backward compatibility.

        Returns:
            GraphMetrics with various graph statistics
        """
        return self.calculate_graph_metrics()

    def generate_summary(
        self,
        top_n: int = 10,
        include_communities: bool = True,
        include_propagations: bool = False,
    ) -> AnalyticsSummary:
        """
        Generate comprehensive analytics summary combining all analyses.

        Args:
            top_n: Number of top critical nodes to include
            include_communities: Whether to include community detection
            include_propagations: Whether to include vulnerability propagations

        Returns:
            AnalyticsSummary with combined analytics results
        """
        logger.info(f"Generating analytics summary (top_n={top_n})")

        # Calculate graph metrics
        graph_metrics = self.calculate_graph_metrics()

        # Calculate centrality for top critical nodes
        centrality_result = self.calculate_centrality(
            CentralityMetric.PAGERANK, top_n=top_n
        )
        top_critical_nodes = centrality_result.nodes

        # Detect communities if requested
        communities = None
        if include_communities:
            communities = self.detect_communities(CommunityAlgorithm.GREEDY_MODULARITY)

        # Find high-risk propagations if requested
        high_risk_propagations = []
        if include_propagations:
            # Find top vulnerabilities by CVSS score
            vuln_nodes = [
                (node, data)
                for node, data in self.graph.nodes(data=True)
                if data.get("node_type") == "vulnerability"
            ]
            # Sort by CVSS score (descending)
            vuln_nodes.sort(
                key=lambda x: x[1].get("cvss_score", 0.0), reverse=True
            )

            # Analyze propagation for top 5 vulnerabilities
            for node_id, data in vuln_nodes[:5]:
                cve_id = data.get("cve_id") or node_id.replace("cve:", "")
                try:
                    propagation = self.analyze_vulnerability_propagation(
                        cve_id, max_depth=5
                    )
                    high_risk_propagations.append(propagation)
                except ValueError:
                    # Vulnerability not found or invalid
                    continue

        # Generate recommendations based on analysis
        recommendations = self._generate_recommendations(
            graph_metrics=graph_metrics,
            top_critical_nodes=top_critical_nodes,
            communities=communities,
        )

        summary = AnalyticsSummary(
            graph_metrics=graph_metrics,
            top_critical_nodes=top_critical_nodes,
            communities=communities,
            high_risk_propagations=high_risk_propagations,
            recommendations=recommendations,
        )

        logger.info("Analytics summary generated")
        return summary

    def _generate_recommendations(
        self,
        graph_metrics: GraphMetrics,
        top_critical_nodes: List[NodeCentrality],
        communities: Optional[CommunityDetectionResult],
    ) -> List[str]:
        """
        Generate security recommendations based on analytics.

        Args:
            graph_metrics: Overall graph metrics
            top_critical_nodes: Top critical nodes by centrality
            communities: Community detection results

        Returns:
            List of actionable recommendations
        """
        recommendations = []

        # Security score recommendations
        if graph_metrics.security_score < 30:
            recommendations.append(
                "CRITICAL: Security score is very low. Immediate remediation required."
            )
        elif graph_metrics.security_score < 60:
            recommendations.append(
                "WARNING: Security score is below acceptable levels. Review critical vulnerabilities."
            )

        # Critical node recommendations
        if graph_metrics.critical_node_count > graph_metrics.total_nodes * 0.2:
            recommendations.append(
                f"High number of critical nodes ({graph_metrics.critical_node_count}). "
                "Focus on reducing bottleneck dependencies."
            )

        # Vulnerability concentration
        if graph_metrics.vulnerability_concentration > 0.7:
            recommendations.append(
                "Vulnerabilities are highly concentrated. Consider diversifying dependencies "
                "to reduce risk from single package failures."
            )

        # Density recommendations
        if graph_metrics.density > 0.5:
            recommendations.append(
                "High graph density detected. Tightly coupled dependencies increase "
                "vulnerability propagation risk."
            )

        # Top critical nodes
        if top_critical_nodes:
            vuln_nodes = [
                n for n in top_critical_nodes if n.node_type == "vulnerability"
            ]
            if vuln_nodes:
                recommendations.append(
                    f"Prioritize fixing top {len(vuln_nodes)} critical vulnerabilities "
                    "with high centrality scores."
                )

        # Community recommendations
        if communities and communities.total_communities > 10:
            recommendations.append(
                f"Detected {communities.total_communities} isolated communities. "
                "Consider consolidating dependencies to reduce attack surface."
            )

        # Default recommendation if all metrics look good
        if not recommendations:
            recommendations.append(
                "Overall graph security appears healthy. Continue monitoring for new vulnerabilities."
            )

        return recommendations
