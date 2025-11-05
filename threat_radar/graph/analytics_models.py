"""Data models for graph analytics results."""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
from enum import Enum


class CentralityMetric(Enum):
    """Supported centrality metrics."""
    DEGREE = "degree"
    BETWEENNESS = "betweenness"
    CLOSENESS = "closeness"
    PAGERANK = "pagerank"
    EIGENVECTOR = "eigenvector"


class CommunityAlgorithm(Enum):
    """Supported community detection algorithms."""
    LOUVAIN = "louvain"
    LABEL_PROPAGATION = "label_propagation"
    GREEDY_MODULARITY = "greedy_modularity"


@dataclass
class NodeCentrality:
    """
    Centrality score for a single node.

    Attributes:
        node_id: Node identifier
        score: Centrality score (0.0-1.0 for most metrics)
        rank: Rank among all nodes (1 = highest)
        node_type: Type of node (package, vulnerability, etc.)
        properties: Additional node properties
    """
    node_id: str
    score: float
    rank: int
    node_type: str = "unknown"
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CentralityResult:
    """
    Results from centrality analysis.

    Attributes:
        metric: Type of centrality metric used
        nodes: List of node centrality scores, sorted by rank
        total_nodes: Total number of nodes analyzed
        avg_score: Average centrality score
        max_score: Highest centrality score
        min_score: Lowest centrality score
    """
    metric: CentralityMetric
    nodes: List[NodeCentrality]
    total_nodes: int
    avg_score: float
    max_score: float
    min_score: float

    def get_top_n(self, n: int) -> List[NodeCentrality]:
        """Get top N nodes by centrality score."""
        return self.nodes[:n]

    def get_critical_nodes(self, threshold: float = 0.5) -> List[NodeCentrality]:
        """Get nodes above a centrality threshold."""
        return [node for node in self.nodes if node.score >= threshold]


@dataclass
class Community:
    """
    A detected community (cluster) of related nodes.

    Attributes:
        community_id: Unique identifier for this community
        nodes: Set of node IDs in this community
        size: Number of nodes in community
        density: Internal edge density (0.0-1.0)
        description: Human-readable description
        node_types: Count of each node type in community
        avg_cvss: Average CVSS score of vulnerabilities in community
    """
    community_id: int
    nodes: Set[str]
    size: int
    density: float = 0.0
    description: str = ""
    node_types: Dict[str, int] = field(default_factory=dict)
    avg_cvss: Optional[float] = None

    def get_vulnerabilities(self) -> Set[str]:
        """Get vulnerability nodes in this community."""
        return {node for node in self.nodes if node.startswith("cve:")}

    def get_packages(self) -> Set[str]:
        """Get package nodes in this community."""
        return {node for node in self.nodes if node.startswith("package:")}


@dataclass
class CommunityDetectionResult:
    """
    Results from community detection analysis.

    Attributes:
        algorithm: Algorithm used for detection
        communities: List of detected communities
        total_communities: Number of communities found
        modularity: Modularity score (quality of clustering)
        coverage: Fraction of nodes in communities
    """
    algorithm: CommunityAlgorithm
    communities: List[Community]
    total_communities: int
    modularity: float
    coverage: float

    def get_largest_communities(self, n: int = 5) -> List[Community]:
        """Get N largest communities by size."""
        return sorted(self.communities, key=lambda c: c.size, reverse=True)[:n]

    def get_community_for_node(self, node_id: str) -> Optional[Community]:
        """Find which community a node belongs to."""
        for community in self.communities:
            if node_id in community.nodes:
                return community
        return None


@dataclass
class PropagationStep:
    """
    A single step in vulnerability propagation.

    Attributes:
        node_id: Node at this step
        node_type: Type of node
        depth: Distance from source vulnerability
        path_from_source: Full path from source to this node
        cvss_score: CVSS score if vulnerability node
        package_name: Package name if package node
    """
    node_id: str
    node_type: str
    depth: int
    path_from_source: List[str]
    cvss_score: Optional[float] = None
    package_name: Optional[str] = None


@dataclass
class PropagationReport:
    """
    Analysis of how a vulnerability propagates through the graph.

    Attributes:
        cve_id: Source CVE identifier
        total_affected_nodes: Total nodes affected by propagation
        affected_packages: Packages directly affected
        affected_containers: Containers indirectly affected
        max_depth: Maximum propagation depth
        propagation_paths: All propagation paths from source
        infection_score: Overall infection score (0-100)
        critical_path: Most critical propagation path
    """
    cve_id: str
    total_affected_nodes: int
    affected_packages: List[str]
    affected_containers: List[str]
    max_depth: int
    propagation_paths: List[List[PropagationStep]]
    infection_score: float
    critical_path: Optional[List[PropagationStep]] = None

    def get_direct_impact(self) -> int:
        """Number of directly affected nodes (depth 1)."""
        return len(self.affected_packages)

    def get_transitive_impact(self) -> int:
        """Number of transitively affected nodes (depth > 1)."""
        return self.total_affected_nodes - self.get_direct_impact()


@dataclass
class GraphMetrics:
    """
    Overall graph health and topology metrics.

    Attributes:
        total_nodes: Total number of nodes
        total_edges: Total number of edges
        density: Graph density (0.0-1.0)
        avg_degree: Average node degree
        avg_clustering: Average clustering coefficient
        avg_path_length: Average shortest path length
        diameter: Graph diameter (longest shortest path)
        connected_components: Number of connected components
        largest_component_size: Size of largest connected component
        vulnerability_concentration: Gini coefficient of vulnerability distribution
        critical_node_count: Number of critical nodes (high centrality)
        security_score: Overall security score (0-100, higher is better)
    """
    total_nodes: int
    total_edges: int
    density: float
    avg_degree: float
    avg_clustering: float
    avg_path_length: float
    diameter: int
    connected_components: int
    largest_component_size: int
    vulnerability_concentration: float = 0.0
    critical_node_count: int = 0
    security_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_nodes": self.total_nodes,
            "total_edges": self.total_edges,
            "density": round(self.density, 3),
            "avg_degree": round(self.avg_degree, 2),
            "avg_clustering": round(self.avg_clustering, 3),
            "avg_path_length": round(self.avg_path_length, 2),
            "diameter": self.diameter,
            "connected_components": self.connected_components,
            "largest_component_size": self.largest_component_size,
            "vulnerability_concentration": round(self.vulnerability_concentration, 3),
            "critical_node_count": self.critical_node_count,
            "security_score": round(self.security_score, 1),
        }


@dataclass
class AnalyticsSummary:
    """
    Comprehensive analytics summary combining all analyses.

    Attributes:
        graph_metrics: Overall graph metrics
        top_critical_nodes: Top critical nodes by centrality
        communities: Community detection results
        high_risk_propagations: High-risk vulnerability propagations
        recommendations: Security recommendations based on analytics
    """
    graph_metrics: GraphMetrics
    top_critical_nodes: List[NodeCentrality] = field(default_factory=list)
    communities: Optional[CommunityDetectionResult] = None
    high_risk_propagations: List[PropagationReport] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
