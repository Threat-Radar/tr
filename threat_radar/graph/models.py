"""Data models for graph nodes and edges."""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from enum import Enum


class NodeType(Enum):
    """Supported node types in the vulnerability graph."""
    CONTAINER = "container"
    PACKAGE = "package"
    VULNERABILITY = "vulnerability"
    SERVICE = "service"
    HOST = "host"
    SBOM = "sbom"
    SCAN_RESULT = "scan_result"


class EdgeType(Enum):
    """Supported edge types in the vulnerability graph."""
    CONTAINS = "CONTAINS"  # Container -> Package
    HAS_VULNERABILITY = "HAS_VULNERABILITY"  # Package -> Vulnerability
    DEPENDS_ON = "DEPENDS_ON"  # Container -> Container, Service -> Service
    COMMUNICATES_WITH = "COMMUNICATES_WITH"  # Container -> Container
    RUNS_ON = "RUNS_ON"  # Container -> Host
    EXPOSES = "EXPOSES"  # Container -> Service
    AFFECTS = "AFFECTS"  # Vulnerability -> Package
    FIXED_BY = "FIXED_BY"  # Vulnerability -> Package (fixed version)
    SCANNED_BY = "SCANNED_BY"  # Container -> ScanResult
    GENERATED_FROM = "GENERATED_FROM"  # SBOM -> Container


@dataclass
class GraphNode:
    """
    Represents a node in the vulnerability graph.

    Attributes:
        node_id: Unique identifier for the node
        node_type: Type of the node (container, package, vulnerability, etc.)
        properties: Additional node attributes (name, version, severity, etc.)
    """
    node_id: str
    node_type: NodeType
    properties: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Ensure node_type is a NodeType enum."""
        if isinstance(self.node_type, str):
            self.node_type = NodeType(self.node_type)


@dataclass
class GraphEdge:
    """
    Represents an edge (relationship) in the vulnerability graph.

    Attributes:
        source_id: Node ID of the source node
        target_id: Node ID of the target node
        edge_type: Type of relationship (contains, depends_on, etc.)
        properties: Additional edge attributes (weight, timestamp, etc.)
    """
    source_id: str
    target_id: str
    edge_type: EdgeType
    properties: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        """Ensure edge_type is an EdgeType enum and properties dict exists."""
        if isinstance(self.edge_type, str):
            self.edge_type = EdgeType(self.edge_type)
        if self.properties is None:
            self.properties = {}


@dataclass
class GraphMetadata:
    """
    Metadata about the graph structure.

    Attributes:
        node_count: Total number of nodes
        edge_count: Total number of edges
        node_type_counts: Count of nodes by type
        edge_type_counts: Count of edges by type
    """
    node_count: int = 0
    edge_count: int = 0
    node_type_counts: Dict[str, int] = field(default_factory=dict)
    edge_type_counts: Dict[str, int] = field(default_factory=dict)
