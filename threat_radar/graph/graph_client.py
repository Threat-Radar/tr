"""Graph database client implementations."""

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
import networkx as nx

from .models import GraphNode, GraphEdge, GraphMetadata, NodeType, EdgeType

logger = logging.getLogger(__name__)


class GraphClient(ABC):
    """Abstract base class for graph database clients."""

    @abstractmethod
    def add_node(self, node: GraphNode) -> None:
        """
        Add a node to the graph.

        Args:
            node: GraphNode to add
        """
        pass

    @abstractmethod
    def add_edge(self, edge: GraphEdge) -> None:
        """
        Add an edge to the graph.

        Args:
            edge: GraphEdge to add
        """
        pass

    @abstractmethod
    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """
        Retrieve a node by ID.

        Args:
            node_id: Node identifier

        Returns:
            GraphNode if found, None otherwise
        """
        pass

    @abstractmethod
    def get_neighbors(
        self, node_id: str, edge_type: Optional[EdgeType] = None
    ) -> List[str]:
        """
        Get neighboring nodes.

        Args:
            node_id: Source node ID
            edge_type: Optional edge type filter

        Returns:
            List of neighbor node IDs
        """
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clear all nodes and edges from the graph."""
        pass

    @abstractmethod
    def get_metadata(self) -> GraphMetadata:
        """
        Get graph metadata and statistics.

        Returns:
            GraphMetadata with node/edge counts
        """
        pass

    @abstractmethod
    def save(self, path: str) -> None:
        """
        Persist graph to disk.

        Args:
            path: File path to save graph
        """
        pass

    @abstractmethod
    def load(self, path: str) -> None:
        """
        Load graph from disk.

        Args:
            path: File path to load graph from
        """
        pass


class NetworkXClient(GraphClient):
    """NetworkX-based graph client implementation."""

    def __init__(self):
        """Initialize NetworkX directed graph."""
        self.graph = nx.DiGraph()
        logger.info("Initialized NetworkX graph client")

    def add_node(self, node: GraphNode) -> None:
        """
        Add a node to the NetworkX graph.

        Args:
            node: GraphNode to add
        """
        self.graph.add_node(
            node.node_id, node_type=node.node_type.value, **node.properties
        )
        logger.debug(f"Added node: {node.node_id} (type: {node.node_type.value})")

    def add_edge(self, edge: GraphEdge) -> None:
        """
        Add an edge to the NetworkX graph.

        Args:
            edge: GraphEdge to add
        """
        self.graph.add_edge(
            edge.source_id,
            edge.target_id,
            edge_type=edge.edge_type.value,
            **(edge.properties or {}),
        )
        logger.debug(
            f"Added edge: {edge.source_id} -> {edge.target_id} "
            f"(type: {edge.edge_type.value})"
        )

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """
        Retrieve a node by ID.

        Args:
            node_id: Node identifier

        Returns:
            GraphNode if found, None otherwise
        """
        if node_id not in self.graph:
            return None

        node_data = dict(self.graph.nodes[node_id])  # Make a copy
        node_type_str = node_data.pop("node_type", None)

        if node_type_str is None:
            return None

        node_type = NodeType(node_type_str)

        return GraphNode(node_id=node_id, node_type=node_type, properties=node_data)

    def get_neighbors(
        self,
        node_id: str,
        edge_type: Optional[EdgeType] = None,
        direction: str = "outgoing",
    ) -> List[str]:
        """
        Get neighboring nodes.

        Args:
            node_id: Source node ID
            edge_type: Optional edge type filter
            direction: "outgoing" (successors) or "incoming" (predecessors)

        Returns:
            List of neighbor node IDs
        """
        if node_id not in self.graph:
            return []

        if direction == "outgoing":
            edges = self.graph.out_edges(node_id, data=True)
        elif direction == "incoming":
            edges = self.graph.in_edges(node_id, data=True)
        else:
            raise ValueError(f"Invalid direction: {direction}")

        neighbors = []
        for source, target, data in edges:
            if edge_type is None or data.get("edge_type") == edge_type.value:
                neighbor = target if direction == "outgoing" else source
                neighbors.append(neighbor)

        return neighbors

    def find_nodes_by_type(self, node_type: NodeType) -> List[str]:
        """
        Find all nodes of a specific type.

        Args:
            node_type: Type of nodes to find

        Returns:
            List of node IDs matching the type
        """
        return [
            node_id
            for node_id, data in self.graph.nodes(data=True)
            if data.get("node_type") == node_type.value
        ]

    def find_vulnerable_containers(self, cve_id: str) -> List[str]:
        """
        Find all containers affected by a specific CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            List of container node IDs affected by the CVE
        """
        vuln_node = f"cve:{cve_id}"
        if vuln_node not in self.graph:
            return []

        affected_containers = set()

        # Find packages with this vulnerability (incoming edges to vuln)
        for package_node in self.get_neighbors(
            vuln_node, edge_type=None, direction="incoming"
        ):
            # Find containers that contain these packages
            for container_node in self.get_neighbors(
                package_node, edge_type=None, direction="incoming"
            ):
                if (
                    self.graph.nodes[container_node].get("node_type")
                    == NodeType.CONTAINER.value
                ):
                    affected_containers.add(container_node)

        return list(affected_containers)

    def find_packages_with_vulnerabilities(self) -> Dict[str, List[str]]:
        """
        Find all packages and their associated vulnerabilities.

        Returns:
            Dict mapping package node IDs to lists of CVE IDs
        """
        package_vulns = {}

        for node_id, data in self.graph.nodes(data=True):
            if data.get("node_type") == NodeType.PACKAGE.value:
                vulns = [
                    target
                    for target in self.get_neighbors(
                        node_id, edge_type=EdgeType.HAS_VULNERABILITY
                    )
                ]
                if vulns:
                    package_vulns[node_id] = vulns

        return package_vulns

    def clear(self) -> None:
        """Clear all nodes and edges from the graph."""
        self.graph.clear()
        logger.info("Cleared graph")

    def get_metadata(self) -> GraphMetadata:
        """
        Get graph metadata and statistics.

        Returns:
            GraphMetadata with node/edge counts
        """
        node_type_counts = {}
        for _, data in self.graph.nodes(data=True):
            node_type = data.get("node_type", "unknown")
            node_type_counts[node_type] = node_type_counts.get(node_type, 0) + 1

        edge_type_counts = {}
        for _, _, data in self.graph.edges(data=True):
            edge_type = data.get("edge_type", "unknown")
            edge_type_counts[edge_type] = edge_type_counts.get(edge_type, 0) + 1

        return GraphMetadata(
            node_count=self.graph.number_of_nodes(),
            edge_count=self.graph.number_of_edges(),
            node_type_counts=node_type_counts,
            edge_type_counts=edge_type_counts,
        )

    def save(self, path: str) -> None:
        """
        Persist graph to disk in GraphML format.

        Args:
            path: File path to save graph
        """
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Clean None/list values from attributes (GraphML only supports basic types)
        G = self.graph.copy()
        for node, data in G.nodes(data=True):
            for key in list(data.keys()):
                if data[key] is None:
                    del data[key]
                elif isinstance(data[key], (list, dict)):
                    # Convert complex types to JSON string
                    import json

                    data[key] = json.dumps(data[key])

        for u, v, data in G.edges(data=True):
            for key in list(data.keys()):
                if data[key] is None:
                    del data[key]
                elif isinstance(data[key], (list, dict)):
                    # Convert complex types to JSON string
                    import json

                    data[key] = json.dumps(data[key])

        nx.write_graphml(G, str(output_path))
        logger.info(f"Saved graph to {path}")

    def load(self, path: str) -> None:
        """
        Load graph from disk (GraphML format).

        Args:
            path: File path to load graph from
        """
        if not Path(path).exists():
            raise FileNotFoundError(f"Graph file not found: {path}")

        self.graph = nx.read_graphml(str(path))
        logger.info(f"Loaded graph from {path}")

    def export_to_dict(self) -> Dict[str, Any]:
        """
        Export graph to dictionary format.

        Returns:
            Dictionary representation of the graph
        """
        from networkx.readwrite import json_graph

        return json_graph.node_link_data(self.graph)

    def import_from_dict(self, data: Dict[str, Any]) -> None:
        """
        Import graph from dictionary format.

        Args:
            data: Dictionary representation of the graph
        """
        from networkx.readwrite import json_graph

        self.graph = json_graph.node_link_graph(data)
        logger.info("Imported graph from dictionary")
