"""Graph filtering utilities for focused visualization."""

import logging
from typing import Set, List, Optional, Dict, Any
import networkx as nx

from ..graph.graph_client import NetworkXClient
from ..graph.models import NodeType, EdgeType

logger = logging.getLogger(__name__)


class GraphFilter:
    """
    Graph filtering utilities for focused visualization.

    Provides methods to filter vulnerability graphs based on various criteria
    such as severity, node type, CVE ID, security zone, compliance scope, and more.
    Filtered graphs can be used for targeted analysis and visualization.

    Filter Types:
        - Severity: Filter by vulnerability severity (critical, high, medium, low)
        - Node Type: Filter by node types (container, package, vulnerability, etc.)
        - CVE: Filter by specific CVE identifiers
        - Package: Filter by package names
        - Security Zone: Filter by network zones (DMZ, internal, trusted, etc.)
        - Criticality: Filter by asset criticality levels
        - Compliance: Filter by compliance scope (PCI, HIPAA, SOX, GDPR)
        - Internet-Facing: Filter to show only internet-exposed assets
        - Search: Text search across node properties

    Example:
        >>> client = NetworkXClient()
        >>> client.load("vulnerability_graph.graphml")
        >>> graph_filter = GraphFilter(client)
        >>>
        >>> # Filter to show only CRITICAL vulnerabilities
        >>> critical_client = graph_filter.filter_by_severity("critical")
        >>> visualizer = NetworkGraphVisualizer(critical_client)
        >>> fig = visualizer.visualize()
        >>>
        >>> # Filter to show PCI-scoped assets
        >>> pci_client = graph_filter.filter_by_compliance(["pci"])
        >>>
        >>> # Filter to show specific CVE blast radius
        >>> cve_client = graph_filter.filter_by_cve(["CVE-2023-1234"], include_blast_radius=True)
        >>>
        >>> # Get available filter values
        >>> stats = graph_filter.get_filter_statistics()
        >>> print(stats["severities"])  # Show severity distribution
    """

    def __init__(self, client: NetworkXClient):
        """
        Initialize graph filter.

        Args:
            client: NetworkXClient instance with loaded graph
        """
        self.client = client
        self.graph = client.graph
        logger.info("Initialized GraphFilter")

    def filter_by_severity(
        self,
        min_severity: str,
        include_related: bool = True,
    ) -> NetworkXClient:
        """
        Filter graph to show only vulnerabilities above minimum severity.

        Args:
            min_severity: Minimum severity (critical, high, medium, low)
            include_related: Include related packages and containers

        Returns:
            New NetworkXClient with filtered graph
        """
        severity_order = ["negligible", "low", "medium", "high", "critical"]
        min_index = severity_order.index(min_severity.lower())

        # Find vulnerabilities meeting criteria
        vuln_nodes = set()
        for node, data in self.graph.nodes(data=True):
            if data.get("node_type") != NodeType.VULNERABILITY.value:
                continue

            severity = data.get("severity", "unknown").lower()
            if (
                severity in severity_order
                and severity_order.index(severity) >= min_index
            ):
                vuln_nodes.add(node)

        logger.info(f"Found {len(vuln_nodes)} vulnerabilities >= {min_severity}")

        # Build filtered graph
        filtered = self._build_filtered_graph(vuln_nodes, include_related)
        return filtered

    def filter_by_node_type(
        self,
        node_types: List[str],
        include_connections: bool = True,
    ) -> NetworkXClient:
        """
        Filter graph to show only specific node types.

        Args:
            node_types: List of node types to include
            include_connections: Include edges between filtered nodes

        Returns:
            New NetworkXClient with filtered graph
        """
        # Find matching nodes
        matching_nodes = set()
        for node, data in self.graph.nodes(data=True):
            if data.get("node_type") in node_types:
                matching_nodes.add(node)

        logger.info(f"Found {len(matching_nodes)} nodes of types {node_types}")

        # Build filtered graph
        filtered = self._build_filtered_graph(matching_nodes, include_connections)
        return filtered

    def filter_by_cve(
        self,
        cve_ids: List[str],
        include_blast_radius: bool = True,
    ) -> NetworkXClient:
        """
        Filter graph to show specific CVEs and their impact.

        Args:
            cve_ids: List of CVE IDs to include
            include_blast_radius: Include affected packages and containers

        Returns:
            New NetworkXClient with filtered graph
        """
        # Find CVE nodes
        cve_nodes = set()
        for node, data in self.graph.nodes(data=True):
            if data.get("node_type") == NodeType.VULNERABILITY.value:
                cve_id = data.get("cve_id", "")
                if cve_id in cve_ids or node in [f"cve:{cve}" for cve in cve_ids]:
                    cve_nodes.add(node)

        logger.info(f"Found {len(cve_nodes)} CVE nodes")

        # Build filtered graph
        filtered = self._build_filtered_graph(cve_nodes, include_blast_radius)
        return filtered

    def filter_by_package(
        self,
        package_names: List[str],
        include_vulnerabilities: bool = True,
    ) -> NetworkXClient:
        """
        Filter graph to show specific packages.

        Args:
            package_names: List of package names to include
            include_vulnerabilities: Include package vulnerabilities

        Returns:
            New NetworkXClient with filtered graph
        """
        # Find package nodes
        package_nodes = set()
        for node, data in self.graph.nodes(data=True):
            if data.get("node_type") == NodeType.PACKAGE.value:
                pkg_name = data.get("name", "")
                if any(pname in pkg_name for pname in package_names):
                    package_nodes.add(node)

        logger.info(f"Found {len(package_nodes)} package nodes")

        # Build filtered graph
        filtered = self._build_filtered_graph(package_nodes, include_vulnerabilities)
        return filtered

    def filter_by_zone(
        self,
        zones: List[str],
        include_related: bool = True,
    ) -> NetworkXClient:
        """
        Filter graph to show nodes in specific security zones.

        Args:
            zones: List of zone names
            include_related: Include related nodes

        Returns:
            New NetworkXClient with filtered graph
        """
        # Find nodes in zones
        zone_nodes = set()
        for node, data in self.graph.nodes(data=True):
            node_zone = data.get("zone", "").lower()
            if node_zone in [z.lower() for z in zones]:
                zone_nodes.add(node)

        logger.info(f"Found {len(zone_nodes)} nodes in zones {zones}")

        # Build filtered graph
        filtered = self._build_filtered_graph(zone_nodes, include_related)
        return filtered

    def filter_by_criticality(
        self,
        min_criticality: str,
        include_related: bool = True,
    ) -> NetworkXClient:
        """
        Filter graph to show nodes above minimum criticality.

        Args:
            min_criticality: Minimum criticality (critical, high, medium, low)
            include_related: Include related nodes

        Returns:
            New NetworkXClient with filtered graph
        """
        criticality_order = ["low", "medium", "high", "critical"]
        min_index = criticality_order.index(min_criticality.lower())

        # Find nodes meeting criteria
        critical_nodes = set()
        for node, data in self.graph.nodes(data=True):
            criticality = data.get("criticality", "").lower()
            if (
                criticality in criticality_order
                and criticality_order.index(criticality) >= min_index
            ):
                critical_nodes.add(node)

        logger.info(
            f"Found {len(critical_nodes)} nodes with criticality >= {min_criticality}"
        )

        # Build filtered graph
        filtered = self._build_filtered_graph(critical_nodes, include_related)
        return filtered

    def filter_by_compliance(
        self,
        compliance_types: List[str],
        include_related: bool = True,
    ) -> NetworkXClient:
        """
        Filter graph to show nodes in compliance scope.

        Args:
            compliance_types: List of compliance types (pci, hipaa, sox, gdpr)
            include_related: Include related nodes

        Returns:
            New NetworkXClient with filtered graph
        """
        # Find nodes in compliance scope
        compliance_nodes = set()
        for node, data in self.graph.nodes(data=True):
            for comp_type in compliance_types:
                if data.get(f"{comp_type.lower()}_scope"):
                    compliance_nodes.add(node)
                    break

        logger.info(f"Found {len(compliance_nodes)} nodes in {compliance_types} scope")

        # Build filtered graph
        filtered = self._build_filtered_graph(compliance_nodes, include_related)
        return filtered

    def filter_by_internet_facing(
        self,
        include_related: bool = True,
    ) -> NetworkXClient:
        """
        Filter graph to show internet-facing assets.

        Args:
            include_related: Include related nodes

        Returns:
            New NetworkXClient with filtered graph
        """
        # Find internet-facing nodes
        internet_nodes = set()
        for node, data in self.graph.nodes(data=True):
            if data.get("internet_facing") or data.get("has_public_port"):
                internet_nodes.add(node)

        logger.info(f"Found {len(internet_nodes)} internet-facing nodes")

        # Build filtered graph
        filtered = self._build_filtered_graph(internet_nodes, include_related)
        return filtered

    def filter_by_search(
        self,
        search_term: str,
        search_fields: Optional[List[str]] = None,
        include_related: bool = True,
    ) -> NetworkXClient:
        """
        Filter graph by searching node properties.

        Args:
            search_term: Search term to match
            search_fields: Fields to search (default: name, cve_id, description)
            include_related: Include related nodes

        Returns:
            New NetworkXClient with filtered graph
        """
        if search_fields is None:
            search_fields = ["name", "cve_id", "description", "package_name"]

        # Find matching nodes
        matching_nodes = set()
        search_lower = search_term.lower()

        for node, data in self.graph.nodes(data=True):
            # Check if node ID matches
            if search_lower in node.lower():
                matching_nodes.add(node)
                continue

            # Check fields
            for field in search_fields:
                value = data.get(field, "")
                if value and search_lower in str(value).lower():
                    matching_nodes.add(node)
                    break

        logger.info(f"Found {len(matching_nodes)} nodes matching '{search_term}'")

        # Build filtered graph
        filtered = self._build_filtered_graph(matching_nodes, include_related)
        return filtered

    def filter_subgraph(
        self,
        center_nodes: Set[str],
        hops: int = 1,
    ) -> NetworkXClient:
        """
        Extract subgraph within N hops of center nodes.

        Args:
            center_nodes: Center nodes to start from
            hops: Number of hops to include (default: 1)

        Returns:
            New NetworkXClient with subgraph
        """
        # Find all nodes within N hops
        subgraph_nodes = set(center_nodes)

        for _ in range(hops):
            new_nodes = set()
            for node in subgraph_nodes:
                if node in self.graph:
                    new_nodes.update(self.graph.predecessors(node))
                    new_nodes.update(self.graph.successors(node))

            subgraph_nodes.update(new_nodes)

        logger.info(
            f"Extracted subgraph with {len(subgraph_nodes)} nodes ({hops} hops)"
        )

        # Build filtered graph
        filtered_graph = self.graph.subgraph(subgraph_nodes).copy()

        # Create new client
        filtered_client = NetworkXClient()
        filtered_client.graph = filtered_graph

        return filtered_client

    def _build_filtered_graph(
        self,
        seed_nodes: Set[str],
        include_related: bool,
    ) -> NetworkXClient:
        """
        Build filtered graph from seed nodes.

        Args:
            seed_nodes: Starting nodes
            include_related: Whether to include related nodes

        Returns:
            New NetworkXClient with filtered graph
        """
        if not include_related:
            # Only include seed nodes
            filtered_graph = self.graph.subgraph(seed_nodes).copy()
        else:
            # Include seed nodes + immediate neighbors
            all_nodes = set(seed_nodes)

            for node in seed_nodes:
                if node in self.graph:
                    all_nodes.update(self.graph.predecessors(node))
                    all_nodes.update(self.graph.successors(node))

            filtered_graph = self.graph.subgraph(all_nodes).copy()

        logger.debug(
            f"Built filtered graph: {filtered_graph.number_of_nodes()} nodes, {filtered_graph.number_of_edges()} edges"
        )

        # Create new client
        filtered_client = NetworkXClient()
        filtered_client.graph = filtered_graph

        return filtered_client

    def get_filter_statistics(self) -> Dict[str, Any]:
        """Get statistics about available filter values."""
        stats = {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "node_types": {},
            "severities": {},
            "zones": {},
            "criticalities": {},
            "compliance_scopes": {
                "pci": 0,
                "hipaa": 0,
                "sox": 0,
                "gdpr": 0,
            },
            "internet_facing": 0,
        }

        for node, data in self.graph.nodes(data=True):
            # Node types
            node_type = data.get("node_type", "unknown")
            stats["node_types"][node_type] = stats["node_types"].get(node_type, 0) + 1

            # Severities
            if node_type == NodeType.VULNERABILITY.value:
                severity = data.get("severity", "unknown")
                stats["severities"][severity] = stats["severities"].get(severity, 0) + 1

            # Zones
            zone = data.get("zone", "")
            if zone:
                stats["zones"][zone] = stats["zones"].get(zone, 0) + 1

            # Criticalities
            criticality = data.get("criticality", "")
            if criticality:
                stats["criticalities"][criticality] = (
                    stats["criticalities"].get(criticality, 0) + 1
                )

            # Compliance
            for comp in ["pci", "hipaa", "sox", "gdpr"]:
                if data.get(f"{comp}_scope"):
                    stats["compliance_scopes"][comp] += 1

            # Internet-facing
            if data.get("internet_facing") or data.get("has_public_port"):
                stats["internet_facing"] += 1

        return stats
