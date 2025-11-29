"""Graph builders for converting scan results to graph structures."""

import logging
from typing import Optional, List
from datetime import datetime

from .models import GraphNode, GraphEdge, NodeType, EdgeType
from .graph_client import GraphClient
from ..core.grype_integration import GrypeScanResult, GrypeVulnerability
from ..core.container_analyzer import ContainerAnalysis
from ..core.package_extractors import Package

logger = logging.getLogger(__name__)


class GraphBuilder:
    """
    Build vulnerability graphs from scan results.

    This class converts flat scan data (CVE results, container analysis)
    into graph structures for relationship-based queries.
    """

    def __init__(self, client: GraphClient):
        """
        Initialize graph builder.

        Args:
            client: Graph client to populate
        """
        self.client = client

    def build_from_scan(
        self,
        scan: GrypeScanResult,
        container: Optional[ContainerAnalysis] = None,
    ) -> None:
        """
        Build graph from CVE scan results and optional container analysis.

        Args:
            scan: GrypeScanResult from Grype scan
            container: Optional ContainerAnalysis for container metadata
        """
        logger.info(f"Building graph from scan: {scan.target}")

        # Add scan result node
        scan_node_id = self._add_scan_result_node(scan)

        # Add container node if available
        container_node_id = None
        if container:
            container_node_id = self._add_container_node(container)

            # Link scan to container
            self.client.add_edge(
                GraphEdge(
                    source_id=container_node_id,
                    target_id=scan_node_id,
                    edge_type=EdgeType.SCANNED_BY,
                    properties={"scan_date": datetime.now().isoformat()},
                )
            )

            # Add packages from container analysis
            self._add_packages_from_container(container, container_node_id)

        # Add vulnerabilities and packages from scan
        self._add_vulnerabilities_from_scan(scan, container_node_id)

        metadata = self.client.get_metadata()
        logger.info(
            f"Graph built: {metadata.node_count} nodes, " f"{metadata.edge_count} edges"
        )

    def _add_scan_result_node(self, scan: GrypeScanResult) -> str:
        """Add scan result node to graph."""
        scan_node_id = f"scan:{scan.target}:{datetime.now().timestamp()}"

        scan_node = GraphNode(
            node_id=scan_node_id,
            node_type=NodeType.SCAN_RESULT,
            properties={
                "target": scan.target,
                "total_vulnerabilities": scan.total_count,
                "critical_count": scan.severity_counts.get("critical", 0),
                "high_count": scan.severity_counts.get("high", 0),
                "medium_count": scan.severity_counts.get("medium", 0),
                "low_count": scan.severity_counts.get("low", 0),
                "timestamp": datetime.now().isoformat(),
            },
        )
        self.client.add_node(scan_node)
        logger.debug(f"Added scan result node: {scan_node_id}")

        return scan_node_id

    def _add_container_node(self, container: ContainerAnalysis) -> str:
        """Add container node to graph."""
        container_node_id = f"container:{container.image_id}"

        container_node = GraphNode(
            node_id=container_node_id,
            node_type=NodeType.CONTAINER,
            properties={
                "image_name": container.image_name,
                "image_id": container.image_id,
                "distro": container.distro,
                "distro_version": container.distro_version,
                "architecture": container.architecture,
                "os": container.os,
                "size": container.size,
                "created": container.created,
            },
        )
        self.client.add_node(container_node)
        logger.debug(f"Added container node: {container_node_id}")

        return container_node_id

    def _add_packages_from_container(
        self, container: ContainerAnalysis, container_node_id: str
    ) -> None:
        """Add package nodes from container analysis and link to container."""
        if not container.packages:
            return

        for pkg in container.packages:
            pkg_node_id = self._add_package_node(pkg)

            # Container CONTAINS package
            self.client.add_edge(
                GraphEdge(
                    source_id=container_node_id,
                    target_id=pkg_node_id,
                    edge_type=EdgeType.CONTAINS,
                )
            )

    def _add_package_node(self, pkg: Package) -> str:
        """Add package node to graph."""
        pkg_node_id = f"package:{pkg.name}@{pkg.version}"

        # Check if package already exists to avoid duplicates
        existing_node = self.client.get_node(pkg_node_id)
        if existing_node:
            return pkg_node_id

        pkg_node = GraphNode(
            node_id=pkg_node_id,
            node_type=NodeType.PACKAGE,
            properties={
                "name": pkg.name,
                "version": pkg.version,
                "architecture": pkg.architecture,
                "ecosystem": getattr(pkg, "package_type", "unknown"),
            },
        )
        self.client.add_node(pkg_node)
        logger.debug(f"Added package node: {pkg_node_id}")

        return pkg_node_id

    def _add_vulnerabilities_from_scan(
        self, scan: GrypeScanResult, container_node_id: Optional[str] = None
    ) -> None:
        """Add vulnerability nodes from scan and link to packages."""
        for vuln in scan.vulnerabilities:
            # Add vulnerability node
            vuln_node_id = self._add_vulnerability_node(vuln)

            # Add package node if not exists
            pkg_node_id = f"package:{vuln.package_name}@{vuln.package_version}"

            # Add package node with minimal info if not already present
            existing_pkg = self.client.get_node(pkg_node_id)
            if not existing_pkg:
                pkg_node = GraphNode(
                    node_id=pkg_node_id,
                    node_type=NodeType.PACKAGE,
                    properties={
                        "name": vuln.package_name,
                        "version": vuln.package_version,
                        "ecosystem": vuln.package_type,
                    },
                )
                self.client.add_node(pkg_node)

                # Link to container if available
                if container_node_id:
                    self.client.add_edge(
                        GraphEdge(
                            source_id=container_node_id,
                            target_id=pkg_node_id,
                            edge_type=EdgeType.CONTAINS,
                        )
                    )

            # Package HAS_VULNERABILITY
            self.client.add_edge(
                GraphEdge(
                    source_id=pkg_node_id,
                    target_id=vuln_node_id,
                    edge_type=EdgeType.HAS_VULNERABILITY,
                    properties={
                        "detected_version": vuln.package_version,
                    },
                )
            )

            # Add FIXED_BY edge if fix available
            if vuln.fixed_in_version:
                fixed_pkg_id = f"package:{vuln.package_name}@{vuln.fixed_in_version}"

                # Add fixed package node if not exists
                existing_fixed = self.client.get_node(fixed_pkg_id)
                if not existing_fixed:
                    fixed_node = GraphNode(
                        node_id=fixed_pkg_id,
                        node_type=NodeType.PACKAGE,
                        properties={
                            "name": vuln.package_name,
                            "version": vuln.fixed_in_version,
                            "ecosystem": vuln.package_type,
                            "is_fix": True,
                        },
                    )
                    self.client.add_node(fixed_node)

                # Vulnerability FIXED_BY package version
                self.client.add_edge(
                    GraphEdge(
                        source_id=vuln_node_id,
                        target_id=fixed_pkg_id,
                        edge_type=EdgeType.FIXED_BY,
                    )
                )

    def _add_vulnerability_node(self, vuln: GrypeVulnerability) -> str:
        """Add vulnerability node to graph."""
        vuln_node_id = f"cve:{vuln.id}"

        # Check if vulnerability already exists
        existing_vuln = self.client.get_node(vuln_node_id)
        if existing_vuln:
            return vuln_node_id

        vuln_node = GraphNode(
            node_id=vuln_node_id,
            node_type=NodeType.VULNERABILITY,
            properties={
                "cve_id": vuln.id,
                "severity": vuln.severity,
                "cvss_score": (
                    float(vuln.cvss_score) if vuln.cvss_score is not None else None
                ),
                "description": vuln.description,
                "data_source": vuln.data_source,
                "namespace": vuln.namespace,
                "urls": vuln.urls,
            },
        )
        self.client.add_node(vuln_node)
        logger.debug(f"Added vulnerability node: {vuln_node_id}")

        return vuln_node_id

    def add_container_dependencies(
        self, container_id: str, depends_on: List[str]
    ) -> None:
        """
        Add DEPENDS_ON edges between containers.

        Args:
            container_id: Source container ID
            depends_on: List of target container IDs
        """
        source_node_id = f"container:{container_id}"

        for dep_id in depends_on:
            target_node_id = f"container:{dep_id}"

            self.client.add_edge(
                GraphEdge(
                    source_id=source_node_id,
                    target_id=target_node_id,
                    edge_type=EdgeType.DEPENDS_ON,
                )
            )

        logger.info(
            f"Added {len(depends_on)} dependencies for container {container_id}"
        )

    def add_service_exposure(
        self, container_id: str, service_name: str, service_properties: dict
    ) -> None:
        """
        Add service node and EXPOSES edge.

        Args:
            container_id: Container exposing the service
            service_name: Name of the service
            service_properties: Service metadata (port, protocol, etc.)
        """
        container_node_id = f"container:{container_id}"
        service_node_id = f"service:{service_name}"

        # Add service node
        service_node = GraphNode(
            node_id=service_node_id,
            node_type=NodeType.SERVICE,
            properties=service_properties,
        )
        self.client.add_node(service_node)

        # Container EXPOSES service
        self.client.add_edge(
            GraphEdge(
                source_id=container_node_id,
                target_id=service_node_id,
                edge_type=EdgeType.EXPOSES,
            )
        )

        logger.info(f"Added service {service_name} exposed by {container_id}")
