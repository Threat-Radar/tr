"""Advanced graph query and analysis functions."""

import logging
from typing import List, Dict, Tuple, Set, Optional
import networkx as nx

from .graph_client import NetworkXClient
from .models import NodeType, EdgeType

logger = logging.getLogger(__name__)


class GraphAnalyzer:
    """Advanced graph analysis and query operations."""

    def __init__(self, client: NetworkXClient):
        """
        Initialize graph analyzer.

        Args:
            client: NetworkXClient instance to analyze
        """
        self.client = client
        self.graph = client.graph

    def blast_radius(self, cve_id: str) -> Dict[str, List[str]]:
        """
        Calculate the blast radius of a vulnerability.

        Finds all assets affected by a CVE by traversing the graph.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2023-1234")

        Returns:
            Dictionary mapping asset types to lists of affected asset IDs
        """
        cve_node = f"cve:{cve_id}"
        if cve_node not in self.graph:
            logger.warning(f"CVE not found in graph: {cve_id}")
            return {
                "packages": [],
                "containers": [],
                "services": [],
                "hosts": []
            }

        affected = {
            "packages": [],
            "containers": [],
            "services": [],
            "hosts": []
        }

        # Get all packages affected by this CVE (incoming HAS_VULNERABILITY edges)
        for node in self.graph.predecessors(cve_node):
            node_type = self.graph.nodes[node].get("node_type")

            if node_type == NodeType.PACKAGE.value:
                affected["packages"].append(node)

                # Find containers containing these packages
                for container in self.graph.predecessors(node):
                    container_type = self.graph.nodes[container].get("node_type")
                    if container_type == NodeType.CONTAINER.value:
                        if container not in affected["containers"]:
                            affected["containers"].append(container)

                        # Find services exposed by these containers
                        for successor in self.graph.successors(container):
                            successor_type = self.graph.nodes[successor].get("node_type")
                            if successor_type == NodeType.SERVICE.value:
                                if successor not in affected["services"]:
                                    affected["services"].append(successor)

                        # Find hosts running these containers
                        for successor in self.graph.successors(container):
                            successor_type = self.graph.nodes[successor].get("node_type")
                            if successor_type == NodeType.HOST.value:
                                if successor not in affected["hosts"]:
                                    affected["hosts"].append(successor)

        logger.info(
            f"Blast radius for {cve_id}: "
            f"{len(affected['packages'])} packages, "
            f"{len(affected['containers'])} containers, "
            f"{len(affected['services'])} services, "
            f"{len(affected['hosts'])} hosts"
        )

        return affected

    def most_vulnerable_packages(self, top_n: int = 10) -> List[Tuple[str, int, float]]:
        """
        Find packages with the most vulnerabilities.

        Args:
            top_n: Number of top packages to return

        Returns:
            List of tuples (package_id, vuln_count, avg_cvss_score)
        """
        vuln_counts = {}

        for node in self.graph.nodes():
            if self.graph.nodes[node].get("node_type") == NodeType.PACKAGE.value:
                # Count outgoing HAS_VULNERABILITY edges
                vulns = []
                for successor in self.graph.successors(node):
                    edge_data = self.graph.get_edge_data(node, successor)
                    if edge_data.get("edge_type") == EdgeType.HAS_VULNERABILITY.value:
                        vulns.append(successor)

                if vulns:
                    # Calculate average CVSS score
                    cvss_scores = []
                    for vuln_node in vulns:
                        cvss = self.graph.nodes[vuln_node].get("cvss_score")
                        if cvss is not None:
                            try:
                                cvss_scores.append(float(cvss))
                            except (ValueError, TypeError):
                                pass

                    avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0

                    vuln_counts[node] = (len(vulns), avg_cvss)

        # Sort by vulnerability count descending, then by CVSS score
        sorted_packages = sorted(
            vuln_counts.items(),
            key=lambda x: (x[1][0], x[1][1]),
            reverse=True
        )[:top_n]

        # Format results
        results = [
            (pkg, count, cvss)
            for pkg, (count, cvss) in sorted_packages
        ]

        logger.info(f"Found {len(results)} most vulnerable packages")
        return results

    def critical_path(
        self,
        source: str,
        target: str,
        max_length: int = 10
    ) -> List[List[str]]:
        """
        Find all paths from source to target (attack paths).

        Useful for identifying attack vectors through the infrastructure.

        Args:
            source: Source node ID
            target: Target node ID
            max_length: Maximum path length to search

        Returns:
            List of paths (each path is a list of node IDs)
        """
        if source not in self.graph or target not in self.graph:
            logger.warning(f"Source or target not found: {source} -> {target}")
            return []

        try:
            paths = list(nx.all_simple_paths(
                self.graph,
                source=source,
                target=target,
                cutoff=max_length
            ))
            logger.info(f"Found {len(paths)} paths from {source} to {target}")
            return paths
        except nx.NetworkXNoPath:
            logger.info(f"No path exists from {source} to {target}")
            return []

    def dependency_depth(self, container_id: str) -> int:
        """
        Calculate maximum dependency depth for a container.

        Args:
            container_id: Container node ID

        Returns:
            Maximum dependency chain length
        """
        container_node = f"container:{container_id}"
        if container_node not in self.graph:
            return 0

        try:
            # Use BFS to find maximum depth
            depths = nx.single_source_shortest_path_length(self.graph, container_node)
            return max(depths.values()) if depths else 0
        except nx.NetworkXError:
            return 0

    def find_fix_candidates(self, severity: Optional[str] = None) -> List[Dict]:
        """
        Find vulnerabilities with available fixes.

        Args:
            severity: Optional severity filter (critical, high, medium, low)

        Returns:
            List of fix candidate dictionaries with vuln and fix info
        """
        fix_candidates = []

        for node in self.graph.nodes():
            if self.graph.nodes[node].get("node_type") == NodeType.VULNERABILITY.value:
                vuln_severity = self.graph.nodes[node].get("severity", "").lower()

                # Apply severity filter
                if severity and vuln_severity != severity.lower():
                    continue

                # Find FIXED_BY edges
                for successor in self.graph.successors(node):
                    edge_data = self.graph.get_edge_data(node, successor)
                    if edge_data.get("edge_type") == EdgeType.FIXED_BY.value:
                        # Get affected packages (predecessors)
                        affected_packages = [
                            pred for pred in self.graph.predecessors(node)
                            if self.graph.nodes[pred].get("node_type") == NodeType.PACKAGE.value
                        ]

                        fix_candidates.append({
                            "cve_id": self.graph.nodes[node].get("cve_id"),
                            "severity": vuln_severity,
                            "cvss_score": self.graph.nodes[node].get("cvss_score"),
                            "affected_packages": affected_packages,
                            "fix_package": successor,
                            "fix_version": self.graph.nodes[successor].get("version"),
                        })

        logger.info(f"Found {len(fix_candidates)} fix candidates")
        return fix_candidates

    def vulnerability_statistics(self) -> Dict:
        """
        Calculate vulnerability statistics across the graph.

        Returns:
            Dictionary with vulnerability statistics
        """
        stats = {
            "total_vulnerabilities": 0,
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "negligible": 0,
            },
            "with_fixes": 0,
            "without_fixes": 0,
            "avg_cvss_score": 0.0,
        }

        cvss_scores = []

        for node in self.graph.nodes():
            if self.graph.nodes[node].get("node_type") == NodeType.VULNERABILITY.value:
                stats["total_vulnerabilities"] += 1

                # Count by severity
                severity = self.graph.nodes[node].get("severity", "").lower()
                if severity in stats["by_severity"]:
                    stats["by_severity"][severity] += 1

                # Check for fixes
                has_fix = any(
                    self.graph.get_edge_data(node, succ).get("edge_type") == EdgeType.FIXED_BY.value
                    for succ in self.graph.successors(node)
                )

                if has_fix:
                    stats["with_fixes"] += 1
                else:
                    stats["without_fixes"] += 1

                # Collect CVSS scores
                cvss = self.graph.nodes[node].get("cvss_score")
                if cvss is not None:
                    try:
                        cvss_scores.append(float(cvss))
                    except (ValueError, TypeError):
                        pass

        if cvss_scores:
            stats["avg_cvss_score"] = round(sum(cvss_scores) / len(cvss_scores), 2)

        return stats

    def package_usage_count(self) -> Dict[str, int]:
        """
        Count how many containers use each package.

        Returns:
            Dictionary mapping package names to usage counts
        """
        package_counts = {}

        for node in self.graph.nodes():
            if self.graph.nodes[node].get("node_type") == NodeType.PACKAGE.value:
                pkg_name = self.graph.nodes[node].get("name")
                if not pkg_name:
                    continue

                # Count incoming CONTAINS edges from containers
                container_count = sum(
                    1 for pred in self.graph.predecessors(node)
                    if self.graph.nodes[pred].get("node_type") == NodeType.CONTAINER.value
                )

                if pkg_name in package_counts:
                    package_counts[pkg_name] += container_count
                else:
                    package_counts[pkg_name] = container_count

        return package_counts

    def find_shared_vulnerabilities(self, container_ids: List[str]) -> List[str]:
        """
        Find vulnerabilities shared across multiple containers.

        Args:
            container_ids: List of container IDs to check

        Returns:
            List of CVE IDs present in all specified containers
        """
        if not container_ids:
            return []

        # Get vulnerabilities for each container
        container_vulns = []
        for container_id in container_ids:
            container_node = f"container:{container_id}"
            if container_node not in self.graph:
                continue

            vulns = set()
            # Get packages in container
            for pkg in self.graph.successors(container_node):
                if self.graph.nodes[pkg].get("node_type") == NodeType.PACKAGE.value:
                    # Get vulnerabilities in package
                    for vuln in self.graph.successors(pkg):
                        if self.graph.nodes[vuln].get("node_type") == NodeType.VULNERABILITY.value:
                            vulns.add(vuln)

            container_vulns.append(vulns)

        # Find intersection of all vulnerability sets
        if container_vulns:
            shared = set.intersection(*container_vulns)
            return list(shared)

        return []
