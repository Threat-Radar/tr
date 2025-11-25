"""Advanced graph query and analysis functions."""

import logging
from typing import List, Dict, Tuple, Set, Optional
import networkx as nx
from itertools import combinations
import signal
from contextlib import contextmanager

from .graph_client import NetworkXClient
from .models import (
    NodeType,
    EdgeType,
    AttackPath,
    AttackStep,
    AttackStepType,
    ThreatLevel,
    PrivilegeEscalationPath,
    LateralMovementOpportunity,
    AttackSurface,
)
from .exceptions import (
    GraphTraversalError,
    MalformedGraphError,
    TraversalLimitExceeded,
    TimeoutExceeded,
)
from . import constants

logger = logging.getLogger(__name__)


@contextmanager
def timeout_handler(seconds: int):
    """Context manager for operation timeout."""
    def timeout_signal_handler(signum, frame):
        raise TimeoutExceeded(f"Operation exceeded {seconds} second timeout")

    # Set the signal handler and alarm
    old_handler = signal.signal(signal.SIGALRM, timeout_signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


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

    def identify_entry_points(self) -> List[str]:
        """
        Identify potential entry points in the infrastructure.

        Entry points are assets that are:
        - Internet-facing (exposed to public)
        - Have public exposed ports
        - Services accessible from outside

        Returns:
            List of node IDs that are potential entry points
        """
        entry_points = []

        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            node_type = node_data.get("node_type")

            # Check for internet-facing assets
            if node_data.get("internet_facing") is True:
                entry_points.append(node)
                continue

            # Check for public exposed ports
            if node_data.get("has_public_port") is True:
                entry_points.append(node)
                continue

            # Check for assets in DMZ or public zones
            zone = node_data.get("zone", "").lower()
            if zone in ["dmz", "public", "internet"]:
                entry_points.append(node)
                continue

            # Check for services with public exposure
            if node_type == NodeType.SERVICE.value:
                if node_data.get("public") is True:
                    entry_points.append(node)

        logger.info(f"Identified {len(entry_points)} potential entry points")
        return entry_points

    def identify_high_value_targets(self) -> List[str]:
        """
        Identify high-value targets in the infrastructure.

        High-value targets are assets that:
        - Have critical business context
        - Are in PCI/HIPAA scope
        - Handle sensitive data
        - Have high criticality scores

        Returns:
            List of node IDs that are high-value targets
        """
        high_value_targets = []

        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]

            # Check criticality level
            criticality = node_data.get("criticality", "").lower()
            if criticality in ["critical", "high"]:
                high_value_targets.append(node)
                continue

            # Check criticality score
            criticality_score = node_data.get("criticality_score", 0)
            if criticality_score >= 80:
                high_value_targets.append(node)
                continue

            # Check compliance scope
            if node_data.get("pci_scope") is True or node_data.get("hipaa_scope") is True:
                high_value_targets.append(node)
                continue

            # Check data classification
            data_class = node_data.get("data_classification", "").lower()
            if data_class in ["pci", "hipaa", "confidential"]:
                high_value_targets.append(node)
                continue

            # Check for database or payment processing functions
            function = node_data.get("function", "").lower()
            if any(keyword in function for keyword in ["database", "payment", "auth", "credential"]):
                high_value_targets.append(node)

        logger.info(f"Identified {len(high_value_targets)} high-value targets")
        return high_value_targets

    def find_shortest_attack_paths(
        self,
        entry_points: Optional[List[str]] = None,
        targets: Optional[List[str]] = None,
        max_length: Optional[int] = None,
        max_paths: Optional[int] = None
    ) -> List[AttackPath]:
        """
        Find shortest attack paths from entry points to high-value targets.

        Args:
            entry_points: List of entry point node IDs (auto-detected if None)
            targets: List of target node IDs (auto-detected if None)
            max_length: Maximum path length to consider (default: constants.MAX_PATH_LENGTH)
            max_paths: Maximum number of paths to return (default: constants.MAX_ATTACK_PATHS)

        Returns:
            List of AttackPath objects representing shortest paths

        Raises:
            GraphTraversalError: If graph traversal fails
            TraversalLimitExceeded: If traversal exceeds safety limits
            TimeoutExceeded: If operation times out
        """
        # Apply default limits
        if max_length is None:
            max_length = constants.MAX_PATH_LENGTH
        if max_paths is None:
            max_paths = constants.MAX_ATTACK_PATHS

        # Validate inputs
        if max_length > constants.MAX_GRAPH_TRAVERSAL_DEPTH:
            raise TraversalLimitExceeded(
                f"max_length ({max_length}) exceeds safety limit ({constants.MAX_GRAPH_TRAVERSAL_DEPTH})"
            )

        try:
            # Auto-detect entry points and targets if not provided
            if entry_points is None:
                entry_points = self.identify_entry_points()

            if targets is None:
                targets = self.identify_high_value_targets()

            if not entry_points:
                logger.warning("No entry points found")
                return []

            if not targets:
                logger.warning("No high-value targets found")
                return []

            # Check for DoS risk
            max_combinations = len(entry_points) * len(targets)
            if max_combinations > constants.MAX_NODES_TO_VISIT:
                logger.warning(
                    f"Large graph: {len(entry_points)} entry points × {len(targets)} targets = "
                    f"{max_combinations} combinations. Limiting to first {constants.MAX_NODES_TO_VISIT} checks."
                )

            attack_paths = []
            path_id = 0
            checks_performed = 0

            # Find shortest path from each entry point to each target
            for entry in entry_points:
                for target in targets:
                    if entry == target:
                        continue

                    # DoS prevention: limit number of path checks
                    checks_performed += 1
                    if checks_performed > constants.MAX_NODES_TO_VISIT:
                        logger.warning(
                            f"Exceeded maximum path checks ({constants.MAX_NODES_TO_VISIT}). "
                            f"Returning {len(attack_paths)} paths found so far."
                        )
                        break

                    # Stop if we've found enough paths
                    if len(attack_paths) >= max_paths:
                        logger.info(f"Reached max_paths limit ({max_paths})")
                        break

                    try:
                        # Use NetworkX shortest path algorithm
                        shortest_path = nx.shortest_path(
                            self.graph,
                            source=entry,
                            target=target
                        )

                        if len(shortest_path) <= max_length:
                            attack_path = self._convert_to_attack_path(
                                path_id=f"path_{path_id}",
                                node_path=shortest_path,
                                entry_point=entry,
                                target=target
                            )
                            attack_paths.append(attack_path)
                            path_id += 1

                    except nx.NetworkXNoPath:
                        logger.debug(f"No path from {entry} to {target}")
                        continue
                    except nx.NodeNotFound as e:
                        logger.warning(f"Node not found: {e}")
                        continue
                    except Exception as e:
                        logger.error(f"Unexpected error finding path {entry} -> {target}: {e}")
                        continue

                # Break outer loop if max paths reached
                if len(attack_paths) >= max_paths:
                    break

        except TimeoutExceeded:
            logger.error("Attack path discovery timed out")
            raise
        except Exception as e:
            logger.error(f"Error during attack path discovery: {e}")
            raise GraphTraversalError(f"Failed to find attack paths: {e}") from e

        # Sort by threat level and path length
        attack_paths.sort(
            key=lambda p: (
                p.threat_level == ThreatLevel.CRITICAL,
                -p.total_cvss,
                p.path_length
            ),
            reverse=True
        )

        logger.info(f"Found {len(attack_paths)} attack paths")
        return attack_paths

    def _convert_to_attack_path(
        self,
        path_id: str,
        node_path: List[str],
        entry_point: str,
        target: str
    ) -> AttackPath:
        """
        Convert a node path to an AttackPath with detailed steps.

        Args:
            path_id: Unique identifier for the path
            node_path: List of node IDs in the path
            entry_point: Entry point node ID
            target: Target node ID

        Returns:
            AttackPath object with detailed attack steps
        """
        steps = []
        vulnerabilities = []
        total_cvss = 0.0

        for i, node_id in enumerate(node_path):
            node_data = self.graph.nodes[node_id]

            # Determine step type
            if i == 0:
                step_type = AttackStepType.ENTRY_POINT
            elif i == len(node_path) - 1:
                step_type = AttackStepType.TARGET_ACCESS
            else:
                # Check if this is a privilege escalation or lateral movement
                if self._is_privilege_escalation_step(node_path[i-1], node_id):
                    step_type = AttackStepType.PRIVILEGE_ESCALATION
                elif self._is_lateral_movement_step(node_path[i-1], node_id):
                    step_type = AttackStepType.LATERAL_MOVEMENT
                else:
                    step_type = AttackStepType.EXPLOIT_VULNERABILITY

            # Get vulnerabilities for this node
            # Need to traverse: CONTAINER -> PACKAGE -> VULNERABILITY
            node_vulns = []
            cvss_score = None

            # First, find all packages contained by this node
            for package_node in self.graph.successors(node_id):
                package_data = self.graph.nodes.get(package_node, {})

                # Check if this is a package node
                if package_data.get("node_type") == NodeType.PACKAGE.value:
                    # Then find vulnerabilities for this package
                    for vuln_node in self.graph.successors(package_node):
                        vuln_data = self.graph.nodes.get(vuln_node, {})

                        if vuln_data.get("node_type") == NodeType.VULNERABILITY.value:
                            cve_id = vuln_data.get("cve_id")
                            if cve_id:
                                node_vulns.append(cve_id)
                                vulnerabilities.append(cve_id)

                                # Get highest CVSS score
                                node_cvss = vuln_data.get("cvss_score")
                                if node_cvss:
                                    try:
                                        cvss_val = float(node_cvss)
                                        total_cvss += cvss_val
                                        if cvss_score is None or cvss_val > cvss_score:
                                            cvss_score = cvss_val
                                    except (ValueError, TypeError):
                                        pass

                # Also check for direct vulnerability connections (for backwards compatibility)
                elif package_data.get("node_type") == NodeType.VULNERABILITY.value:
                    cve_id = package_data.get("cve_id")
                    if cve_id:
                        node_vulns.append(cve_id)
                        vulnerabilities.append(cve_id)

                        # Get highest CVSS score
                        node_cvss = package_data.get("cvss_score")
                        if node_cvss:
                            try:
                                cvss_val = float(node_cvss)
                                total_cvss += cvss_val
                                if cvss_score is None or cvss_val > cvss_score:
                                    cvss_score = cvss_val
                            except (ValueError, TypeError):
                                pass

            # Create attack step
            step = AttackStep(
                node_id=node_id,
                step_type=step_type,
                description=self._generate_step_description(node_id, step_type, node_data),
                vulnerabilities=node_vulns,
                cvss_score=cvss_score
            )
            steps.append(step)

        # Determine threat level based on maximum CVSS in the path
        # An attack path is as dangerous as its most critical vulnerability
        max_cvss = max((step.cvss_score for step in steps if step.cvss_score is not None), default=0.0)

        # Apply business context multipliers to CVSS
        target_data = self.graph.nodes.get(target, {})
        business_multiplier = self._calculate_business_multiplier(target_data)
        effective_cvss = min(10.0, max_cvss * business_multiplier)

        # Classify threat level using constants
        if effective_cvss >= constants.CVSS_CRITICAL_THRESHOLD:
            threat_level = ThreatLevel.CRITICAL
        elif effective_cvss >= constants.CVSS_HIGH_THRESHOLD:
            threat_level = ThreatLevel.HIGH
        elif effective_cvss >= constants.CVSS_MEDIUM_THRESHOLD:
            threat_level = ThreatLevel.MEDIUM
        else:
            threat_level = ThreatLevel.LOW

        # Calculate exploitability (based on path length and CVSS)
        # Shorter paths with higher CVSS are more exploitable
        exploitability = max(
            constants.MIN_EXPLOITABILITY,
            min(
                constants.MAX_EXPLOITABILITY,
                constants.MAX_EXPLOITABILITY - (len(node_path) * constants.EXPLOITABILITY_STEP_PENALTY)
            )
        )

        return AttackPath(
            path_id=path_id,
            entry_point=entry_point,
            target=target,
            steps=steps,
            total_cvss=round(total_cvss, 2),
            threat_level=threat_level,
            exploitability=exploitability,
            path_length=len(node_path),
            description=f"Attack path from {entry_point} to {target} via {len(node_path)-2} intermediate nodes"
        )

    def _calculate_business_multiplier(self, target_data: Dict) -> float:
        """
        Calculate business context multiplier for threat scoring.

        Considers criticality, compliance scope, and customer-facing status
        to adjust CVSS scores based on business impact.

        Args:
            target_data: Node data dictionary for the target asset

        Returns:
            Multiplier value (>= 1.0) to apply to CVSS score
        """
        multiplier = 1.0

        # Criticality multiplier
        criticality = target_data.get("criticality", "").lower()
        if criticality == "critical":
            multiplier *= constants.BUSINESS_CRITICAL_MULTIPLIER
        elif criticality == "high":
            multiplier *= constants.BUSINESS_HIGH_MULTIPLIER

        # Compliance scope multipliers
        if target_data.get("pci_scope"):
            multiplier *= constants.PCI_SCOPE_MULTIPLIER

        if target_data.get("hipaa_scope"):
            multiplier *= constants.HIPAA_SCOPE_MULTIPLIER

        # Customer-facing multiplier
        if target_data.get("customer_facing"):
            multiplier *= constants.CUSTOMER_FACING_MULTIPLIER

        return multiplier

    def _is_privilege_escalation_step(self, from_node: str, to_node: str) -> bool:
        """Check if a step represents privilege escalation."""
        from_data = self.graph.nodes[from_node]
        to_data = self.graph.nodes[to_node]

        # Check for zone escalation (DMZ -> internal)
        from_zone = from_data.get("zone", "").lower()
        to_zone = to_data.get("zone", "").lower()

        zone_escalations = [
            ("dmz", "internal"),
            ("public", "internal"),
            ("untrusted", "trusted"),
        ]

        if (from_zone, to_zone) in zone_escalations:
            return True

        # Check for privilege level changes
        from_priv = from_data.get("privilege_level", "user")
        to_priv = to_data.get("privilege_level", "user")

        if from_priv == "user" and to_priv in ["admin", "root"]:
            return True

        return False

    def _is_lateral_movement_step(self, from_node: str, to_node: str) -> bool:
        """Check if a step represents lateral movement."""
        from_type = self.graph.nodes[from_node].get("node_type")
        to_type = self.graph.nodes[to_node].get("node_type")

        # Movement between containers/assets in same zone is lateral movement
        if from_type == to_type and from_type in [NodeType.CONTAINER.value, NodeType.HOST.value]:
            from_zone = self.graph.nodes[from_node].get("zone", "")
            to_zone = self.graph.nodes[to_node].get("zone", "")

            if from_zone == to_zone and from_zone:
                return True

        return False

    def _generate_step_description(self, node_id: str, step_type: AttackStepType, node_data: Dict) -> str:
        """Generate human-readable description for an attack step."""
        node_name = node_data.get("name", node_id)
        node_type = node_data.get("node_type", "unknown")

        if step_type == AttackStepType.ENTRY_POINT:
            return f"Gain initial access via {node_name} ({node_type})"
        elif step_type == AttackStepType.EXPLOIT_VULNERABILITY:
            return f"Exploit vulnerabilities in {node_name}"
        elif step_type == AttackStepType.PRIVILEGE_ESCALATION:
            return f"Escalate privileges through {node_name}"
        elif step_type == AttackStepType.LATERAL_MOVEMENT:
            return f"Move laterally to {node_name}"
        elif step_type == AttackStepType.TARGET_ACCESS:
            return f"Gain access to target: {node_name}"
        else:
            return f"Access {node_name}"

    def detect_privilege_escalation_paths(
        self,
        max_paths: int = 20
    ) -> List[PrivilegeEscalationPath]:
        """
        Detect privilege escalation opportunities in the infrastructure.

        Identifies paths where an attacker can escalate from lower to higher
        privilege levels by exploiting vulnerabilities or misconfigurations.

        Args:
            max_paths: Maximum number of paths to return

        Returns:
            List of PrivilegeEscalationPath objects
        """
        escalation_paths = []

        # Find all low-privilege entry points
        low_priv_nodes = []
        high_priv_nodes = []

        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            zone = node_data.get("zone", "").lower()
            priv_level = node_data.get("privilege_level", "user")

            # Low privilege: DMZ, public zones, user-level access
            if zone in ["dmz", "public", "untrusted"] or priv_level == "user":
                low_priv_nodes.append(node)

            # High privilege: internal zones, admin/root access
            if zone in ["internal", "trusted"] or priv_level in ["admin", "root"]:
                high_priv_nodes.append(node)

        logger.info(f"Analyzing {len(low_priv_nodes)} low-priv -> {len(high_priv_nodes)} high-priv combinations")

        # Find paths from low to high privilege
        for low_node in low_priv_nodes:
            for high_node in high_priv_nodes:
                if low_node == high_node:
                    continue

                try:
                    # Find shortest path
                    path = nx.shortest_path(self.graph, low_node, high_node)

                    # Check if path actually involves privilege escalation
                    has_escalation = False
                    for i in range(len(path) - 1):
                        if self._is_privilege_escalation_step(path[i], path[i+1]):
                            has_escalation = True
                            break

                    if has_escalation and len(path) <= 10:
                        # Convert to attack path
                        attack_path = self._convert_to_attack_path(
                            path_id=f"privesc_{len(escalation_paths)}",
                            node_path=path,
                            entry_point=low_node,
                            target=high_node
                        )

                        # Determine difficulty using constants
                        if len(path) <= constants.ESCALATION_EASY_MAX_STEPS:
                            difficulty = "easy"
                        elif len(path) <= constants.ESCALATION_MEDIUM_MAX_STEPS:
                            difficulty = "medium"
                        else:
                            difficulty = "hard"

                        # Extract unique vulnerabilities
                        vulns = list(set([
                            vuln for step in attack_path.steps
                            for vuln in step.vulnerabilities
                        ]))

                        escalation_path = PrivilegeEscalationPath(
                            from_privilege=self.graph.nodes[low_node].get("zone", "public"),
                            to_privilege=self.graph.nodes[high_node].get("zone", "internal"),
                            path=attack_path,
                            vulnerabilities=vulns,
                            difficulty=difficulty,
                            mitigation=self._generate_mitigation_steps(attack_path)
                        )

                        escalation_paths.append(escalation_path)

                        if len(escalation_paths) >= max_paths:
                            break

                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

            if len(escalation_paths) >= max_paths:
                break

        logger.info(f"Found {len(escalation_paths)} privilege escalation paths")
        return escalation_paths

    def identify_lateral_movement_opportunities(
        self,
        max_opportunities: int = 50
    ) -> List[LateralMovementOpportunity]:
        """
        Identify lateral movement opportunities between assets.

        Finds ways an attacker could move between compromised assets to
        expand their foothold in the infrastructure.

        Args:
            max_opportunities: Maximum number of opportunities to return

        Returns:
            List of LateralMovementOpportunity objects
        """
        opportunities = []

        # Get all container and host nodes
        assets = [
            node for node in self.graph.nodes()
            if self.graph.nodes[node].get("node_type") in [
                NodeType.CONTAINER.value,
                NodeType.HOST.value
            ]
        ]

        logger.info(f"Analyzing {len(assets)} assets for lateral movement")

        # Check pairs of assets in the same zone
        for i, asset1 in enumerate(assets):
            for asset2 in assets[i+1:]:
                if asset1 == asset2:
                    continue

                asset1_data = self.graph.nodes[asset1]
                asset2_data = self.graph.nodes[asset2]

                # Check if in same zone (lateral movement opportunity)
                zone1 = asset1_data.get("zone", "")
                zone2 = asset2_data.get("zone", "")

                if zone1 and zone1 == zone2:
                    # Check if there's a network path
                    try:
                        path = nx.shortest_path(self.graph, asset1, asset2)

                        if len(path) <= 5:  # Short paths more likely for lateral movement
                            # Convert to attack path
                            attack_path = self._convert_to_attack_path(
                                path_id=f"lateral_{len(opportunities)}",
                                node_path=path,
                                entry_point=asset1,
                                target=asset2
                            )

                            # Determine movement type
                            if any("COMMUNICATES_WITH" in str(self.graph.get_edge_data(path[i], path[i+1]))
                                   for i in range(len(path)-1)):
                                movement_type = "network"
                            else:
                                movement_type = "vulnerability"

                            # Extract vulnerabilities
                            vulns = list(set([
                                vuln for step in attack_path.steps
                                for vuln in step.vulnerabilities
                            ]))

                            opportunity = LateralMovementOpportunity(
                                from_asset=asset1,
                                to_asset=asset2,
                                movement_type=movement_type,
                                path=attack_path,
                                vulnerabilities=vulns,
                                network_requirements=[f"Access to {zone1} zone"],
                                prerequisites=[f"Compromise of {asset1_data.get('name', asset1)}"],
                                detection_difficulty=(
                                    "easy" if len(path) <= constants.LATERAL_MOVEMENT_EASY_MAX_STEPS
                                    else "medium" if len(path) <= constants.LATERAL_MOVEMENT_MEDIUM_MAX_STEPS
                                    else "hard"
                                )
                            )

                            opportunities.append(opportunity)

                            if len(opportunities) >= max_opportunities:
                                break

                    except (nx.NetworkXNoPath, nx.NodeNotFound):
                        continue

            if len(opportunities) >= max_opportunities:
                break

        logger.info(f"Found {len(opportunities)} lateral movement opportunities")
        return opportunities

    def analyze_attack_surface(
        self,
        entry_points: Optional[List[str]] = None,
        targets: Optional[List[str]] = None,
        max_paths: int = 50
    ) -> AttackSurface:
        """
        Comprehensive attack surface analysis.

        Combines all attack path analysis methods to provide a complete
        security assessment.

        Args:
            entry_points: Optional list of entry point node IDs
            targets: Optional list of target node IDs
            max_paths: Maximum paths to analyze

        Returns:
            AttackSurface object with complete analysis
        """
        logger.info("Starting comprehensive attack surface analysis")

        # Identify entry points and targets
        if entry_points is None:
            entry_points = self.identify_entry_points()

        if targets is None:
            targets = self.identify_high_value_targets()

        # Find attack paths
        attack_paths = self.find_shortest_attack_paths(
            entry_points=entry_points,
            targets=targets,
            max_length=10
        )[:max_paths]

        # Detect privilege escalations
        privilege_escalations = self.detect_privilege_escalation_paths(
            max_paths=max_paths // 2
        )

        # Identify lateral movements
        lateral_movements = self.identify_lateral_movement_opportunities(
            max_opportunities=max_paths
        )

        # Calculate total risk score
        total_risk_score = self._calculate_total_risk(
            attack_paths=attack_paths,
            privilege_escalations=privilege_escalations,
            lateral_movements=lateral_movements
        )

        # Generate recommendations
        recommendations = self._generate_security_recommendations(
            attack_paths=attack_paths,
            privilege_escalations=privilege_escalations,
            lateral_movements=lateral_movements
        )

        attack_surface = AttackSurface(
            entry_points=entry_points,
            high_value_targets=targets,
            attack_paths=attack_paths,
            privilege_escalations=privilege_escalations,
            lateral_movements=lateral_movements,
            total_risk_score=total_risk_score,
            recommendations=recommendations
        )

        logger.info(
            f"Attack surface analysis complete: "
            f"{len(attack_paths)} paths, "
            f"{len(privilege_escalations)} privilege escalations, "
            f"{len(lateral_movements)} lateral movements"
        )

        return attack_surface

    def _calculate_total_risk(
        self,
        attack_paths: List[AttackPath],
        privilege_escalations: List[PrivilegeEscalationPath],
        lateral_movements: List[LateralMovementOpportunity]
    ) -> float:
        """Calculate overall risk score from attack surface analysis."""
        if not attack_paths:
            return 0.0

        # Weight factors
        critical_paths = sum(1 for p in attack_paths if p.threat_level == ThreatLevel.CRITICAL)
        high_paths = sum(1 for p in attack_paths if p.threat_level == ThreatLevel.HIGH)
        avg_cvss = sum(p.total_cvss for p in attack_paths) / len(attack_paths)
        avg_exploitability = sum(p.exploitability for p in attack_paths) / len(attack_paths)

        # Risk formula using configured weights
        risk_score = (
            (critical_paths * constants.RISK_WEIGHT_CRITICAL) +
            (high_paths * constants.RISK_WEIGHT_HIGH) +
            (len(privilege_escalations) * constants.RISK_WEIGHT_PRIVILEGE_ESCALATION) +
            (len(lateral_movements) * constants.RISK_WEIGHT_LATERAL_MOVEMENT) +
            (avg_cvss * avg_exploitability)
        )

        # Normalize to 0-100 scale using logarithmic scaling to prevent saturation
        # This ensures diverse scores while still reflecting severity:
        # - Low risk (0-30): 1-3 critical paths, limited escalation
        # - Medium risk (30-60): 4-7 critical paths, moderate escalation
        # - High risk (60-85): 8-15 critical paths, significant escalation
        # - Critical risk (85-100): 15+ critical paths, extensive attack surface
        import math
        if risk_score < 10:
            # Linear scaling for low risk
            normalized_risk = risk_score * 5.0  # Max ~50 for risk_score=10
        else:
            # Logarithmic scaling for higher risk to prevent immediate saturation
            # log10(10) = 1 → 50, log10(100) = 2 → 75, log10(1000) = 3 → 90
            normalized_risk = 50 + (math.log10(risk_score) - 1) * 25

        # Cap at 100 but allow full range
        normalized_risk = min(100.0, max(0.0, normalized_risk))

        return round(normalized_risk, 2)

    def _generate_mitigation_steps(self, attack_path: AttackPath) -> List[str]:
        """Generate mitigation recommendations for an attack path."""
        mitigations = []

        # Patch vulnerabilities
        unique_vulns = set()
        for step in attack_path.steps:
            unique_vulns.update(step.vulnerabilities)

        if unique_vulns:
            mitigations.append(f"Patch {len(unique_vulns)} vulnerabilities: {', '.join(list(unique_vulns)[:5])}")

        # Network segmentation
        if any(step.step_type == AttackStepType.LATERAL_MOVEMENT for step in attack_path.steps):
            mitigations.append("Implement network segmentation to prevent lateral movement")

        # Privilege management
        if attack_path.requires_privileges:
            mitigations.append("Implement principle of least privilege and restrict privilege escalation vectors")

        # Monitoring
        mitigations.append("Deploy monitoring and detection for this attack pattern")

        return mitigations

    def _generate_security_recommendations(
        self,
        attack_paths: List[AttackPath],
        privilege_escalations: List[PrivilegeEscalationPath],
        lateral_movements: List[LateralMovementOpportunity]
    ) -> List[str]:
        """Generate overall security recommendations."""
        recommendations = []

        # Critical path recommendations
        critical_paths = [p for p in attack_paths if p.threat_level == ThreatLevel.CRITICAL]
        if critical_paths:
            recommendations.append(
                f"URGENT: Address {len(critical_paths)} critical attack paths immediately"
            )

        # Vulnerability patching
        all_vulns = set()
        for path in attack_paths:
            for step in path.steps:
                all_vulns.update(step.vulnerabilities)

        if all_vulns:
            recommendations.append(
                f"Prioritize patching {len(all_vulns)} unique vulnerabilities across attack paths"
            )

        # Privilege escalation
        if privilege_escalations:
            recommendations.append(
                f"Review and restrict {len(privilege_escalations)} privilege escalation opportunities"
            )

        # Lateral movement
        if lateral_movements:
            recommendations.append(
                f"Implement network segmentation to mitigate {len(lateral_movements)} lateral movement opportunities"
            )

        # Entry point hardening
        if attack_paths:
            entry_points = set(p.entry_point for p in attack_paths)
            recommendations.append(
                f"Harden {len(entry_points)} entry points with additional security controls"
            )

        # Monitoring
        recommendations.append(
            "Deploy comprehensive monitoring and alerting for attack path indicators"
        )

        return recommendations
