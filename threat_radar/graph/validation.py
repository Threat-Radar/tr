"""Graph data quality validation and diagnostics."""

import logging
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import networkx as nx

from .graph_client import NetworkXClient
from .models import NodeType, EdgeType

logger = logging.getLogger(__name__)


class ValidationSeverity(str, Enum):
    """Severity levels for validation issues."""
    CRITICAL = "critical"  # Will prevent correct graph analysis
    WARNING = "warning"    # May cause issues but graph is usable
    INFO = "info"          # Informational, best practice


@dataclass
class ValidationIssue:
    """Represents a data quality issue found during validation."""
    severity: ValidationSeverity
    category: str
    message: str
    affected_items: List[str] = field(default_factory=list)
    suggestion: Optional[str] = None

    def __str__(self) -> str:
        """Format issue for display."""
        severity_icon = {
            ValidationSeverity.CRITICAL: "❌",
            ValidationSeverity.WARNING: "⚠️",
            ValidationSeverity.INFO: "ℹ️"
        }
        icon = severity_icon.get(self.severity, "•")

        result = f"{icon} [{self.severity.upper()}] {self.category}: {self.message}"

        if self.affected_items:
            count = len(self.affected_items)
            if count <= 3:
                result += f"\n   Affected: {', '.join(self.affected_items)}"
            else:
                result += f"\n   Affected: {', '.join(self.affected_items[:3])} ... ({count} total)"

        if self.suggestion:
            result += f"\n   💡 Suggestion: {self.suggestion}"

        return result


@dataclass
class ValidationReport:
    """Complete validation report for a graph."""
    issues: List[ValidationIssue] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)

    def add_issue(self, issue: ValidationIssue):
        """Add an issue to the report."""
        self.issues.append(issue)

    def has_critical_issues(self) -> bool:
        """Check if report contains critical issues."""
        return any(issue.severity == ValidationSeverity.CRITICAL for issue in self.issues)

    def has_warnings(self) -> bool:
        """Check if report contains warnings."""
        return any(issue.severity == ValidationSeverity.WARNING for issue in self.issues)

    def get_issues_by_severity(self, severity: ValidationSeverity) -> List[ValidationIssue]:
        """Get all issues of a specific severity."""
        return [issue for issue in self.issues if issue.severity == severity]

    def summary(self) -> str:
        """Generate a summary of the validation report."""
        critical = len(self.get_issues_by_severity(ValidationSeverity.CRITICAL))
        warnings = len(self.get_issues_by_severity(ValidationSeverity.WARNING))
        info = len(self.get_issues_by_severity(ValidationSeverity.INFO))

        if critical > 0:
            status = "❌ VALIDATION FAILED"
        elif warnings > 0:
            status = "⚠️  VALIDATION PASSED WITH WARNINGS"
        else:
            status = "✅ VALIDATION PASSED"

        return f"{status}\n  Critical: {critical}, Warnings: {warnings}, Info: {info}"


class GraphValidator:
    """Validates graph data quality and structure."""

    def __init__(self, client: NetworkXClient):
        """Initialize validator with graph client."""
        self.client = client
        self.graph = client.graph

    def validate_all(self) -> ValidationReport:
        """Run all validation checks."""
        report = ValidationReport()

        # Collect graph statistics
        report.stats = self._collect_stats()

        # Run all validation checks
        self._validate_node_types(report)
        self._validate_edge_types(report)
        self._validate_asset_package_connectivity(report)
        self._validate_package_vulnerability_connectivity(report)
        self._validate_vulnerability_attributes(report)
        self._validate_orphaned_nodes(report)
        self._validate_graph_connectivity(report)

        return report

    def _collect_stats(self) -> Dict[str, int]:
        """Collect basic graph statistics."""
        stats = {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
        }

        # Count by node type
        node_types = {}
        for node in self.graph.nodes():
            node_type = self.graph.nodes[node].get('node_type', 'unknown')
            node_types[node_type] = node_types.get(node_type, 0) + 1

        stats.update({f"nodes_{ntype}": count for ntype, count in node_types.items()})

        # Count by edge type
        edge_types = {}
        for u, v in self.graph.edges():
            edge_data = self.graph.get_edge_data(u, v)
            edge_type = edge_data.get('edge_type', 'unknown') if edge_data else 'unknown'
            edge_types[edge_type] = edge_types.get(edge_type, 0) + 1

        stats.update({f"edges_{etype}": count for etype, count in edge_types.items()})

        return stats

    def _validate_node_types(self, report: ValidationReport):
        """Validate that all nodes have proper type attributes."""
        nodes_without_type = []
        unknown_type_nodes = []

        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            node_type = node_data.get('node_type')

            if node_type is None:
                nodes_without_type.append(node[:60])
            elif node_type == 'unknown':
                unknown_type_nodes.append(node[:60])

        if nodes_without_type:
            report.add_issue(ValidationIssue(
                severity=ValidationSeverity.CRITICAL,
                category="Missing Node Types",
                message=f"{len(nodes_without_type)} nodes missing 'node_type' attribute",
                affected_items=nodes_without_type[:10],
                suggestion="Ensure all nodes have a 'node_type' attribute set during graph building"
            ))

        if unknown_type_nodes:
            report.add_issue(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="Unknown Node Types",
                message=f"{len(unknown_type_nodes)} nodes have type 'unknown'",
                affected_items=unknown_type_nodes[:10],
                suggestion="Review node creation logic to assign proper types"
            ))

    def _validate_edge_types(self, report: ValidationReport):
        """Validate that all edges have proper type attributes."""
        edges_without_type = []

        for u, v in self.graph.edges():
            edge_data = self.graph.get_edge_data(u, v)
            edge_type = edge_data.get('edge_type') if edge_data else None

            if edge_type is None:
                edges_without_type.append(f"{u[:40]} → {v[:40]}")

        if edges_without_type:
            report.add_issue(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="Missing Edge Types",
                message=f"{len(edges_without_type)} edges missing 'edge_type' attribute",
                affected_items=edges_without_type[:5],
                suggestion="Ensure all edges have an 'edge_type' attribute"
            ))

    def _validate_asset_package_connectivity(self, report: ValidationReport):
        """Validate that assets are connected to packages via CONTAINS edges."""
        assets_without_packages = []
        total_contains_edges = 0

        # Find all asset nodes (containers, VMs, etc.)
        asset_nodes = [
            node for node in self.graph.nodes()
            if self.graph.nodes[node].get('node_type') in ['asset', 'container']
        ]

        for asset in asset_nodes:
            # Check if asset has CONTAINS edges to packages
            has_packages = False
            for successor in self.graph.successors(asset):
                edge_data = self.graph.get_edge_data(asset, successor)
                successor_type = self.graph.nodes[successor].get('node_type')

                if (edge_data and edge_data.get('edge_type') == EdgeType.CONTAINS.value or
                    successor_type == NodeType.PACKAGE.value):
                    has_packages = True
                    total_contains_edges += 1
                    break

            if not has_packages:
                asset_name = self.graph.nodes[asset].get('name', asset[:60])
                assets_without_packages.append(asset_name)

        if assets_without_packages:
            report.add_issue(ValidationIssue(
                severity=ValidationSeverity.CRITICAL,
                category="Asset-Package Disconnect",
                message=f"{len(assets_without_packages)}/{len(asset_nodes)} assets have no CONTAINS edges to packages",
                affected_items=assets_without_packages[:10],
                suggestion=(
                    "This usually means asset image names don't match scan targets. "
                    "Ensure asset 'software.image' field matches the scan target exactly."
                )
            ))

        if total_contains_edges == 0 and asset_nodes:
            report.add_issue(ValidationIssue(
                severity=ValidationSeverity.CRITICAL,
                category="No CONTAINS Edges",
                message="Graph has 0 CONTAINS edges - assets cannot reach vulnerabilities",
                suggestion=(
                    "Check that 'env build-graph --merge-scan' is matching scans to assets. "
                    "Verify asset image names match scan targets exactly."
                )
            ))

    def _validate_package_vulnerability_connectivity(self, report: ValidationReport):
        """Validate that packages are connected to vulnerabilities."""
        packages_without_vulns = 0
        total_has_vuln_edges = 0

        package_nodes = [
            node for node in self.graph.nodes()
            if self.graph.nodes[node].get('node_type') == NodeType.PACKAGE.value
        ]

        for package in package_nodes:
            has_vulns = False
            for successor in self.graph.successors(package):
                edge_data = self.graph.get_edge_data(package, successor)
                if edge_data and edge_data.get('edge_type') == EdgeType.HAS_VULNERABILITY.value:
                    has_vulns = True
                    total_has_vuln_edges += 1

            if not has_vulns:
                packages_without_vulns += 1

        if package_nodes and total_has_vuln_edges == 0:
            report.add_issue(ValidationIssue(
                severity=ValidationSeverity.CRITICAL,
                category="No Package-Vulnerability Edges",
                message="Packages have no HAS_VULNERABILITY edges",
                suggestion="Ensure vulnerability data is being merged correctly during graph building"
            ))

        # Info: Some packages having no vulnerabilities is normal
        if packages_without_vulns > 0:
            percentage = (packages_without_vulns / len(package_nodes)) * 100
            if percentage > 80:
                report.add_issue(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="Low Vulnerability Coverage",
                    message=f"{percentage:.1f}% of packages have no vulnerabilities",
                    suggestion="This may indicate incomplete scan data or very secure packages"
                ))

    def _validate_vulnerability_attributes(self, report: ValidationReport):
        """Validate vulnerability nodes have required attributes."""
        vulns_missing_severity = []
        vulns_missing_cvss = []

        vuln_nodes = [
            node for node in self.graph.nodes()
            if self.graph.nodes[node].get('node_type') == NodeType.VULNERABILITY.value
        ]

        for vuln in vuln_nodes:
            node_data = self.graph.nodes[vuln]

            if not node_data.get('severity'):
                vulns_missing_severity.append(vuln[:60])

            if node_data.get('cvss_score') is None:
                vulns_missing_cvss.append(vuln[:60])

        if vulns_missing_severity:
            report.add_issue(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="Missing Severity",
                message=f"{len(vulns_missing_severity)} vulnerabilities missing severity rating",
                affected_items=vulns_missing_severity[:5]
            ))

        if vulns_missing_cvss:
            report.add_issue(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="Missing CVSS Score",
                message=f"{len(vulns_missing_cvss)} vulnerabilities missing CVSS score",
                affected_items=vulns_missing_cvss[:5]
            ))

    def _validate_orphaned_nodes(self, report: ValidationReport):
        """Find nodes with no connections."""
        orphaned = []

        for node in self.graph.nodes():
            in_degree = self.graph.in_degree(node)
            out_degree = self.graph.out_degree(node)

            if in_degree == 0 and out_degree == 0:
                node_type = self.graph.nodes[node].get('node_type', 'unknown')
                orphaned.append(f"{node[:60]} (type: {node_type})")

        if orphaned:
            report.add_issue(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="Orphaned Nodes",
                message=f"{len(orphaned)} nodes have no connections",
                affected_items=orphaned[:5],
                suggestion="These nodes may be unreachable in graph analysis"
            ))

    def _validate_graph_connectivity(self, report: ValidationReport):
        """Validate end-to-end connectivity from assets to vulnerabilities."""
        # Find assets and vulnerabilities
        assets = [
            node for node in self.graph.nodes()
            if self.graph.nodes[node].get('node_type') in ['asset', 'container']
        ]

        vulns = [
            node for node in self.graph.nodes()
            if self.graph.nodes[node].get('node_type') == NodeType.VULNERABILITY.value
        ]

        if not assets or not vulns:
            return

        # Check if at least one asset has direct vulnerability data (CONTAINS edges to packages)
        assets_with_scan_data = 0

        for asset in assets:
            # Check for direct CONTAINS edges to packages (indicates scan data exists)
            has_contains_edges = any(
                edge_data.get('edge_type') == EdgeType.CONTAINS.value
                for _, _, edge_data in self.graph.out_edges(asset, data=True)
            )

            if has_contains_edges:
                assets_with_scan_data += 1

        if assets_with_scan_data == 0:
            report.add_issue(ValidationIssue(
                severity=ValidationSeverity.CRITICAL,
                category="No Asset Scan Data",
                message="No assets have scan data (missing CONTAINS edges)",
                suggestion=(
                    "This indicates missing CONTAINS edges. "
                    "Verify that asset image names match scan targets exactly."
                )
            ))
        elif assets_with_scan_data < len(assets):
            missing_count = len(assets) - assets_with_scan_data
            report.add_issue(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="Partial Asset Coverage",
                message=(
                    f"Only {assets_with_scan_data}/{len(assets)} assets have vulnerability scan data. "
                    f"{missing_count} asset(s) missing scans."
                ),
                suggestion=(
                    f"Scan the {missing_count} missing asset(s) to get complete vulnerability coverage. "
                    "Assets without scans cannot be analyzed for vulnerabilities."
                )
            ))


def validate_asset_scan_matching(
    environment_config: Dict,
    scan_files: List[str]
) -> ValidationReport:
    """
    Validate that environment assets match scan targets before graph building.

    This pre-flight check helps catch configuration issues early.
    """
    report = ValidationReport()

    # Extract asset image names from environment
    assets = environment_config.get('assets', [])
    asset_images = {}

    for asset in assets:
        asset_id = asset.get('id', 'unknown')
        software = asset.get('software', {})
        image = software.get('image')

        if image:
            asset_images[asset_id] = image

    # Load scan targets
    import json
    scan_targets = {}

    for scan_file in scan_files:
        try:
            with open(scan_file) as f:
                scan_data = json.load(f)
                target = scan_data.get('target', scan_data.get('artifact', {}).get('name'))
                if target:
                    scan_targets[scan_file] = target
        except Exception as e:
            logger.warning(f"Could not load scan file {scan_file}: {e}")

    # Check for matches
    matched_assets = set()
    unmatched_scans = []

    for scan_file, scan_target in scan_targets.items():
        matched = False

        for asset_id, asset_image in asset_images.items():
            if asset_image in scan_target or scan_target in asset_image:
                matched = True
                matched_assets.add(asset_id)
                break

        if not matched:
            unmatched_scans.append(f"{scan_file} (target: {scan_target})")

    # Find unmatched assets
    unmatched_assets = []
    for asset_id, asset_image in asset_images.items():
        if asset_id not in matched_assets:
            unmatched_assets.append(f"{asset_id} (image: {asset_image})")

    # Report issues
    if unmatched_assets:
        report.add_issue(ValidationIssue(
            severity=ValidationSeverity.CRITICAL,
            category="Unmatched Assets",
            message=f"{len(unmatched_assets)} assets have no matching scan data",
            affected_items=unmatched_assets,
            suggestion=(
                "Update asset 'software.image' fields to match scan targets exactly. "
                "Asset images must match the container image names that were scanned."
            )
        ))

    if unmatched_scans:
        report.add_issue(ValidationIssue(
            severity=ValidationSeverity.WARNING,
            category="Unmatched Scans",
            message=f"{len(unmatched_scans)} scans don't match any assets",
            affected_items=unmatched_scans,
            suggestion="These scans will create separate nodes not linked to environment assets"
        ))

    if not unmatched_assets and not unmatched_scans:
        report.add_issue(ValidationIssue(
            severity=ValidationSeverity.INFO,
            category="Perfect Match",
            message=f"✅ All {len(asset_images)} assets matched with scan data",
            suggestion="Graph building should create proper CONTAINS edges"
        ))

    return report
