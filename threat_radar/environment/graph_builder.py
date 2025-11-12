"""Build graph structures from environment configurations.

This module converts environment definitions with business context into
graph nodes and edges for topology-aware vulnerability analysis.
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime

from ..graph import (
    GraphClient,
    GraphNode,
    GraphEdge,
    NodeType,
    EdgeType,
)
from .models import (
    Environment,
    Asset,
    Dependency,
    AssetType,
    DependencyType,
    Criticality,
)

logger = logging.getLogger(__name__)


class EnvironmentGraphBuilder:
    """
    Build vulnerability graphs from environment configurations.

    Converts technology-agnostic environment definitions into graph
    structures that combine infrastructure topology with business context.
    """

    def __init__(self, client: GraphClient):
        """
        Initialize environment graph builder.

        Args:
            client: Graph client to populate
        """
        self.client = client
        self._asset_to_node_map: Dict[str, str] = {}

    def _find_asset_zone(self, asset_id: str, environment: Environment) -> Optional[str]:
        """
        Find the network zone for an asset.

        Args:
            asset_id: Asset ID to look up
            environment: Environment configuration

        Returns:
            Zone name if found, None otherwise
        """
        if not environment.network_topology or not environment.network_topology.zones:
            return None

        for zone in environment.network_topology.zones:
            if asset_id in zone.assets:
                return zone.name

        return None

    def build_from_environment(self, environment: Environment) -> None:
        """
        Build complete graph from environment configuration.

        Creates nodes for all assets with business context and establishes
        dependency relationships as edges.

        Args:
            environment: Environment configuration with assets and dependencies
        """
        logger.info(f"Building graph from environment: {environment.environment.name}")

        # Add all asset nodes
        for asset in environment.assets:
            self._add_asset_node(asset, environment)

        # Add dependency edges
        for dependency in environment.dependencies:
            self._add_dependency_edge(dependency, environment)

        # Add network topology information
        if environment.network_topology:
            self._add_network_topology(environment)

        metadata = self.client.get_metadata()
        logger.info(
            f"Environment graph built: {metadata.node_count} nodes, "
            f"{metadata.edge_count} edges"
        )

    def _add_asset_node(self, asset: Asset, environment: Environment) -> str:
        """
        Add asset as a graph node with business context.

        Args:
            asset: Asset to add
            environment: Parent environment for context

        Returns:
            Node ID of created asset node
        """
        # Determine node type based on asset type
        node_type_map = {
            AssetType.CONTAINER: NodeType.CONTAINER,
            AssetType.VM: NodeType.CONTAINER,  # Treat VM as container-like
            AssetType.BARE_METAL: NodeType.CONTAINER,
            AssetType.SERVERLESS: NodeType.SERVICE,
            AssetType.SAAS: NodeType.SERVICE,
            AssetType.DATABASE: NodeType.CONTAINER,  # Database as specialized container
            AssetType.LOAD_BALANCER: NodeType.SERVICE,
            AssetType.API_GATEWAY: NodeType.SERVICE,
            AssetType.SERVICE: NodeType.SERVICE,
        }

        node_type = node_type_map.get(asset.type, NodeType.SERVICE)
        node_id = f"asset:{asset.id}"

        # Build properties with business context
        properties = {
            "asset_id": asset.id,
            "name": asset.name,
            "asset_type": asset.type.value,
            "host": asset.host,

            # Business context
            "criticality": asset.business_context.criticality.value,
            "criticality_score": asset.business_context.criticality_score,
            "function": asset.business_context.function,
            "data_classification": asset.business_context.data_classification.value if asset.business_context.data_classification else None,
            "revenue_impact": asset.business_context.revenue_impact.value if asset.business_context.revenue_impact else None,
            "customer_facing": asset.business_context.customer_facing,
            "sla_tier": asset.business_context.sla_tier,
            "mttr_target": asset.business_context.mttr_target,
            "owner_team": asset.business_context.owner_team,

            # Environment context
            "environment": environment.environment.name,
            "environment_type": environment.environment.type.value,
            "cloud_provider": environment.environment.cloud_provider.value if environment.environment.cloud_provider else None,
            "region": environment.environment.region,
        }

        # Add software information if available
        if asset.software:
            properties.update({
                "software_image": asset.software.image,
                "os": asset.software.os,
                "runtime": asset.software.runtime,
            })

        # Add network information if available
        if asset.network:
            # Check if asset has public-facing ports
            has_public_port = any(
                port.public for port in asset.network.exposed_ports
            ) if asset.network.exposed_ports else False

            # Find asset's network zone from topology
            asset_zone = self._find_asset_zone(asset.id, environment)

            properties.update({
                "internal_ip": asset.network.internal_ip,
                "public_ip": asset.network.public_ip,
                "zone": asset_zone,
                "internet_accessible": bool(asset.network.public_ip),
                "internet_facing": bool(asset.network.public_ip) or has_public_port,
                "has_public_port": has_public_port,
            })

        # Add compliance scope
        if asset.business_context.compliance_scope:
            compliance_list = [c.value for c in asset.business_context.compliance_scope]
            properties["compliance_scope"] = compliance_list

            # Add specific compliance flags for attack path discovery
            properties["pci_scope"] = any(c in ["pci", "pci-dss", "pci_dss"] for c in compliance_list)
            properties["hipaa_scope"] = any(c in ["hipaa", "hipaa-hitech"] for c in compliance_list)

        # Also check business_context for direct PCI/HIPAA scope flags
        if hasattr(asset.business_context, "pci_scope") and asset.business_context.pci_scope:
            properties["pci_scope"] = True
        if hasattr(asset.business_context, "hipaa_scope") and asset.business_context.hipaa_scope:
            properties["hipaa_scope"] = True

        # Add metadata if available
        if asset.metadata:
            if asset.metadata.last_scanned:
                properties["last_scanned"] = asset.metadata.last_scanned.isoformat()
            if asset.metadata.last_patched:
                properties["last_patched"] = asset.metadata.last_patched.isoformat()
            if asset.metadata.tags:
                properties["tags"] = asset.metadata.tags

        # Create node
        node = GraphNode(
            node_id=node_id,
            node_type=node_type,
            properties=properties
        )
        self.client.add_node(node)

        # Store mapping for dependency resolution
        self._asset_to_node_map[asset.id] = node_id

        logger.debug(f"Added asset node: {node_id} (criticality: {asset.business_context.criticality.value})")
        return node_id

    def _add_dependency_edge(self, dependency: Dependency, environment: Environment) -> None:
        """
        Add dependency relationship as graph edge.

        Args:
            dependency: Dependency relationship
            environment: Parent environment for context
        """
        source_node = self._asset_to_node_map.get(dependency.source)
        target_node = self._asset_to_node_map.get(dependency.target)

        if not source_node or not target_node:
            logger.warning(
                f"Skipping dependency {dependency.source} -> {dependency.target}: "
                f"Node(s) not found"
            )
            return

        # Map dependency type to edge type
        edge_type_map = {
            DependencyType.DEPENDS_ON: EdgeType.DEPENDS_ON,
            DependencyType.COMMUNICATES_WITH: EdgeType.COMMUNICATES_WITH,
            DependencyType.READS_FROM: EdgeType.DEPENDS_ON,  # Treat as dependency
            DependencyType.WRITES_TO: EdgeType.DEPENDS_ON,
            DependencyType.AUTHENTICATES_TO: EdgeType.DEPENDS_ON,
        }

        edge_type = edge_type_map.get(dependency.type, EdgeType.DEPENDS_ON)

        # Build edge properties
        properties = {
            "dependency_type": dependency.type.value,
            "protocol": dependency.protocol,
            "port": dependency.port,
            "encrypted": dependency.encrypted,
        }

        # Add criticality and data flow information
        if dependency.criticality:
            properties["criticality"] = dependency.criticality.value

        if dependency.data_flow:
            properties["data_flow"] = dependency.data_flow.value
            properties["sensitive_data"] = True  # Flag for AI analysis

        # Create edge
        edge = GraphEdge(
            source_id=source_node,
            target_id=target_node,
            edge_type=edge_type,
            properties=properties
        )
        self.client.add_edge(edge)

        logger.debug(
            f"Added dependency edge: {dependency.source} -> {dependency.target} "
            f"({dependency.type.value})"
        )

    def _add_network_topology(self, environment: Environment) -> None:
        """
        Add network topology information to graph.

        Creates zone metadata and updates asset nodes with zone membership.

        Args:
            environment: Environment with network topology
        """
        if not environment.network_topology or not environment.network_topology.zones:
            return

        # Update assets with zone information
        for zone in environment.network_topology.zones:
            for asset_id in zone.assets:
                node_id = self._asset_to_node_map.get(asset_id)
                if node_id:
                    # Get existing node
                    node = self.client.get_node(node_id)
                    if node:
                        # Add zone properties
                        node.properties["network_zone"] = zone.name
                        node.properties["zone_trust_level"] = zone.trust_level.value
                        node.properties["zone_internet_accessible"] = zone.internet_accessible

                        # Re-add node with updated properties
                        self.client.add_node(node)

        logger.info(f"Added network topology: {len(environment.network_topology.zones)} zones")

    def merge_vulnerability_data(
        self,
        scan_results: Dict[str, any],
        asset_image_mapping: Optional[Dict[str, str]] = None
    ) -> None:
        """
        Merge vulnerability scan results with environment graph.

        Links CVE data to assets based on software images or asset IDs.

        Args:
            scan_results: Dictionary of scan results keyed by image/asset
            asset_image_mapping: Optional mapping of asset IDs to scan result keys
        """
        logger.info("Merging vulnerability data with environment graph")

        # This would integrate with existing GraphBuilder
        # to add vulnerability nodes and HAS_VULNERABILITY edges
        # Implementation would depend on scan result format

        # Placeholder for now - would be implemented in integration phase
        pass

    def calculate_risk_scores(self, environment: Environment) -> Dict[str, float]:
        """
        Calculate risk scores for assets based on business context.

        Combines criticality, exposure, and other factors into risk score.

        Args:
            environment: Environment configuration

        Returns:
            Dictionary mapping asset IDs to risk scores (0-100)
        """
        risk_scores = {}

        for asset in environment.assets:
            # Base score from criticality
            criticality_scores = {
                Criticality.CRITICAL: 40,
                Criticality.HIGH: 30,
                Criticality.MEDIUM: 20,
                Criticality.LOW: 10,
            }
            score = criticality_scores.get(asset.business_context.criticality, 0)

            # Add points for internet exposure
            if asset.network and asset.network.public_ip:
                score += 20

            # Add points for sensitive data
            if asset.business_context.data_classification:
                data_scores = {
                    "pci": 20,
                    "phi": 20,
                    "pii": 15,
                    "confidential": 10,
                    "internal": 5,
                    "public": 0,
                }
                score += data_scores.get(
                    asset.business_context.data_classification.value, 0
                )

            # Add points for customer-facing
            if asset.business_context.customer_facing:
                score += 10

            # Add points for compliance scope
            if asset.business_context.compliance_scope:
                score += len(asset.business_context.compliance_scope) * 5

            # Cap at 100
            risk_scores[asset.id] = min(score, 100)

        return risk_scores

    def find_critical_paths(
        self,
        environment: Environment,
        entry_points: Optional[List[str]] = None
    ) -> List[List[str]]:
        """
        Find critical attack paths through the infrastructure.

        Identifies paths from entry points (internet-facing assets) to
        critical assets (high-value targets).

        Args:
            environment: Environment configuration
            entry_points: Optional list of entry point asset IDs
                         (defaults to internet-facing assets)

        Returns:
            List of attack paths (each path is list of asset IDs)
        """
        import networkx as nx

        if entry_points is None:
            # Find internet-facing assets as entry points
            entry_points = [
                asset.id for asset in environment.get_internet_facing_assets()
            ]

        # Find critical assets as targets
        critical_targets = [
            asset.id for asset in environment.get_critical_assets()
        ]

        paths = []
        G = self.client.graph if hasattr(self.client, 'graph') else None

        if G:
            for entry in entry_points:
                entry_node = f"asset:{entry}"
                for target in critical_targets:
                    target_node = f"asset:{target}"
                    if entry_node in G and target_node in G:
                        try:
                            # Find all simple paths
                            for path in nx.all_simple_paths(
                                G,
                                source=entry_node,
                                target=target_node,
                                cutoff=10  # Max path length
                            ):
                                # Convert back to asset IDs
                                asset_path = [
                                    node_id.replace("asset:", "")
                                    for node_id in path
                                ]
                                paths.append(asset_path)
                        except nx.NetworkXNoPath:
                            continue

        logger.info(f"Found {len(paths)} critical paths")
        return paths
