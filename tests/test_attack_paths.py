"""Tests for attack path discovery and analysis."""

import pytest
from pathlib import Path
import tempfile

from threat_radar.graph import (
    NetworkXClient,
    GraphBuilder,
    GraphAnalyzer,
    GraphNode,
    GraphEdge,
    NodeType,
    EdgeType,
)
from threat_radar.graph.models import (
    AttackPath,
    AttackStep,
    AttackStepType,
    ThreatLevel,
    PrivilegeEscalationPath,
    LateralMovementOpportunity,
    AttackSurface,
)
from threat_radar.core.grype_integration import GrypeScanResult, GrypeVulnerability


@pytest.fixture
def attack_graph_client():
    """Create a graph with attack path test data."""
    client = NetworkXClient()

    # Add DMZ entry point (internet-facing)
    client.add_node(
        GraphNode(
            node_id="asset:dmz-web",
            node_type=NodeType.CONTAINER,
            properties={
                "name": "DMZ Web Server",
                "zone": "dmz",
                "internet_facing": True,
                "has_public_port": True,
                "criticality": "medium",
            },
        )
    )

    # Add vulnerable package in DMZ
    client.add_node(
        GraphNode(
            node_id="package:nginx:1.18",
            node_type=NodeType.PACKAGE,
            properties={
                "name": "nginx",
                "version": "1.18.0",
            },
        )
    )

    # Add critical vulnerability
    client.add_node(
        GraphNode(
            node_id="cve:CVE-2023-0001",
            node_type=NodeType.VULNERABILITY,
            properties={
                "cve_id": "CVE-2023-0001",
                "severity": "critical",
                "cvss_score": 9.8,
            },
        )
    )

    # Add internal application server
    client.add_node(
        GraphNode(
            node_id="asset:internal-app",
            node_type=NodeType.CONTAINER,
            properties={
                "name": "Internal Application Server",
                "zone": "internal",
                "criticality": "high",
                "criticality_score": 85,
            },
        )
    )

    # Add internal package
    client.add_node(
        GraphNode(
            node_id="package:openssl:1.1.1",
            node_type=NodeType.PACKAGE,
            properties={
                "name": "openssl",
                "version": "1.1.1",
            },
        )
    )

    # Add high severity vulnerability
    client.add_node(
        GraphNode(
            node_id="cve:CVE-2023-0002",
            node_type=NodeType.VULNERABILITY,
            properties={
                "cve_id": "CVE-2023-0002",
                "severity": "high",
                "cvss_score": 7.5,
            },
        )
    )

    # Add critical database target (PCI scope)
    client.add_node(
        GraphNode(
            node_id="asset:database",
            node_type=NodeType.CONTAINER,
            properties={
                "name": "Database Server",
                "zone": "internal",
                "criticality": "critical",
                "criticality_score": 95,
                "pci_scope": True,
                "data_classification": "pci",
                "function": "database",
            },
        )
    )

    # Add another DMZ asset for lateral movement testing
    client.add_node(
        GraphNode(
            node_id="asset:dmz-api",
            node_type=NodeType.CONTAINER,
            properties={
                "name": "DMZ API Gateway",
                "zone": "dmz",
                "internet_facing": True,
                "criticality": "medium",
            },
        )
    )

    # Create relationships (attack paths)
    # DMZ web -> package
    client.add_edge(
        GraphEdge(
            source_id="asset:dmz-web",
            target_id="package:nginx:1.18",
            edge_type=EdgeType.CONTAINS,
        )
    )

    # Package -> vulnerability
    client.add_edge(
        GraphEdge(
            source_id="package:nginx:1.18",
            target_id="cve:CVE-2023-0001",
            edge_type=EdgeType.HAS_VULNERABILITY,
        )
    )

    # DMZ web -> internal app (network connection / dependency)
    client.add_edge(
        GraphEdge(
            source_id="asset:dmz-web",
            target_id="asset:internal-app",
            edge_type=EdgeType.COMMUNICATES_WITH,
        )
    )

    # Internal app -> package
    client.add_edge(
        GraphEdge(
            source_id="asset:internal-app",
            target_id="package:openssl:1.1.1",
            edge_type=EdgeType.CONTAINS,
        )
    )

    # Package -> vulnerability
    client.add_edge(
        GraphEdge(
            source_id="package:openssl:1.1.1",
            target_id="cve:CVE-2023-0002",
            edge_type=EdgeType.HAS_VULNERABILITY,
        )
    )

    # Internal app -> database
    client.add_edge(
        GraphEdge(
            source_id="asset:internal-app",
            target_id="asset:database",
            edge_type=EdgeType.DEPENDS_ON,
        )
    )

    # DMZ web -> DMZ API (lateral movement)
    client.add_edge(
        GraphEdge(
            source_id="asset:dmz-web",
            target_id="asset:dmz-api",
            edge_type=EdgeType.COMMUNICATES_WITH,
        )
    )

    return client


class TestAttackPathModels:
    """Test attack path data models."""

    def test_attack_step_creation(self):
        """Test creating an attack step."""
        step = AttackStep(
            node_id="asset:test",
            step_type=AttackStepType.ENTRY_POINT,
            description="Gain initial access",
            vulnerabilities=["CVE-2023-0001"],
            cvss_score=9.8,
        )

        assert step.node_id == "asset:test"
        assert step.step_type == AttackStepType.ENTRY_POINT
        assert len(step.vulnerabilities) == 1
        assert step.cvss_score == 9.8

    def test_attack_path_creation(self):
        """Test creating an attack path."""
        steps = [
            AttackStep(
                node_id="asset:entry",
                step_type=AttackStepType.ENTRY_POINT,
                description="Initial access",
            ),
            AttackStep(
                node_id="asset:target",
                step_type=AttackStepType.TARGET_ACCESS,
                description="Target compromised",
            ),
        ]

        path = AttackPath(
            path_id="path_1",
            entry_point="asset:entry",
            target="asset:target",
            steps=steps,
            total_cvss=15.0,
            threat_level=ThreatLevel.HIGH,
        )

        assert path.path_id == "path_1"
        assert path.path_length == 2
        assert path.threat_level == ThreatLevel.HIGH
        assert not path.requires_privileges

    def test_attack_path_privilege_detection(self):
        """Test automatic privilege escalation detection."""
        steps = [
            AttackStep(
                node_id="asset:entry",
                step_type=AttackStepType.ENTRY_POINT,
                description="Initial access",
            ),
            AttackStep(
                node_id="asset:escalation",
                step_type=AttackStepType.PRIVILEGE_ESCALATION,
                description="Escalate privileges",
            ),
            AttackStep(
                node_id="asset:target",
                step_type=AttackStepType.TARGET_ACCESS,
                description="Target compromised",
            ),
        ]

        path = AttackPath(
            path_id="path_1",
            entry_point="asset:entry",
            target="asset:target",
            steps=steps,
            total_cvss=20.0,
            threat_level=ThreatLevel.CRITICAL,
        )

        assert path.requires_privileges  # Auto-detected

    def test_privilege_escalation_path(self):
        """Test privilege escalation path model."""
        attack_path = AttackPath(
            path_id="priv_1",
            entry_point="asset:dmz",
            target="asset:internal",
            steps=[],
            total_cvss=15.0,
            threat_level=ThreatLevel.HIGH,
        )

        priv_path = PrivilegeEscalationPath(
            from_privilege="dmz",
            to_privilege="internal",
            path=attack_path,
            vulnerabilities=["CVE-2023-0001", "CVE-2023-0002"],
            difficulty="medium",
            mitigation=["Patch vulnerabilities", "Implement network segmentation"],
        )

        assert priv_path.from_privilege == "dmz"
        assert priv_path.to_privilege == "internal"
        assert len(priv_path.vulnerabilities) == 2
        assert len(priv_path.mitigation) == 2

    def test_lateral_movement_opportunity(self):
        """Test lateral movement opportunity model."""
        attack_path = AttackPath(
            path_id="lateral_1",
            entry_point="asset:web1",
            target="asset:web2",
            steps=[],
            total_cvss=10.0,
            threat_level=ThreatLevel.MEDIUM,
        )

        lateral = LateralMovementOpportunity(
            from_asset="asset:web1",
            to_asset="asset:web2",
            movement_type="network",
            path=attack_path,
            vulnerabilities=["CVE-2023-0001"],
            network_requirements=["Access to DMZ zone"],
            prerequisites=["Compromise of web1"],
            detection_difficulty="medium",
        )

        assert lateral.from_asset == "asset:web1"
        assert lateral.to_asset == "asset:web2"
        assert lateral.movement_type == "network"
        assert lateral.detection_difficulty == "medium"

    def test_attack_surface(self):
        """Test attack surface model."""
        surface = AttackSurface(
            entry_points=["asset:dmz-web", "asset:dmz-api"],
            high_value_targets=["asset:database", "asset:payment"],
            attack_paths=[],
            privilege_escalations=[],
            lateral_movements=[],
            total_risk_score=75.5,
            recommendations=[
                "Patch critical vulnerabilities",
                "Implement network segmentation",
            ],
        )

        assert len(surface.entry_points) == 2
        assert len(surface.high_value_targets) == 2
        assert surface.total_risk_score == 75.5
        assert len(surface.recommendations) == 2


class TestEntryPointDetection:
    """Test entry point identification."""

    def test_identify_internet_facing(self, attack_graph_client):
        """Test identifying internet-facing assets."""
        analyzer = GraphAnalyzer(attack_graph_client)
        entry_points = analyzer.identify_entry_points()

        assert len(entry_points) > 0
        assert "asset:dmz-web" in entry_points
        assert "asset:dmz-api" in entry_points

    def test_no_entry_points(self):
        """Test when no entry points exist."""
        client = NetworkXClient()
        client.add_node(
            GraphNode(
                node_id="asset:internal",
                node_type=NodeType.CONTAINER,
                properties={"zone": "internal"},
            )
        )

        analyzer = GraphAnalyzer(client)
        entry_points = analyzer.identify_entry_points()

        assert len(entry_points) == 0


class TestHighValueTargets:
    """Test high-value target identification."""

    def test_identify_critical_assets(self, attack_graph_client):
        """Test identifying critical assets."""
        analyzer = GraphAnalyzer(attack_graph_client)
        targets = analyzer.identify_high_value_targets()

        assert len(targets) > 0
        assert "asset:database" in targets  # Critical + PCI scope
        assert "asset:internal-app" in targets  # High criticality score

    def test_identify_pci_scope(self, attack_graph_client):
        """Test identifying PCI-scoped assets."""
        analyzer = GraphAnalyzer(attack_graph_client)
        targets = analyzer.identify_high_value_targets()

        # Database has pci_scope=True
        assert "asset:database" in targets

    def test_no_high_value_targets(self):
        """Test when no high-value targets exist."""
        client = NetworkXClient()
        client.add_node(
            GraphNode(
                node_id="asset:low-priority",
                node_type=NodeType.CONTAINER,
                properties={"criticality": "low"},
            )
        )

        analyzer = GraphAnalyzer(client)
        targets = analyzer.identify_high_value_targets()

        assert len(targets) == 0


class TestAttackPathDiscovery:
    """Test attack path discovery algorithms."""

    def test_find_shortest_paths(self, attack_graph_client):
        """Test finding shortest attack paths."""
        analyzer = GraphAnalyzer(attack_graph_client)

        attack_paths = analyzer.find_shortest_attack_paths(max_length=10)

        assert len(attack_paths) > 0

        # Check path structure
        for path in attack_paths:
            assert isinstance(path, AttackPath)
            assert path.entry_point
            assert path.target
            assert len(path.steps) > 0
            assert path.total_cvss >= 0
            assert isinstance(path.threat_level, ThreatLevel)

    def test_attack_path_from_dmz_to_database(self, attack_graph_client):
        """Test finding path from DMZ to database."""
        analyzer = GraphAnalyzer(attack_graph_client)

        attack_paths = analyzer.find_shortest_attack_paths(
            entry_points=["asset:dmz-web"], targets=["asset:database"], max_length=10
        )

        assert len(attack_paths) > 0

        # Verify path goes from DMZ to database
        path = attack_paths[0]
        assert path.entry_point == "asset:dmz-web"
        assert path.target == "asset:database"

        # Should have multiple steps
        assert path.path_length >= 2

    def test_threat_level_calculation(self, attack_graph_client):
        """Test threat level is calculated correctly."""
        analyzer = GraphAnalyzer(attack_graph_client)

        attack_paths = analyzer.find_shortest_attack_paths()

        # Paths with high CVSS should be high threat
        critical_paths = [
            p for p in attack_paths if p.threat_level == ThreatLevel.CRITICAL
        ]
        high_paths = [p for p in attack_paths if p.threat_level == ThreatLevel.HIGH]

        # Should have at least some high-severity paths given test data
        assert len(critical_paths) + len(high_paths) > 0

    def test_exploitability_scoring(self, attack_graph_client):
        """Test exploitability scoring."""
        analyzer = GraphAnalyzer(attack_graph_client)

        attack_paths = analyzer.find_shortest_attack_paths()

        for path in attack_paths:
            # Exploitability should be 0.0 to 1.0
            assert 0.0 <= path.exploitability <= 1.0

            # Shorter paths should be more exploitable
            if path.path_length <= 3:
                assert path.exploitability >= 0.5


class TestPrivilegeEscalation:
    """Test privilege escalation detection."""

    def test_detect_dmz_to_internal(self, attack_graph_client):
        """Test detecting DMZ to internal zone escalation."""
        analyzer = GraphAnalyzer(attack_graph_client)

        escalations = analyzer.detect_privilege_escalation_paths(max_paths=10)

        # Should find escalations from DMZ to internal
        dmz_to_internal = [
            e
            for e in escalations
            if "dmz" in e.from_privilege.lower()
            and "internal" in e.to_privilege.lower()
        ]

        assert len(dmz_to_internal) > 0

    def test_escalation_difficulty(self, attack_graph_client):
        """Test escalation difficulty rating."""
        analyzer = GraphAnalyzer(attack_graph_client)

        escalations = analyzer.detect_privilege_escalation_paths()

        for esc in escalations:
            # Difficulty should be one of the valid values
            assert esc.difficulty in ["easy", "medium", "hard"]

            # Shorter paths should be easier
            if esc.path.path_length <= 3:
                assert esc.difficulty in ["easy", "medium"]

    def test_escalation_mitigation(self, attack_graph_client):
        """Test mitigation recommendations are generated."""
        analyzer = GraphAnalyzer(attack_graph_client)

        escalations = analyzer.detect_privilege_escalation_paths()

        for esc in escalations:
            # Should have mitigation steps
            assert len(esc.mitigation) > 0
            assert isinstance(esc.mitigation, list)


class TestLateralMovement:
    """Test lateral movement identification."""

    def test_identify_same_zone_movement(self, attack_graph_client):
        """Test identifying movement within same zone."""
        analyzer = GraphAnalyzer(attack_graph_client)

        movements = analyzer.identify_lateral_movement_opportunities(
            max_opportunities=20
        )

        # Should find movement between DMZ assets
        dmz_movements = [
            m for m in movements if "dmz" in m.from_asset and "dmz" in m.to_asset
        ]

        assert len(dmz_movements) > 0

    def test_movement_detection_difficulty(self, attack_graph_client):
        """Test detection difficulty rating."""
        analyzer = GraphAnalyzer(attack_graph_client)

        movements = analyzer.identify_lateral_movement_opportunities()

        for mov in movements:
            # Detection difficulty should be valid
            assert mov.detection_difficulty in ["easy", "medium", "hard"]

    def test_movement_prerequisites(self, attack_graph_client):
        """Test prerequisites are identified."""
        analyzer = GraphAnalyzer(attack_graph_client)

        movements = analyzer.identify_lateral_movement_opportunities()

        for mov in movements:
            # Should have prerequisites
            assert len(mov.prerequisites) > 0
            assert len(mov.network_requirements) > 0


class TestAttackSurfaceAnalysis:
    """Test comprehensive attack surface analysis."""

    def test_complete_analysis(self, attack_graph_client):
        """Test complete attack surface analysis."""
        analyzer = GraphAnalyzer(attack_graph_client)

        surface = analyzer.analyze_attack_surface(max_paths=20)

        assert isinstance(surface, AttackSurface)
        assert len(surface.entry_points) > 0
        assert len(surface.high_value_targets) > 0
        assert len(surface.attack_paths) > 0
        assert surface.total_risk_score >= 0
        assert surface.total_risk_score <= 100
        assert len(surface.recommendations) > 0

    def test_risk_score_calculation(self, attack_graph_client):
        """Test risk score is calculated."""
        analyzer = GraphAnalyzer(attack_graph_client)

        surface = analyzer.analyze_attack_surface()

        # Risk score should be non-zero given vulnerabilities
        assert surface.total_risk_score > 0

        # Should be within valid range
        assert 0 <= surface.total_risk_score <= 100

    def test_recommendations_generated(self, attack_graph_client):
        """Test security recommendations are generated."""
        analyzer = GraphAnalyzer(attack_graph_client)

        surface = analyzer.analyze_attack_surface()

        # Should have multiple recommendations
        assert len(surface.recommendations) >= 3

        # Recommendations should be strings
        for rec in surface.recommendations:
            assert isinstance(rec, str)
            assert len(rec) > 10  # Should be descriptive

    def test_all_components_present(self, attack_graph_client):
        """Test all analysis components are present."""
        analyzer = GraphAnalyzer(attack_graph_client)

        surface = analyzer.analyze_attack_surface(max_paths=20)

        # Should have all components
        assert hasattr(surface, "entry_points")
        assert hasattr(surface, "high_value_targets")
        assert hasattr(surface, "attack_paths")
        assert hasattr(surface, "privilege_escalations")
        assert hasattr(surface, "lateral_movements")
        assert hasattr(surface, "total_risk_score")
        assert hasattr(surface, "recommendations")


class TestAttackPathEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_graph(self):
        """Test analysis on empty graph."""
        client = NetworkXClient()
        analyzer = GraphAnalyzer(client)

        entry_points = analyzer.identify_entry_points()
        targets = analyzer.identify_high_value_targets()
        paths = analyzer.find_shortest_attack_paths()

        assert len(entry_points) == 0
        assert len(targets) == 0
        assert len(paths) == 0

    def test_disconnected_graph(self):
        """Test when entry points and targets are disconnected."""
        client = NetworkXClient()

        # Add entry point
        client.add_node(
            GraphNode(
                node_id="asset:entry",
                node_type=NodeType.CONTAINER,
                properties={"internet_facing": True},
            )
        )

        # Add target (disconnected)
        client.add_node(
            GraphNode(
                node_id="asset:target",
                node_type=NodeType.CONTAINER,
                properties={"criticality": "critical", "criticality_score": 95},
            )
        )

        analyzer = GraphAnalyzer(client)
        paths = analyzer.find_shortest_attack_paths()

        # Should find no paths due to disconnection
        assert len(paths) == 0

    def test_max_path_limit(self, attack_graph_client):
        """Test max path limit is respected."""
        analyzer = GraphAnalyzer(attack_graph_client)

        paths = analyzer.find_shortest_attack_paths(max_length=2)

        # All paths should respect max length
        for path in paths:
            assert path.path_length <= 2
