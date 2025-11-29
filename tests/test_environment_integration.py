"""Tests for environment configuration and business context integration."""

import pytest
from pathlib import Path
import tempfile
import json
from datetime import datetime

from threat_radar.environment import (
    Environment,
    EnvironmentMetadata,
    Asset,
    Dependency,
    NetworkTopology,
    NetworkZone,
    GlobalBusinessContext,
    BusinessContext,
    Software,
    Network,
    ExposedPort,
    AssetMetadata,
    AssetType,
    Criticality,
    DataClassification,
    DependencyType,
    ComplianceFramework,
    EnvironmentType,
    CloudProvider,
    TrustLevel,
    RiskTolerance,
    EnvironmentParser,
    EnvironmentGraphBuilder,
)
from threat_radar.graph import NetworkXClient, NodeType


@pytest.fixture
def sample_business_context():
    """Create sample business context."""
    return BusinessContext(
        criticality=Criticality.HIGH,
        criticality_score=80,
        function="api-gateway",
        data_classification=DataClassification.PII,
        revenue_impact=Criticality.HIGH,  # Uses Criticality enum
        customer_facing=True,
        compliance_scope=[ComplianceFramework.PCI_DSS, ComplianceFramework.GDPR],
        sla_tier="tier-1",
        mttr_target=60,
        owner_team="platform-team",
    )


@pytest.fixture
def sample_asset(sample_business_context):
    """Create a sample asset."""
    return Asset(
        id="api-gateway-001",
        name="API Gateway",
        type=AssetType.API_GATEWAY,
        host="10.0.1.10",
        software=Software(
            image="nginx:1.25-alpine",
            os="Alpine Linux 3.18",
            runtime="nginx/1.25.0",
        ),
        network=Network(
            internal_ip="10.0.1.10",
            public_ip="203.0.113.10",
            exposed_ports=[
                ExposedPort(port=443, protocol="https", public=True),
                ExposedPort(port=80, protocol="http", public=True),
            ],
        ),
        business_context=sample_business_context,
        metadata=AssetMetadata(
            last_scanned=datetime.now(),
            last_patched=datetime.now(),
            tags={"environment": "production", "team": "platform"},
        ),
    )


@pytest.fixture
def sample_dependency():
    """Create a sample dependency."""
    return Dependency(
        source="api-gateway-001",
        target="payment-api-001",
        type=DependencyType.DEPENDS_ON,
        protocol="https",
        port=8443,
        encrypted=True,
        criticality=Criticality.CRITICAL,
        data_flow=DataClassification.PII,  # Uses DataClassification enum
    )


@pytest.fixture
def sample_network_topology():
    """Create sample network topology."""
    return NetworkTopology(
        zones=[
            NetworkZone(
                id="zone-dmz",
                name="dmz",
                trust_level=TrustLevel.UNTRUSTED,
                internet_accessible=True,
                assets=["api-gateway-001"],
            ),
            NetworkZone(
                id="zone-app-tier",
                name="app-tier",
                trust_level=TrustLevel.MEDIUM,
                internet_accessible=False,
                assets=["payment-api-001"],
            ),
        ],
        segmentation_rules=[
            {"from_zone": "dmz", "to_zone": "app-tier", "allowed": True},
            {"from_zone": "app-tier", "to_zone": "dmz", "allowed": False},
        ],
    )


@pytest.fixture
def sample_environment_metadata():
    """Create sample environment metadata."""
    return EnvironmentMetadata(
        name="test-environment",
        type=EnvironmentType.PRODUCTION,
        cloud_provider=CloudProvider.AWS,
        region="us-east-1",
        compliance_requirements=[ComplianceFramework.PCI_DSS, ComplianceFramework.SOX],
        owner="security-team@company.com",
        tags={"cost-center": "engineering", "project": "payment-platform"},
    )


@pytest.fixture
def sample_global_business_context():
    """Create sample global business context."""
    return GlobalBusinessContext(
        organization="Test Corp",
        business_unit="Engineering",
        risk_tolerance=RiskTolerance.MEDIUM,
    )


@pytest.fixture
def sample_environment(
    sample_environment_metadata,
    sample_asset,
    sample_dependency,
    sample_network_topology,
    sample_global_business_context,
):
    """Create a complete sample environment."""
    # Add target asset for dependency validation
    payment_api = Asset(
        id="payment-api-001",
        name="Payment API",
        type=AssetType.SERVICE,
        host="10.0.2.10",
        business_context=BusinessContext(
            criticality=Criticality.CRITICAL,
            criticality_score=95,
        ),
    )

    return Environment(
        environment=sample_environment_metadata,
        assets=[sample_asset, payment_api],
        dependencies=[sample_dependency],
        network_topology=sample_network_topology,
        business_context=sample_global_business_context,
    )


@pytest.fixture
def minimal_environment_dict():
    """Create minimal valid environment dictionary."""
    return {
        "environment": {
            "name": "minimal-env",
            "type": "development",
            "owner": "dev-team@company.com",
        },
        "assets": [
            {
                "id": "asset-1",
                "name": "Test Asset",
                "type": "container",
                "host": "10.0.1.1",
                "business_context": {
                    "criticality": "medium",
                    "criticality_score": 50,
                },
            }
        ],
        "dependencies": [],
    }


@pytest.fixture
def graph_client():
    """Create a fresh NetworkX graph client."""
    return NetworkXClient()


class TestBusinessContext:
    """Test BusinessContext model and validation."""

    def test_create_business_context(self, sample_business_context):
        """Test creating business context."""
        assert sample_business_context.criticality == Criticality.HIGH
        assert sample_business_context.criticality_score == 80
        assert sample_business_context.function == "api-gateway"
        assert sample_business_context.customer_facing is True

    def test_criticality_score_validation_critical(self):
        """Test that critical assets require score >= 80."""
        with pytest.raises(ValueError, match="criticality_score >= 80"):
            BusinessContext(
                criticality=Criticality.CRITICAL,
                criticality_score=70,  # Too low for critical
            )

    def test_criticality_score_validation_low(self):
        """Test that low criticality requires score <= 40."""
        with pytest.raises(ValueError, match="criticality_score <= 40"):
            BusinessContext(
                criticality=Criticality.LOW,
                criticality_score=50,  # Too high for low
            )

    def test_valid_criticality_scores(self):
        """Test valid criticality score combinations."""
        # Critical with 80+
        bc1 = BusinessContext(criticality=Criticality.CRITICAL, criticality_score=90)
        assert bc1.criticality_score == 90

        # High (no validator, any score works)
        bc2 = BusinessContext(criticality=Criticality.HIGH, criticality_score=70)
        assert bc2.criticality_score == 70

        # Medium (no validator, any score works)
        bc3 = BusinessContext(criticality=Criticality.MEDIUM, criticality_score=50)
        assert bc3.criticality_score == 50

        # Low with <=40
        bc4 = BusinessContext(criticality=Criticality.LOW, criticality_score=30)
        assert bc4.criticality_score == 30


class TestAsset:
    """Test Asset model."""

    def test_create_asset(self, sample_asset):
        """Test creating an asset."""
        assert sample_asset.id == "api-gateway-001"
        assert sample_asset.name == "API Gateway"
        assert sample_asset.type == AssetType.API_GATEWAY
        assert sample_asset.host == "10.0.1.10"
        assert sample_asset.business_context.criticality == Criticality.HIGH

    def test_asset_with_network(self, sample_asset):
        """Test asset with network configuration."""
        assert sample_asset.network is not None
        assert sample_asset.network.internal_ip == "10.0.1.10"
        assert sample_asset.network.public_ip == "203.0.113.10"
        assert len(sample_asset.network.exposed_ports) == 2

    def test_asset_with_software(self, sample_asset):
        """Test asset with software configuration."""
        assert sample_asset.software is not None
        assert sample_asset.software.image == "nginx:1.25-alpine"
        assert sample_asset.software.os == "Alpine Linux 3.18"

    def test_asset_compliance_scope(self, sample_asset):
        """Test asset compliance scope."""
        assert (
            ComplianceFramework.PCI_DSS
            in sample_asset.business_context.compliance_scope
        )
        assert (
            ComplianceFramework.GDPR in sample_asset.business_context.compliance_scope
        )


class TestDependency:
    """Test Dependency model."""

    def test_create_dependency(self, sample_dependency):
        """Test creating a dependency."""
        assert sample_dependency.source == "api-gateway-001"
        assert sample_dependency.target == "payment-api-001"
        assert sample_dependency.type == DependencyType.DEPENDS_ON
        assert sample_dependency.protocol == "https"
        assert sample_dependency.encrypted is True

    def test_dependency_with_criticality(self, sample_dependency):
        """Test dependency with criticality."""
        assert sample_dependency.criticality == Criticality.CRITICAL
        assert sample_dependency.data_flow == DataClassification.PII


class TestEnvironment:
    """Test Environment model."""

    def test_create_environment(self, sample_environment):
        """Test creating an environment."""
        assert sample_environment.environment.name == "test-environment"
        assert sample_environment.environment.type == EnvironmentType.PRODUCTION
        assert len(sample_environment.assets) == 2  # api-gateway + payment-api
        assert len(sample_environment.dependencies) == 1

    def test_get_asset(self, sample_environment):
        """Test getting asset by ID."""
        asset = sample_environment.get_asset("api-gateway-001")
        assert asset is not None
        assert asset.name == "API Gateway"

        # Non-existent asset
        assert sample_environment.get_asset("nonexistent") is None

    def test_get_critical_assets(self, sample_environment):
        """Test getting critical assets."""
        # Sample environment already has payment-api-001 which is CRITICAL
        critical = sample_environment.get_critical_assets()
        assert len(critical) == 1  # payment-api-001 is critical
        assert critical[0].id == "payment-api-001"

        # Add another critical asset
        critical_asset = Asset(
            id="db-001",
            name="Payment Database",
            type=AssetType.DATABASE,
            host="10.0.2.10",
            business_context=BusinessContext(
                criticality=Criticality.CRITICAL,
                criticality_score=95,
            ),
        )
        sample_environment.assets.append(critical_asset)

        critical = sample_environment.get_critical_assets()
        assert len(critical) == 2  # Now both are critical
        assert "payment-api-001" in [a.id for a in critical]
        assert "db-001" in [a.id for a in critical]

    def test_get_internet_facing_assets(self, sample_environment):
        """Test getting internet-facing assets."""
        internet_facing = sample_environment.get_internet_facing_assets()
        assert len(internet_facing) == 1
        assert internet_facing[0].id == "api-gateway-001"

    def test_get_pci_scope_assets(self, sample_environment):
        """Test getting PCI-DSS scope assets."""
        pci_assets = sample_environment.get_pci_scope_assets()
        assert len(pci_assets) == 1
        assert pci_assets[0].id == "api-gateway-001"

    def test_calculate_total_risk_score(self, sample_environment):
        """Test calculating total risk score."""
        risk_scores = sample_environment.calculate_total_risk_score()

        assert "total_assets" in risk_scores
        assert "critical_assets" in risk_scores
        assert "internet_facing_assets" in risk_scores
        assert "pci_scope_assets" in risk_scores
        assert "average_criticality" in risk_scores
        assert "high_risk_percentage" in risk_scores

        # Check values
        # Sample environment has: api-gateway (HIGH=3), payment-api (CRITICAL=4)
        # Average: (3+4)/2 = 3.5
        assert risk_scores["total_assets"] == 2
        assert risk_scores["critical_assets"] == 1  # payment-api
        assert risk_scores["internet_facing_assets"] == 1  # api-gateway
        assert risk_scores["pci_scope_assets"] == 1  # api-gateway
        assert risk_scores["average_criticality"] == 3.5
        assert risk_scores["high_risk_percentage"] == 50.0  # 1 critical out of 2


class TestEnvironmentParser:
    """Test EnvironmentParser functionality."""

    def test_load_from_dict(self, minimal_environment_dict):
        """Test loading environment from dictionary."""
        env = EnvironmentParser.load_from_dict(minimal_environment_dict)
        assert env.environment.name == "minimal-env"
        assert len(env.assets) == 1

    def test_load_from_json_file(self, minimal_environment_dict):
        """Test loading environment from JSON file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(minimal_environment_dict, f)
            temp_path = f.name

        try:
            env = EnvironmentParser.load_from_file(temp_path)
            assert env.environment.name == "minimal-env"
            assert env.environment.type == EnvironmentType.DEVELOPMENT
        finally:
            Path(temp_path).unlink()

    def test_load_from_yaml_file(self, minimal_environment_dict):
        """Test loading environment from YAML file."""
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(minimal_environment_dict, f)
            temp_path = f.name

        try:
            env = EnvironmentParser.load_from_file(temp_path)
            assert env.environment.name == "minimal-env"
        finally:
            Path(temp_path).unlink()

    def test_save_to_file(self, sample_environment):
        """Test saving environment to file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_path = f.name

        try:
            EnvironmentParser.save_to_file(sample_environment, temp_path)
            assert Path(temp_path).exists()

            # Load it back
            env = EnvironmentParser.load_from_file(temp_path)
            assert env.environment.name == "test-environment"
        finally:
            Path(temp_path).unlink()

    def test_validate_file_success(self, minimal_environment_dict):
        """Test validating a valid file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(minimal_environment_dict, f)
            temp_path = f.name

        try:
            is_valid = EnvironmentParser.validate_file(temp_path)
            assert is_valid is True
        finally:
            Path(temp_path).unlink()

    def test_validate_file_failure(self):
        """Test validating an invalid file."""
        invalid_data = {"environment": {"name": "test"}}  # Missing required fields

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(invalid_data, f)
            temp_path = f.name

        try:
            is_valid = EnvironmentParser.validate_file(temp_path)
            assert is_valid is False
        finally:
            Path(temp_path).unlink()

    def test_generate_template(self):
        """Test generating environment template."""
        template = EnvironmentParser.generate_template()

        assert "environment" in template
        assert "assets" in template
        assert "dependencies" in template
        assert template["environment"]["name"] == "my-environment"
        assert len(template["assets"]) == 1


class TestEnvironmentGraphBuilder:
    """Test EnvironmentGraphBuilder functionality."""

    def test_build_from_environment(self, sample_environment, graph_client):
        """Test building graph from environment."""
        builder = EnvironmentGraphBuilder(graph_client)
        builder.build_from_environment(sample_environment)

        metadata = graph_client.get_metadata()
        assert metadata.node_count == 2  # Two assets (api-gateway + payment-api)
        assert metadata.edge_count == 1  # One dependency

    def test_add_asset_node(self, sample_asset, graph_client):
        """Test adding asset as node."""
        builder = EnvironmentGraphBuilder(graph_client)
        env_metadata = EnvironmentMetadata(
            name="test",
            type=EnvironmentType.PRODUCTION,
            owner="test@test.com",
        )
        env = Environment(
            environment=env_metadata,
            assets=[sample_asset],
            dependencies=[],
        )

        node_id = builder._add_asset_node(sample_asset, env)

        assert node_id == "asset:api-gateway-001"
        node = graph_client.get_node(node_id)
        assert node is not None
        assert node.properties["name"] == "API Gateway"
        assert node.properties["criticality"] == "high"
        assert node.properties["criticality_score"] == 80
        assert node.properties["customer_facing"] is True

    def test_add_dependency_edge(self, sample_environment, graph_client):
        """Test adding dependency as edge."""
        # Add target asset so dependency can be created
        target_asset = Asset(
            id="payment-api-001",
            name="Payment API",
            type=AssetType.SERVICE,
            host="10.0.2.10",
            business_context=BusinessContext(
                criticality=Criticality.CRITICAL,
                criticality_score=95,
            ),
        )
        sample_environment.assets.append(target_asset)

        builder = EnvironmentGraphBuilder(graph_client)
        builder.build_from_environment(sample_environment)

        metadata = graph_client.get_metadata()
        assert metadata.node_count == 2  # Two assets
        assert metadata.edge_count == 1  # One dependency

    def test_calculate_risk_scores(self, sample_environment, graph_client):
        """Test calculating risk scores for assets."""
        builder = EnvironmentGraphBuilder(graph_client)
        risk_scores = builder.calculate_risk_scores(sample_environment)

        assert "api-gateway-001" in risk_scores
        score = risk_scores["api-gateway-001"]

        # Check score components:
        # - HIGH criticality: 30 points
        # - Internet-facing: 20 points
        # - PII data: 15 points
        # - Customer-facing: 10 points
        # - Compliance (2 frameworks): 10 points
        # Total: 85 points
        assert score == 85

    def test_add_network_topology(self, sample_environment, graph_client):
        """Test adding network topology to graph."""
        builder = EnvironmentGraphBuilder(graph_client)
        builder.build_from_environment(sample_environment)

        # Check that asset has zone information
        node = graph_client.get_node("asset:api-gateway-001")
        assert node is not None
        assert node.properties.get("network_zone") == "dmz"
        assert node.properties.get("zone_trust_level") == "untrusted"
        assert node.properties.get("zone_internet_accessible") is True

    def test_find_critical_paths(self, graph_client):
        """Test finding critical attack paths."""
        # Create environment with attack path
        env = Environment(
            environment=EnvironmentMetadata(
                name="test",
                type=EnvironmentType.PRODUCTION,
                owner="test@test.com",
            ),
            assets=[
                Asset(
                    id="gateway",
                    name="API Gateway",
                    type=AssetType.API_GATEWAY,
                    host="10.0.1.10",
                    network=Network(
                        internal_ip="10.0.1.10",
                        public_ip="203.0.113.10",
                    ),
                    business_context=BusinessContext(
                        criticality=Criticality.MEDIUM,
                        criticality_score=50,
                    ),
                ),
                Asset(
                    id="api",
                    name="API Server",
                    type=AssetType.SERVICE,
                    host="10.0.2.10",
                    business_context=BusinessContext(
                        criticality=Criticality.HIGH,
                        criticality_score=75,
                    ),
                ),
                Asset(
                    id="database",
                    name="Database",
                    type=AssetType.DATABASE,
                    host="10.0.3.10",
                    business_context=BusinessContext(
                        criticality=Criticality.CRITICAL,
                        criticality_score=95,
                    ),
                ),
            ],
            dependencies=[
                Dependency(
                    source="gateway",
                    target="api",
                    type=DependencyType.DEPENDS_ON,
                ),
                Dependency(
                    source="api",
                    target="database",
                    type=DependencyType.DEPENDS_ON,
                ),
            ],
        )

        builder = EnvironmentGraphBuilder(graph_client)
        builder.build_from_environment(env)

        paths = builder.find_critical_paths(env)

        # Should find path: gateway -> api -> database
        assert len(paths) > 0
        # Check that we have a path from internet-facing to critical
        assert any("gateway" in path and "database" in path for path in paths)


class TestNetworkTopology:
    """Test NetworkTopology model."""

    def test_create_network_zone(self):
        """Test creating network zone."""
        zone = NetworkZone(
            id="zone-dmz",
            name="dmz",
            trust_level=TrustLevel.UNTRUSTED,
            internet_accessible=True,
            assets=["asset-1", "asset-2"],
        )

        assert zone.id == "zone-dmz"
        assert zone.name == "dmz"
        assert zone.trust_level == TrustLevel.UNTRUSTED
        assert zone.internet_accessible is True
        assert len(zone.assets) == 2

    def test_create_network_topology(self, sample_network_topology):
        """Test creating network topology."""
        assert len(sample_network_topology.zones) == 2
        assert len(sample_network_topology.segmentation_rules) == 2

        dmz = sample_network_topology.zones[0]
        assert dmz.name == "dmz"
        assert dmz.internet_accessible is True


class TestIntegrationScenarios:
    """Test complete integration scenarios."""

    def test_complete_environment_workflow(self):
        """Test complete workflow: load -> validate -> build graph -> analyze."""
        # Create environment
        env_dict = {
            "environment": {
                "name": "production",
                "type": "production",
                "cloud_provider": "aws",
                "region": "us-east-1",
                "compliance_requirements": ["pci-dss", "sox"],
                "owner": "security@company.com",
            },
            "assets": [
                {
                    "id": "web-server",
                    "name": "Web Server",
                    "type": "container",
                    "host": "10.0.1.10",
                    "network": {
                        "internal_ip": "10.0.1.10",
                        "public_ip": "203.0.113.10",
                    },
                    "business_context": {
                        "criticality": "high",
                        "criticality_score": 75,
                        "customer_facing": True,
                    },
                },
                {
                    "id": "database",
                    "name": "Database",
                    "type": "database",
                    "host": "10.0.2.10",
                    "business_context": {
                        "criticality": "critical",
                        "criticality_score": 95,
                        "data_classification": "pii",
                    },
                },
            ],
            "dependencies": [
                {
                    "source": "web-server",
                    "target": "database",
                    "type": "depends_on",
                    "protocol": "postgresql",
                    "port": 5432,
                }
            ],
        }

        # Load environment
        env = EnvironmentParser.load_from_dict(env_dict)
        assert env.environment.name == "production"

        # Build graph
        client = NetworkXClient()
        builder = EnvironmentGraphBuilder(client)
        builder.build_from_environment(env)

        # Verify graph
        metadata = client.get_metadata()
        assert metadata.node_count == 2
        assert metadata.edge_count == 1

        # Calculate risk
        risk_scores = builder.calculate_risk_scores(env)
        assert "web-server" in risk_scores
        assert "database" in risk_scores

        # Database should have higher risk due to:
        # - CRITICAL (40) + PII (15) = 55
        # Web server:
        # - HIGH (30) + Internet (20) + Customer-facing (10) = 60
        assert risk_scores["web-server"] == 60
        assert risk_scores["database"] == 55

    def test_multi_zone_environment(self):
        """Test environment with multiple network zones."""
        env_dict = {
            "environment": {
                "name": "multi-zone",
                "type": "production",
                "owner": "ops@company.com",
            },
            "assets": [
                {
                    "id": "dmz-lb",
                    "name": "Load Balancer",
                    "type": "load-balancer",
                    "host": "10.0.1.10",
                    "business_context": {
                        "criticality": "medium",
                        "criticality_score": 50,
                    },
                },
                {
                    "id": "app-server",
                    "name": "App Server",
                    "type": "service",
                    "host": "10.0.2.10",
                    "business_context": {
                        "criticality": "high",
                        "criticality_score": 70,
                    },
                },
                {
                    "id": "db-server",
                    "name": "Database",
                    "type": "database",
                    "host": "10.0.3.10",
                    "business_context": {
                        "criticality": "critical",
                        "criticality_score": 90,
                    },
                },
            ],
            "dependencies": [
                {
                    "source": "dmz-lb",
                    "target": "app-server",
                    "type": "depends_on",
                },
                {
                    "source": "app-server",
                    "target": "db-server",
                    "type": "depends_on",
                },
            ],
            "network_topology": {
                "zones": [
                    {
                        "id": "zone-dmz",
                        "name": "dmz",
                        "trust_level": "untrusted",
                        "internet_accessible": True,
                        "assets": ["dmz-lb"],
                    },
                    {
                        "id": "zone-app-tier",
                        "name": "app-tier",
                        "trust_level": "medium",
                        "internet_accessible": False,
                        "assets": ["app-server"],
                    },
                    {
                        "id": "zone-data-tier",
                        "name": "data-tier",
                        "trust_level": "trusted",
                        "internet_accessible": False,
                        "assets": ["db-server"],
                    },
                ],
            },
        }

        env = EnvironmentParser.load_from_dict(env_dict)
        assert len(env.network_topology.zones) == 3

        client = NetworkXClient()
        builder = EnvironmentGraphBuilder(client)
        builder.build_from_environment(env)

        # Verify zones are applied
        dmz_node = client.get_node("asset:dmz-lb")
        assert dmz_node.properties["network_zone"] == "dmz"
        assert dmz_node.properties["zone_trust_level"] == "untrusted"

        app_node = client.get_node("asset:app-server")
        assert app_node.properties["network_zone"] == "app-tier"
        assert app_node.properties["zone_trust_level"] == "medium"

        db_node = client.get_node("asset:db-server")
        assert db_node.properties["network_zone"] == "data-tier"
        assert db_node.properties["zone_trust_level"] == "trusted"
