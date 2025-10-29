"""
Advanced Environment Configuration Examples

This script demonstrates advanced features including:
- Network topology and zones
- Dependencies between assets
- Compliance scoping
- Graph integration
"""

import json
from pathlib import Path
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
    EnvironmentType,
    AssetType,
    Criticality,
    DataClassification,
    DependencyType,
    ComplianceFramework,
    CloudProvider,
    TrustLevel,
    RiskTolerance,
    EnvironmentParser,
    EnvironmentGraphBuilder,
)
from threat_radar.graph import NetworkXClient


def example_1_network_topology():
    """Example 1: Define network topology with security zones."""
    print("\n" + "=" * 70)
    print("Example 1: Network Topology with Security Zones")
    print("=" * 70)

    env = Environment(
        environment=EnvironmentMetadata(
            name="segmented-network",
            type=EnvironmentType.PRODUCTION,
            owner="network-team@company.com",
        ),
        assets=[
            Asset(
                id="lb-1",
                name="Load Balancer",
                type=AssetType.LOAD_BALANCER,
                host="10.0.1.10",
                network=Network(
                    internal_ip="10.0.1.10",
                    public_ip="203.0.113.10",
                ),
                business_context=BusinessContext(
                    criticality=Criticality.HIGH,
                    criticality_score=75,
                ),
            ),
            Asset(
                id="app-1",
                name="Application Server",
                type=AssetType.SERVICE,
                host="10.0.2.10",
                business_context=BusinessContext(
                    criticality=Criticality.HIGH,
                    criticality_score=80,
                ),
            ),
            Asset(
                id="db-1",
                name="Database",
                type=AssetType.DATABASE,
                host="10.0.3.10",
                business_context=BusinessContext(
                    criticality=Criticality.CRITICAL,
                    criticality_score=95,
                ),
            ),
        ],
        dependencies=[],
        network_topology=NetworkTopology(
            zones=[
                NetworkZone(
                    id="dmz",
                    name="DMZ",
                    trust_level=TrustLevel.UNTRUSTED,
                    internet_accessible=True,
                    assets=["lb-1"],
                ),
                NetworkZone(
                    id="app-tier",
                    name="Application Tier",
                    trust_level=TrustLevel.MEDIUM,
                    internet_accessible=False,
                    assets=["app-1"],
                ),
                NetworkZone(
                    id="data-tier",
                    name="Data Tier",
                    trust_level=TrustLevel.TRUSTED,
                    internet_accessible=False,
                    assets=["db-1"],
                ),
            ],
            segmentation_rules=[
                {"from_zone": "dmz", "to_zone": "app-tier", "allowed": True},
                {"from_zone": "app-tier", "to_zone": "data-tier", "allowed": True},
                {"from_zone": "dmz", "to_zone": "data-tier", "allowed": False},
            ],
        ),
    )

    print(f"\n✓ Created segmented network environment")
    print(f"  Total zones: {len(env.network_topology.zones)}")

    for zone in env.network_topology.zones:
        print(f"\n  Zone: {zone.name}")
        print(f"    Trust level: {zone.trust_level.value}")
        print(f"    Internet accessible: {zone.internet_accessible}")
        print(f"    Assets: {len(zone.assets)}")

    print(f"\n  Segmentation rules:")
    for rule in env.network_topology.segmentation_rules:
        status = "✓" if rule.allowed else "✗"
        print(f"    {status} {rule.from_zone} → {rule.to_zone}")


def example_2_asset_dependencies():
    """Example 2: Define dependencies between assets."""
    print("\n" + "=" * 70)
    print("Example 2: Asset Dependencies and Data Flows")
    print("=" * 70)

    env = Environment(
        environment=EnvironmentMetadata(
            name="microservices-app",
            type=EnvironmentType.PRODUCTION,
            cloud_provider=CloudProvider.AWS,
            region="us-east-1",
            owner="platform@company.com",
        ),
        assets=[
            Asset(
                id="api-gateway",
                name="API Gateway",
                type=AssetType.API_GATEWAY,
                host="10.0.1.10",
                network=Network(
                    internal_ip="10.0.1.10",
                    public_ip="203.0.113.10",
                ),
                business_context=BusinessContext(
                    criticality=Criticality.HIGH,
                    criticality_score=80,
                    customer_facing=True,
                ),
            ),
            Asset(
                id="auth-service",
                name="Authentication Service",
                type=AssetType.SERVICE,
                host="10.0.2.10",
                business_context=BusinessContext(
                    criticality=Criticality.CRITICAL,
                    criticality_score=90,
                    data_classification=DataClassification.PII,
                ),
            ),
            Asset(
                id="payment-service",
                name="Payment Service",
                type=AssetType.SERVICE,
                host="10.0.2.20",
                business_context=BusinessContext(
                    criticality=Criticality.CRITICAL,
                    criticality_score=95,
                    data_classification=DataClassification.PCI,
                    compliance_scope=[ComplianceFramework.PCI_DSS],
                ),
            ),
            Asset(
                id="user-db",
                name="User Database",
                type=AssetType.DATABASE,
                host="10.0.3.10",
                business_context=BusinessContext(
                    criticality=Criticality.CRITICAL,
                    criticality_score=95,
                    data_classification=DataClassification.PII,
                    compliance_scope=[ComplianceFramework.GDPR],
                ),
            ),
        ],
        dependencies=[
            Dependency(
                source="api-gateway",
                target="auth-service",
                type=DependencyType.DEPENDS_ON,
                protocol="https",
                port=8443,
                encrypted=True,
                criticality=Criticality.CRITICAL,
            ),
            Dependency(
                source="api-gateway",
                target="payment-service",
                type=DependencyType.DEPENDS_ON,
                protocol="https",
                port=8443,
                encrypted=True,
                criticality=Criticality.CRITICAL,
                data_flow=DataClassification.PCI,
            ),
            Dependency(
                source="auth-service",
                target="user-db",
                type=DependencyType.READS_FROM,
                protocol="postgresql",
                port=5432,
                encrypted=True,
                data_flow=DataClassification.PII,
            ),
            Dependency(
                source="payment-service",
                target="user-db",
                type=DependencyType.READS_FROM,
                protocol="postgresql",
                port=5432,
                encrypted=True,
                data_flow=DataClassification.PCI,
            ),
        ],
    )

    print(f"\n✓ Created microservices environment")
    print(f"  Assets: {len(env.assets)}")
    print(f"  Dependencies: {len(env.dependencies)}")

    print(f"\n  Dependency Graph:")
    for dep in env.dependencies:
        source_asset = env.get_asset(dep.source)
        target_asset = env.get_asset(dep.target)
        encrypted_icon = "🔒" if dep.encrypted else "🔓"
        print(f"    {encrypted_icon} {source_asset.name} → {target_asset.name}")
        print(f"       Type: {dep.type.value}, Protocol: {dep.protocol}, Port: {dep.port}")
        if dep.data_flow:
            print(f"       Data flow: {dep.data_flow.value}")


def example_3_compliance_scoping():
    """Example 3: Compliance scoping and requirements."""
    print("\n" + "=" * 70)
    print("Example 3: Compliance Scoping")
    print("=" * 70)

    env = Environment(
        environment=EnvironmentMetadata(
            name="compliance-env",
            type=EnvironmentType.PRODUCTION,
            compliance_requirements=[
                ComplianceFramework.PCI_DSS,
                ComplianceFramework.HIPAA,
                ComplianceFramework.SOX,
            ],
            owner="compliance@company.com",
        ),
        assets=[
            Asset(
                id="payment-api",
                name="Payment API",
                type=AssetType.SERVICE,
                host="10.0.1.10",
                business_context=BusinessContext(
                    criticality=Criticality.CRITICAL,
                    criticality_score=95,
                    data_classification=DataClassification.PCI,
                    compliance_scope=[ComplianceFramework.PCI_DSS, ComplianceFramework.SOX],
                ),
            ),
            Asset(
                id="medical-db",
                name="Medical Records Database",
                type=AssetType.DATABASE,
                host="10.0.2.10",
                business_context=BusinessContext(
                    criticality=Criticality.CRITICAL,
                    criticality_score=95,
                    data_classification=DataClassification.PHI,
                    compliance_scope=[ComplianceFramework.HIPAA],
                ),
            ),
            Asset(
                id="financial-reports",
                name="Financial Reporting Service",
                type=AssetType.SERVICE,
                host="10.0.3.10",
                business_context=BusinessContext(
                    criticality=Criticality.HIGH,
                    criticality_score=85,
                    data_classification=DataClassification.CONFIDENTIAL,
                    compliance_scope=[ComplianceFramework.SOX],
                ),
            ),
        ],
        dependencies=[],
        business_context=GlobalBusinessContext(
            organization="Healthcare Financial Services Inc.",
            business_unit="Operations",
            risk_tolerance=RiskTolerance.LOW,
        ),
    )

    print(f"\n✓ Environment: {env.environment.name}")
    print(f"  Organization: {env.business_context.organization}")
    print(f"  Risk tolerance: {env.business_context.risk_tolerance.value}")
    print(f"\n  Compliance Requirements:")
    for req in env.environment.compliance_requirements:
        print(f"    - {req.value.upper()}")

    # Group assets by compliance scope
    print(f"\n  Assets by Compliance Framework:")

    for framework in [ComplianceFramework.PCI_DSS, ComplianceFramework.HIPAA, ComplianceFramework.SOX]:
        assets = [a for a in env.assets if framework in a.business_context.compliance_scope]
        if assets:
            print(f"\n    {framework.value.upper()} ({len(assets)} assets):")
            for asset in assets:
                print(f"      - {asset.name} ({asset.business_context.data_classification.value})")


def example_4_build_graph():
    """Example 4: Build graph from environment configuration."""
    print("\n" + "=" * 70)
    print("Example 4: Build Graph from Environment")
    print("=" * 70)

    # Create environment
    env = Environment(
        environment=EnvironmentMetadata(
            name="graph-example",
            type=EnvironmentType.PRODUCTION,
            owner="ops@company.com",
        ),
        assets=[
            Asset(
                id="web",
                name="Web Server",
                type=AssetType.CONTAINER,
                host="10.0.1.10",
                network=Network(
                    internal_ip="10.0.1.10",
                    public_ip="203.0.113.10",
                ),
                business_context=BusinessContext(
                    criticality=Criticality.HIGH,
                    criticality_score=75,
                ),
            ),
            Asset(
                id="api",
                name="API Server",
                type=AssetType.SERVICE,
                host="10.0.2.10",
                business_context=BusinessContext(
                    criticality=Criticality.HIGH,
                    criticality_score=80,
                ),
            ),
            Asset(
                id="db",
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
                source="web",
                target="api",
                type=DependencyType.DEPENDS_ON,
                protocol="https",
                port=443,
            ),
            Dependency(
                source="api",
                target="db",
                type=DependencyType.DEPENDS_ON,
                protocol="postgresql",
                port=5432,
            ),
        ],
    )

    # Build graph
    client = NetworkXClient()
    builder = EnvironmentGraphBuilder(client)
    builder.build_from_environment(env)

    metadata = client.get_metadata()
    print(f"\n✓ Built graph from environment")
    print(f"  Nodes: {metadata.node_count}")
    print(f"  Edges: {metadata.edge_count}")
    print(f"  Node types: {metadata.node_type_counts}")

    # Calculate risk scores
    risk_scores = builder.calculate_risk_scores(env)
    print(f"\n  Risk Scores (0-100):")
    for asset_id, score in sorted(risk_scores.items(), key=lambda x: x[1], reverse=True):
        asset = env.get_asset(asset_id)
        risk_level = "🔴" if score >= 80 else "🟠" if score >= 60 else "🟡"
        print(f"    {risk_level} {asset.name}: {score}")

    # Find critical paths
    paths = builder.find_critical_paths(env)
    print(f"\n  Critical Attack Paths: {len(paths)}")
    for i, path in enumerate(paths[:3], 1):  # Show first 3
        path_names = [env.get_asset(asset_id).name for asset_id in path]
        print(f"    Path {i}: {' → '.join(path_names)}")


def example_5_complex_environment():
    """Example 5: Complete complex environment."""
    print("\n" + "=" * 70)
    print("Example 5: Complete Complex Environment")
    print("=" * 70)

    env = Environment(
        environment=EnvironmentMetadata(
            name="ecommerce-platform",
            type=EnvironmentType.PRODUCTION,
            cloud_provider=CloudProvider.AWS,
            region="us-east-1",
            compliance_requirements=[
                ComplianceFramework.PCI_DSS,
                ComplianceFramework.GDPR,
                ComplianceFramework.SOX,
            ],
            owner="platform-team@company.com",
            tags={"cost-center": "engineering", "project": "ecommerce"},
        ),
        assets=[
            # DMZ
            Asset(
                id="lb-1",
                name="Load Balancer",
                type=AssetType.LOAD_BALANCER,
                host="10.0.1.10",
                network=Network(
                    internal_ip="10.0.1.10",
                    public_ip="203.0.113.10",
                    exposed_ports=[
                        ExposedPort(port=443, protocol="https", public=True),
                        ExposedPort(port=80, protocol="http", public=True),
                    ],
                ),
                business_context=BusinessContext(
                    criticality=Criticality.HIGH,
                    criticality_score=75,
                    function="load-balancer",
                    customer_facing=True,
                    sla_tier="tier-1",
                    mttr_target=30,
                ),
            ),
            # Web Tier
            Asset(
                id="web-1",
                name="Frontend Web Server",
                type=AssetType.CONTAINER,
                host="10.0.2.10",
                software=Software(
                    image="nginx:1.25-alpine",
                    os="Alpine Linux 3.18",
                ),
                business_context=BusinessContext(
                    criticality=Criticality.HIGH,
                    criticality_score=80,
                    function="web-server",
                    customer_facing=True,
                    sla_tier="tier-1",
                ),
            ),
            # App Tier
            Asset(
                id="api-1",
                name="API Gateway",
                type=AssetType.API_GATEWAY,
                host="10.0.3.10",
                business_context=BusinessContext(
                    criticality=Criticality.HIGH,
                    criticality_score=85,
                    function="api-gateway",
                    data_classification=DataClassification.PII,
                    customer_facing=True,
                ),
            ),
            Asset(
                id="payment-1",
                name="Payment Service",
                type=AssetType.SERVICE,
                host="10.0.3.20",
                business_context=BusinessContext(
                    criticality=Criticality.CRITICAL,
                    criticality_score=95,
                    function="payment-processing",
                    data_classification=DataClassification.PCI,
                    compliance_scope=[ComplianceFramework.PCI_DSS],
                    sla_tier="tier-1",
                    mttr_target=15,
                ),
            ),
            # Data Tier
            Asset(
                id="db-1",
                name="User Database",
                type=AssetType.DATABASE,
                host="10.0.4.10",
                business_context=BusinessContext(
                    criticality=Criticality.CRITICAL,
                    criticality_score=95,
                    function="user-data-storage",
                    data_classification=DataClassification.PII,
                    compliance_scope=[ComplianceFramework.GDPR],
                ),
            ),
            Asset(
                id="cache-1",
                name="Redis Cache",
                type=AssetType.SERVICE,
                host="10.0.4.20",
                business_context=BusinessContext(
                    criticality=Criticality.MEDIUM,
                    criticality_score=60,
                    function="caching",
                ),
            ),
            # Analytics
            Asset(
                id="analytics-1",
                name="Analytics Service",
                type=AssetType.SERVICE,
                host="10.0.5.10",
                business_context=BusinessContext(
                    criticality=Criticality.MEDIUM,
                    criticality_score=50,
                    function="analytics",
                    data_classification=DataClassification.INTERNAL,
                ),
            ),
        ],
        dependencies=[
            # User traffic flow
            Dependency(
                source="lb-1",
                target="web-1",
                type=DependencyType.DEPENDS_ON,
                protocol="http",
                port=80,
            ),
            Dependency(
                source="web-1",
                target="api-1",
                type=DependencyType.DEPENDS_ON,
                protocol="https",
                port=443,
                encrypted=True,
            ),
            Dependency(
                source="api-1",
                target="payment-1",
                type=DependencyType.DEPENDS_ON,
                protocol="https",
                port=8443,
                encrypted=True,
                criticality=Criticality.CRITICAL,
                data_flow=DataClassification.PCI,
            ),
            # Database connections
            Dependency(
                source="api-1",
                target="db-1",
                type=DependencyType.READS_FROM,
                protocol="postgresql",
                port=5432,
                encrypted=True,
                data_flow=DataClassification.PII,
            ),
            Dependency(
                source="payment-1",
                target="db-1",
                type=DependencyType.READS_FROM,
                protocol="postgresql",
                port=5432,
                encrypted=True,
                data_flow=DataClassification.PCI,
            ),
            # Caching
            Dependency(
                source="api-1",
                target="cache-1",
                type=DependencyType.DEPENDS_ON,
                protocol="redis",
                port=6379,
            ),
            # Analytics
            Dependency(
                source="api-1",
                target="analytics-1",
                type=DependencyType.COMMUNICATES_WITH,
                protocol="https",
                port=8080,
            ),
        ],
        network_topology=NetworkTopology(
            zones=[
                NetworkZone(
                    id="dmz",
                    name="DMZ",
                    trust_level=TrustLevel.UNTRUSTED,
                    internet_accessible=True,
                    assets=["lb-1"],
                ),
                NetworkZone(
                    id="web-tier",
                    name="Web Tier",
                    trust_level=TrustLevel.MEDIUM,
                    internet_accessible=False,
                    assets=["web-1"],
                ),
                NetworkZone(
                    id="app-tier",
                    name="Application Tier",
                    trust_level=TrustLevel.MEDIUM,
                    internet_accessible=False,
                    assets=["api-1", "payment-1"],
                ),
                NetworkZone(
                    id="data-tier",
                    name="Data Tier",
                    trust_level=TrustLevel.TRUSTED,
                    internet_accessible=False,
                    assets=["db-1", "cache-1"],
                ),
                NetworkZone(
                    id="analytics",
                    name="Analytics",
                    trust_level=TrustLevel.MEDIUM,
                    internet_accessible=False,
                    assets=["analytics-1"],
                ),
            ],
        ),
        business_context=GlobalBusinessContext(
            organization="E-Commerce Corp",
            business_unit="Platform Engineering",
            risk_tolerance=RiskTolerance.MEDIUM,
        ),
    )

    # Summary
    print(f"\n✓ Created complex e-commerce environment")
    print(f"  Environment: {env.environment.name}")
    print(f"  Cloud: {env.environment.cloud_provider.value}")
    print(f"  Organization: {env.business_context.organization}")

    print(f"\n  Statistics:")
    print(f"    Total assets: {len(env.assets)}")
    print(f"    Dependencies: {len(env.dependencies)}")
    print(f"    Network zones: {len(env.network_topology.zones)}")

    # Risk analysis
    risk_scores = env.calculate_total_risk_score()
    print(f"\n  Risk Assessment:")
    print(f"    Critical assets: {risk_scores['critical_assets']}")
    print(f"    Internet-facing: {risk_scores['internet_facing_assets']}")
    print(f"    PCI scope: {risk_scores['pci_scope_assets']}")
    print(f"    Average criticality: {risk_scores['average_criticality']:.2f}/4.0")
    print(f"    High-risk %: {risk_scores['high_risk_percentage']:.1f}%")

    # Save to file
    output_file = Path("/tmp/ecommerce-environment.json")
    EnvironmentParser.save_to_file(env, output_file)
    print(f"\n✓ Saved to: {output_file}")

    # Clean up
    output_file.unlink()


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("THREAT RADAR - Environment Configuration Examples")
    print("Advanced Configuration Examples")
    print("=" * 70)

    # Run all examples
    example_1_network_topology()
    example_2_asset_dependencies()
    example_3_compliance_scoping()
    example_4_build_graph()
    example_5_complex_environment()

    print("\n" + "=" * 70)
    print("All examples completed successfully!")
    print("=" * 70 + "\n")
