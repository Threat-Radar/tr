"""
Basic Environment Configuration Examples

This script demonstrates basic usage of the environment configuration module,
including creating, validating, and analyzing environment configurations.
"""

import json
from pathlib import Path
from threat_radar.environment import (
    Environment,
    EnvironmentMetadata,
    Asset,
    Dependency,
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
    EnvironmentParser,
)


def example_1_create_simple_environment():
    """Example 1: Create a minimal environment configuration."""
    print("\n" + "=" * 70)
    print("Example 1: Create Simple Environment")
    print("=" * 70)

    # Create a minimal environment with one asset
    env = Environment(
        environment=EnvironmentMetadata(
            name="dev-environment",
            type=EnvironmentType.DEVELOPMENT,
            owner="dev-team@company.com",
        ),
        assets=[
            Asset(
                id="web-server-1",
                name="Development Web Server",
                type=AssetType.CONTAINER,
                host="10.0.1.10",
                business_context=BusinessContext(
                    criticality=Criticality.LOW,
                    criticality_score=20,
                    function="development-server",
                ),
            )
        ],
        dependencies=[],
    )

    print(f"\n✓ Created environment: {env.environment.name}")
    print(f"  Type: {env.environment.type.value}")
    print(f"  Assets: {len(env.assets)}")
    print(f"\n  Asset details:")
    for asset in env.assets:
        print(f"    - {asset.name} (ID: {asset.id})")
        print(f"      Type: {asset.type.value}")
        print(f"      Criticality: {asset.business_context.criticality.value}")


def example_2_add_business_context():
    """Example 2: Create environment with rich business context."""
    print("\n" + "=" * 70)
    print("Example 2: Environment with Business Context")
    print("=" * 70)

    env = Environment(
        environment=EnvironmentMetadata(
            name="production-api",
            type=EnvironmentType.PRODUCTION,
            cloud_provider=CloudProvider.AWS,
            region="us-east-1",
            compliance_requirements=[ComplianceFramework.PCI_DSS, ComplianceFramework.GDPR],
            owner="platform-team@company.com",
        ),
        assets=[
            Asset(
                id="api-gateway",
                name="API Gateway",
                type=AssetType.API_GATEWAY,
                host="10.0.1.10",
                software=Software(
                    image="nginx:1.25-alpine",
                    os="Alpine Linux 3.18",
                ),
                network=Network(
                    internal_ip="10.0.1.10",
                    public_ip="203.0.113.10",
                    exposed_ports=[
                        ExposedPort(port=443, protocol="https", public=True),
                    ],
                ),
                business_context=BusinessContext(
                    criticality=Criticality.HIGH,
                    criticality_score=80,
                    function="api-gateway",
                    data_classification=DataClassification.PII,
                    customer_facing=True,
                    compliance_scope=[ComplianceFramework.PCI_DSS, ComplianceFramework.GDPR],
                    sla_tier="tier-1",
                    mttr_target=60,
                    owner_team="platform-team",
                ),
            )
        ],
        dependencies=[],
    )

    print(f"\n✓ Created production environment: {env.environment.name}")
    print(f"  Cloud: {env.environment.cloud_provider.value}")
    print(f"  Region: {env.environment.region}")
    print(f"  Compliance: {[c.value for c in env.environment.compliance_requirements]}")

    asset = env.assets[0]
    print(f"\n  Asset: {asset.name}")
    print(f"    Criticality: {asset.business_context.criticality.value} ({asset.business_context.criticality_score}/100)")
    print(f"    Customer-facing: {asset.business_context.customer_facing}")
    print(f"    Data classification: {asset.business_context.data_classification.value}")
    print(f"    SLA tier: {asset.business_context.sla_tier}")
    print(f"    MTTR target: {asset.business_context.mttr_target} hours")


def example_3_validate_environment():
    """Example 3: Validate environment configuration."""
    print("\n" + "=" * 70)
    print("Example 3: Validate Environment Configuration")
    print("=" * 70)

    # Create a valid environment
    valid_env = {
        "environment": {
            "name": "test-env",
            "type": "staging",
            "owner": "qa-team@company.com",
        },
        "assets": [
            {
                "id": "test-server",
                "name": "Test Server",
                "type": "container",
                "host": "10.0.1.50",
                "business_context": {
                    "criticality": "medium",
                    "criticality_score": 50,
                },
            }
        ],
        "dependencies": [],
    }

    try:
        env = EnvironmentParser.load_from_dict(valid_env)
        print(f"\n✓ Validation successful!")
        print(f"  Environment: {env.environment.name}")
        print(f"  Assets: {len(env.assets)}")
    except Exception as e:
        print(f"\n✗ Validation failed: {e}")

    # Demonstrate validation failure
    print("\n" + "-" * 70)
    print("Testing invalid configuration (critical asset with low score)...")

    invalid_env = {
        "environment": {
            "name": "invalid",
            "type": "production",
            "owner": "test@company.com",
        },
        "assets": [
            {
                "id": "asset-1",
                "name": "Invalid Asset",
                "type": "container",
                "host": "10.0.1.1",
                "business_context": {
                    "criticality": "critical",
                    "criticality_score": 50,  # Too low for critical!
                },
            }
        ],
        "dependencies": [],
    }

    try:
        env = EnvironmentParser.load_from_dict(invalid_env)
        print("✓ Validation passed (unexpected)")
    except Exception as e:
        print(f"✗ Validation failed (expected): {type(e).__name__}")
        print(f"  Reason: Critical assets require criticality_score >= 80")


def example_4_save_and_load():
    """Example 4: Save and load environment configurations."""
    print("\n" + "=" * 70)
    print("Example 4: Save and Load Environment")
    print("=" * 70)

    # Create environment
    env = Environment(
        environment=EnvironmentMetadata(
            name="example-env",
            type=EnvironmentType.STAGING,
            owner="ops@company.com",
        ),
        assets=[
            Asset(
                id="app-server",
                name="Application Server",
                type=AssetType.SERVICE,
                host="10.0.2.10",
                business_context=BusinessContext(
                    criticality=Criticality.MEDIUM,
                    criticality_score=50,
                ),
            )
        ],
        dependencies=[],
    )

    # Save to file
    output_file = Path("/tmp/example-environment.json")
    EnvironmentParser.save_to_file(env, output_file)
    print(f"\n✓ Saved environment to: {output_file}")

    # Load from file
    loaded_env = EnvironmentParser.load_from_file(output_file)
    print(f"✓ Loaded environment: {loaded_env.environment.name}")
    print(f"  Assets: {len(loaded_env.assets)}")
    print(f"  First asset: {loaded_env.assets[0].name}")

    # Clean up
    output_file.unlink()
    print(f"\n✓ Cleaned up temporary file")


def example_5_query_assets():
    """Example 5: Query and filter assets."""
    print("\n" + "=" * 70)
    print("Example 5: Query and Filter Assets")
    print("=" * 70)

    # Create environment with multiple assets
    env = Environment(
        environment=EnvironmentMetadata(
            name="multi-asset-env",
            type=EnvironmentType.PRODUCTION,
            owner="ops@company.com",
        ),
        assets=[
            Asset(
                id="web-1",
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
                    customer_facing=True,
                ),
            ),
            Asset(
                id="db-1",
                name="Database",
                type=AssetType.DATABASE,
                host="10.0.2.10",
                business_context=BusinessContext(
                    criticality=Criticality.CRITICAL,
                    criticality_score=95,
                    data_classification=DataClassification.PII,
                    compliance_scope=[ComplianceFramework.PCI_DSS],
                ),
            ),
            Asset(
                id="api-1",
                name="API Service",
                type=AssetType.SERVICE,
                host="10.0.2.20",
                business_context=BusinessContext(
                    criticality=Criticality.MEDIUM,
                    criticality_score=50,
                ),
            ),
        ],
        dependencies=[],
    )

    # Query assets
    print(f"\n✓ Environment: {env.environment.name}")
    print(f"  Total assets: {len(env.assets)}")

    # Get critical assets
    critical = env.get_critical_assets()
    print(f"\n  Critical assets ({len(critical)}):")
    for asset in critical:
        print(f"    - {asset.name} (criticality: {asset.business_context.criticality.value})")

    # Get internet-facing assets
    internet_facing = env.get_internet_facing_assets()
    print(f"\n  Internet-facing assets ({len(internet_facing)}):")
    for asset in internet_facing:
        print(f"    - {asset.name} (public IP: {asset.network.public_ip})")

    # Get PCI scope assets
    pci_scope = env.get_pci_scope_assets()
    print(f"\n  PCI-DSS scope assets ({len(pci_scope)}):")
    for asset in pci_scope:
        print(f"    - {asset.name}")

    # Get specific asset
    asset = env.get_asset("db-1")
    if asset:
        print(f"\n  Retrieved asset 'db-1': {asset.name}")
        print(f"    Type: {asset.type.value}")
        print(f"    Criticality: {asset.business_context.criticality.value}")


def example_6_calculate_risk():
    """Example 6: Calculate risk scores."""
    print("\n" + "=" * 70)
    print("Example 6: Calculate Risk Scores")
    print("=" * 70)

    # Create environment with varied assets
    env = Environment(
        environment=EnvironmentMetadata(
            name="risk-analysis",
            type=EnvironmentType.PRODUCTION,
            owner="security@company.com",
        ),
        assets=[
            Asset(
                id="public-web",
                name="Public Web Server",
                type=AssetType.CONTAINER,
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
                id="payment-db",
                name="Payment Database",
                type=AssetType.DATABASE,
                host="10.0.3.10",
                business_context=BusinessContext(
                    criticality=Criticality.CRITICAL,
                    criticality_score=95,
                    data_classification=DataClassification.PCI,
                    compliance_scope=[ComplianceFramework.PCI_DSS],
                ),
            ),
            Asset(
                id="internal-api",
                name="Internal API",
                type=AssetType.SERVICE,
                host="10.0.2.10",
                business_context=BusinessContext(
                    criticality=Criticality.MEDIUM,
                    criticality_score=50,
                ),
            ),
            Asset(
                id="test-service",
                name="Test Service",
                type=AssetType.SERVICE,
                host="10.0.4.10",
                business_context=BusinessContext(
                    criticality=Criticality.LOW,
                    criticality_score=20,
                ),
            ),
        ],
        dependencies=[],
    )

    # Calculate risk scores
    risk_scores = env.calculate_total_risk_score()

    print(f"\n✓ Risk Analysis for: {env.environment.name}")
    print(f"\n  Overall Metrics:")
    print(f"    Total assets: {risk_scores['total_assets']}")
    print(f"    Critical assets: {risk_scores['critical_assets']}")
    print(f"    Internet-facing: {risk_scores['internet_facing_assets']}")
    print(f"    PCI scope: {risk_scores['pci_scope_assets']}")
    print(f"    Average criticality: {risk_scores['average_criticality']:.2f}/4.0")
    print(f"    High-risk percentage: {risk_scores['high_risk_percentage']:.1f}%")

    print(f"\n  Interpretation:")
    if risk_scores['average_criticality'] >= 3.5:
        print("    ⚠️  HIGH RISK - Environment contains many critical assets")
    elif risk_scores['average_criticality'] >= 2.5:
        print("    ⚡ MODERATE RISK - Review critical assets and exposure")
    else:
        print("    ✓ LOW RISK - Environment is relatively low-risk")


def example_7_generate_template():
    """Example 7: Generate environment template."""
    print("\n" + "=" * 70)
    print("Example 7: Generate Environment Template")
    print("=" * 70)

    # Generate template
    template = EnvironmentParser.generate_template()

    print("\n✓ Generated environment template:")
    print(f"\n{json.dumps(template, indent=2)}")

    # Save template for customization
    output_file = Path("/tmp/environment-template.json")
    with open(output_file, 'w') as f:
        json.dump(template, f, indent=2)

    print(f"\n✓ Saved template to: {output_file}")
    print(f"\n  Next steps:")
    print(f"    1. Edit the template with your infrastructure details")
    print(f"    2. Validate: threat-radar env validate {output_file}")
    print(f"    3. Build graph: threat-radar env build-graph {output_file} --auto-save")

    # Clean up
    output_file.unlink()


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("THREAT RADAR - Environment Configuration Examples")
    print("Basic Usage Examples")
    print("=" * 70)

    # Run all examples
    example_1_create_simple_environment()
    example_2_add_business_context()
    example_3_validate_environment()
    example_4_save_and_load()
    example_5_query_assets()
    example_6_calculate_risk()
    example_7_generate_template()

    print("\n" + "=" * 70)
    print("All examples completed successfully!")
    print("=" * 70 + "\n")
