"""
Real-World Workflow Examples

This script demonstrates complete end-to-end workflows for common use cases:
- CI/CD integration
- Security audits
- Compliance reporting
- Vulnerability prioritization with business context
"""

import json
from pathlib import Path
from datetime import datetime
from threat_radar.environment import (
    Environment,
    EnvironmentMetadata,
    Asset,
    Dependency,
    NetworkTopology,
    NetworkZone,
    BusinessContext,
    Software,
    Network,
    EnvironmentType,
    AssetType,
    Criticality,
    DataClassification,
    DependencyType,
    ComplianceFramework,
    CloudProvider,
    TrustLevel,
    EnvironmentParser,
    EnvironmentGraphBuilder,
)
from threat_radar.graph import NetworkXClient


def workflow_1_security_audit():
    """Workflow 1: Complete security audit of environment."""
    print("\n" + "=" * 70)
    print("Workflow 1: Security Audit")
    print("=" * 70)

    # Step 1: Load environment configuration
    print("\n[Step 1] Loading environment configuration...")

    env_config = {
        "environment": {
            "name": "production-api",
            "type": "production",
            "cloud_provider": "aws",
            "region": "us-east-1",
            "compliance_requirements": ["pci-dss", "gdpr"],
            "owner": "security@company.com",
        },
        "assets": [
            {
                "id": "api-gateway",
                "name": "API Gateway",
                "type": "api-gateway",
                "host": "10.0.1.10",
                "network": {
                    "internal_ip": "10.0.1.10",
                    "public_ip": "203.0.113.10",
                    "exposed_ports": [
                        {"port": 443, "protocol": "https", "public": True}
                    ],
                },
                "business_context": {
                    "criticality": "high",
                    "criticality_score": 85,
                    "customer_facing": True,
                    "data_classification": "pii",
                },
            },
            {
                "id": "payment-service",
                "name": "Payment Service",
                "type": "service",
                "host": "10.0.2.10",
                "business_context": {
                    "criticality": "critical",
                    "criticality_score": 95,
                    "data_classification": "pci",
                    "compliance_scope": ["pci-dss"],
                },
            },
            {
                "id": "user-db",
                "name": "User Database",
                "type": "database",
                "host": "10.0.3.10",
                "business_context": {
                    "criticality": "critical",
                    "criticality_score": 95,
                    "data_classification": "pii",
                    "compliance_scope": ["gdpr"],
                },
            },
        ],
        "dependencies": [
            {
                "source": "api-gateway",
                "target": "payment-service",
                "type": "depends_on",
                "protocol": "https",
                "port": 8443,
                "encrypted": True,
                "data_flow": "pci",
            },
            {
                "source": "payment-service",
                "target": "user-db",
                "type": "reads_from",
                "protocol": "postgresql",
                "port": 5432,
                "encrypted": True,
                "data_flow": "pii",
            },
        ],
    }

    env = EnvironmentParser.load_from_dict(env_config)
    print(f"✓ Loaded environment: {env.environment.name}")

    # Step 2: Validate configuration
    print("\n[Step 2] Validating configuration...")
    print(f"✓ Configuration valid")
    print(f"  Assets: {len(env.assets)}")
    print(f"  Dependencies: {len(env.dependencies)}")
    print(f"  Compliance requirements: {[c.value for c in env.environment.compliance_requirements]}")

    # Step 3: Identify high-risk assets
    print("\n[Step 3] Identifying high-risk assets...")

    critical_assets = env.get_critical_assets()
    internet_facing = env.get_internet_facing_assets()
    pci_scope = env.get_pci_scope_assets()

    print(f"\n  Critical Assets ({len(critical_assets)}):")
    for asset in critical_assets:
        print(f"    🔴 {asset.name}")
        print(f"       Criticality: {asset.business_context.criticality.value}")
        print(f"       Data: {asset.business_context.data_classification.value if asset.business_context.data_classification else 'N/A'}")

    print(f"\n  Internet-Facing Assets ({len(internet_facing)}):")
    for asset in internet_facing:
        print(f"    🌐 {asset.name} (IP: {asset.network.public_ip})")

    print(f"\n  PCI-DSS Scope ({len(pci_scope)}):")
    for asset in pci_scope:
        print(f"    💳 {asset.name}")

    # Step 4: Analyze risk scores
    print("\n[Step 4] Calculating risk scores...")
    risk_scores = env.calculate_total_risk_score()

    print(f"\n  Overall Risk Assessment:")
    print(f"    Total assets: {risk_scores['total_assets']}")
    print(f"    Critical assets: {risk_scores['critical_assets']}")
    print(f"    Average criticality: {risk_scores['average_criticality']:.2f}/4.0")
    print(f"    High-risk percentage: {risk_scores['high_risk_percentage']:.1f}%")

    if risk_scores['high_risk_percentage'] > 50:
        print(f"\n  ⚠️  WARNING: Environment has high risk profile!")
        print(f"     {risk_scores['critical_assets']} critical assets require immediate attention")

    # Step 5: Build graph for analysis
    print("\n[Step 5] Building dependency graph...")
    client = NetworkXClient()
    builder = EnvironmentGraphBuilder(client)
    builder.build_from_environment(env)

    # Find attack paths
    paths = builder.find_critical_paths(env)
    print(f"\n  Critical Attack Paths: {len(paths)}")
    for i, path in enumerate(paths[:3], 1):
        path_names = [env.get_asset(asset_id).name for asset_id in path]
        print(f"    Path {i}: {' → '.join(path_names)}")

    # Step 6: Generate audit report
    print("\n[Step 6] Generating audit report...")
    audit_report = {
        "audit_date": datetime.now().isoformat(),
        "environment": env.environment.name,
        "risk_summary": risk_scores,
        "critical_findings": {
            "critical_assets": [a.name for a in critical_assets],
            "internet_facing": [a.name for a in internet_facing],
            "pci_scope": [a.name for a in pci_scope],
            "attack_paths": len(paths),
        },
        "recommendations": [
            "Review security controls for internet-facing assets",
            "Audit PCI-DSS compliance for payment service",
            "Implement network segmentation to limit attack paths",
            "Review encryption for all sensitive data flows",
        ],
    }

    print(f"✓ Audit report generated")
    print(f"\n  Key Findings:")
    print(f"    - {len(critical_assets)} critical assets identified")
    print(f"    - {len(internet_facing)} internet-facing assets")
    print(f"    - {len(paths)} potential attack paths")

    print(f"\n  Recommendations:")
    for i, rec in enumerate(audit_report['recommendations'], 1):
        print(f"    {i}. {rec}")

    print(f"\n✓ Security audit complete!")


def workflow_2_vulnerability_prioritization():
    """Workflow 2: Prioritize vulnerabilities using business context."""
    print("\n" + "=" * 70)
    print("Workflow 2: Vulnerability Prioritization with Business Context")
    print("=" * 70)

    # Step 1: Create environment
    print("\n[Step 1] Loading environment configuration...")

    env = Environment(
        environment=EnvironmentMetadata(
            name="web-application",
            type=EnvironmentType.PRODUCTION,
            owner="devops@company.com",
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
                    criticality_score=80,
                    customer_facing=True,
                ),
            ),
            Asset(
                id="api-1",
                name="API Server",
                type=AssetType.SERVICE,
                host="10.0.2.10",
                business_context=BusinessContext(
                    criticality=Criticality.CRITICAL,
                    criticality_score=90,
                    data_classification=DataClassification.PII,
                ),
            ),
            Asset(
                id="worker-1",
                name="Background Worker",
                type=AssetType.SERVICE,
                host="10.0.3.10",
                business_context=BusinessContext(
                    criticality=Criticality.MEDIUM,
                    criticality_score=50,
                ),
            ),
        ],
        dependencies=[
            Dependency(
                source="web-1",
                target="api-1",
                type=DependencyType.DEPENDS_ON,
            ),
        ],
    )

    print(f"✓ Environment: {env.environment.name}")

    # Step 2: Simulate vulnerability scan results
    print("\n[Step 2] Processing vulnerability scan results...")

    # Mock vulnerability data - would come from actual scan
    vulnerabilities = [
        {
            "cve": "CVE-2023-0001",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "package": "openssl",
            "affected_assets": ["web-1", "api-1"],
            "fix_available": True,
        },
        {
            "cve": "CVE-2023-0002",
            "severity": "HIGH",
            "cvss": 7.5,
            "package": "curl",
            "affected_assets": ["web-1", "worker-1"],
            "fix_available": True,
        },
        {
            "cve": "CVE-2023-0003",
            "severity": "CRITICAL",
            "cvss": 9.1,
            "package": "python",
            "affected_assets": ["worker-1"],
            "fix_available": False,
        },
    ]

    print(f"✓ Found {len(vulnerabilities)} vulnerabilities")

    # Step 3: Calculate business risk for each vulnerability
    print("\n[Step 3] Calculating business risk scores...")

    prioritized_vulns = []
    for vuln in vulnerabilities:
        # Get affected assets
        affected = [env.get_asset(asset_id) for asset_id in vuln["affected_assets"]]

        # Calculate business impact
        max_criticality = max(
            [a.business_context.criticality_score for a in affected]
        )

        # Check for internet exposure
        internet_exposed = any(
            a.network and a.network.public_ip for a in affected
        )

        # Check for sensitive data
        sensitive_data = any(
            a.business_context.data_classification in [
                DataClassification.PII,
                DataClassification.PCI,
                DataClassification.PHI,
            ]
            for a in affected
        )

        # Calculate business risk score (0-100)
        business_risk = 0
        business_risk += vuln["cvss"] * 5  # CVSS contribution (0-50)
        business_risk += max_criticality * 0.3  # Criticality (0-30)
        business_risk += 10 if internet_exposed else 0  # Exposure (0-10)
        business_risk += 10 if sensitive_data else 0  # Data sensitivity (0-10)
        business_risk = min(business_risk, 100)

        prioritized_vulns.append({
            **vuln,
            "business_risk": business_risk,
            "max_criticality": max_criticality,
            "internet_exposed": internet_exposed,
            "sensitive_data": sensitive_data,
            "affected_asset_names": [a.name for a in affected],
        })

    # Sort by business risk
    prioritized_vulns.sort(key=lambda x: x["business_risk"], reverse=True)

    print(f"\n  Prioritized Vulnerabilities:")
    for i, vuln in enumerate(prioritized_vulns, 1):
        risk_icon = "🔴" if vuln["business_risk"] >= 80 else "🟠" if vuln["business_risk"] >= 60 else "🟡"
        print(f"\n    {risk_icon} Priority {i}: {vuln['cve']}")
        print(f"       Severity: {vuln['severity']} (CVSS: {vuln['cvss']})")
        print(f"       Business Risk Score: {vuln['business_risk']:.1f}/100")
        print(f"       Affected: {', '.join(vuln['affected_asset_names'])}")
        print(f"       Internet Exposed: {'Yes' if vuln['internet_exposed'] else 'No'}")
        print(f"       Sensitive Data: {'Yes' if vuln['sensitive_data'] else 'No'}")
        print(f"       Fix Available: {'Yes' if vuln['fix_available'] else 'No'}")

    # Step 4: Generate remediation plan
    print("\n[Step 4] Generating remediation plan...")

    print(f"\n  Immediate Actions (Business Risk >= 80):")
    high_risk = [v for v in prioritized_vulns if v["business_risk"] >= 80]
    for vuln in high_risk:
        print(f"    - Patch {vuln['cve']} in {', '.join(vuln['affected_asset_names'])}")

    print(f"\n  Next Actions (Business Risk 60-79):")
    medium_risk = [v for v in prioritized_vulns if 60 <= v["business_risk"] < 80]
    for vuln in medium_risk:
        print(f"    - Schedule patch for {vuln['cve']}")

    print(f"\n✓ Prioritization complete!")


def workflow_3_compliance_reporting():
    """Workflow 3: Generate compliance reports."""
    print("\n" + "=" * 70)
    print("Workflow 3: Compliance Reporting")
    print("=" * 70)

    # Step 1: Load environment
    print("\n[Step 1] Loading environment for compliance audit...")

    env = Environment(
        environment=EnvironmentMetadata(
            name="financial-services",
            type=EnvironmentType.PRODUCTION,
            compliance_requirements=[
                ComplianceFramework.PCI_DSS,
                ComplianceFramework.SOX,
                ComplianceFramework.GDPR,
            ],
            owner="compliance@company.com",
        ),
        assets=[
            Asset(
                id="payment-gateway",
                name="Payment Gateway",
                type=AssetType.API_GATEWAY,
                host="10.0.1.10",
                network=Network(
                    internal_ip="10.0.1.10",
                    public_ip="203.0.113.10",
                ),
                business_context=BusinessContext(
                    criticality=Criticality.CRITICAL,
                    criticality_score=95,
                    data_classification=DataClassification.PCI,
                    compliance_scope=[ComplianceFramework.PCI_DSS],
                ),
            ),
            Asset(
                id="customer-db",
                name="Customer Database",
                type=AssetType.DATABASE,
                host="10.0.2.10",
                business_context=BusinessContext(
                    criticality=Criticality.CRITICAL,
                    criticality_score=95,
                    data_classification=DataClassification.PII,
                    compliance_scope=[ComplianceFramework.GDPR],
                ),
            ),
            Asset(
                id="financial-reports",
                name="Financial Reporting",
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
    )

    print(f"✓ Environment: {env.environment.name}")

    # Step 2: Generate compliance scope reports
    print("\n[Step 2] Generating compliance scope reports...")

    for framework in env.environment.compliance_requirements:
        print(f"\n  {framework.value.upper()} Compliance Report")
        print(f"  " + "-" * 68)

        # Find assets in scope
        in_scope = [
            a for a in env.assets
            if framework in a.business_context.compliance_scope
        ]

        print(f"    Assets in scope: {len(in_scope)}")

        if in_scope:
            print(f"    Assets:")
            for asset in in_scope:
                print(f"      - {asset.name}")
                print(f"        Criticality: {asset.business_context.criticality.value}")
                print(f"        Data: {asset.business_context.data_classification.value if asset.business_context.data_classification else 'N/A'}")
                if asset.network and asset.network.public_ip:
                    print(f"        ⚠️  Internet-accessible")

    # Step 3: Compliance summary
    print("\n[Step 3] Compliance summary...")

    risk_scores = env.calculate_total_risk_score()
    pci_assets = env.get_pci_scope_assets()
    internet_facing = env.get_internet_facing_assets()

    print(f"\n  Overall Compliance Posture:")
    print(f"    Total assets: {risk_scores['total_assets']}")
    print(f"    Critical assets: {risk_scores['critical_assets']}")
    print(f"    PCI scope: {len(pci_assets)}")
    print(f"    Internet-facing: {len(internet_facing)}")

    # Check for compliance risks
    print(f"\n  Compliance Risks:")
    if len(internet_facing) > 0:
        print(f"    ⚠️  {len(internet_facing)} internet-facing assets require enhanced controls")
    if len(pci_assets) > 0:
        print(f"    💳 {len(pci_assets)} assets in PCI-DSS scope require quarterly scans")

    print(f"\n✓ Compliance reporting complete!")


def workflow_4_ci_cd_integration():
    """Workflow 4: CI/CD pipeline integration."""
    print("\n" + "=" * 70)
    print("Workflow 4: CI/CD Pipeline Integration")
    print("=" * 70)

    print("\n[Simulated CI/CD Pipeline]")
    print("-" * 70)

    # Step 1: Load environment from repository
    print("\n[Step 1] Loading environment configuration from repository...")

    env_file = "infrastructure/production-environment.json"
    print(f"  Environment file: {env_file}")

    # Create minimal environment for demo
    env = Environment(
        environment=EnvironmentMetadata(
            name="production-app",
            type=EnvironmentType.PRODUCTION,
            owner="platform@company.com",
        ),
        assets=[
            Asset(
                id="app-1",
                name="Application",
                type=AssetType.CONTAINER,
                host="10.0.1.10",
                network=Network(
                    internal_ip="10.0.1.10",
                    public_ip="203.0.113.10",
                ),
                business_context=BusinessContext(
                    criticality=Criticality.HIGH,
                    criticality_score=85,
                    customer_facing=True,
                ),
            ),
        ],
        dependencies=[],
    )

    print(f"✓ Loaded environment: {env.environment.name}")

    # Step 2: Validate environment
    print("\n[Step 2] Validating environment configuration...")
    print(f"✓ Configuration valid")

    # Step 3: Check for policy violations
    print("\n[Step 3] Checking for policy violations...")

    violations = []

    # Check: All critical assets must not be internet-facing without justification
    for asset in env.get_critical_assets():
        if asset.network and asset.network.public_ip:
            violations.append(
                f"Critical asset '{asset.name}' is internet-facing"
            )

    # Check: All customer-facing assets must be HIGH or CRITICAL
    for asset in env.assets:
        if asset.business_context.customer_facing:
            if asset.business_context.criticality not in [
                Criticality.HIGH,
                Criticality.CRITICAL,
            ]:
                violations.append(
                    f"Customer-facing asset '{asset.name}' has insufficient criticality"
                )

    if violations:
        print(f"  ⚠️  Found {len(violations)} policy violations:")
        for v in violations:
            print(f"    - {v}")
    else:
        print(f"✓ No policy violations found")

    # Step 4: Calculate deployment risk
    print("\n[Step 4] Calculating deployment risk...")

    risk_scores = env.calculate_total_risk_score()

    deployment_risk = "LOW"
    if risk_scores["high_risk_percentage"] > 50:
        deployment_risk = "HIGH"
    elif risk_scores["high_risk_percentage"] > 25:
        deployment_risk = "MEDIUM"

    print(f"  Deployment Risk: {deployment_risk}")
    print(f"  Critical assets: {risk_scores['critical_assets']}")
    print(f"  Internet-facing: {risk_scores['internet_facing_assets']}")

    # Step 5: Decision
    print("\n[Step 5] Deployment decision...")

    if deployment_risk == "HIGH" and violations:
        print(f"  ❌ DEPLOYMENT BLOCKED")
        print(f"     High risk with policy violations")
        print(f"     Manual approval required")
    elif violations:
        print(f"  ⚠️  DEPLOYMENT REQUIRES APPROVAL")
        print(f"     Policy violations detected")
    else:
        print(f"  ✅ DEPLOYMENT APPROVED")
        print(f"     All checks passed")

    print(f"\n✓ CI/CD integration complete!")


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("THREAT RADAR - Environment Configuration Examples")
    print("Real-World Workflows")
    print("=" * 70)

    # Run all workflows
    workflow_1_security_audit()
    workflow_2_vulnerability_prioritization()
    workflow_3_compliance_reporting()
    workflow_4_ci_cd_integration()

    print("\n" + "=" * 70)
    print("All workflows completed successfully!")
    print("=" * 70 + "\n")
