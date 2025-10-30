#!/usr/bin/env python3
"""
AI Business Context Analysis Examples

This example demonstrates how to use Threat Radar's AI analysis
with business context from environment configurations.

The business context-aware analysis enhances traditional CVE scanning by:
- Incorporating asset criticality levels
- Considering data classification (PII, PCI, PHI)
- Factoring network exposure (internet-facing)
- Accounting for compliance requirements
- Computing business risk scores (0-100)
"""

import json
from threat_radar.ai import BusinessContextAnalyzer
from threat_radar.environment.models import (
    Environment,
    EnvironmentMetadata,
    Asset,
    BusinessContext,
    Network,
    ExposedPort,
    Software,
    EnvironmentType,
    AssetType,
    Criticality,
    DataClassification,
    ComplianceFramework,
    CloudProvider,
)
from threat_radar.core.grype_integration import GrypeScanResult, GrypeVulnerability


def create_sample_environment():
    """Create a sample production environment with business context"""

    # API Gateway - Critical, internet-facing, handles PCI data
    api_gateway = Asset(
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
            ],
        ),
        business_context=BusinessContext(
            criticality=Criticality.CRITICAL,
            criticality_score=95,
            function="api-gateway",
            data_classification=DataClassification.PCI,
            revenue_impact="high",
            customer_facing=True,
            compliance_scope=[ComplianceFramework.PCI_DSS, ComplianceFramework.GDPR],
            sla_tier="tier-1",
            mttr_target=30,
            owner_team="platform-team",
        ),
    )

    # Payment Service - Critical, internal, handles PCI data
    payment_service = Asset(
        id="payment-service-001",
        name="Payment Processing Service",
        type=AssetType.SERVICE,
        host="10.0.2.20",
        software=Software(
            image="python:3.11-alpine",
            os="Alpine Linux 3.18",
            runtime="Python 3.11",
        ),
        network=Network(
            internal_ip="10.0.2.20",
            exposed_ports=[
                ExposedPort(port=8443, protocol="https", public=False),
            ],
        ),
        business_context=BusinessContext(
            criticality=Criticality.CRITICAL,
            criticality_score=98,
            function="payment-processing",
            data_classification=DataClassification.PCI,
            revenue_impact="critical",
            customer_facing=False,
            compliance_scope=[ComplianceFramework.PCI_DSS],
            sla_tier="tier-1",
            mttr_target=15,
            owner_team="payments-team",
        ),
    )

    # Analytics Service - Medium criticality, internal, PII data
    analytics_service = Asset(
        id="analytics-001",
        name="Analytics Service",
        type=AssetType.SERVICE,
        host="10.0.3.30",
        software=Software(
            image="node:18-alpine",
            os="Alpine Linux 3.18",
            runtime="Node.js 18",
        ),
        network=Network(
            internal_ip="10.0.3.30",
        ),
        business_context=BusinessContext(
            criticality=Criticality.MEDIUM,
            criticality_score=55,
            function="analytics",
            data_classification=DataClassification.PII,
            revenue_impact="low",
            customer_facing=False,
            compliance_scope=[ComplianceFramework.GDPR],
            sla_tier="tier-2",
            mttr_target=120,
            owner_team="data-team",
        ),
    )

    return Environment(
        environment=EnvironmentMetadata(
            name="production-ecommerce",
            type=EnvironmentType.PRODUCTION,
            cloud_provider=CloudProvider.AWS,
            region="us-east-1",
            compliance_requirements=[
                ComplianceFramework.PCI_DSS,
                ComplianceFramework.GDPR,
            ],
            owner="platform@company.com",
            tags={"cost-center": "engineering", "environment": "production"},
        ),
        assets=[api_gateway, payment_service, analytics_service],
        dependencies=[],
    )


def create_sample_cve_scan():
    """Create a sample CVE scan with various severity levels"""

    # Simulate a scan of nginx:1.25-alpine with various vulnerabilities
    vulnerabilities = [
        # Critical vulnerability in a network library
        GrypeVulnerability(
            id="CVE-2024-1234",
            severity="critical",
            package_name="libssl",
            package_version="3.0.0",
            package_type="apk",
            fixed_in_version="3.0.10",
            description="Remote code execution vulnerability in SSL/TLS handling. "
                       "Allows unauthenticated attackers to execute arbitrary code.",
            cvss_score=9.8,
            urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
            data_source="nvd",
        ),
        # High severity vulnerability
        GrypeVulnerability(
            id="CVE-2024-5678",
            severity="high",
            package_name="nginx",
            package_version="1.25.0",
            package_type="apk",
            fixed_in_version="1.25.3",
            description="HTTP request smuggling vulnerability allowing bypass of "
                       "security controls and access restrictions.",
            cvss_score=7.5,
            urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-5678"],
            data_source="nvd",
        ),
        # Medium severity - denial of service
        GrypeVulnerability(
            id="CVE-2024-9012",
            severity="medium",
            package_name="zlib",
            package_version="1.2.11",
            package_type="apk",
            fixed_in_version="1.2.13",
            description="Denial of service vulnerability through malformed compressed data.",
            cvss_score=5.3,
            urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-9012"],
            data_source="nvd",
        ),
        # Low severity - information disclosure
        GrypeVulnerability(
            id="CVE-2024-3456",
            severity="low",
            package_name="libcurl",
            package_version="8.0.0",
            package_type="apk",
            fixed_in_version="8.0.1",
            description="Information disclosure through error messages.",
            cvss_score=3.7,
            urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-3456"],
            data_source="nvd",
        ),
    ]

    return GrypeScanResult(
        target="nginx:1.25-alpine",
        vulnerabilities=vulnerabilities,
        total_count=len(vulnerabilities),
        severity_counts={
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 1,
        },
        scan_metadata={
            "scanner": "grype",
            "timestamp": "2025-01-15T10:00:00Z",
        },
    )


def example_1_basic_business_context_analysis():
    """
    Example 1: Basic Business Context Analysis

    Demonstrates how business context affects risk scoring:
    - Same CVE has different business risk on different assets
    - Internet-facing assets get higher risk scores
    - Critical assets elevate risk levels
    - Data classification impacts business risk
    """
    print("\n" + "="*80)
    print("Example 1: Basic Business Context Analysis")
    print("="*80 + "\n")

    # Create environment and scan
    env = create_sample_environment()
    scan = create_sample_cve_scan()

    print(f"Environment: {env.environment.name}")
    print(f"Assets: {len(env.assets)}")
    print(f"Vulnerabilities: {scan.total_count}\n")

    # Initialize analyzer
    # NOTE: This requires AI provider to be configured (OpenAI, Anthropic, or Ollama)
    # Set environment variables: AI_PROVIDER, AI_MODEL, and provider-specific API key
    try:
        analyzer = BusinessContextAnalyzer()

        # Analyze for API Gateway (critical, internet-facing, PCI data)
        print("Analyzing vulnerabilities for API Gateway...")
        print("Asset: API Gateway")
        print("  - Criticality: CRITICAL (Score: 95/100)")
        print("  - Internet-Facing: Yes")
        print("  - Data: PCI (payment card data)")
        print("  - Compliance: PCI-DSS, GDPR\n")

        # Map scan to API Gateway asset
        asset_mapping = {"nginx:1.25-alpine": "api-gateway-001"}

        analysis = analyzer.analyze_with_business_context(
            scan_result=scan,
            environment=env,
            asset_mapping=asset_mapping,
            batch_mode="disabled",  # Disable for small example
        )

        print(f"Overall Risk Rating: {analysis.overall_risk_rating}\n")

        print("Business Risk Assessments:\n")
        for assessment in analysis.business_assessments:
            print(f"  {assessment.cve_id} ({assessment.package_name})")
            print(f"    Technical Severity: {assessment.technical_severity} (CVSS: {assessment.cvss_score})")
            print(f"    Business Risk Score: {assessment.business_risk_score}/100 ({assessment.business_risk_level})")
            print(f"    Remediation Urgency: {assessment.remediation_urgency}")
            print(f"    Risk Factors:")
            for factor in assessment.risk_factors:
                print(f"      - {factor}")
            if assessment.compliance_impact:
                print(f"    Compliance Impact: {', '.join(assessment.compliance_impact)}")
            print()

        # Compare: Same vulnerability on different assets
        print("\n" + "-"*80)
        print("Comparing Risk Scores Across Assets:")
        print("-"*80 + "\n")

        # The same CVE-2024-1234 vulnerability would have different business risk
        # on different assets. Let's demonstrate this conceptually:

        critical_asset = env.assets[0]  # API Gateway - critical, internet-facing, PCI
        medium_asset = env.assets[2]   # Analytics - medium, internal, PII

        print(f"CVE-2024-1234 (libssl RCE, CVSS 9.8) Business Risk Comparison:\n")
        print(f"On {critical_asset.name}:")
        print(f"  - Base technical score: 40 (critical severity)")
        print(f"  - + CVSS contribution: 30 (9.8 * 3)")
        print(f"  - + Asset criticality: 19 (95 * 0.2)")
        print(f"  - + Internet exposure: 10 (public-facing)")
        print(f"  - + Data sensitivity: 10 (PCI data)")
        print(f"  - = Business Risk: 100/100 (CRITICAL, IMMEDIATE remediation)")
        print()

        print(f"On {medium_asset.name}:")
        print(f"  - Base technical score: 40 (critical severity)")
        print(f"  - + CVSS contribution: 30 (9.8 * 3)")
        print(f"  - + Asset criticality: 11 (55 * 0.2)")
        print(f"  - + Internet exposure: 0 (internal only)")
        print(f"  - + Data sensitivity: 8 (PII data)")
        print(f"  - = Business Risk: 89/100 (CRITICAL, URGENT remediation)")
        print()

        print("Key Insight: The same CVE has different business risk based on:")
        print("  - Asset criticality (what it does)")
        print("  - Network exposure (who can reach it)")
        print("  - Data sensitivity (what it handles)")
        print("  - Compliance scope (regulatory impact)")

    except Exception as e:
        print(f"\nNote: This example requires AI provider configuration.")
        print(f"Error: {str(e)}")
        print("\nTo run this example:")
        print("1. Set AI_PROVIDER environment variable (openai, anthropic, or ollama)")
        print("2. Set AI_MODEL environment variable (e.g., gpt-4o, claude-3-5-sonnet-20241022, llama2)")
        print("3. Set provider-specific API key (OPENAI_API_KEY or ANTHROPIC_API_KEY)")
        print("4. For Ollama, start ollama service and pull a model")


def example_2_prioritization_with_context():
    """
    Example 2: Business Context-Aware Prioritization

    Shows how business context changes vulnerability prioritization:
    - Critical assets get priority even for lower-severity CVEs
    - Internet-facing vulnerabilities prioritized higher
    - Compliance-scoped assets require faster remediation
    """
    print("\n" + "="*80)
    print("Example 2: Business Context-Aware Prioritization")
    print("="*80 + "\n")

    env = create_sample_environment()
    scan = create_sample_cve_scan()

    print("Traditional CVSS-based prioritization:")
    print("1. CVE-2024-1234 (libssl) - CVSS 9.8 (CRITICAL)")
    print("2. CVE-2024-5678 (nginx) - CVSS 7.5 (HIGH)")
    print("3. CVE-2024-9012 (zlib) - CVSS 5.3 (MEDIUM)")
    print("4. CVE-2024-3456 (libcurl) - CVSS 3.7 (LOW)")
    print()

    print("Business context-aware prioritization:\n")

    # Simulate business risk scores for each CVE on critical API Gateway
    business_priorities = [
        {
            "cve": "CVE-2024-1234",
            "package": "libssl",
            "cvss": 9.8,
            "business_risk": 100,
            "urgency": "IMMEDIATE",
            "reason": "Critical RCE on internet-facing PCI-scoped asset",
        },
        {
            "cve": "CVE-2024-5678",
            "package": "nginx",
            "cvss": 7.5,
            "business_risk": 95,
            "urgency": "IMMEDIATE",
            "reason": "HTTP smuggling on critical customer-facing gateway",
        },
        {
            "cve": "CVE-2024-9012",
            "package": "zlib",
            "cvss": 5.3,
            "business_risk": 75,
            "urgency": "URGENT",
            "reason": "DoS risk on tier-1 SLA asset (MTTR: 30min target)",
        },
        {
            "cve": "CVE-2024-3456",
            "package": "libcurl",
            "cvss": 3.7,
            "business_risk": 60,
            "urgency": "STANDARD",
            "reason": "Info disclosure on compliance-scoped asset",
        },
    ]

    for idx, item in enumerate(business_priorities, 1):
        risk_level = "CRITICAL" if item["business_risk"] >= 80 else "HIGH" if item["business_risk"] >= 60 else "MEDIUM"
        print(f"{idx}. {item['cve']} ({item['package']}) - Business Risk: {item['business_risk']}/100 ({risk_level})")
        print(f"   Technical: CVSS {item['cvss']}")
        print(f"   Urgency: {item['urgency']}")
        print(f"   Reason: {item['reason']}")
        print()

    print("Key Changes:")
    print("  ✓ Even MEDIUM/LOW technical severity gets elevated due to business context")
    print("  ✓ Internet-facing + PCI-scoped assets require immediate action")
    print("  ✓ SLA targets drive remediation timelines")
    print("  ✓ Compliance requirements cannot be deferred")


def example_3_compliance_driven_remediation():
    """
    Example 3: Compliance-Driven Remediation

    Demonstrates how compliance requirements affect remediation timelines:
    - PCI-DSS requires immediate patching of critical vulnerabilities
    - GDPR has strict breach notification timelines
    - Compliance scope determines priority
    """
    print("\n" + "="*80)
    print("Example 3: Compliance-Driven Remediation")
    print("="*80 + "\n")

    env = create_sample_environment()

    print("Compliance Framework Requirements:\n")

    print("PCI-DSS:")
    print("  - Critical vulnerabilities: Patch within 30 days")
    print("  - High vulnerabilities: Patch within 90 days")
    print("  - Regular vulnerability scanning required")
    print("  - Applies to: API Gateway, Payment Service\n")

    print("GDPR:")
    print("  - Data breach notification: 72 hours")
    print("  - Reasonable security measures required")
    print("  - Applies to: API Gateway, Analytics Service\n")

    print("Remediation Timeline for CVE-2024-1234 (Critical RCE):\n")

    scenarios = [
        {
            "asset": "API Gateway",
            "compliance": ["PCI-DSS", "GDPR"],
            "deadline": "IMMEDIATE (within 24 hours)",
            "reason": "Internet-facing, PCI-scoped, GDPR applies. RCE = potential data breach.",
        },
        {
            "asset": "Payment Service",
            "compliance": ["PCI-DSS"],
            "deadline": "URGENT (within 7 days)",
            "reason": "Internal, but PCI-scoped. RCE = potential payment data compromise.",
        },
        {
            "asset": "Analytics Service",
            "compliance": ["GDPR"],
            "deadline": "STANDARD (within 30 days)",
            "reason": "Internal, PII data. RCE = potential GDPR breach but lower exposure.",
        },
    ]

    for scenario in scenarios:
        print(f"Asset: {scenario['asset']}")
        print(f"  Compliance Scope: {', '.join(scenario['compliance'])}")
        print(f"  Remediation Deadline: {scenario['deadline']}")
        print(f"  Reason: {scenario['reason']}")
        print()

    print("Key Insights:")
    print("  ✓ PCI-DSS compliance drives aggressive patching timelines")
    print("  ✓ Internet exposure + compliance = highest priority")
    print("  ✓ Internal assets get more time but still must patch")
    print("  ✓ Business context determines realistic SLAs")


def example_4_saving_and_loading_results():
    """
    Example 4: Saving and Loading Business Context Analysis

    Shows how to save analysis results for reporting and tracking.
    """
    print("\n" + "="*80)
    print("Example 4: Saving and Loading Business Context Analysis")
    print("="*80 + "\n")

    env = create_sample_environment()
    scan = create_sample_cve_scan()

    print("Business context analysis results can be saved for:")
    print("  - Historical tracking (trend analysis)")
    print("  - Compliance reporting (audit trail)")
    print("  - Executive dashboards (business risk metrics)")
    print("  - Team coordination (remediation planning)\n")

    # Simulate saved analysis structure
    analysis_structure = {
        "base_analysis": {
            "vulnerabilities": ["...technical analysis..."],
            "summary": "AI-generated technical summary",
        },
        "business_assessments": [
            {
                "cve_id": "CVE-2024-1234",
                "package_name": "libssl",
                "asset_id": "api-gateway-001",
                "business_risk_score": 100,
                "business_risk_level": "CRITICAL",
                "risk_factors": [
                    "Technical severity: CRITICAL",
                    "CVSS score: 9.8",
                    "Asset criticality: CRITICAL",
                    "Internet-facing asset",
                    "Sensitive data: PCI",
                    "Customer-facing service",
                ],
                "compliance_impact": ["PCI-DSS", "GDPR"],
                "remediation_urgency": "IMMEDIATE",
            }
        ],
        "environment_summary": "API Gateway in production with critical business functions...",
        "overall_risk_rating": "CRITICAL",
        "compliance_summary": "PCI-DSS and GDPR compliance at risk...",
        "prioritized_actions": [
            "Immediately patch CVE-2024-1234 (libssl RCE) on API Gateway",
            "Apply nginx security update for CVE-2024-5678",
            "Schedule zlib update within 7 days",
        ],
        "metadata": {
            "asset_id": "api-gateway-001",
            "asset_name": "API Gateway",
            "asset_criticality": "critical",
            "criticality_score": 95,
            "internet_facing": True,
            "compliance_scope": ["PCI-DSS", "GDPR"],
        },
    }

    print("Sample Analysis Output Structure:\n")
    print(json.dumps(analysis_structure, indent=2))

    print("\n\nUsage Examples:\n")
    print("# Save to file")
    print("threat-radar ai analyze-with-context scan.json env.json -o analysis.json\n")

    print("# Auto-save to storage/ai_analysis/")
    print("threat-radar ai analyze-with-context scan.json env.json --auto-save\n")

    print("# Load and process in Python")
    print("with open('analysis.json') as f:")
    print("    analysis = json.load(f)")
    print("    critical_risks = [a for a in analysis['business_assessments']")
    print("                      if a['business_risk_level'] == 'CRITICAL']")


def main():
    """Run all examples"""

    print("\n" + "="*80)
    print("AI Business Context Analysis Examples")
    print("="*80)
    print("\nThese examples demonstrate how Threat Radar integrates business context")
    print("from environment configurations into AI-powered vulnerability analysis.\n")

    print("Business Context Factors:")
    print("  - Asset Criticality: CRITICAL, HIGH, MEDIUM, LOW (with 0-100 scores)")
    print("  - Data Classification: PCI, PHI, PII, Confidential, Internal, Public")
    print("  - Network Exposure: Internet-facing vs Internal")
    print("  - Compliance Requirements: PCI-DSS, HIPAA, GDPR, SOX, etc.")
    print("  - SLA Targets: Tier-1, Tier-2, etc. with MTTR requirements")
    print()

    print("Business Risk Score Calculation (0-100):")
    print("  Base Score (0-40):        Technical severity (Critical=40, High=30, Medium=20, Low=10)")
    print("  + CVSS (0-30):            CVSS score * 3")
    print("  + Criticality (0-20):     Asset criticality score * 0.2")
    print("  + Exposure (0-10):        +10 if internet-facing")
    print("  + Data Sensitivity (0-10): PCI/PHI=10, PII=8, Confidential=6, Internal=3, Public=0")
    print("  = Business Risk (0-100):  CRITICAL ≥80, HIGH ≥60, MEDIUM ≥40, LOW <40")
    print()

    # Run examples
    example_1_basic_business_context_analysis()
    example_2_prioritization_with_context()
    example_3_compliance_driven_remediation()
    example_4_saving_and_loading_results()

    print("\n" + "="*80)
    print("Examples Complete!")
    print("="*80 + "\n")

    print("Next Steps:")
    print("  1. Configure your environment (see examples/07_environment_configuration/)")
    print("  2. Scan your containers (threat-radar cve scan-image <image> --auto-save)")
    print("  3. Run business context analysis:")
    print("     threat-radar ai analyze-with-context scan.json environment.json")
    print()


if __name__ == "__main__":
    main()
