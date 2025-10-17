#!/usr/bin/env python3
"""
Example: AI-Powered Report Generation

Demonstrates how to generate reports with AI-powered executive summaries.
This example shows how the AI integration enhances reports with intelligent
risk assessment and remediation recommendations.
"""

import os
from pathlib import Path
from threat_radar.utils import ComprehensiveReportGenerator, ReportLevel
from threat_radar.utils.report_formatters import get_formatter
from threat_radar.core.grype_integration import GrypeScanResult, GrypeVulnerability


def create_realistic_scan_result():
    """Create a realistic scan result with various severity levels."""
    vulnerabilities = [
        # Critical vulnerabilities
        GrypeVulnerability(
            id="CVE-2024-1234",
            severity="critical",
            package_name="openssl",
            package_version="1.1.1k",
            package_type="apk",
            fixed_in_version="1.1.1w",
            description="Remote code execution vulnerability in SSL/TLS implementation allowing attackers to execute arbitrary code",
            cvss_score=9.8,
            urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
        ),
        GrypeVulnerability(
            id="CVE-2024-2345",
            severity="critical",
            package_name="glibc",
            package_version="2.31",
            package_type="deb",
            fixed_in_version="2.31-13ubuntu2.1",
            description="Buffer overflow in glibc allowing privilege escalation",
            cvss_score=9.1,
            urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-2345"],
        ),
        # High severity
        GrypeVulnerability(
            id="CVE-2024-5678",
            severity="high",
            package_name="nginx",
            package_version="1.20.0",
            package_type="apk",
            fixed_in_version="1.20.2",
            description="HTTP request smuggling vulnerability allowing cache poisoning attacks",
            cvss_score=7.5,
            urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-5678"],
        ),
        GrypeVulnerability(
            id="CVE-2024-6789",
            severity="high",
            package_name="postgresql-client",
            package_version="12.5",
            package_type="deb",
            fixed_in_version="12.9",
            description="SQL injection vulnerability in PostgreSQL client libraries",
            cvss_score=8.2,
            urls=[],
        ),
        # Medium severity
        GrypeVulnerability(
            id="CVE-2024-3456",
            severity="medium",
            package_name="libxml2",
            package_version="2.9.10",
            package_type="apk",
            fixed_in_version=None,  # No fix available
            description="XML external entity injection vulnerability",
            cvss_score=5.3,
            urls=[],
        ),
        # Low severity
        GrypeVulnerability(
            id="CVE-2024-7890",
            severity="low",
            package_name="libpng",
            package_version="1.6.37",
            package_type="apk",
            fixed_in_version="1.6.38",
            description="Minor information disclosure in PNG processing",
            cvss_score=3.7,
            urls=[],
        ),
    ]

    return GrypeScanResult(
        target="myapp:production-v2.1",
        vulnerabilities=vulnerabilities,
        total_count=len(vulnerabilities),
        severity_counts={"critical": 2, "high": 2, "medium": 1, "low": 1},
        scan_metadata={
            "scanner": "grype",
            "db_version": "5",
            "timestamp": "2024-01-15T10:30:00Z",
        },
    )


def example_executive_summary_with_ai():
    """Generate executive summary with AI (requires API key)."""
    print("=" * 70)
    print("EXAMPLE 1: AI-Powered Executive Summary")
    print("=" * 70)

    # Check if AI is configured
    ai_provider = os.getenv("AI_PROVIDER", "openai")
    ai_model = os.getenv("AI_MODEL", "gpt-4")
    has_api_key = os.getenv("OPENAI_API_KEY") or os.getenv("AI_PROVIDER") == "ollama"

    if not has_api_key:
        print("\n⚠️  Warning: No AI configuration detected")
        print("   Set OPENAI_API_KEY or AI_PROVIDER=ollama in .env")
        print("   Generating report with fallback executive summary...\n")

    scan_result = create_realistic_scan_result()

    # Generate report with AI executive summary
    generator = ComprehensiveReportGenerator(
        ai_provider=ai_provider,
        ai_model=ai_model,
    )

    report = generator.generate_report(
        scan_result=scan_result,
        report_level=ReportLevel.EXECUTIVE,
        include_executive_summary=True,  # Enable AI summary
        include_dashboard_data=True,
    )

    # Display executive summary
    if report.executive_summary:
        print("\n📊 EXECUTIVE SUMMARY")
        print("=" * 70)
        print(f"\n🎯 Overall Risk Rating: {report.executive_summary.overall_risk_rating}")

        print(f"\n📌 Key Findings:")
        for i, finding in enumerate(report.executive_summary.key_findings, 1):
            print(f"   {i}. {finding}")

        print(f"\n⚡ Immediate Actions Required:")
        for i, action in enumerate(report.executive_summary.immediate_actions, 1):
            print(f"   {i}. {action}")

        print(f"\n📋 Risk Summary:")
        print(f"   {report.executive_summary.risk_summary}")

        print(f"\n⚖️  Compliance Impact:")
        print(f"   {report.executive_summary.compliance_impact}")

        print(f"\n💼 Business Context:")
        print(f"   {report.executive_summary.business_context}")

        print(f"\n🔧 Remediation Metrics:")
        print(f"   Critical Items: {report.executive_summary.critical_items_requiring_attention}")
        print(f"   Estimated Effort: {report.executive_summary.estimated_remediation_effort}")
        print(f"   Timeline: {report.executive_summary.days_to_patch_critical} days to patch critical issues")

    # Save full report
    formatter = get_formatter("markdown")
    output = formatter.format(report)

    output_path = Path("output/executive_summary.md")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output)

    print(f"\n✓ Full executive report saved to: {output_path}")


def example_comparison_with_without_ai():
    """Compare reports with and without AI."""
    print("\n" + "=" * 70)
    print("EXAMPLE 2: Comparison - AI vs Fallback Summary")
    print("=" * 70)

    scan_result = create_realistic_scan_result()

    # Generate without AI
    print("\n📝 Generating report WITHOUT AI...")
    generator_no_ai = ComprehensiveReportGenerator()
    report_no_ai = generator_no_ai.generate_report(
        scan_result=scan_result,
        include_executive_summary=False,
        include_dashboard_data=False,
    )

    # Generate with AI (or fallback)
    print("🤖 Generating report WITH AI (or fallback)...")
    generator_ai = ComprehensiveReportGenerator(
        ai_provider=os.getenv("AI_PROVIDER", "openai"),
        ai_model=os.getenv("AI_MODEL", "gpt-4"),
    )
    report_ai = generator_ai.generate_report(
        scan_result=scan_result,
        include_executive_summary=True,
        include_dashboard_data=False,
    )

    print("\n" + "=" * 70)
    print("COMPARISON")
    print("=" * 70)

    print("\nWithout AI:")
    print(f"  - No executive summary")
    print(f"  - Basic statistics only")
    print(f"  - Generic remediation recommendations: {len(report_no_ai.remediation_recommendations)}")

    if report_ai.executive_summary:
        print("\nWith AI:")
        print(f"  - Executive summary: ✓")
        print(f"  - Risk rating: {report_ai.executive_summary.overall_risk_rating}")
        print(f"  - Key findings: {len(report_ai.executive_summary.key_findings)}")
        print(f"  - Immediate actions: {len(report_ai.executive_summary.immediate_actions)}")
        print(f"  - Compliance concerns identified: ✓")
        print(f"  - Business context: ✓")


def example_different_ai_providers():
    """Demonstrate using different AI providers."""
    print("\n" + "=" * 70)
    print("EXAMPLE 3: Different AI Providers")
    print("=" * 70)

    scan_result = create_realistic_scan_result()

    providers = [
        ("openai", "gpt-4", "OpenAI GPT-4 (cloud)"),
        ("ollama", "llama2", "Ollama Llama2 (local)"),
    ]

    for provider, model, description in providers:
        print(f"\n🔧 Testing {description}...")
        print(f"   Provider: {provider}, Model: {model}")

        try:
            generator = ComprehensiveReportGenerator(
                ai_provider=provider,
                ai_model=model,
            )

            # Quick generation without saving
            report = generator.generate_report(
                scan_result=scan_result,
                report_level=ReportLevel.EXECUTIVE,
                include_executive_summary=True,
                include_dashboard_data=False,
            )

            if report.executive_summary:
                print(f"   ✓ Successfully generated with {description}")
                print(f"   Risk Rating: {report.executive_summary.overall_risk_rating}")
            else:
                print(f"   ⚠️  Fallback summary used (API may not be configured)")

        except Exception as e:
            print(f"   ❌ Error: {str(e)[:100]}")


def example_full_workflow():
    """Complete workflow: Scan → AI Analysis → Report."""
    print("\n" + "=" * 70)
    print("EXAMPLE 4: Complete AI-Enhanced Workflow")
    print("=" * 70)

    print("\n📝 Step 1: Simulating vulnerability scan...")
    scan_result = create_realistic_scan_result()
    print(f"   ✓ Found {scan_result.total_count} vulnerabilities")

    print("\n🤖 Step 2: Generating AI-powered analysis...")
    generator = ComprehensiveReportGenerator(
        ai_provider=os.getenv("AI_PROVIDER", "openai"),
        ai_model=os.getenv("AI_MODEL", "gpt-4"),
    )

    report = generator.generate_report(
        scan_result=scan_result,
        report_level=ReportLevel.DETAILED,
        include_executive_summary=True,
        include_dashboard_data=True,
    )
    print("   ✓ AI analysis complete")

    print("\n📊 Step 3: Generating multi-format reports...")

    # Save JSON (for automation)
    json_formatter = get_formatter("json")
    json_path = Path("output/ai_full_report.json")
    json_path.write_text(json_formatter.format(report))
    print(f"   ✓ JSON report: {json_path}")

    # Save Markdown (for documentation)
    md_formatter = get_formatter("markdown")
    md_path = Path("output/ai_full_report.md")
    md_path.write_text(md_formatter.format(report))
    print(f"   ✓ Markdown report: {md_path}")

    # Save HTML (for sharing)
    html_formatter = get_formatter("html")
    html_path = Path("output/ai_full_report.html")
    html_path.write_text(html_formatter.format(report))
    print(f"   ✓ HTML report: {html_path}")

    # Export dashboard data
    import json
    dashboard_path = Path("output/ai_dashboard_data.json")
    dashboard_path.write_text(json.dumps(report.dashboard_data.to_dict(), indent=2))
    print(f"   ✓ Dashboard data: {dashboard_path}")

    print("\n✅ Complete workflow finished!")
    print(f"   All reports saved to the 'output' directory")


if __name__ == "__main__":
    print("\n🤖 THREAT RADAR - AI-Powered Report Examples\n")

    # Check AI configuration
    if not os.getenv("OPENAI_API_KEY") and os.getenv("AI_PROVIDER") != "ollama":
        print("💡 TIP: Set up AI configuration for enhanced reports:")
        print("   - For OpenAI: Set OPENAI_API_KEY in .env")
        print("   - For local AI: Set AI_PROVIDER=ollama and install Ollama")
        print("   - Reports will use fallback summaries if AI is not configured\n")

    # Run examples
    example_executive_summary_with_ai()
    example_comparison_with_without_ai()
    example_different_ai_providers()
    example_full_workflow()

    print("\n" + "=" * 70)
    print("All AI examples completed!")
    print("=" * 70)
