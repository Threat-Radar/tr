#!/usr/bin/env python3
"""
Example: Basic Report Generation

Demonstrates how to generate comprehensive vulnerability reports from scan results.
This example shows the basic workflow of loading scan results and generating
reports in different formats.
"""

from pathlib import Path
from threat_radar.utils import ComprehensiveReportGenerator, ReportLevel
from threat_radar.utils.report_formatters import get_formatter
from threat_radar.core.grype_integration import GrypeScanResult, GrypeVulnerability


def create_sample_scan_result():
    """Create a sample scan result for demonstration."""
    vulnerabilities = [
        GrypeVulnerability(
            id="CVE-2024-1234",
            severity="critical",
            package_name="openssl",
            package_version="1.1.1k",
            package_type="apk",
            fixed_in_version="1.1.1w",
            description="Critical remote code execution vulnerability in OpenSSL",
            cvss_score=9.8,
            urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
        ),
        GrypeVulnerability(
            id="CVE-2024-5678",
            severity="high",
            package_name="nginx",
            package_version="1.20.0",
            package_type="apk",
            fixed_in_version="1.20.2",
            description="HTTP request smuggling vulnerability",
            cvss_score=7.5,
            urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-5678"],
        ),
        GrypeVulnerability(
            id="CVE-2024-9012",
            severity="high",
            package_name="curl",
            package_version="7.68.0",
            package_type="deb",
            fixed_in_version="7.68.1",
            description="Buffer overflow in curl",
            cvss_score=7.2,
            urls=[],
        ),
        GrypeVulnerability(
            id="CVE-2024-3456",
            severity="medium",
            package_name="libxml2",
            package_version="2.9.10",
            package_type="apk",
            fixed_in_version=None,
            description="XML parsing vulnerability",
            cvss_score=5.3,
            urls=[],
        ),
    ]

    return GrypeScanResult(
        target="alpine:3.18",
        vulnerabilities=vulnerabilities,
        total_count=len(vulnerabilities),
        severity_counts={"critical": 1, "high": 2, "medium": 1},
        scan_metadata={"scanner": "grype", "db_version": "5"},
    )


def example_basic_json_report():
    """Generate a basic JSON report."""
    print("=" * 70)
    print("EXAMPLE 1: Basic JSON Report")
    print("=" * 70)

    # Create sample data
    scan_result = create_sample_scan_result()

    # Generate report
    generator = ComprehensiveReportGenerator()
    report = generator.generate_report(
        scan_result=scan_result,
        report_level=ReportLevel.DETAILED,
        include_executive_summary=False,  # Skip AI for this example
        include_dashboard_data=True,
    )

    # Format as JSON
    formatter = get_formatter("json")
    json_output = formatter.format(report)

    # Save to file
    output_path = Path("output/basic_report.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json_output)

    print(f"\n✓ Report saved to: {output_path}")
    print(f"\nReport Summary:")
    print(f"  Report ID: {report.report_id}")
    print(f"  Target: {report.target}")
    print(f"  Total Vulnerabilities: {report.summary.total_vulnerabilities}")
    print(f"  Critical: {report.summary.critical}")
    print(f"  High: {report.summary.high}")
    print(f"  Medium: {report.summary.medium}")
    print(f"  Vulnerable Packages: {len(report.packages)}")


def example_markdown_report():
    """Generate a Markdown report."""
    print("\n" + "=" * 70)
    print("EXAMPLE 2: Markdown Report")
    print("=" * 70)

    scan_result = create_sample_scan_result()

    generator = ComprehensiveReportGenerator()
    report = generator.generate_report(
        scan_result=scan_result,
        report_level=ReportLevel.SUMMARY,
        include_executive_summary=False,
        include_dashboard_data=False,
    )

    # Format as Markdown
    formatter = get_formatter("markdown")
    md_output = formatter.format(report)

    # Save to file
    output_path = Path("output/vulnerability_report.md")
    output_path.write_text(md_output)

    print(f"\n✓ Markdown report saved to: {output_path}")
    print("\nPreview (first 500 characters):")
    print("-" * 70)
    print(md_output[:500] + "...")


def example_html_report():
    """Generate an HTML report."""
    print("\n" + "=" * 70)
    print("EXAMPLE 3: HTML Report")
    print("=" * 70)

    scan_result = create_sample_scan_result()

    generator = ComprehensiveReportGenerator()
    report = generator.generate_report(
        scan_result=scan_result,
        report_level=ReportLevel.DETAILED,
        include_executive_summary=False,
        include_dashboard_data=True,
    )

    # Format as HTML
    formatter = get_formatter("html")
    html_output = formatter.format(report)

    # Save to file
    output_path = Path("output/vulnerability_report.html")
    output_path.write_text(html_output)

    print(f"\n✓ HTML report saved to: {output_path}")
    print(f"  Open {output_path} in your browser to view the styled report")


def example_critical_only_report():
    """Generate a critical-only filtered report."""
    print("\n" + "=" * 70)
    print("EXAMPLE 4: Critical-Only Report")
    print("=" * 70)

    scan_result = create_sample_scan_result()

    generator = ComprehensiveReportGenerator()
    report = generator.generate_report(
        scan_result=scan_result,
        report_level=ReportLevel.CRITICAL_ONLY,
        include_executive_summary=False,
        include_dashboard_data=False,
    )

    print(f"\n✓ Critical-only report generated")
    print(f"  Total vulnerabilities in full scan: {scan_result.total_count}")
    print(f"  Critical/High vulnerabilities: {report.summary.total_vulnerabilities}")
    print(f"\nFiltered findings:")
    for finding in report.findings:
        print(f"  - {finding.cve_id} ({finding.severity.upper()}) - {finding.package_name}")


def example_dashboard_data_export():
    """Export dashboard-ready data."""
    print("\n" + "=" * 70)
    print("EXAMPLE 5: Dashboard Data Export")
    print("=" * 70)

    scan_result = create_sample_scan_result()

    generator = ComprehensiveReportGenerator()
    report = generator.generate_report(
        scan_result=scan_result,
        include_executive_summary=False,
        include_dashboard_data=True,
    )

    # Extract and save dashboard data
    dashboard_data = report.dashboard_data.to_dict()

    import json
    output_path = Path("output/dashboard_data.json")
    output_path.write_text(json.dumps(dashboard_data, indent=2))

    print(f"\n✓ Dashboard data exported to: {output_path}")
    print(f"\nDashboard metrics included:")
    print(f"  Summary Cards: {len(dashboard_data['summary_cards'])} metrics")
    print(f"  Severity Distribution: {len(dashboard_data['severity_distribution_chart'])} categories")
    print(f"  Top Packages: {len(dashboard_data['top_vulnerable_packages_chart'])} packages")
    print(f"  Critical Items: {len(dashboard_data['critical_items'])} items")


if __name__ == "__main__":
    print("\n🛡️  THREAT RADAR - Report Generation Examples\n")

    # Run all examples
    example_basic_json_report()
    example_markdown_report()
    example_html_report()
    example_critical_only_report()
    example_dashboard_data_export()

    print("\n" + "=" * 70)
    print("All examples completed! Check the 'output' directory for generated reports.")
    print("=" * 70)
