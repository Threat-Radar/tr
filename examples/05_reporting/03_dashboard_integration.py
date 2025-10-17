#!/usr/bin/env python3
"""
Example: Dashboard Integration

Demonstrates how to use the dashboard data structures for building
custom visualization dashboards (Grafana, custom web apps, etc.)
"""

import json
from pathlib import Path
from threat_radar.utils import ComprehensiveReportGenerator
from threat_radar.core.grype_integration import GrypeScanResult, GrypeVulnerability


def create_dashboard_sample_data():
    """Create comprehensive sample data for dashboard demonstration."""
    vulnerabilities = [
        # Critical - OpenSSL
        GrypeVulnerability(
            id="CVE-2024-1001", severity="critical", package_name="openssl",
            package_version="1.1.1k", package_type="apk", fixed_in_version="1.1.1w",
            description="RCE in SSL/TLS", cvss_score=9.8, urls=[],
        ),
        GrypeVulnerability(
            id="CVE-2024-1002", severity="critical", package_name="openssl",
            package_version="1.1.1k", package_type="apk", fixed_in_version="1.1.1w",
            description="DoS in crypto", cvss_score=9.1, urls=[],
        ),
        # High - Various packages
        GrypeVulnerability(
            id="CVE-2024-2001", severity="high", package_name="nginx",
            package_version="1.20.0", package_type="apk", fixed_in_version="1.20.2",
            description="Request smuggling", cvss_score=7.5, urls=[],
        ),
        GrypeVulnerability(
            id="CVE-2024-2002", severity="high", package_name="curl",
            package_version="7.68.0", package_type="deb", fixed_in_version="7.68.1",
            description="Buffer overflow", cvss_score=8.1, urls=[],
        ),
        GrypeVulnerability(
            id="CVE-2024-2003", severity="high", package_name="postgresql-client",
            package_version="12.5", package_type="deb", fixed_in_version=None,
            description="SQL injection", cvss_score=7.8, urls=[],
        ),
        # Medium
        GrypeVulnerability(
            id="CVE-2024-3001", severity="medium", package_name="libxml2",
            package_version="2.9.10", package_type="apk", fixed_in_version=None,
            description="XXE vulnerability", cvss_score=5.3, urls=[],
        ),
        GrypeVulnerability(
            id="CVE-2024-3002", severity="medium", package_name="python3",
            package_version="3.9.5", package_type="apk", fixed_in_version="3.9.10",
            description="Path traversal", cvss_score=6.1, urls=[],
        ),
        # Low
        GrypeVulnerability(
            id="CVE-2024-4001", severity="low", package_name="libpng",
            package_version="1.6.37", package_type="apk", fixed_in_version="1.6.38",
            description="Info disclosure", cvss_score=3.7, urls=[],
        ),
    ]

    return GrypeScanResult(
        target="production-app:v2.5.0",
        vulnerabilities=vulnerabilities,
        total_count=len(vulnerabilities),
        severity_counts={"critical": 2, "high": 3, "medium": 2, "low": 1},
    )


def example_extract_dashboard_data():
    """Extract and display dashboard data structure."""
    print("=" * 70)
    print("EXAMPLE 1: Dashboard Data Structure")
    print("=" * 70)

    scan_result = create_dashboard_sample_data()
    generator = ComprehensiveReportGenerator()

    report = generator.generate_report(
        scan_result=scan_result,
        include_executive_summary=False,
        include_dashboard_data=True,
    )

    dashboard = report.dashboard_data

    print("\n📊 SUMMARY CARDS")
    print("-" * 70)
    for key, value in dashboard.summary_cards.items():
        print(f"  {key}: {value}")

    print("\n📈 SEVERITY DISTRIBUTION")
    print("-" * 70)
    for item in dashboard.severity_distribution_chart:
        bar_length = int(item['count'] * 5)
        bar = '█' * bar_length
        print(f"  {item['severity']:10s} {bar} {item['count']} (color: {item['color']})")

    print("\n📦 TOP VULNERABLE PACKAGES")
    print("-" * 70)
    for i, pkg in enumerate(dashboard.top_vulnerable_packages_chart[:5], 1):
        print(f"  {i}. {pkg['package']:30s} {pkg['vulnerability_count']} vulns ({pkg['severity']})")

    print("\n🔢 CVSS SCORE DISTRIBUTION")
    print("-" * 70)
    for bucket in dashboard.cvss_score_histogram:
        if bucket['count'] > 0:
            print(f"  Score {bucket['score_range']}: {bucket['count']} vulnerabilities")

    print("\n📊 FIX AVAILABILITY")
    print("-" * 70)
    fix_data = dashboard.fix_availability_pie
    total = fix_data['with_fix'] + fix_data['without_fix']
    with_fix_pct = (fix_data['with_fix'] / total * 100) if total > 0 else 0
    print(f"  With Fix:    {fix_data['with_fix']:2d} ({with_fix_pct:.1f}%)")
    print(f"  Without Fix: {fix_data['without_fix']:2d} ({100-with_fix_pct:.1f}%)")

    print("\n🚨 CRITICAL ITEMS (Top 5)")
    print("-" * 70)
    for item in dashboard.critical_items[:5]:
        fix_status = f"Fix: {item['fixed_in']}" if item['has_fix'] else "No fix"
        print(f"  {item['cve_id']:15s} {item['package']:25s} CVSS: {item['cvss_score']:.1f} ({fix_status})")

    # Save dashboard data
    output_path = Path("output/dashboard_structure.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(dashboard.to_dict(), indent=2))
    print(f"\n✓ Full dashboard data saved to: {output_path}")


def example_grafana_ready_format():
    """Format data for Grafana dashboard."""
    print("\n" + "=" * 70)
    print("EXAMPLE 2: Grafana-Ready JSON Format")
    print("=" * 70)

    scan_result = create_dashboard_sample_data()
    generator = ComprehensiveReportGenerator()
    report = generator.generate_report(
        scan_result=scan_result,
        include_dashboard_data=True,
    )

    dashboard = report.dashboard_data

    # Create Grafana-compatible JSON structure
    grafana_data = {
        "panels": [
            {
                "id": 1,
                "title": "Vulnerability Summary",
                "type": "stat",
                "targets": [
                    {
                        "metric": "total_vulnerabilities",
                        "value": dashboard.summary_cards['total_vulnerabilities']
                    },
                    {
                        "metric": "critical_vulnerabilities",
                        "value": dashboard.summary_cards['critical_vulnerabilities']
                    },
                    {
                        "metric": "average_cvss_score",
                        "value": dashboard.summary_cards['average_cvss_score']
                    },
                ]
            },
            {
                "id": 2,
                "title": "Severity Distribution",
                "type": "piechart",
                "targets": [
                    {
                        "labels": [item['severity'] for item in dashboard.severity_distribution_chart],
                        "values": [item['count'] for item in dashboard.severity_distribution_chart],
                        "colors": [item['color'] for item in dashboard.severity_distribution_chart],
                    }
                ]
            },
            {
                "id": 3,
                "title": "Top Vulnerable Packages",
                "type": "barchart",
                "targets": [
                    {
                        "labels": [item['package'] for item in dashboard.top_vulnerable_packages_chart],
                        "values": [item['vulnerability_count'] for item in dashboard.top_vulnerable_packages_chart],
                    }
                ]
            },
        ]
    }

    output_path = Path("output/grafana_dashboard.json")
    output_path.write_text(json.dumps(grafana_data, indent=2))

    print("\n✓ Grafana dashboard JSON created")
    print(f"  Saved to: {output_path}")
    print(f"  Panels: {len(grafana_data['panels'])}")
    print("\n  Import this JSON into Grafana to create your dashboard")


def example_react_dashboard_format():
    """Format data for React/JavaScript dashboard."""
    print("\n" + "=" * 70)
    print("EXAMPLE 3: React/JavaScript Dashboard Format")
    print("=" * 70)

    scan_result = create_dashboard_sample_data()
    generator = ComprehensiveReportGenerator()
    report = generator.generate_report(
        scan_result=scan_result,
        include_dashboard_data=True,
    )

    dashboard = report.dashboard_data

    # Create React-friendly format
    react_data = {
        "summary": {
            "cards": [
                {
                    "title": "Total Vulnerabilities",
                    "value": dashboard.summary_cards['total_vulnerabilities'],
                    "icon": "🛡️",
                    "color": "blue"
                },
                {
                    "title": "Critical",
                    "value": dashboard.summary_cards['critical_vulnerabilities'],
                    "icon": "🔴",
                    "color": "red"
                },
                {
                    "title": "Average CVSS",
                    "value": round(dashboard.summary_cards['average_cvss_score'], 1),
                    "icon": "📊",
                    "color": "orange"
                },
                {
                    "title": "Fix Available",
                    "value": f"{dashboard.summary_cards['fix_available_percentage']:.0f}%",
                    "icon": "✅",
                    "color": "green"
                },
            ]
        },
        "charts": {
            "severityDistribution": {
                "type": "pie",
                "data": [
                    {
                        "name": item['severity'],
                        "value": item['count'],
                        "color": item['color']
                    }
                    for item in dashboard.severity_distribution_chart
                ]
            },
            "topPackages": {
                "type": "horizontalBar",
                "data": [
                    {
                        "package": item['package'].split('@')[0],  # Just package name
                        "vulnerabilities": item['vulnerability_count'],
                        "severity": item['severity']
                    }
                    for item in dashboard.top_vulnerable_packages_chart[:10]
                ]
            },
            "cvssHistogram": {
                "type": "bar",
                "data": [
                    {
                        "range": item['score_range'],
                        "count": item['count']
                    }
                    for item in dashboard.cvss_score_histogram
                    if item['count'] > 0
                ]
            }
        },
        "criticalItems": [
            {
                "id": item['cve_id'],
                "package": item['package'],
                "severity": item['severity'],
                "cvss": item['cvss_score'],
                "hasFix": item['has_fix'],
                "fixedIn": item['fixed_in']
            }
            for item in dashboard.critical_items
        ]
    }

    output_path = Path("output/react_dashboard_data.json")
    output_path.write_text(json.dumps(react_data, indent=2))

    print("\n✓ React dashboard data created")
    print(f"  Saved to: {output_path}")
    print("\n  Use this JSON in your React components:")
    print("  ```javascript")
    print("  import dashboardData from './react_dashboard_data.json';")
    print("  ```")


def example_custom_visualization():
    """Create custom visualization data."""
    print("\n" + "=" * 70)
    print("EXAMPLE 4: Custom Visualization Metrics")
    print("=" * 70)

    scan_result = create_dashboard_sample_data()
    generator = ComprehensiveReportGenerator()
    report = generator.generate_report(
        scan_result=scan_result,
        include_dashboard_data=True,
    )

    # Create custom metrics
    custom_metrics = {
        "risk_score": calculate_risk_score(report),
        "remediation_priority": get_remediation_priority(report),
        "package_health": analyze_package_health(report),
        "trend_indicators": {
            "severity_trend": "worsening",  # Would come from historical data
            "package_count_trend": "stable",
            "fix_availability_trend": "improving"
        }
    }

    print("\n🎯 CUSTOM METRICS")
    print("-" * 70)
    print(f"  Risk Score: {custom_metrics['risk_score']}/100")
    print(f"  Remediation Priority: {custom_metrics['remediation_priority']}")
    print(f"\n  Package Health Score: {custom_metrics['package_health']['score']}/100")
    print(f"  Packages Needing Update: {custom_metrics['package_health']['needs_update']}")
    print(f"  Packages Without Fix: {custom_metrics['package_health']['no_fix_available']}")

    output_path = Path("output/custom_metrics.json")
    output_path.write_text(json.dumps(custom_metrics, indent=2))
    print(f"\n✓ Custom metrics saved to: {output_path}")


def calculate_risk_score(report):
    """Calculate overall risk score (0-100)."""
    score = 0
    score += report.summary.critical * 25
    score += report.summary.high * 10
    score += report.summary.medium * 3
    score += report.summary.low * 1
    return min(100, score)


def get_remediation_priority(report):
    """Get remediation priority level."""
    critical_high = report.summary.critical + report.summary.high
    if critical_high > 10:
        return "URGENT"
    elif critical_high > 3:
        return "HIGH"
    elif critical_high > 0:
        return "MEDIUM"
    else:
        return "LOW"


def analyze_package_health(report):
    """Analyze overall package health."""
    total_packages = len(report.packages)
    packages_with_fix = sum(1 for pkg in report.packages if pkg.recommended_version)

    health_score = (packages_with_fix / total_packages * 100) if total_packages > 0 else 100

    return {
        "score": round(health_score, 1),
        "total_packages": total_packages,
        "needs_update": packages_with_fix,
        "no_fix_available": total_packages - packages_with_fix
    }


if __name__ == "__main__":
    print("\n📊 THREAT RADAR - Dashboard Integration Examples\n")

    example_extract_dashboard_data()
    example_grafana_ready_format()
    example_react_dashboard_format()
    example_custom_visualization()

    print("\n" + "=" * 70)
    print("Dashboard integration examples completed!")
    print("Check the 'output' directory for all generated data files.")
    print("=" * 70)
