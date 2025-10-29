"""Complete graph database workflows for real-world scenarios.

This example demonstrates end-to-end workflows for:
1. CI/CD pipeline integration
2. Multi-container stack analysis
3. Vulnerability trend tracking
4. Security audit reporting
5. Remediation planning

Run these workflows to see how graph analysis fits into your security operations.
"""

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from threat_radar.graph import NetworkXClient, GraphBuilder, GraphAnalyzer
from threat_radar.core.grype_integration import GrypeScanResult, GrypeVulnerability
from threat_radar.utils.graph_storage import GraphStorageManager


def create_mock_scan(image_name: str, vuln_count: int = 5):
    """Create a mock scan result for demonstration."""
    base_vulns = [
        ("CVE-2023-0001", "critical", "openssl", "1.1.1", "1.1.1k", 9.8),
        ("CVE-2023-0002", "high", "curl", "7.79.0", "7.79.1", 7.5),
        ("CVE-2023-0003", "high", "libxml2", "2.9.10", "2.9.14", 7.2),
        ("CVE-2023-0004", "medium", "zlib", "1.2.11", "1.2.12", 5.3),
        ("CVE-2023-0005", "low", "busybox", "1.35.0", "1.35.1", 3.1),
    ]

    vulnerabilities = []
    for i in range(min(vuln_count, len(base_vulns))):
        cve_id, severity, pkg, version, fix, cvss = base_vulns[i]
        vulnerabilities.append(
            GrypeVulnerability(
                id=cve_id,
                severity=severity,
                package_name=pkg,
                package_version=version,
                package_type="apk",
                fixed_in_version=fix,
                description=f"{severity.title()} vulnerability in {pkg}",
                cvss_score=cvss,
            )
        )

    return GrypeScanResult(target=image_name, vulnerabilities=vulnerabilities)


def workflow_cicd_pipeline():
    """Workflow 1: CI/CD Pipeline Integration.

    Scenario: Check container security before deployment
    Decision: Pass/fail based on vulnerability thresholds
    """
    print("=" * 70)
    print("WORKFLOW 1: CI/CD Pipeline Security Check")
    print("=" * 70)

    print("\n📦 Scanning container image: myapp:latest")
    print("   (In real CI/CD, this would be: docker build -t myapp:latest .)")

    # Simulate scan
    scan_result = create_mock_scan("myapp:latest", vuln_count=4)

    # Build graph
    client = NetworkXClient()
    builder = GraphBuilder(client)
    builder.build_from_scan(scan_result)

    # Analyze for CI/CD decision
    analyzer = GraphAnalyzer(client)
    stats = analyzer.vulnerability_statistics()

    print(f"\n📊 Scan Results:")
    print(f"   • Total vulnerabilities: {stats['total_vulnerabilities']}")
    print(f"   • Critical: {stats['by_severity']['critical']}")
    print(f"   • High: {stats['by_severity']['high']}")
    print(f"   • Average CVSS: {stats['avg_cvss_score']:.1f}")

    # Define thresholds
    CRITICAL_THRESHOLD = 0  # No critical vulnerabilities allowed
    HIGH_THRESHOLD = 2  # Max 2 high severity
    CVSS_THRESHOLD = 7.0  # Max average CVSS

    print(f"\n🎯 Policy Thresholds:")
    print(f"   • Critical: {CRITICAL_THRESHOLD} (current: {stats['by_severity']['critical']})")
    print(f"   • High: ≤ {HIGH_THRESHOLD} (current: {stats['by_severity']['high']})")
    print(f"   • Avg CVSS: ≤ {CVSS_THRESHOLD} (current: {stats['avg_cvss_score']:.1f})")

    # Make decision
    violations = []
    if stats['by_severity']['critical'] > CRITICAL_THRESHOLD:
        violations.append(f"Critical vulnerabilities: {stats['by_severity']['critical']}")
    if stats['by_severity']['high'] > HIGH_THRESHOLD:
        violations.append(f"High vulnerabilities: {stats['by_severity']['high']}")
    if stats['avg_cvss_score'] > CVSS_THRESHOLD:
        violations.append(f"Average CVSS too high: {stats['avg_cvss_score']:.1f}")

    if violations:
        print(f"\n❌ BUILD FAILED - Policy violations:")
        for violation in violations:
            print(f"   • {violation}")

        # Show actionable fixes
        print(f"\n🔧 Recommended Actions:")
        fixes = analyzer.find_fix_candidates(severity="critical")
        if fixes:
            print(f"   Critical fixes available:")
            for fix in fixes[:3]:
                print(f"     • {fix['cve_id']}: Upgrade {fix['affected_packages'][0]}")
        else:
            print(f"   Review HIGH severity vulnerabilities")

        return False
    else:
        print(f"\n✅ BUILD PASSED - No policy violations")
        print(f"   • Container meets security requirements")
        print(f"   • Safe to deploy")
        return True


def workflow_multi_container_stack():
    """Workflow 2: Analyze entire application stack.

    Scenario: Microservices application with multiple containers
    Goal: Find shared vulnerabilities and prioritize fixes
    """
    print("\n" + "=" * 70)
    print("WORKFLOW 2: Multi-Container Stack Analysis")
    print("=" * 70)

    containers = [
        ("frontend:latest", 3),
        ("backend:latest", 4),
        ("api:latest", 5),
        ("worker:latest", 2),
    ]

    print(f"\n🏗️  Application Stack:")
    for image, _ in containers:
        print(f"   • {image}")

    # Scan all containers
    all_clients = []
    all_stats = {}

    print(f"\n📦 Scanning containers...")
    for image, vuln_count in containers:
        scan = create_mock_scan(image, vuln_count)

        client = NetworkXClient()
        builder = GraphBuilder(client)
        builder.build_from_scan(scan)

        analyzer = GraphAnalyzer(client)
        stats = analyzer.vulnerability_statistics()

        all_clients.append((image, client, analyzer))
        all_stats[image] = stats

        status = "🔴" if stats['by_severity']['critical'] > 0 else "🟢"
        print(f"   {status} {image}: {stats['total_vulnerabilities']} vulnerabilities")

    # Aggregate statistics
    print(f"\n📊 Stack-Wide Statistics:")
    total_vulns = sum(s['total_vulnerabilities'] for s in all_stats.values())
    total_critical = sum(s['by_severity']['critical'] for s in all_stats.values())
    total_high = sum(s['by_severity']['high'] for s in all_stats.values())

    print(f"   • Total vulnerabilities: {total_vulns}")
    print(f"   • Critical: {total_critical}")
    print(f"   • High: {total_high}")

    # Find worst offender
    worst_image = max(all_stats.items(), key=lambda x: x[1]['total_vulnerabilities'])
    print(f"\n⚠️  Highest Risk Container:")
    print(f"   {worst_image[0]} with {worst_image[1]['total_vulnerabilities']} vulnerabilities")

    # Prioritization
    print(f"\n🎯 Remediation Priority:")
    sorted_containers = sorted(
        all_stats.items(),
        key=lambda x: (
            x[1]['by_severity']['critical'] * 10 +
            x[1]['by_severity']['high']
        ),
        reverse=True
    )

    for i, (image, stats) in enumerate(sorted_containers, 1):
        risk_score = stats['by_severity']['critical'] * 10 + stats['by_severity']['high']
        print(f"   {i}. {image} (risk score: {risk_score})")


def workflow_trend_tracking():
    """Workflow 3: Track vulnerability trends over time.

    Scenario: Weekly security scans to monitor progress
    Goal: Identify improving/worsening security posture
    """
    print("\n" + "=" * 70)
    print("WORKFLOW 3: Vulnerability Trend Tracking")
    print("=" * 70)

    print(f"\n📅 Simulating weekly scans over 4 weeks...")

    # Simulate 4 weeks of scans with improving trend
    weeks_data = [
        ("2025-01-01", 8, "Week 1 - Initial scan"),
        ("2025-01-08", 6, "Week 2 - Fixed 2 vulnerabilities"),
        ("2025-01-15", 4, "Week 3 - Continued progress"),
        ("2025-01-22", 3, "Week 4 - Near target"),
    ]

    storage = GraphStorageManager()
    historical_stats = []

    for date_str, vuln_count, description in weeks_data:
        scan = create_mock_scan("production:latest", vuln_count)

        client = NetworkXClient()
        builder = GraphBuilder(client)
        builder.build_from_scan(scan)

        analyzer = GraphAnalyzer(client)
        stats = analyzer.vulnerability_statistics()

        historical_stats.append({
            'date': date_str,
            'description': description,
            'total': stats['total_vulnerabilities'],
            'critical': stats['by_severity']['critical'],
            'high': stats['by_severity']['high'],
            'cvss': stats['avg_cvss_score'],
        })

    # Display trend
    print(f"\n📈 Trend Analysis:")
    print(f"{'Date':<12} {'Total':<8} {'Critical':<10} {'High':<8} {'Avg CVSS':<10} {'Change':<10}")
    print("-" * 70)

    for i, data in enumerate(historical_stats):
        change = ""
        if i > 0:
            prev_total = historical_stats[i-1]['total']
            diff = data['total'] - prev_total
            if diff < 0:
                change = f"↓ {abs(diff)}"
            elif diff > 0:
                change = f"↑ {diff}"
            else:
                change = "→ 0"

        print(
            f"{data['date']:<12} "
            f"{data['total']:<8} "
            f"{data['critical']:<10} "
            f"{data['high']:<8} "
            f"{data['cvss']:<10.1f} "
            f"{change:<10}"
        )

    # Calculate trend
    first_total = historical_stats[0]['total']
    last_total = historical_stats[-1]['total']
    improvement = first_total - last_total
    improvement_pct = (improvement / first_total * 100) if first_total > 0 else 0

    print(f"\n📊 Overall Progress:")
    if improvement > 0:
        print(f"   ✅ IMPROVING: {improvement} fewer vulnerabilities ({improvement_pct:.1f}% reduction)")
        print(f"   • Continue current remediation efforts")
    elif improvement < 0:
        print(f"   ⚠️  WORSENING: {abs(improvement)} more vulnerabilities")
        print(f"   • Increase security focus")
    else:
        print(f"   → STABLE: No change in vulnerability count")


def workflow_security_audit():
    """Workflow 4: Generate comprehensive security audit report.

    Scenario: Quarterly security review for compliance
    Goal: Detailed analysis for stakeholders
    """
    print("\n" + "=" * 70)
    print("WORKFLOW 4: Security Audit Report")
    print("=" * 70)

    print(f"\n📋 Generating Q1 2025 Security Audit...")

    # Create sample scan
    scan = create_mock_scan("production:v2.1.0", vuln_count=5)

    client = NetworkXClient()
    builder = GraphBuilder(client)
    builder.build_from_scan(scan)

    analyzer = GraphAnalyzer(client)
    stats = analyzer.vulnerability_statistics()

    # Report sections
    print(f"\n" + "=" * 70)
    print(f"SECURITY AUDIT REPORT")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d')}")
    print(f"Target: production:v2.1.0")
    print(f"=" * 70)

    # Executive Summary
    print(f"\n📊 EXECUTIVE SUMMARY")
    print(f"-" * 70)
    print(f"Total Vulnerabilities: {stats['total_vulnerabilities']}")
    print(f"Average Severity (CVSS): {stats['avg_cvss_score']:.1f}/10.0")
    print(f"Fix Availability: {stats['with_fixes']} fixed, {stats['without_fixes']} unfixed")

    # Risk Assessment
    if stats['by_severity']['critical'] > 0:
        risk_level = "🔴 CRITICAL"
    elif stats['by_severity']['high'] > 0:
        risk_level = "🟠 HIGH"
    elif stats['by_severity']['medium'] > 0:
        risk_level = "🟡 MEDIUM"
    else:
        risk_level = "🟢 LOW"

    print(f"\nRisk Level: {risk_level}")

    # Detailed Findings
    print(f"\n📝 DETAILED FINDINGS")
    print(f"-" * 70)
    print(f"Severity Breakdown:")
    for severity in ['critical', 'high', 'medium', 'low']:
        count = stats['by_severity'][severity]
        if count > 0:
            print(f"  • {severity.title()}: {count}")

    # Top Vulnerable Packages
    print(f"\n🎯 TOP VULNERABLE PACKAGES")
    print(f"-" * 70)
    top_pkgs = analyzer.most_vulnerable_packages(top_n=5)
    for pkg_id, vuln_count, avg_cvss in top_pkgs:
        pkg_name = pkg_id.split(":")[-1]
        print(f"  • {pkg_name}: {vuln_count} vulnerabilities (avg CVSS: {avg_cvss:.1f})")

    # Recommendations
    print(f"\n💡 RECOMMENDATIONS")
    print(f"-" * 70)
    fixes = analyzer.find_fix_candidates()

    print(f"1. Immediate Actions ({stats['by_severity']['critical']} critical)")
    critical_fixes = [f for f in fixes if f['severity'] == 'critical']
    if critical_fixes:
        for fix in critical_fixes[:3]:
            print(f"   • Patch {fix['cve_id']} in {fix['affected_packages'][0]}")
    else:
        print(f"   ✓ No critical vulnerabilities")

    print(f"\n2. Short-term (Next Sprint)")
    print(f"   • Address {stats['by_severity']['high']} high-severity issues")
    print(f"   • Focus on packages with multiple vulnerabilities")

    print(f"\n3. Long-term (Next Quarter)")
    print(f"   • Review and update {stats['by_severity']['medium']} medium-severity items")
    print(f"   • Establish automated scanning in CI/CD")

    print(f"\n" + "=" * 70)
    print(f"END OF REPORT")
    print(f"=" * 70)


def workflow_remediation_planning():
    """Workflow 5: Create actionable remediation plan.

    Scenario: Security team needs step-by-step fix plan
    Goal: Prioritized, actionable remediation tasks
    """
    print("\n" + "=" * 70)
    print("WORKFLOW 5: Remediation Planning")
    print("=" * 70)

    print(f"\n🔧 Creating Remediation Plan...")

    scan = create_mock_scan("app:production", vuln_count=5)

    client = NetworkXClient()
    builder = GraphBuilder(client)
    builder.build_from_scan(scan)

    analyzer = GraphAnalyzer(client)
    fixes = analyzer.find_fix_candidates()

    print(f"\n📋 REMEDIATION PLAN")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"=" * 70)

    # Group by package
    package_fixes = {}
    for fix in fixes:
        pkg_name = fix['affected_packages'][0].split(":")[1].split("@")[0] if ":" in fix['affected_packages'][0] else "unknown"
        if pkg_name not in package_fixes:
            package_fixes[pkg_name] = []
        package_fixes[pkg_name].append(fix)

    # Create tasks
    task_num = 1
    for pkg_name, pkg_fixes in sorted(package_fixes.items()):
        # Sort fixes by severity
        pkg_fixes.sort(key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x['severity'], 4))

        print(f"\n{'='*70}")
        print(f"TASK #{task_num}: Update {pkg_name}")
        print(f"{'='*70}")

        # Priority
        max_severity = pkg_fixes[0]['severity']
        if max_severity == 'critical':
            priority = "🔴 URGENT (24-48 hours)"
        elif max_severity == 'high':
            priority = "🟠 HIGH (this week)"
        else:
            priority = "🟡 MEDIUM (this sprint)"

        print(f"Priority: {priority}")
        print(f"Effort: ~1-2 hours (testing + deployment)")

        # Vulnerabilities addressed
        print(f"\nVulnerabilities Fixed:")
        for fix in pkg_fixes:
            print(f"  • {fix['cve_id']} ({fix['severity'].upper()}, CVSS: {fix['cvss_score']:.1f})")

        # Action steps
        print(f"\nAction Steps:")
        print(f"  1. Review change log for breaking changes")
        print(f"  2. Update Dockerfile/requirements:")
        print(f"     FROM alpine:3.18")
        print(f"     RUN apk upgrade {pkg_name}  # to version {pkg_fixes[0]['fix_version']}")
        print(f"  3. Run tests: pytest tests/")
        print(f"  4. Build image: docker build -t app:patched .")
        print(f"  5. Test in staging environment")
        print(f"  6. Deploy to production")

        # Testing
        print(f"\nTesting Checklist:")
        print(f"  [ ] Unit tests pass")
        print(f"  [ ] Integration tests pass")
        print(f"  [ ] Staging smoke tests pass")
        print(f"  [ ] Performance regression check")

        # Rollback plan
        print(f"\nRollback Plan:")
        print(f"  If issues occur, revert to previous version:")
        print(f"  docker tag app:current app:rollback && docker deploy app:previous")

        task_num += 1

    print(f"\n{'='*70}")
    print(f"PLAN SUMMARY")
    print(f"{'='*70}")
    print(f"Total Tasks: {len(package_fixes)}")
    print(f"Estimated Time: {len(package_fixes) * 2} hours")
    print(f"Team Size: 1-2 engineers")
    print(f"Target Completion: {(datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d')}")


def main():
    """Run all workflow examples."""
    print("\n" + "🔷" * 35)
    print("THREAT RADAR - REAL-WORLD GRAPH WORKFLOWS")
    print("End-to-End Security Operations Scenarios")
    print("🔷" * 35)

    try:
        # Run workflows
        workflow_cicd_pipeline()
        workflow_multi_container_stack()
        workflow_trend_tracking()
        workflow_security_audit()
        workflow_remediation_planning()

        print("\n" + "=" * 70)
        print("✅ All workflow examples completed!")
        print("=" * 70)

        print("\n💡 Apply These Workflows:")
        print("  1. CI/CD: Integrate security checks in your build pipeline")
        print("  2. Multi-Container: Analyze your microservices stack")
        print("  3. Trend Tracking: Set up weekly automated scans")
        print("  4. Audit Reports: Generate compliance documentation")
        print("  5. Remediation: Create actionable fix plans for teams")

        print("\n🚀 Production Integration:")
        print("  • Automate with: cron jobs, GitHub Actions, Jenkins")
        print("  • Store graphs: --auto-save for historical analysis")
        print("  • Alert on: Critical vulns, policy violations, trends")
        print("  • Report to: Slack, email, dashboards, tickets")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
