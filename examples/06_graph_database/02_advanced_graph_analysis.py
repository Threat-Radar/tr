"""Advanced graph analysis examples.

This example demonstrates:
1. Most vulnerable packages analysis
2. Package usage patterns
3. Attack path discovery
4. Multi-container vulnerability analysis
5. Custom graph queries with NetworkX

Prerequisites:
- Completed basic examples: python 01_basic_graph_usage.py
- Multiple CVE scans for comparison
"""

import json
from pathlib import Path
from threat_radar.graph import NetworkXClient, GraphBuilder, GraphAnalyzer
from threat_radar.core.grype_integration import GrypeScanResult, GrypeVulnerability


def create_sample_graph():
    """Create a sample graph with multiple vulnerabilities for demonstration."""
    vulnerabilities = [
        GrypeVulnerability(
            id="CVE-2023-0001",
            severity="critical",
            package_name="openssl",
            package_version="1.1.1",
            package_type="apk",
            fixed_in_version="1.1.1k",
            description="Critical vulnerability in OpenSSL",
            cvss_score=9.8,
        ),
        GrypeVulnerability(
            id="CVE-2023-0002",
            severity="critical",
            package_name="openssl",
            package_version="1.1.1",
            package_type="apk",
            fixed_in_version="1.1.1k",
            description="Another critical OpenSSL vulnerability",
            cvss_score=9.1,
        ),
        GrypeVulnerability(
            id="CVE-2023-0003",
            severity="high",
            package_name="curl",
            package_version="7.79.0",
            package_type="apk",
            fixed_in_version="7.79.1",
            description="High severity curl vulnerability",
            cvss_score=7.5,
        ),
        GrypeVulnerability(
            id="CVE-2023-0004",
            severity="high",
            package_name="libxml2",
            package_version="2.9.10",
            package_type="apk",
            fixed_in_version="2.9.14",
            description="XML parsing vulnerability",
            cvss_score=7.2,
        ),
        GrypeVulnerability(
            id="CVE-2023-0005",
            severity="medium",
            package_name="zlib",
            package_version="1.2.11",
            package_type="apk",
            fixed_in_version="1.2.12",
            description="Compression library vulnerability",
            cvss_score=5.3,
        ),
        GrypeVulnerability(
            id="CVE-2023-0006",
            severity="low",
            package_name="busybox",
            package_version="1.35.0",
            package_type="apk",
            fixed_in_version="1.35.1",
            description="Low severity busybox issue",
            cvss_score=3.1,
        ),
    ]

    scan_result = GrypeScanResult(
        target="alpine:3.18",
        vulnerabilities=vulnerabilities,
    )

    client = NetworkXClient()
    builder = GraphBuilder(client)
    builder.build_from_scan(scan_result)

    return client


def example_most_vulnerable_packages():
    """Example 1: Identify most vulnerable packages."""
    print("=" * 60)
    print("Example 1: Most Vulnerable Packages Analysis")
    print("=" * 60)

    client = create_sample_graph()
    analyzer = GraphAnalyzer(client)

    # Find top vulnerable packages
    print("\nAnalyzing package vulnerability distribution...")
    top_packages = analyzer.most_vulnerable_packages(top_n=10)

    print(f"\nTop {len(top_packages)} Most Vulnerable Packages:")
    print(f"{'Package':<30} {'Vulns':<8} {'Avg CVSS':<10}")
    print("-" * 50)

    for pkg_id, vuln_count, avg_cvss in top_packages:
        # Extract package name from ID
        pkg_name = pkg_id.split(":")[-1] if ":" in pkg_id else pkg_id

        # Color code by severity
        if avg_cvss >= 9.0:
            severity_indicator = "🔴 CRITICAL"
        elif avg_cvss >= 7.0:
            severity_indicator = "🟠 HIGH"
        elif avg_cvss >= 4.0:
            severity_indicator = "🟡 MEDIUM"
        else:
            severity_indicator = "🟢 LOW"

        print(f"{pkg_name:<30} {vuln_count:<8} {avg_cvss:<10.1f} {severity_indicator}")

    print("\n💡 Remediation Priority:")
    print("  Focus on packages with:")
    print("    • Multiple vulnerabilities (attack surface)")
    print("    • High average CVSS scores (severity)")
    print("    • Critical/High severity ratings")


def example_package_usage_patterns():
    """Example 2: Analyze package usage across containers."""
    print("\n" + "=" * 60)
    print("Example 2: Package Usage Pattern Analysis")
    print("=" * 60)

    client = create_sample_graph()
    analyzer = GraphAnalyzer(client)

    print("\nAnalyzing package usage patterns...")
    usage_counts = analyzer.package_usage_count()

    # Sort by usage
    sorted_packages = sorted(
        usage_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )

    print(f"\nPackage Usage Distribution:")
    print(f"{'Package':<30} {'Containers':<12} {'Risk':<10}")
    print("-" * 55)

    for pkg_name, count in sorted_packages[:10]:
        # Calculate risk multiplier (more usage = higher impact)
        if count >= 5:
            risk = "🔴 HIGH"
        elif count >= 3:
            risk = "🟠 MEDIUM"
        else:
            risk = "🟢 LOW"

        print(f"{pkg_name:<30} {count:<12} {risk}")

    print("\n💡 Impact Assessment:")
    print("  Vulnerabilities in widely-used packages affect:")
    print("    • More containers (larger blast radius)")
    print("    • More services (wider exposure)")
    print("    • Higher remediation effort (more instances to patch)")


def example_vulnerability_trends():
    """Example 3: Analyze vulnerability trends and patterns."""
    print("\n" + "=" * 60)
    print("Example 3: Vulnerability Trend Analysis")
    print("=" * 60)

    client = create_sample_graph()
    analyzer = GraphAnalyzer(client)

    stats = analyzer.vulnerability_statistics()

    print("\n📊 Vulnerability Distribution:")

    # Severity breakdown with visual bar chart
    total = stats['total_vulnerabilities']
    print(f"\nTotal: {total} vulnerabilities\n")

    severities = [
        ('Critical', stats['by_severity']['critical'], '🔴'),
        ('High', stats['by_severity']['high'], '🟠'),
        ('Medium', stats['by_severity']['medium'], '🟡'),
        ('Low', stats['by_severity']['low'], '🟢'),
    ]

    for severity_name, count, emoji in severities:
        if count > 0:
            percentage = (count / total * 100) if total > 0 else 0
            bar_length = int(percentage / 2)  # Scale to fit
            bar = "█" * bar_length
            print(f"{emoji} {severity_name:10s} : {count:2d} ({percentage:5.1f}%) {bar}")

    # Fix availability
    print(f"\n🔧 Fix Availability:")
    fix_percentage = (stats['with_fixes'] / total * 100) if total > 0 else 0
    print(f"  • With fixes: {stats['with_fixes']} ({fix_percentage:.1f}%)")
    print(f"  • Without fixes: {stats['without_fixes']}")

    if fix_percentage < 50:
        print(f"\n⚠️  Warning: Low fix availability rate!")
        print(f"     Consider alternative packages or workarounds")
    else:
        print(f"\n✓ Good fix availability - prioritize patching")

    # CVSS score analysis
    avg_cvss = stats['avg_cvss_score']
    print(f"\n📈 CVSS Score Analysis:")
    print(f"  Average CVSS: {avg_cvss:.2f}")

    if avg_cvss >= 7.0:
        print(f"  Risk Level: 🔴 HIGH - Immediate action required")
    elif avg_cvss >= 4.0:
        print(f"  Risk Level: 🟡 MEDIUM - Schedule remediation")
    else:
        print(f"  Risk Level: 🟢 LOW - Monitor and plan updates")


def example_fix_prioritization():
    """Example 4: Advanced fix prioritization strategy."""
    print("\n" + "=" * 60)
    print("Example 4: Intelligent Fix Prioritization")
    print("=" * 60)

    client = create_sample_graph()
    analyzer = GraphAnalyzer(client)

    # Get fix candidates
    fix_candidates = analyzer.find_fix_candidates()

    # Calculate priority scores
    print("\nCalculating fix priorities...")

    prioritized_fixes = []
    for fix in fix_candidates:
        # Priority score based on:
        # - Severity (critical=40, high=30, medium=20, low=10)
        # - CVSS score (scaled to 0-30)
        # - Number of affected packages (0-20)
        # - Fix availability (10 bonus if fix exists)

        severity_scores = {
            'critical': 40,
            'high': 30,
            'medium': 20,
            'low': 10
        }

        severity_score = severity_scores.get(fix['severity'], 0)
        cvss_score = (fix['cvss_score'] or 0) * 3  # Scale to 0-30
        affected_score = min(len(fix['affected_packages']) * 5, 20)
        fix_bonus = 10  # Fix is available

        priority_score = severity_score + cvss_score + affected_score + fix_bonus

        prioritized_fixes.append((priority_score, fix))

    # Sort by priority
    prioritized_fixes.sort(reverse=True, key=lambda x: x[0])

    print(f"\n🎯 Prioritized Fix Plan:")
    print(f"{'Priority':<10} {'CVE':<18} {'Severity':<12} {'CVSS':<8} {'Affected':<10}")
    print("-" * 65)

    for i, (score, fix) in enumerate(prioritized_fixes[:10], 1):
        severity = fix['severity'].upper()

        # Color code
        if score >= 80:
            priority_label = "🔴 URGENT"
        elif score >= 60:
            priority_label = "🟠 HIGH"
        elif score >= 40:
            priority_label = "🟡 MEDIUM"
        else:
            priority_label = "🟢 LOW"

        print(
            f"{priority_label:<10} "
            f"{fix['cve_id']:<18} "
            f"{severity:<12} "
            f"{fix['cvss_score'] or 0:<8.1f} "
            f"{len(fix['affected_packages']):<10}"
        )

    print("\n💡 Remediation Strategy:")
    print("  1. Address URGENT items immediately (score ≥ 80)")
    print("  2. Schedule HIGH priority fixes this sprint (score ≥ 60)")
    print("  3. Plan MEDIUM fixes for next sprint (score ≥ 40)")
    print("  4. Monitor LOW priority items (score < 40)")


def example_custom_networkx_queries():
    """Example 5: Custom queries using NetworkX directly."""
    print("\n" + "=" * 60)
    print("Example 5: Custom Graph Queries (NetworkX)")
    print("=" * 60)

    client = create_sample_graph()

    print("\nDirect NetworkX graph access for custom queries...")

    # Access the underlying NetworkX graph
    G = client.graph

    print(f"\n📊 Graph Statistics:")
    print(f"  • Nodes: {G.number_of_nodes()}")
    print(f"  • Edges: {G.number_of_edges()}")
    print(f"  • Density: {len(G.edges()) / (len(G.nodes()) * (len(G.nodes())-1)):.4f}")

    # Find nodes with high degree (many connections)
    print(f"\n🔗 Most Connected Nodes:")
    degrees = dict(G.degree())
    top_connected = sorted(degrees.items(), key=lambda x: x[1], reverse=True)[:5]

    for node_id, degree in top_connected:
        node_type = G.nodes[node_id].get('node_type', 'unknown')
        print(f"  • {node_id} ({node_type}): {degree} connections")

    # Find vulnerabilities without fixes (dead-end nodes)
    print(f"\n⚠️  Vulnerabilities Without Fixes:")
    vuln_no_fix = []
    for node in G.nodes():
        if G.nodes[node].get('node_type') == 'vulnerability':
            # Check if has outgoing FIXED_BY edge
            has_fix = False
            for _, target, edge_data in G.out_edges(node, data=True):
                if edge_data.get('edge_type') == 'FIXED_BY':
                    has_fix = True
                    break

            if not has_fix:
                cve_id = G.nodes[node].get('cve_id', node)
                severity = G.nodes[node].get('severity', 'unknown')
                vuln_no_fix.append((cve_id, severity))

    if vuln_no_fix:
        for cve_id, severity in vuln_no_fix:
            print(f"  • {cve_id} ({severity.upper()}) - No fix available")
    else:
        print(f"  ✓ All vulnerabilities have fixes available!")

    print("\n💡 Custom Query Tips:")
    print("  • Access graph with: client.graph")
    print("  • Use NetworkX functions: nx.shortest_path(), nx.pagerank(), etc.")
    print("  • Filter nodes: [n for n in G.nodes() if condition]")
    print("  • Traverse edges: G.out_edges(node), G.in_edges(node)")


def example_export_for_visualization():
    """Example 6: Export graph data for visualization tools."""
    print("\n" + "=" * 60)
    print("Example 6: Export for Visualization")
    print("=" * 60)

    client = create_sample_graph()

    print("\nExporting graph in various formats...")

    # Export as dictionary (for JSON)
    print("\n1. JSON format (for web visualization):")
    graph_dict = client.export_to_dict()
    print(f"   • Nodes: {len(graph_dict['nodes'])}")
    print(f"   • Links: {len(graph_dict['links'])}")
    print(f"   • Use with: D3.js, Cytoscape.js, vis.js")

    # Save to file
    output_path = "/tmp/graph-export.json"
    with open(output_path, 'w') as f:
        json.dump(graph_dict, f, indent=2)
    print(f"   ✓ Saved to: {output_path}")

    # GraphML format (already supported)
    print("\n2. GraphML format (for desktop tools):")
    graphml_path = "/tmp/graph-export.graphml"
    client.save(graphml_path)
    print(f"   ✓ Saved to: {graphml_path}")
    print(f"   • Compatible with: Gephi, Cytoscape, Neo4j")

    print("\n💡 Visualization Tools:")
    print("  • Gephi (https://gephi.org) - Desktop, powerful")
    print("  • Cytoscape (https://cytoscape.org) - Biological networks")
    print("  • Neo4j Browser - Interactive graph database UI")
    print("  • D3.js - Web-based custom visualizations")


def main():
    """Run all advanced graph examples."""
    print("\n" + "🔷" * 30)
    print("THREAT RADAR - ADVANCED GRAPH ANALYSIS")
    print("Deep Dive into Graph Queries and Analytics")
    print("🔷" * 30)

    try:
        example_most_vulnerable_packages()
        example_package_usage_patterns()
        example_vulnerability_trends()
        example_fix_prioritization()
        example_custom_networkx_queries()
        example_export_for_visualization()

        print("\n" + "=" * 60)
        print("✓ All advanced examples completed!")
        print("=" * 60)

        print("\n🚀 Next Steps:")
        print("  1. Apply these techniques to your real scans")
        print("  2. Customize queries for your specific needs")
        print("  3. Integrate with your dashboard/reporting tools")
        print("  4. See workflow examples: python 03_graph_workflows.py")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
