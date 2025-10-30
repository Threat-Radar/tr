"""Basic graph database usage examples.

This example demonstrates how to:
1. Build graphs from CVE scan results
2. Query graphs for basic information
3. Find vulnerable containers and packages
4. Save and load graphs

Prerequisites:
- Run CVE scan first: threat-radar cve scan-image alpine:3.18 -o scan.json
"""

import json
from pathlib import Path
from threat_radar.graph import NetworkXClient, GraphBuilder, GraphAnalyzer
from threat_radar.core.grype_integration import GrypeScanResult, GrypeVulnerability
from threat_radar.utils.graph_storage import GraphStorageManager


def example_build_graph_from_scan():
    """Example 1: Build a graph from CVE scan results."""
    print("=" * 60)
    print("Example 1: Build Graph from CVE Scan Results")
    print("=" * 60)

    # Note: This example uses mock data
    # In real usage, load from: threat-radar cve scan-image alpine:3.18 -o scan.json

    # Create sample vulnerabilities
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
            severity="high",
            package_name="curl",
            package_version="7.79.0",
            package_type="apk",
            fixed_in_version="7.79.1",
            description="High severity vulnerability in curl",
            cvss_score=7.5,
        ),
    ]

    scan_result = GrypeScanResult(
        target="alpine:3.18",
        vulnerabilities=vulnerabilities,
    )

    # Create graph client and builder
    client = NetworkXClient()
    builder = GraphBuilder(client)

    # Build graph
    print("\nBuilding graph...")
    builder.build_from_scan(scan_result)

    # Get metadata
    metadata = client.get_metadata()
    print(f"✓ Graph built successfully!")
    print(f"  • Total nodes: {metadata.node_count}")
    print(f"  • Total edges: {metadata.edge_count}")
    print(f"\n  Node breakdown:")
    for node_type, count in metadata.node_type_counts.items():
        print(f"    - {node_type}: {count}")

    return client


def example_query_graph_metadata(client: NetworkXClient):
    """Example 2: Query graph metadata and statistics."""
    print("\n" + "=" * 60)
    print("Example 2: Query Graph Metadata")
    print("=" * 60)

    metadata = client.get_metadata()

    print(f"\nGraph Statistics:")
    print(f"  Total nodes: {metadata.node_count}")
    print(f"  Total edges: {metadata.edge_count}")

    print(f"\n  Nodes by type:")
    for node_type, count in sorted(metadata.node_type_counts.items()):
        print(f"    {node_type:20s} : {count:3d}")

    print(f"\n  Edges by type:")
    for edge_type, count in sorted(metadata.edge_type_counts.items()):
        print(f"    {edge_type:20s} : {count:3d}")


def example_find_vulnerable_packages(client: NetworkXClient):
    """Example 3: Find packages with vulnerabilities."""
    print("\n" + "=" * 60)
    print("Example 3: Find Vulnerable Packages")
    print("=" * 60)

    # Get packages with vulnerabilities
    package_vulns = client.find_packages_with_vulnerabilities()

    print(f"\nFound {len(package_vulns)} vulnerable packages:")
    for package_id, vuln_nodes in package_vulns.items():
        print(f"\n  {package_id}")
        print(f"    Vulnerabilities: {len(vuln_nodes)}")
        for vuln_node in vuln_nodes[:3]:  # Show first 3
            vuln = client.get_node(vuln_node)
            if vuln:
                severity = vuln.properties.get('severity', 'unknown')
                cve_id = vuln.properties.get('cve_id', 'unknown')
                print(f"      • {cve_id} ({severity.upper()})")


def example_blast_radius_analysis(client: NetworkXClient):
    """Example 4: Calculate vulnerability blast radius."""
    print("\n" + "=" * 60)
    print("Example 4: Vulnerability Blast Radius")
    print("=" * 60)

    analyzer = GraphAnalyzer(client)

    # Find blast radius for a CVE
    cve_id = "CVE-2023-0001"
    print(f"\nCalculating blast radius for {cve_id}...")

    blast_radius = analyzer.blast_radius(cve_id)

    print(f"\nImpact Analysis:")
    print(f"  Affected packages: {len(blast_radius['packages'])}")
    print(f"  Affected containers: {len(blast_radius['containers'])}")
    print(f"  Affected services: {len(blast_radius['services'])}")
    print(f"  Affected hosts: {len(blast_radius['hosts'])}")

    if blast_radius['packages']:
        print(f"\n  Vulnerable packages:")
        for pkg in blast_radius['packages'][:5]:
            print(f"    • {pkg}")

    if blast_radius['containers']:
        print(f"\n  Impacted containers:")
        for container in blast_radius['containers']:
            print(f"    • {container}")


def example_find_fixes(client: NetworkXClient):
    """Example 5: Find vulnerabilities with available fixes."""
    print("\n" + "=" * 60)
    print("Example 5: Find Available Fixes")
    print("=" * 60)

    analyzer = GraphAnalyzer(client)

    # Find fix candidates
    print("\nSearching for vulnerabilities with fixes...")
    fix_candidates = analyzer.find_fix_candidates()

    print(f"\nFound {len(fix_candidates)} vulnerabilities with fixes:")
    for fix in fix_candidates:
        print(f"\n  {fix['cve_id']} ({fix['severity'].upper()})")
        print(f"    CVSS Score: {fix['cvss_score']}")
        print(f"    Affected packages: {len(fix['affected_packages'])}")
        print(f"    Fix version: {fix['fix_version']}")
        print(f"    Upgrade: {fix['affected_packages'][0]} → {fix['fix_package']}")


def example_save_and_load_graph(client: NetworkXClient):
    """Example 6: Save and load graphs."""
    print("\n" + "=" * 60)
    print("Example 6: Save and Load Graphs")
    print("=" * 60)

    # Save graph
    print("\nSaving graph to file...")
    temp_path = "/tmp/example-graph.graphml"
    client.save(temp_path)
    print(f"✓ Graph saved to: {temp_path}")

    # Load graph
    print("\nLoading graph from file...")
    new_client = NetworkXClient()
    new_client.load(temp_path)

    metadata = new_client.get_metadata()
    print(f"✓ Graph loaded successfully!")
    print(f"  • Nodes: {metadata.node_count}")
    print(f"  • Edges: {metadata.edge_count}")

    # Use storage manager for better organization
    print("\n--- Using Storage Manager ---")
    storage = GraphStorageManager()

    saved_path = storage.save_graph(
        client,
        "example-alpine",
        metadata={
            "source": "example",
            "target": "alpine:3.18",
            "description": "Example graph for demonstration"
        }
    )
    print(f"✓ Saved to storage: {saved_path.name}")

    # List stored graphs
    graphs = storage.list_graphs()
    print(f"\nStored graphs: {len(graphs)}")
    for graph_path in graphs[:3]:  # Show first 3
        print(f"  • {graph_path.name}")


def example_vulnerability_statistics(client: NetworkXClient):
    """Example 7: Get vulnerability statistics."""
    print("\n" + "=" * 60)
    print("Example 7: Vulnerability Statistics")
    print("=" * 60)

    analyzer = GraphAnalyzer(client)
    stats = analyzer.vulnerability_statistics()

    print(f"\nVulnerability Statistics:")
    print(f"  Total vulnerabilities: {stats['total_vulnerabilities']}")
    print(f"  Average CVSS score: {stats['avg_cvss_score']:.2f}")

    print(f"\n  By Severity:")
    for severity in ['critical', 'high', 'medium', 'low']:
        count = stats['by_severity'].get(severity, 0)
        if count > 0:
            bar = "█" * (count * 2)
            print(f"    {severity:10s} : {count:3d} {bar}")

    print(f"\n  Fix Availability:")
    print(f"    With fixes: {stats['with_fixes']}")
    print(f"    Without fixes: {stats['without_fixes']}")
    fix_rate = (stats['with_fixes'] / stats['total_vulnerabilities'] * 100) if stats['total_vulnerabilities'] > 0 else 0
    print(f"    Fix rate: {fix_rate:.1f}%")


def main():
    """Run all basic graph examples."""
    print("\n" + "🔷" * 30)
    print("THREAT RADAR - GRAPH DATABASE EXAMPLES")
    print("Basic Usage and Queries")
    print("🔷" * 30)

    try:
        # Build graph
        client = example_build_graph_from_scan()

        # Query examples
        example_query_graph_metadata(client)
        example_find_vulnerable_packages(client)
        example_blast_radius_analysis(client)
        example_find_fixes(client)
        example_vulnerability_statistics(client)
        example_save_and_load_graph(client)

        print("\n" + "=" * 60)
        print("✓ All examples completed successfully!")
        print("=" * 60)

        print("\n💡 Next Steps:")
        print("  1. Try with real scan data:")
        print("     threat-radar cve scan-image alpine:3.18 -o scan.json")
        print("     threat-radar graph build scan.json --auto-save")
        print("\n  2. Query your graphs:")
        print("     threat-radar graph query graph.graphml --stats")
        print("     threat-radar graph query graph.graphml --cve CVE-2023-XXXX")
        print("\n  3. See advanced examples:")
        print("     python 02_advanced_graph_analysis.py")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
