#!/usr/bin/env python3
"""
Example 4: Filtered Visualization

This example demonstrates how to apply filters to focus on
specific aspects of the vulnerability graph.
"""

from pathlib import Path
from threat_radar.graph import NetworkXClient
from threat_radar.visualization import NetworkGraphVisualizer, GraphFilter


def main():
    """Create filtered visualizations."""

    # Paths
    examples_dir = Path(__file__).parent
    sample_graph = examples_dir / "sample_graph.graphml"
    output_dir = examples_dir / "output"
    output_dir.mkdir(exist_ok=True)

    # Check if sample graph exists
    if not sample_graph.exists():
        print("⚠️  Sample graph not found. Please run the setup script first:")
        print(f"   python {examples_dir / '00_setup.py'}")
        return

    print("🔍 Filtered Visualization Examples\n")
    print("=" * 60)

    # Load graph
    print("\n📊 Loading vulnerability graph...")
    client = NetworkXClient()
    client.load(str(sample_graph))

    metadata = client.get_metadata()
    print(f"   ✓ Loaded graph with {metadata.node_count} nodes and {metadata.edge_count} edges")

    # Create filter
    graph_filter = GraphFilter(client)

    # Show filter statistics first
    print("\n📈 Available Filter Values:")
    stats = graph_filter.get_filter_statistics()

    if stats['severities']:
        print(f"\n   Severities:")
        for severity, count in sorted(stats['severities'].items(), key=lambda x: -x[1]):
            print(f"      • {severity}: {count}")

    if stats['zones']:
        print(f"\n   Security Zones:")
        for zone, count in sorted(stats['zones'].items(), key=lambda x: -x[1]):
            print(f"      • {zone}: {count}")

    if stats['criticalities']:
        print(f"\n   Criticality Levels:")
        for crit, count in sorted(stats['criticalities'].items(), key=lambda x: -x[1]):
            print(f"      • {crit}: {count}")

    # Example 1: Filter by severity (HIGH and above)
    print("\n1️⃣  Filtering by severity (HIGH+)...")
    filtered_high = graph_filter.filter_by_severity("high", include_related=True)
    filtered_meta = filtered_high.get_metadata()
    print(f"   ✓ Filtered to {filtered_meta.node_count} nodes ({filtered_meta.edge_count} edges)")

    visualizer = NetworkGraphVisualizer(filtered_high)
    fig1 = visualizer.visualize(
        layout="spring",
        title="High Severity Vulnerabilities",
        color_by="severity",
    )
    output1 = output_dir / "filtered_high_severity.html"
    visualizer.save_html(fig1, output1)
    print(f"   ✓ Saved to: {output1}")

    # Example 2: Filter by severity (CRITICAL only)
    print("\n2️⃣  Filtering by severity (CRITICAL)...")
    filtered_critical = graph_filter.filter_by_severity("critical", include_related=True)
    filtered_meta = filtered_critical.get_metadata()
    print(f"   ✓ Filtered to {filtered_meta.node_count} nodes ({filtered_meta.edge_count} edges)")

    visualizer = NetworkGraphVisualizer(filtered_critical)
    fig2 = visualizer.visualize(
        layout="hierarchical",
        title="Critical Vulnerabilities Only",
        color_by="severity",
    )
    output2 = output_dir / "filtered_critical_only.html"
    visualizer.save_html(fig2, output2)
    print(f"   ✓ Saved to: {output2}")

    # Example 3: Filter by node type (vulnerabilities and packages only)
    print("\n3️⃣  Filtering by node type (vulnerabilities & packages)...")
    from threat_radar.graph.models import NodeType

    filtered_types = graph_filter.filter_by_node_type(
        node_types=[NodeType.VULNERABILITY.value, NodeType.PACKAGE.value],
        include_connections=True,
    )
    filtered_meta = filtered_types.get_metadata()
    print(f"   ✓ Filtered to {filtered_meta.node_count} nodes ({filtered_meta.edge_count} edges)")

    visualizer = NetworkGraphVisualizer(filtered_types)
    fig3 = visualizer.visualize(
        layout="circular",
        title="Vulnerabilities and Packages",
        color_by="node_type",
    )
    output3 = output_dir / "filtered_vuln_packages.html"
    visualizer.save_html(fig3, output3)
    print(f"   ✓ Saved to: {output3}")

    # Example 4: Filter by security zone
    if stats['zones']:
        zone_name = list(stats['zones'].keys())[0]
        print(f"\n4️⃣  Filtering by zone ({zone_name})...")
        filtered_zone = graph_filter.filter_by_zone(
            zones=[zone_name],
            include_related=True,
        )
        filtered_meta = filtered_zone.get_metadata()
        print(f"   ✓ Filtered to {filtered_meta.node_count} nodes ({filtered_meta.edge_count} edges)")

        visualizer = NetworkGraphVisualizer(filtered_zone)
        fig4 = visualizer.visualize(
            layout="spring",
            title=f"Security Zone: {zone_name.upper()}",
            color_by="node_type",
        )
        output4 = output_dir / f"filtered_zone_{zone_name}.html"
        visualizer.save_html(fig4, output4)
        print(f"   ✓ Saved to: {output4}")

    # Example 5: Filter by criticality
    if stats['criticalities']:
        print("\n5️⃣  Filtering by criticality (CRITICAL+)...")
        filtered_crit = graph_filter.filter_by_criticality(
            min_criticality="critical",
            include_related=True,
        )
        filtered_meta = filtered_crit.get_metadata()
        print(f"   ✓ Filtered to {filtered_meta.node_count} nodes ({filtered_meta.edge_count} edges)")

        visualizer = NetworkGraphVisualizer(filtered_crit)
        fig5 = visualizer.visualize(
            layout="hierarchical",
            title="Critical Assets",
            color_by="node_type",
        )
        output5 = output_dir / "filtered_critical_assets.html"
        visualizer.save_html(fig5, output5)
        print(f"   ✓ Saved to: {output5}")

    # Example 6: Filter by compliance scope
    if any(stats['compliance_scopes'].values()):
        compliance_types = [k for k, v in stats['compliance_scopes'].items() if v > 0]
        if compliance_types:
            print(f"\n6️⃣  Filtering by compliance ({', '.join(compliance_types)})...")
            filtered_compliance = graph_filter.filter_by_compliance(
                compliance_types=compliance_types,
                include_related=True,
            )
            filtered_meta = filtered_compliance.get_metadata()
            print(f"   ✓ Filtered to {filtered_meta.node_count} nodes ({filtered_meta.edge_count} edges)")

            visualizer = NetworkGraphVisualizer(filtered_compliance)
            fig6 = visualizer.visualize(
                layout="spring",
                title=f"Compliance Scope: {', '.join(c.upper() for c in compliance_types)}",
                color_by="node_type",
            )
            output6 = output_dir / "filtered_compliance.html"
            visualizer.save_html(fig6, output6)
            print(f"   ✓ Saved to: {output6}")

    # Example 7: Filter internet-facing assets
    print("\n7️⃣  Filtering internet-facing assets...")
    filtered_internet = graph_filter.filter_by_internet_facing(include_related=True)
    filtered_meta = filtered_internet.get_metadata()
    print(f"   ✓ Filtered to {filtered_meta.node_count} nodes ({filtered_meta.edge_count} edges)")

    if filtered_meta.node_count > 0:
        visualizer = NetworkGraphVisualizer(filtered_internet)
        fig7 = visualizer.visualize(
            layout="spring",
            title="Internet-Facing Assets",
            color_by="node_type",
        )
        output7 = output_dir / "filtered_internet_facing.html"
        visualizer.save_html(fig7, output7)
        print(f"   ✓ Saved to: {output7}")

    # Example 8: Search for specific term
    print("\n8️⃣  Searching for 'openssl'...")
    filtered_search = graph_filter.filter_by_search(
        search_term="openssl",
        include_related=True,
    )
    filtered_meta = filtered_search.get_metadata()
    print(f"   ✓ Found {filtered_meta.node_count} nodes ({filtered_meta.edge_count} edges)")

    if filtered_meta.node_count > 0:
        visualizer = NetworkGraphVisualizer(filtered_search)
        fig8 = visualizer.visualize(
            layout="spring",
            title="Search Results: 'openssl'",
            color_by="node_type",
        )
        output8 = output_dir / "filtered_search_openssl.html"
        visualizer.save_html(fig8, output8)
        print(f"   ✓ Saved to: {output8}")

    print("\n✅ Filtered visualizations created successfully!")
    print("\n💡 Tips:")
    print("   • Use filters to focus on specific security concerns")
    print("   • Combine multiple filters for targeted analysis")
    print("   • --no-related flag shows only filtered nodes (no neighbors)")
    print("   • Run 'threat-radar visualize stats' to see available filter values")


if __name__ == "__main__":
    main()
