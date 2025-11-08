#!/usr/bin/env python3
"""
Example 6: Complete Visualization Workflow

This example demonstrates a complete end-to-end workflow:
1. Scan for vulnerabilities
2. Build graph
3. Create visualizations
4. Analyze attack paths
5. Apply filters
6. Export to multiple formats
"""

from pathlib import Path
from threat_radar.graph import NetworkXClient, GraphBuilder, GraphAnalyzer
from threat_radar.visualization import (
    NetworkGraphVisualizer,
    AttackPathVisualizer,
    NetworkTopologyVisualizer,
    GraphFilter,
    GraphExporter,
)


def main():
    """Complete visualization workflow."""

    # Paths
    examples_dir = Path(__file__).parent
    sample_graph = examples_dir / "sample_graph.graphml"
    output_dir = examples_dir / "output" / "complete_workflow"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Check if sample graph exists
    if not sample_graph.exists():
        print("⚠️  Sample graph not found. Please run the setup script first:")
        print(f"   python {examples_dir / '00_setup.py'}")
        return

    print("🎯 Complete Visualization Workflow\n")
    print("=" * 60)

    # Step 1: Load graph
    print("\n📊 Step 1: Loading vulnerability graph...")
    client = NetworkXClient()
    client.load(str(sample_graph))

    metadata = client.get_metadata()
    print(f"   ✓ Loaded graph with {metadata.node_count} nodes and {metadata.edge_count} edges")

    # Step 2: Create basic overview visualization
    print("\n🎨 Step 2: Creating overview visualization...")
    visualizer = NetworkGraphVisualizer(client)

    fig_overview = visualizer.visualize(
        layout="hierarchical",
        title="Vulnerability Graph - Overview",
        width=1400,
        height=900,
        color_by="node_type",
    )

    overview_output = output_dir / "01_overview.html"
    visualizer.save_html(fig_overview, overview_output)
    print(f"   ✓ Saved overview to: {overview_output}")

    # Step 3: Analyze attack paths
    print("\n🛤️  Step 3: Analyzing attack paths...")
    analyzer = GraphAnalyzer(client)

    entry_points = analyzer.identify_entry_points()
    targets = analyzer.identify_high_value_targets()

    if entry_points and targets:
        attack_paths = analyzer.find_shortest_attack_paths(
            entry_points=entry_points,
            targets=targets,
            max_paths=20,
        )

        print(f"   ✓ Found {len(attack_paths)} attack paths")

        # Visualize attack paths
        if attack_paths:
            path_visualizer = AttackPathVisualizer(client)

            fig_paths = path_visualizer.visualize_attack_paths(
                attack_paths=attack_paths,
                layout="hierarchical",
                title="Attack Paths Analysis",
                max_paths_display=10,
            )

            paths_output = output_dir / "02_attack_paths.html"
            path_visualizer.save_html(fig_paths, paths_output)
            print(f"   ✓ Saved attack paths to: {paths_output}")

            # Export attack path data
            exporter = GraphExporter(client)
            paths_json = output_dir / "attack_paths.json"
            exporter.export_attack_paths(attack_paths, paths_json)
            print(f"   ✓ Exported path data to: {paths_json}")
    else:
        print("   ⚠️  No entry points or targets found (needs environment config)")

    # Step 4: Create topology view
    print("\n🌐 Step 4: Creating network topology view...")
    topo_visualizer = NetworkTopologyVisualizer(client)

    fig_topo = topo_visualizer.visualize_topology(
        layout="hierarchical",
        title="Network Topology",
        color_by="zone",
        show_zones=True,
        show_compliance=True,
    )

    topo_output = output_dir / "03_topology.html"
    topo_visualizer.save_html(fig_topo, topo_output)
    print(f"   ✓ Saved topology to: {topo_output}")

    # Step 5: Create filtered views
    print("\n🔍 Step 5: Creating filtered views...")
    graph_filter = GraphFilter(client)

    # Get filter statistics
    stats = graph_filter.get_filter_statistics()

    # Filter by high severity
    filtered_high = graph_filter.filter_by_severity("high", include_related=True)
    filtered_meta = filtered_high.get_metadata()

    if filtered_meta.node_count > 0:
        visualizer_filtered = NetworkGraphVisualizer(filtered_high)

        fig_filtered = visualizer_filtered.visualize(
            layout="spring",
            title="High Severity Vulnerabilities",
            color_by="severity",
        )

        filtered_output = output_dir / "04_filtered_high_severity.html"
        visualizer_filtered.save_html(fig_filtered, filtered_output)
        print(f"   ✓ Saved filtered view to: {filtered_output}")
        print(f"      Filtered to {filtered_meta.node_count} nodes")

    # Filter by critical severity
    filtered_critical = graph_filter.filter_by_severity("critical", include_related=True)
    filtered_meta = filtered_critical.get_metadata()

    if filtered_meta.node_count > 0:
        visualizer_critical = NetworkGraphVisualizer(filtered_critical)

        fig_critical = visualizer_critical.visualize(
            layout="hierarchical",
            title="Critical Vulnerabilities",
            color_by="severity",
        )

        critical_output = output_dir / "05_filtered_critical.html"
        visualizer_critical.save_html(fig_critical, critical_output)
        print(f"   ✓ Saved critical view to: {critical_output}")
        print(f"      Filtered to {filtered_meta.node_count} nodes")

    # Step 6: Export to multiple formats
    print("\n📦 Step 6: Exporting to multiple formats...")
    exporter = GraphExporter(client)

    # Export overview to multiple formats
    base_path = output_dir / "exports" / "overview"
    base_path.parent.mkdir(exist_ok=True)

    outputs = exporter.export_all_formats(
        fig=fig_overview,
        base_path=base_path,
        formats=['html', 'json', 'cytoscape', 'gexf'],
    )

    print(f"   ✓ Exported to {len(outputs)} formats:")
    for fmt, path in outputs.items():
        print(f"      • {fmt.upper()}: {path.name}")

    # Step 7: Generate summary report
    print("\n📊 Step 7: Generating summary report...")

    summary = {
        "total_nodes": stats["total_nodes"],
        "total_edges": stats["total_edges"],
        "node_types": stats["node_types"],
        "severities": stats["severities"],
        "zones": stats["zones"],
        "criticalities": stats["criticalities"],
        "compliance_scopes": stats["compliance_scopes"],
        "internet_facing": stats["internet_facing"],
    }

    import json
    summary_output = output_dir / "summary.json"
    with open(summary_output, 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"   ✓ Saved summary to: {summary_output}")

    # Print summary
    print("\n📈 Workflow Summary:")
    print(f"   • Total Nodes: {summary['total_nodes']}")
    print(f"   • Total Edges: {summary['total_edges']}")

    if summary['severities']:
        print(f"\n   Vulnerability Severity:")
        for severity, count in sorted(summary['severities'].items(), key=lambda x: -x[1]):
            print(f"      • {severity.upper()}: {count}")

    if summary['zones']:
        print(f"\n   Security Zones:")
        for zone, count in sorted(summary['zones'].items(), key=lambda x: -x[1]):
            print(f"      • {zone.upper()}: {count} assets")

    if summary['compliance_scopes']:
        print(f"\n   Compliance Scope:")
        for comp, count in summary['compliance_scopes'].items():
            if count > 0:
                print(f"      • {comp.upper()}: {count} assets")

    print("\n✅ Complete workflow finished!")
    print(f"\n📁 All outputs saved to: {output_dir}")
    print("\n   Generated files:")
    print("   1. 01_overview.html - Full graph overview")
    if entry_points and targets and attack_paths:
        print("   2. 02_attack_paths.html - Attack path visualization")
        print("      attack_paths.json - Attack path data")
    print("   3. 03_topology.html - Network topology view")
    print("   4. 04_filtered_high_severity.html - High severity issues")
    print("   5. 05_filtered_critical.html - Critical issues")
    print("   6. exports/ - Multi-format exports")
    print("   7. summary.json - Analysis summary")


if __name__ == "__main__":
    main()
