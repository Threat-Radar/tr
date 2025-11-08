#!/usr/bin/env python3
"""
Example 2: Attack Path Visualization

This example demonstrates how to visualize attack paths with
highlighted routes and threat level indicators.
"""

import json
from pathlib import Path
from threat_radar.graph import NetworkXClient, GraphAnalyzer
from threat_radar.visualization import AttackPathVisualizer


def main():
    """Visualize attack paths with threat highlighting."""

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

    print("🎯 Attack Path Visualization Examples\n")
    print("=" * 60)

    # Load graph
    print("\n📊 Loading vulnerability graph...")
    client = NetworkXClient()
    client.load(str(sample_graph))

    metadata = client.get_metadata()
    print(f"   ✓ Loaded graph with {metadata.node_count} nodes")

    # Create analyzer
    print("\n🔍 Analyzing attack paths...")
    analyzer = GraphAnalyzer(client)

    # Identify entry points and targets
    entry_points = analyzer.identify_entry_points()
    targets = analyzer.identify_high_value_targets()

    print(f"   ✓ Found {len(entry_points)} entry points")
    print(f"   ✓ Found {len(targets)} high-value targets")

    if not entry_points or not targets:
        print("\n⚠️  No entry points or targets found in this graph.")
        print("   Try using a graph with environment configuration.")
        return

    # Find attack paths
    print("\n🛤️  Finding attack paths...")
    attack_paths = analyzer.find_shortest_attack_paths(
        entry_points=entry_points,
        targets=targets,
        max_length=10,
        max_paths=20,
    )

    if not attack_paths:
        print("   ⚠️  No attack paths found")
        return

    print(f"   ✓ Found {len(attack_paths)} attack paths")

    # Show threat distribution
    threat_counts = {}
    for path in attack_paths:
        level = path.threat_level.value
        threat_counts[level] = threat_counts.get(level, 0) + 1

    print(f"\n   Threat Level Distribution:")
    for level in ["critical", "high", "medium", "low"]:
        count = threat_counts.get(level, 0)
        if count > 0:
            print(f"      • {level.upper()}: {count} path(s)")

    # Create visualizer
    visualizer = AttackPathVisualizer(client)

    # Example 1: Visualize all attack paths
    print("\n1️⃣  Creating multi-path visualization...")
    fig1 = visualizer.visualize_attack_paths(
        attack_paths=attack_paths,
        layout="hierarchical",
        title="Attack Paths - All Routes",
        width=1400,
        height=900,
        max_paths_display=10,
    )
    output1 = output_dir / "attack_paths_all.html"
    visualizer.save_html(fig1, output1)
    print(f"   ✓ Saved to: {output1}")

    # Example 2: Visualize only critical paths
    critical_paths = [p for p in attack_paths if p.threat_level.value == "critical"]
    if critical_paths:
        print("\n2️⃣  Creating critical paths visualization...")
        fig2 = visualizer.visualize_attack_paths(
            attack_paths=critical_paths,
            layout="hierarchical",
            title="Attack Paths - Critical Threats Only",
            width=1400,
            height=900,
        )
        output2 = output_dir / "attack_paths_critical.html"
        visualizer.save_html(fig2, output2)
        print(f"   ✓ Saved to: {output2}")
        print(f"      Found {len(critical_paths)} critical path(s)")

    # Example 3: Single path detailed view
    if attack_paths:
        print("\n3️⃣  Creating detailed single path view...")
        most_critical = max(attack_paths, key=lambda p: p.total_cvss)

        fig3 = visualizer.visualize_single_path(
            attack_path=most_critical,
            layout="hierarchical",
            title=f"Attack Path Detail - {most_critical.path_id}",
            width=1200,
            height=800,
            show_step_details=True,
        )
        output3 = output_dir / "attack_path_detail.html"
        visualizer.save_html(fig3, output3)
        print(f"   ✓ Saved to: {output3}")
        print(f"      Path: {most_critical.entry_point} → {most_critical.target}")
        print(f"      Threat Level: {most_critical.threat_level.value.upper()}")
        print(f"      Total CVSS: {most_critical.total_cvss:.1f}")
        print(f"      Steps: {most_critical.path_length}")
        print(f"      Exploitability: {most_critical.exploitability:.0%}")

    # Export attack path data
    print("\n📦 Exporting attack path data...")
    from threat_radar.visualization import GraphExporter

    exporter = GraphExporter(client)
    output_json = output_dir / "attack_paths.json"
    exporter.export_attack_paths(attack_paths, output_json)
    print(f"   ✓ Saved attack path data to: {output_json}")

    print("\n✅ Attack path visualizations created successfully!")
    print("\n💡 Tips:")
    print("   • Hover over nodes to see attack step details")
    print("   • Red paths are critical threats")
    print("   • Orange paths are high severity")
    print("   • Yellow paths are medium severity")
    print("   • Blue paths are low severity")


if __name__ == "__main__":
    main()
