#!/usr/bin/env python3
"""
Visualization Example: Security Zones with Attack Path Overlays

This example demonstrates how to create interactive visualizations showing:
1. Security zone topology with color-coded zones
2. Attack paths overlaid on the topology
3. Critical vulnerability filtering
4. Multi-format export for reports

Usage:
    python 05_visualize_zones_and_paths.py
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from threat_radar.graph import NetworkXClient
from threat_radar.graph.models import AttackPath, AttackStep, AttackStepType, ThreatLevel
from threat_radar.visualization import (
    NetworkTopologyVisualizer,
    AttackPathVisualizer,
    GraphFilter,
    GraphExporter,
)


def convert_attack_paths_from_json(attack_data: dict) -> list:
    """Convert JSON attack path data to AttackPath objects."""
    attack_paths = []

    for path_dict in attack_data.get("attack_paths", []):
        # Convert steps
        steps = []
        for step_dict in path_dict.get("steps", []):
            step = AttackStep(
                node_id=step_dict["node_id"],
                step_type=AttackStepType(step_dict["type"]),
                description=step_dict["description"],
                vulnerabilities=step_dict.get("vulnerabilities", []),
                cvss_score=step_dict.get("cvss_score"),
                prerequisites=step_dict.get("prerequisites", []),
                impact=step_dict.get("impact"),
            )
            steps.append(step)

        # Convert path
        path = AttackPath(
            path_id=path_dict["path_id"],
            entry_point=path_dict["entry_point"],
            target=path_dict["target"],
            steps=steps,
            total_cvss=path_dict["total_cvss"],
            threat_level=ThreatLevel(path_dict["threat_level"]),
            exploitability=path_dict.get("exploitability", 0.5),
            impact_score=path_dict.get("impact_score", 0.0),
            path_length=path_dict.get("path_length", len(steps)),
            requires_privileges=path_dict.get("requires_privileges", False),
            description=path_dict.get("description", ""),
        )
        attack_paths.append(path)

    return attack_paths


def main():
    """Generate zone and attack path visualizations."""

    print("=" * 70)
    print("VISUALIZATION: Security Zones with Attack Path Overlays")
    print("=" * 70)

    # Check if graph exists
    graph_file = Path("environment-graph.graphml")
    if not graph_file.exists():
        print(f"❌ Graph file not found: {graph_file}")
        print("   Run: ./run_attack_path_demo.sh first to generate the graph")
        return 1

    # Create output directory
    viz_dir = Path("visualizations")
    viz_dir.mkdir(exist_ok=True)
    print(f"\n✓ Output directory: {viz_dir}/")

    # Load graph
    print(f"\n📊 Loading graph: {graph_file}")
    client = NetworkXClient()
    client.load(str(graph_file))

    node_count = len(client.graph.nodes())
    edge_count = len(client.graph.edges())
    print(f"   • Nodes: {node_count}")
    print(f"   • Edges: {edge_count}")

    # Step 1: Security zones topology view
    print("\n1️⃣  Creating security zones topology visualization...")
    topo_viz = NetworkTopologyVisualizer(client)

    zones_fig = topo_viz.visualize_security_zones(
        title="Security Zones Topology",
        width=1400,
        height=900,
    )

    zones_output = viz_dir / "topology-zones.html"
    topo_viz.save_html(zones_fig, str(zones_output), auto_open=False)
    print(f"   ✓ Saved: {zones_output}")

    # Step 2: Full topology with zone colors
    print("\n2️⃣  Creating full topology view with zone colors...")
    full_fig = topo_viz.visualize_topology(
        layout="hierarchical",
        color_by="zone",
        show_zones=True,
        show_compliance=True,
        title="Complete Infrastructure Topology",
        width=1400,
        height=900,
    )

    full_output = viz_dir / "topology-full.html"
    topo_viz.save_html(full_fig, str(full_output), auto_open=False)
    print(f"   ✓ Saved: {full_output}")

    # Step 3: Attack paths overlay
    if Path("attack-paths.json").exists():
        print("\n3️⃣  Creating attack paths overlay visualization...")
        import json

        with open("attack-paths.json") as f:
            attack_data = json.load(f)

        # Convert JSON to AttackPath objects
        attack_paths = convert_attack_paths_from_json(attack_data)

        if attack_paths:
            path_viz = AttackPathVisualizer(client)

            paths_fig = path_viz.visualize_attack_paths(
                attack_paths=attack_paths,
                layout="hierarchical",
                max_paths_display=10,
                title="Attack Paths Overlay on Topology",
                width=1400,
                height=900,
            )

            paths_output = viz_dir / "attack-paths-overlay.html"
            path_viz.save_html(paths_fig, str(paths_output), auto_open=False)
            print(f"   ✓ Saved: {paths_output}")
            print(f"   • Displayed {min(len(attack_paths), 10)} out of {len(attack_paths)} total paths")
        else:
            print("   ⚠ No attack paths found in attack-paths.json")
    else:
        print("\n3️⃣  Skipping attack paths overlay (attack-paths.json not found)")

    # Step 4: Critical vulnerabilities only (filtered view)
    print("\n4️⃣  Creating filtered view (critical vulnerabilities only)...")
    graph_filter = GraphFilter(client)

    try:
        critical_client = graph_filter.filter_by_severity("critical", include_related=True)
        critical_node_count = len(critical_client.graph.nodes())

        if critical_node_count > 0:
            critical_viz = NetworkTopologyVisualizer(critical_client)

            critical_fig = critical_viz.visualize_topology(
                layout="hierarchical",
                color_by="severity",
                title="Critical Vulnerabilities Only",
                width=1400,
                height=900,
            )

            critical_output = viz_dir / "topology-critical.html"
            critical_viz.save_html(critical_fig, str(critical_output), auto_open=False)
            print(f"   ✓ Saved: {critical_output}")
            print(f"   • Critical nodes: {critical_node_count}")
        else:
            print("   ⚠ No critical vulnerabilities found")
    except Exception as e:
        print(f"   ⚠ Could not create critical view: {e}")

    # Step 5: Export to multiple formats
    print("\n5️⃣  Exporting visualizations to multiple formats...")
    exporter = GraphExporter(client)

    try:
        outputs = exporter.export_all_formats(
            fig=zones_fig,
            base_path=str(viz_dir / "topology-zones"),
            formats=["html", "png"],
        )

        for format_type, path in outputs.items():
            print(f"   ✓ Exported {format_type.upper()}: {path}")
    except Exception as e:
        print(f"   ⚠ Export error: {e}")
        print("   Note: PNG/SVG export requires 'kaleido' package")
        print("         Install: pip install kaleido")

    # Summary
    print("\n" + "=" * 70)
    print("VISUALIZATION COMPLETE")
    print("=" * 70)

    print("\n📁 Generated visualizations:")
    for viz_file in sorted(viz_dir.glob("*.html")):
        size_kb = viz_file.stat().st_size / 1024
        print(f"   • {viz_file.name} ({size_kb:.1f} KB)")

    print("\n🎨 Interactive Features:")
    print("   • Zoom: Scroll or pinch to zoom in/out")
    print("   • Pan: Click and drag to move around")
    print("   • Hover: Mouse over nodes/edges for details")
    print("   • Reset: Double-click to reset view")

    print("\n💡 Tips:")
    print("   • Open HTML files in browser to explore")
    print("   • Use hierarchical layout for clear zone separation")
    print("   • Filter by severity to focus on critical issues")
    print("   • Export PNG for presentations and reports")

    print("\n✅ All visualizations generated successfully!")

    return 0


if __name__ == "__main__":
    sys.exit(main())
