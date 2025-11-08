#!/usr/bin/env python3
"""
Example 3: Network Topology Visualization

This example demonstrates how to visualize network topology
with security zones, compliance scope, and criticality overlays.
"""

from pathlib import Path
from threat_radar.graph import NetworkXClient
from threat_radar.visualization import NetworkTopologyVisualizer


def main():
    """Visualize network topology with security context."""

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

    print("🌐 Network Topology Visualization Examples\n")
    print("=" * 60)

    # Load graph
    print("\n📊 Loading vulnerability graph...")
    client = NetworkXClient()
    client.load(str(sample_graph))

    metadata = client.get_metadata()
    print(f"   ✓ Loaded graph with {metadata.node_count} nodes")

    # Create visualizer
    visualizer = NetworkTopologyVisualizer(client)

    # Example 1: Full topology view with zone coloring
    print("\n1️⃣  Creating full topology view (colored by zone)...")
    fig1 = visualizer.visualize_topology(
        layout="hierarchical",
        title="Network Topology - Security Zones",
        width=1400,
        height=900,
        color_by="zone",
        show_zones=True,
        show_compliance=True,
        show_internet_facing=True,
    )
    output1 = output_dir / "topology_zones.html"
    visualizer.save_html(fig1, output1)
    print(f"   ✓ Saved to: {output1}")

    # Example 2: Topology colored by criticality
    print("\n2️⃣  Creating topology view (colored by criticality)...")
    fig2 = visualizer.visualize_topology(
        layout="hierarchical",
        title="Network Topology - Asset Criticality",
        width=1400,
        height=900,
        color_by="criticality",
        show_zones=True,
    )
    output2 = output_dir / "topology_criticality.html"
    visualizer.save_html(fig2, output2)
    print(f"   ✓ Saved to: {output2}")

    # Example 3: Security zones focused view
    print("\n3️⃣  Creating security zones view...")
    fig3 = visualizer.visualize_security_zones(
        title="Security Zone Map",
        width=1400,
        height=900,
    )
    output3 = output_dir / "topology_zones_focused.html"
    visualizer.save_html(fig3, output3)
    print(f"   ✓ Saved to: {output3}")

    # Example 4: Compliance scope - All
    print("\n4️⃣  Creating compliance scope view (all types)...")
    fig4 = visualizer.visualize_compliance_scope(
        compliance_type=None,  # Show all compliance types
        title="Compliance Scope - All Types",
        width=1400,
        height=900,
    )
    output4 = output_dir / "topology_compliance_all.html"
    visualizer.save_html(fig4, output4)
    print(f"   ✓ Saved to: {output4}")

    # Example 5: PCI-DSS scope only
    print("\n5️⃣  Creating PCI-DSS compliance view...")
    fig5 = visualizer.visualize_compliance_scope(
        compliance_type="pci",
        title="PCI-DSS Compliance Scope",
        width=1400,
        height=900,
    )
    output5 = output_dir / "topology_compliance_pci.html"
    visualizer.save_html(fig5, output5)
    print(f"   ✓ Saved to: {output5}")

    # Example 6: HIPAA scope
    print("\n6️⃣  Creating HIPAA compliance view...")
    fig6 = visualizer.visualize_compliance_scope(
        compliance_type="hipaa",
        title="HIPAA Compliance Scope",
        width=1400,
        height=900,
    )
    output6 = output_dir / "topology_compliance_hipaa.html"
    visualizer.save_html(fig6, output6)
    print(f"   ✓ Saved to: {output6}")

    # Show zone statistics
    print("\n📊 Topology Statistics:")
    zones = visualizer._group_nodes_by_zone()
    print(f"   Security Zones ({len(zones)} total):")
    for zone_name, zone_nodes in sorted(zones.items(), key=lambda x: -len(x[1])):
        print(f"      • {zone_name.upper()}: {len(zone_nodes)} asset(s)")

    # Show compliance statistics
    compliance_nodes = visualizer._find_compliance_nodes()
    print(f"\n   Compliance Scope:")
    for comp_type, nodes in sorted(compliance_nodes.items()):
        if nodes:
            marker = visualizer.COMPLIANCE_MARKERS.get(comp_type, "•")
            print(f"      {marker} {comp_type.upper()}: {len(nodes)} asset(s)")

    print("\n✅ Topology visualizations created successfully!")
    print("\n💡 Tips:")
    print("   • Color coding shows security context")
    print("   • Zone boundaries help identify network segmentation")
    print("   • Compliance markers show regulatory scope")
    print("   • Hover over nodes for detailed security information")


if __name__ == "__main__":
    main()
