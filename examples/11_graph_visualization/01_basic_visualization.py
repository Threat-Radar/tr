#!/usr/bin/env python3
"""
Example 1: Basic Graph Visualization

This example demonstrates how to create interactive visualizations
of vulnerability graphs using different layouts and color schemes.
"""

import json
from pathlib import Path
from threat_radar.graph import NetworkXClient
from threat_radar.visualization import NetworkGraphVisualizer


def main():
    """Create basic graph visualizations."""

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

    print("🎨 Basic Graph Visualization Examples\n")
    print("=" * 60)

    # Load graph
    print("\n📊 Loading vulnerability graph...")
    client = NetworkXClient()
    client.load(str(sample_graph))

    metadata = client.get_metadata()
    print(f"   ✓ Loaded graph with {metadata.node_count} nodes and {metadata.edge_count} edges")

    # Create visualizer
    visualizer = NetworkGraphVisualizer(client)

    # Example 1: Spring layout with node type coloring
    print("\n1️⃣  Creating spring layout visualization...")
    fig1 = visualizer.visualize(
        layout="spring",
        title="Vulnerability Graph - Spring Layout",
        width=1200,
        height=800,
        color_by="node_type",
        show_labels=True,
    )
    output1 = output_dir / "01_spring_layout.html"
    visualizer.save_html(fig1, output1)
    print(f"   ✓ Saved to: {output1}")

    # Example 2: Hierarchical layout (great for vulnerability chains)
    print("\n2️⃣  Creating hierarchical layout visualization...")
    fig2 = visualizer.visualize(
        layout="hierarchical",
        title="Vulnerability Graph - Hierarchical Layout",
        width=1200,
        height=800,
        color_by="node_type",
        show_labels=True,
    )
    output2 = output_dir / "02_hierarchical_layout.html"
    visualizer.save_html(fig2, output2)
    print(f"   ✓ Saved to: {output2}")

    # Example 3: Circular layout
    print("\n3️⃣  Creating circular layout visualization...")
    fig3 = visualizer.visualize(
        layout="circular",
        title="Vulnerability Graph - Circular Layout",
        width=1200,
        height=800,
        color_by="node_type",
        show_labels=True,
    )
    output3 = output_dir / "03_circular_layout.html"
    visualizer.save_html(fig3, output3)
    print(f"   ✓ Saved to: {output3}")

    # Example 4: Severity-based coloring
    print("\n4️⃣  Creating severity-colored visualization...")
    fig4 = visualizer.visualize(
        layout="spring",
        title="Vulnerability Graph - Colored by Severity",
        width=1200,
        height=800,
        color_by="severity",
        show_labels=True,
    )
    output4 = output_dir / "04_severity_colored.html"
    visualizer.save_html(fig4, output4)
    print(f"   ✓ Saved to: {output4}")

    # Example 5: Large visualization without labels
    print("\n5️⃣  Creating large visualization without labels...")
    fig5 = visualizer.visualize(
        layout="spring",
        title="Vulnerability Graph - Clean View",
        width=1600,
        height=1000,
        color_by="node_type",
        show_labels=False,
        node_size=12,
    )
    output5 = output_dir / "05_clean_view.html"
    visualizer.save_html(fig5, output5)
    print(f"   ✓ Saved to: {output5}")

    # Example 6: 3D visualization
    print("\n6️⃣  Creating 3D visualization...")
    fig6 = visualizer.visualize(
        layout="spring",
        title="Vulnerability Graph - 3D View",
        width=1200,
        height=800,
        color_by="node_type",
        show_labels=False,
        three_d=True,
    )
    output6 = output_dir / "06_3d_view.html"
    visualizer.save_html(fig6, output6)
    print(f"   ✓ Saved to: {output6}")

    # Show statistics
    print("\n📈 Graph Statistics:")
    stats = visualizer.get_statistics()
    print(f"   • Total nodes: {stats['total_nodes']}")
    print(f"   • Total edges: {stats['total_edges']}")
    print(f"   • Node types: {stats['node_types']}")
    print(f"   • Edge types: {stats['edge_types']}")

    print("\n✅ All visualizations created successfully!")
    print(f"\n💡 Open the HTML files in {output_dir} to explore the interactive visualizations.")
    print("   You can zoom, pan, and hover over nodes for detailed information.")


if __name__ == "__main__":
    main()
