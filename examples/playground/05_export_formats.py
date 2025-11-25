#!/usr/bin/env python3
"""
Example 5: Multi-Format Export

This example demonstrates how to export visualizations
to various formats for different use cases.
"""

from pathlib import Path
from threat_radar.graph import NetworkXClient
from threat_radar.visualization import NetworkGraphVisualizer, GraphExporter


def main():
    """Export visualizations in multiple formats."""

    # Paths
    examples_dir = Path(__file__).parent
    sample_graph = examples_dir / "sample_graph.graphml"
    output_dir = examples_dir / "output" / "exports"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Check if sample graph exists
    if not sample_graph.exists():
        print("⚠️  Sample graph not found. Please run the setup script first:")
        print(f"   python {examples_dir / '00_setup.py'}")
        return

    print("📦 Multi-Format Export Examples\n")
    print("=" * 60)

    # Load graph
    print("\n📊 Loading vulnerability graph...")
    client = NetworkXClient()
    client.load(str(sample_graph))

    metadata = client.get_metadata()
    print(f"   ✓ Loaded graph with {metadata.node_count} nodes")

    # Create visualizer
    visualizer = NetworkGraphVisualizer(client)

    # Create a visualization
    print("\n🎨 Creating visualization...")
    fig = visualizer.visualize(
        layout="hierarchical",
        title="Vulnerability Graph - Multi-Format Export",
        width=1400,
        height=900,
        color_by="severity",
    )
    print("   ✓ Visualization created")

    # Create exporter
    exporter = GraphExporter(client)

    # Example 1: Export as HTML
    print("\n1️⃣  Exporting as HTML (interactive)...")
    html_output = output_dir / "graph.html"
    exporter.export_html(
        fig=fig,
        output_path=html_output,
        auto_open=False,
        include_plotlyjs='cdn',  # Use CDN for smaller file size
    )
    print(f"   ✓ Saved to: {html_output}")
    print(f"      Size: {html_output.stat().st_size / 1024:.1f} KB")

    # Example 2: Export as PNG (requires kaleido)
    print("\n2️⃣  Exporting as PNG image...")
    try:
        png_output = output_dir / "graph.png"
        exporter.export_image(
            fig=fig,
            output_path=png_output,
            format='png',
            width=1400,
            height=900,
            scale=2.0,  # High resolution
        )
        print(f"   ✓ Saved to: {png_output}")
        print(f"      Size: {png_output.stat().st_size / 1024:.1f} KB")
    except Exception as e:
        print(f"   ⚠️  PNG export failed: {e}")
        print("      Install kaleido: pip install kaleido")

    # Example 3: Export as SVG (vector graphics)
    print("\n3️⃣  Exporting as SVG (vector graphics)...")
    try:
        svg_output = output_dir / "graph.svg"
        exporter.export_image(
            fig=fig,
            output_path=svg_output,
            format='svg',
            width=1400,
            height=900,
        )
        print(f"   ✓ Saved to: {svg_output}")
        print(f"      Size: {svg_output.stat().st_size / 1024:.1f} KB")
    except Exception as e:
        print(f"   ⚠️  SVG export failed: {e}")

    # Example 4: Export as PDF
    print("\n4️⃣  Exporting as PDF (for reports)...")
    try:
        pdf_output = output_dir / "graph.pdf"
        exporter.export_image(
            fig=fig,
            output_path=pdf_output,
            format='pdf',
            width=1400,
            height=900,
        )
        print(f"   ✓ Saved to: {pdf_output}")
        print(f"      Size: {pdf_output.stat().st_size / 1024:.1f} KB")
    except Exception as e:
        print(f"   ⚠️  PDF export failed: {e}")

    # Example 5: Export as JSON (for web apps)
    print("\n5️⃣  Exporting as JSON (with positions)...")
    json_output = output_dir / "graph.json"
    exporter.export_json(
        output_path=json_output,
        include_positions=True,
        layout_algorithm='spring',
    )
    print(f"   ✓ Saved to: {json_output}")
    print(f"      Size: {json_output.stat().st_size / 1024:.1f} KB")

    # Example 6: Export as DOT (Graphviz)
    print("\n6️⃣  Exporting as DOT (Graphviz format)...")
    try:
        dot_output = output_dir / "graph.dot"
        exporter.export_dot(output_path=dot_output)
        print(f"   ✓ Saved to: {dot_output}")
        print(f"      Size: {dot_output.stat().st_size / 1024:.1f} KB")
        print("      Use with: dot -Tpng graph.dot -o graph_dot.png")
    except Exception as e:
        print(f"   ⚠️  DOT export failed: {e}")
        print("      Install pydot: pip install pydot")

    # Example 7: Export as Cytoscape.js format
    print("\n7️⃣  Exporting as Cytoscape.js format...")
    cytoscape_output = output_dir / "graph.cytoscape.json"
    exporter.export_cytoscape(output_path=cytoscape_output)
    print(f"   ✓ Saved to: {cytoscape_output}")
    print(f"      Size: {cytoscape_output.stat().st_size / 1024:.1f} KB")

    # Example 8: Export as GEXF (Gephi format)
    print("\n8️⃣  Exporting as GEXF (Gephi format)...")
    try:
        gexf_output = output_dir / "graph.gexf"
        exporter.export_gexf(output_path=gexf_output)
        print(f"   ✓ Saved to: {gexf_output}")
        print(f"      Size: {gexf_output.stat().st_size / 1024:.1f} KB")
        print("      Open in Gephi for advanced graph analysis")
    except Exception as e:
        print(f"   ⚠️  GEXF export failed: {e}")

    # Example 9: Export visualization data package
    print("\n9️⃣  Exporting complete visualization data package...")
    viz_data_output = output_dir / "visualization_data.json"
    exporter.export_visualization_data(
        output_path=viz_data_output,
        include_metadata=True,
    )
    print(f"   ✓ Saved to: {viz_data_output}")
    print(f"      Size: {viz_data_output.stat().st_size / 1024:.1f} KB")

    # Example 10: Export all formats at once
    print("\n🔟 Exporting all formats at once...")
    base_path = output_dir / "graph_all_formats"
    outputs = exporter.export_all_formats(
        fig=fig,
        base_path=base_path,
        formats=['html', 'json', 'dot', 'cytoscape', 'gexf'],
    )

    print(f"   ✓ Exported {len(outputs)} formats:")
    for fmt, path in outputs.items():
        print(f"      • {fmt.upper()}: {path.name}")

    print("\n✅ All exports completed!")
    print("\n📁 Export Summary:")
    print(f"   Output directory: {output_dir}")
    print("\n   Format Use Cases:")
    print("   • HTML - Interactive web visualization")
    print("   • PNG/SVG/PDF - Static images for reports/presentations")
    print("   • JSON - Custom web applications")
    print("   • DOT - Graphviz rendering")
    print("   • Cytoscape - Cytoscape.js web visualization")
    print("   • GEXF - Gephi advanced graph analysis")


if __name__ == "__main__":
    main()
