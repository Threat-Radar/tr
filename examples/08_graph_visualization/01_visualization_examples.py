"""
Graph Visualization Examples

This script demonstrates various ways to visualize Threat Radar graphs:
1. Simple matplotlib visualization
2. Advanced layouts and styling
3. Export for external tools (Gephi, yEd, Cytoscape)
4. Interactive HTML visualization
"""

import json
from pathlib import Path
from threat_radar.graph import NetworkXClient, GraphBuilder, GraphAnalyzer
from threat_radar.core.grype_integration import GrypeScanResult, GrypeVulnerability
from threat_radar.environment import (
    Environment,
    EnvironmentMetadata,
    Asset,
    Dependency,
    BusinessContext,
    EnvironmentType,
    AssetType,
    Criticality,
    DependencyType,
    EnvironmentGraphBuilder,
)

# Check if visualization libraries are available
try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("⚠️  matplotlib not installed. Install with: pip install matplotlib")

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False


def create_sample_vulnerability_graph():
    """Create a sample graph with vulnerabilities for visualization."""
    client = NetworkXClient()
    builder = GraphBuilder(client)

    # Create mock scan result
    vulnerabilities = [
        GrypeVulnerability(
            id="CVE-2023-0001",
            severity="critical",
            package_name="openssl",
            package_version="1.1.1",
            package_type="apk",
            fixed_in_version="1.1.1k",
            description="Critical vulnerability",
            cvss_score=9.8,
        ),
        GrypeVulnerability(
            id="CVE-2023-0002",
            severity="high",
            package_name="curl",
            package_version="7.79.0",
            package_type="apk",
            fixed_in_version="7.79.1",
            description="High severity vulnerability",
            cvss_score=7.5,
        ),
    ]

    scan_result = GrypeScanResult(
        target="alpine:3.18",
        vulnerabilities=vulnerabilities,
    )

    builder.build_from_scan_result(scan_result)
    return client


def create_sample_environment_graph():
    """Create a sample environment graph for visualization."""
    env = Environment(
        environment=EnvironmentMetadata(
            name="sample-env",
            type=EnvironmentType.PRODUCTION,
            owner="ops@company.com",
        ),
        assets=[
            Asset(
                id="web",
                name="Web Server",
                type=AssetType.CONTAINER,
                host="10.0.1.10",
                business_context=BusinessContext(
                    criticality=Criticality.HIGH,
                    criticality_score=75,
                ),
            ),
            Asset(
                id="api",
                name="API Server",
                type=AssetType.SERVICE,
                host="10.0.2.10",
                business_context=BusinessContext(
                    criticality=Criticality.HIGH,
                    criticality_score=80,
                ),
            ),
            Asset(
                id="db",
                name="Database",
                type=AssetType.DATABASE,
                host="10.0.3.10",
                business_context=BusinessContext(
                    criticality=Criticality.CRITICAL,
                    criticality_score=95,
                ),
            ),
        ],
        dependencies=[
            Dependency(source="web", target="api", type=DependencyType.DEPENDS_ON),
            Dependency(source="api", target="db", type=DependencyType.DEPENDS_ON),
        ],
    )

    client = NetworkXClient()
    builder = EnvironmentGraphBuilder(client)
    builder.build_from_environment(env)
    return client, env


def example_1_simple_visualization():
    """Example 1: Simple graph visualization with matplotlib."""
    print("\n" + "=" * 70)
    print("Example 1: Simple Graph Visualization")
    print("=" * 70)

    if not MATPLOTLIB_AVAILABLE:
        print("\n❌ Skipping: matplotlib not installed")
        return

    # Create sample graph
    client = create_sample_vulnerability_graph()

    print("\n✓ Created sample vulnerability graph")
    metadata = client.get_metadata()
    print(f"  Nodes: {metadata.node_count}")
    print(f"  Edges: {metadata.edge_count}")

    # Visualize
    print("\n✓ Generating visualization...")

    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(client.graph, k=2, iterations=50)

    # Draw nodes
    nx.draw_networkx_nodes(
        client.graph,
        pos,
        node_color='lightblue',
        node_size=3000,
        alpha=0.9
    )

    # Draw edges
    nx.draw_networkx_edges(
        client.graph,
        pos,
        edge_color='gray',
        arrows=True,
        arrowsize=20,
        width=2,
        alpha=0.6
    )

    # Draw labels
    nx.draw_networkx_labels(
        client.graph,
        pos,
        font_size=8,
        font_weight='bold'
    )

    plt.title("Vulnerability Graph - Simple Visualization", fontsize=16, fontweight='bold')
    plt.axis('off')
    plt.tight_layout()

    output_file = "/tmp/graph_simple.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved to: {output_file}")
    plt.close()


def example_2_styled_visualization():
    """Example 2: Styled visualization with node colors by type."""
    print("\n" + "=" * 70)
    print("Example 2: Styled Visualization (Colored by Node Type)")
    print("=" * 70)

    if not MATPLOTLIB_AVAILABLE:
        print("\n❌ Skipping: matplotlib not installed")
        return

    # Create sample graph
    client, env = create_sample_environment_graph()

    print("\n✓ Created environment graph")

    # Define colors for node types
    node_colors = {
        'container': '#3498db',  # Blue
        'service': '#2ecc71',    # Green
        'database': '#e74c3c',   # Red
    }

    # Get node colors based on type
    colors = []
    for node_id in client.graph.nodes():
        node_data = client.graph.nodes[node_id]
        node_type = node_data.get('node_type', 'unknown')
        colors.append(node_colors.get(node_type, '#95a5a6'))

    # Visualize
    print("\n✓ Generating styled visualization...")

    plt.figure(figsize=(14, 10))
    pos = nx.spring_layout(client.graph, k=3, iterations=50)

    # Draw nodes with colors
    nx.draw_networkx_nodes(
        client.graph,
        pos,
        node_color=colors,
        node_size=4000,
        alpha=0.9,
        edgecolors='white',
        linewidths=3
    )

    # Draw edges with custom styling
    nx.draw_networkx_edges(
        client.graph,
        pos,
        edge_color='#34495e',
        arrows=True,
        arrowsize=25,
        width=3,
        alpha=0.7,
        arrowstyle='->'
    )

    # Draw labels
    nx.draw_networkx_labels(
        client.graph,
        pos,
        font_size=10,
        font_weight='bold',
        font_color='white'
    )

    # Create legend
    legend_elements = [
        mpatches.Patch(color=node_colors['container'], label='Container'),
        mpatches.Patch(color=node_colors['service'], label='Service'),
        mpatches.Patch(color=node_colors['database'], label='Database'),
    ]
    plt.legend(handles=legend_elements, loc='upper right', fontsize=12)

    plt.title("Environment Graph - Styled by Asset Type", fontsize=16, fontweight='bold')
    plt.axis('off')
    plt.tight_layout()

    output_file = "/tmp/graph_styled.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved to: {output_file}")
    plt.close()


def example_3_criticality_visualization():
    """Example 3: Visualize with node sizes based on criticality."""
    print("\n" + "=" * 70)
    print("Example 3: Criticality-Based Visualization")
    print("=" * 70)

    if not MATPLOTLIB_AVAILABLE:
        print("\n❌ Skipping: matplotlib not installed")
        return

    # Create sample graph
    client, env = create_sample_environment_graph()

    print("\n✓ Created environment graph with business context")

    # Get node sizes based on criticality
    node_sizes = []
    node_colors = []

    for node_id in client.graph.nodes():
        node_data = client.graph.nodes[node_id]
        criticality_score = node_data.get('criticality_score', 50)

        # Size based on criticality (500-5000)
        size = 500 + (criticality_score * 45)
        node_sizes.append(size)

        # Color based on criticality
        if criticality_score >= 80:
            node_colors.append('#e74c3c')  # Red - Critical
        elif criticality_score >= 60:
            node_colors.append('#f39c12')  # Orange - High
        elif criticality_score >= 30:
            node_colors.append('#f1c40f')  # Yellow - Medium
        else:
            node_colors.append('#2ecc71')  # Green - Low

    # Visualize
    print("\n✓ Generating criticality visualization...")

    plt.figure(figsize=(14, 10))
    pos = nx.spring_layout(client.graph, k=3, iterations=50)

    # Draw nodes
    nx.draw_networkx_nodes(
        client.graph,
        pos,
        node_color=node_colors,
        node_size=node_sizes,
        alpha=0.8,
        edgecolors='white',
        linewidths=3
    )

    # Draw edges
    nx.draw_networkx_edges(
        client.graph,
        pos,
        edge_color='#7f8c8d',
        arrows=True,
        arrowsize=20,
        width=2,
        alpha=0.5
    )

    # Draw labels
    labels = {}
    for node_id in client.graph.nodes():
        node_data = client.graph.nodes[node_id]
        name = node_data.get('name', node_id)
        score = node_data.get('criticality_score', 0)
        labels[node_id] = f"{name}\n({score})"

    nx.draw_networkx_labels(
        client.graph,
        pos,
        labels,
        font_size=9,
        font_weight='bold',
        font_color='white'
    )

    # Create legend
    legend_elements = [
        mpatches.Patch(color='#e74c3c', label='Critical (≥80)'),
        mpatches.Patch(color='#f39c12', label='High (60-79)'),
        mpatches.Patch(color='#f1c40f', label='Medium (30-59)'),
        mpatches.Patch(color='#2ecc71', label='Low (<30)'),
    ]
    plt.legend(handles=legend_elements, loc='upper right', fontsize=12)

    plt.title("Environment Graph - Sized by Criticality", fontsize=16, fontweight='bold')
    plt.axis('off')
    plt.tight_layout()

    output_file = "/tmp/graph_criticality.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved to: {output_file}")
    print(f"\n  Node sizes represent criticality scores")
    print(f"  Colors indicate risk levels")
    plt.close()


def example_4_export_formats():
    """Example 4: Export to various formats for external tools."""
    print("\n" + "=" * 70)
    print("Example 4: Export for External Visualization Tools")
    print("=" * 70)

    # Create sample graph
    client, env = create_sample_environment_graph()

    print("\n✓ Created environment graph")

    # Export to GraphML (for Gephi, yEd, Cytoscape)
    graphml_file = "/tmp/graph.graphml"
    client.save(graphml_file)
    print(f"\n✓ Exported to GraphML: {graphml_file}")
    print(f"  Can be opened in:")
    print(f"    - Gephi (https://gephi.org)")
    print(f"    - yEd (https://www.yworks.com/products/yed)")
    print(f"    - Cytoscape (https://cytoscape.org)")

    # Export to JSON (for D3.js, custom tools)
    json_data = client.export_to_dict()
    json_file = "/tmp/graph.json"
    with open(json_file, 'w') as f:
        json.dump(json_data, f, indent=2)
    print(f"\n✓ Exported to JSON: {json_file}")
    print(f"  Can be used with:")
    print(f"    - D3.js force-directed graphs")
    print(f"    - Custom web visualizations")
    print(f"    - Graph analysis tools")

    # Export to DOT (for Graphviz)
    try:
        from networkx.drawing.nx_agraph import write_dot
        dot_file = "/tmp/graph.dot"
        write_dot(client.graph, dot_file)
        print(f"\n✓ Exported to DOT: {dot_file}")
        print(f"  Can be rendered with Graphviz:")
        print(f"    dot -Tpng {dot_file} -o graph.png")
    except ImportError:
        print(f"\n⚠️  Graphviz not installed (optional)")
        print(f"  Install with: pip install pygraphviz")


def example_5_interactive_html():
    """Example 5: Generate interactive HTML visualization."""
    print("\n" + "=" * 70)
    print("Example 5: Interactive HTML Visualization")
    print("=" * 70)

    # Create sample graph
    client, env = create_sample_environment_graph()

    print("\n✓ Created environment graph")

    # Export to JSON for web visualization
    json_data = client.export_to_dict()

    # Create HTML with D3.js visualization
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Threat Radar - Graph Visualization</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{
            margin: 0;
            font-family: Arial, sans-serif;
            background: #1e1e1e;
            color: #fff;
        }}
        #graph {{
            width: 100vw;
            height: 100vh;
        }}
        .node {{
            stroke: #fff;
            stroke-width: 2px;
            cursor: pointer;
        }}
        .node:hover {{
            stroke-width: 4px;
        }}
        .link {{
            stroke: #999;
            stroke-opacity: 0.6;
        }}
        .label {{
            font-size: 12px;
            fill: #fff;
            text-anchor: middle;
            pointer-events: none;
        }}
        #info {{
            position: absolute;
            top: 20px;
            left: 20px;
            background: rgba(0,0,0,0.8);
            padding: 20px;
            border-radius: 8px;
            max-width: 300px;
        }}
        .legend {{
            position: absolute;
            top: 20px;
            right: 20px;
            background: rgba(0,0,0,0.8);
            padding: 15px;
            border-radius: 8px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            margin: 5px 0;
        }}
        .legend-color {{
            width: 20px;
            height: 20px;
            margin-right: 10px;
            border-radius: 3px;
        }}
    </style>
</head>
<body>
    <div id="info">
        <h2>Threat Radar Graph</h2>
        <p>Interactive visualization of asset dependencies</p>
        <p><strong>Controls:</strong></p>
        <ul>
            <li>Drag nodes to reposition</li>
            <li>Hover for details</li>
            <li>Click to highlight connections</li>
        </ul>
    </div>
    <div class="legend">
        <h3 style="margin-top: 0;">Asset Types</h3>
        <div class="legend-item">
            <div class="legend-color" style="background: #3498db;"></div>
            <span>Container</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #2ecc71;"></div>
            <span>Service</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #e74c3c;"></div>
            <span>Database</span>
        </div>
    </div>
    <svg id="graph"></svg>

    <script>
        const graphData = {json.dumps(json_data)};

        const width = window.innerWidth;
        const height = window.innerHeight;

        const svg = d3.select("#graph")
            .attr("width", width)
            .attr("height", height);

        const colorMap = {{
            'container': '#3498db',
            'service': '#2ecc71',
            'database': '#e74c3c'
        }};

        const simulation = d3.forceSimulation(graphData.nodes)
            .force("link", d3.forceLink(graphData.links).id(d => d.id).distance(150))
            .force("charge", d3.forceManyBody().strength(-300))
            .force("center", d3.forceCenter(width / 2, height / 2));

        const link = svg.append("g")
            .selectAll("line")
            .data(graphData.links)
            .enter().append("line")
            .attr("class", "link")
            .attr("stroke-width", 2);

        const node = svg.append("g")
            .selectAll("circle")
            .data(graphData.nodes)
            .enter().append("circle")
            .attr("class", "node")
            .attr("r", d => {{
                const score = d.criticality_score || 50;
                return 10 + (score / 10);
            }})
            .attr("fill", d => colorMap[d.node_type] || '#95a5a6')
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended))
            .on("click", highlightNode);

        const label = svg.append("g")
            .selectAll("text")
            .data(graphData.nodes)
            .enter().append("text")
            .attr("class", "label")
            .text(d => d.name || d.id)
            .attr("dy", -15);

        simulation.on("tick", () => {{
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);

            node
                .attr("cx", d => d.x)
                .attr("cy", d => d.y);

            label
                .attr("x", d => d.x)
                .attr("y", d => d.y);
        }});

        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}

        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}

        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}

        function highlightNode(event, d) {{
            node.style("opacity", n => {{
                return n === d || graphData.links.some(l =>
                    (l.source === d && l.target === n) ||
                    (l.target === d && l.source === n)
                ) ? 1 : 0.2;
            }});

            link.style("opacity", l =>
                l.source === d || l.target === d ? 1 : 0.1
            );

            label.style("opacity", n =>
                n === d || graphData.links.some(l =>
                    (l.source === d && l.target === n) ||
                    (l.target === d && l.source === n)
                ) ? 1 : 0.2
            );
        }}

        svg.on("click", function(event) {{
            if (event.target === this) {{
                node.style("opacity", 1);
                link.style("opacity", 0.6);
                label.style("opacity", 1);
            }}
        }});
    </script>
</body>
</html>
    """

    html_file = "/tmp/graph_interactive.html"
    with open(html_file, 'w') as f:
        f.write(html_content)

    print(f"\n✓ Generated interactive HTML: {html_file}")
    print(f"\n  Open in browser:")
    print(f"    open {html_file}  # macOS")
    print(f"    xdg-open {html_file}  # Linux")
    print(f"    start {html_file}  # Windows")
    print(f"\n  Features:")
    print(f"    - Interactive drag and drop")
    print(f"    - Click to highlight connections")
    print(f"    - Colored by asset type")
    print(f"    - Sized by criticality")


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("THREAT RADAR - Graph Visualization Examples")
    print("=" * 70)

    if not MATPLOTLIB_AVAILABLE:
        print("\n⚠️  Some examples require matplotlib")
        print("Install with: pip install matplotlib\n")

    # Run all examples
    example_1_simple_visualization()
    example_2_styled_visualization()
    example_3_criticality_visualization()
    example_4_export_formats()
    example_5_interactive_html()

    print("\n" + "=" * 70)
    print("Visualization examples completed!")
    print("\nGenerated files in /tmp:")
    print("  - graph_simple.png")
    print("  - graph_styled.png")
    print("  - graph_criticality.png")
    print("  - graph.graphml (for Gephi/yEd/Cytoscape)")
    print("  - graph.json (for D3.js/custom tools)")
    print("  - graph_interactive.html (interactive web visualization)")
    print("=" * 70 + "\n")
