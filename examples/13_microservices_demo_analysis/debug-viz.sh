#!/usr/bin/env bash
#
# Debug visualization - creates a STATIC (non-animated) version first
# to diagnose why the holographic viz is black
#

set -e

echo "🔍 Debugging Holographic Visualization Issue..."
echo ""

# Find a graph to use
GRAPH="./full-demo-results/05-graphs/main-graph.graphml"

if [ ! -f "$GRAPH" ]; then
    echo "❌ No graph found. Please run ./full-demo.sh first"
    exit 1
fi

OUTPUT_DIR="./debug-viz-output"
mkdir -p "$OUTPUT_DIR"

echo "Creating diagnostic static visualization..."
echo "Graph: $GRAPH"
echo ""

cat > /tmp/debug_viz.py << EOFPYTHON
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from threat_radar.graph import NetworkXClient
    from plotly import graph_objects as go
    import networkx as nx

    print("📊 Loading graph...")
    client = NetworkXClient()
    client.load("$GRAPH")

    G = client.graph
    print(f"  ✓ Nodes: {G.number_of_nodes()}")
    print(f"  ✓ Edges: {G.number_of_edges()}")

    if G.number_of_nodes() == 0:
        print("\n❌ ERROR: Graph has no nodes!")
        sys.exit(1)

    # Show sample nodes
    print("\n📝 Sample nodes:")
    for i, (node, data) in enumerate(list(G.nodes(data=True))[:5]):
        print(f"  {i+1}. {node}")
        print(f"     Type: {data.get('type', 'unknown')}")
        print(f"     Zone: {data.get('zone', 'unknown')}")

    print("\n🎨 Creating 3D positions...")

    # Position nodes in 3D
    zone_levels = {
        'dmz': 0.0, 'public': 0.0,
        'internal': 4.0,
        'trusted': 8.0,
        'database': 12.0,
        'unknown': 2.0,
    }

    pos_2d = nx.spring_layout(G, k=2.5, iterations=50, seed=42)
    pos_3d = {}
    for node, (x, y) in pos_2d.items():
        zone = G.nodes[node].get('zone', 'unknown').lower()
        z = zone_levels.get(zone, 2.0)
        pos_3d[node] = (x * 6, y * 6, z)

    print(f"  ✓ Positioned {len(pos_3d)} nodes in 3D")

    # Show position range
    all_x = [p[0] for p in pos_3d.values()]
    all_y = [p[1] for p in pos_3d.values()]
    all_z = [p[2] for p in pos_3d.values()]

    print(f"\n📏 Position ranges:")
    print(f"  X: {min(all_x):.2f} to {max(all_x):.2f}")
    print(f"  Y: {min(all_y):.2f} to {max(all_y):.2f}")
    print(f"  Z: {min(all_z):.2f} to {max(all_z):.2f}")

    print("\n🎭 Creating STATIC visualization (no animation)...")

    # Create edges
    edge_x, edge_y, edge_z = [], [], []
    for u, v in G.edges():
        if u in pos_3d and v in pos_3d:
            edge_x.extend([pos_3d[u][0], pos_3d[v][0], None])
            edge_y.extend([pos_3d[u][1], pos_3d[v][1], None])
            edge_z.extend([pos_3d[u][2], pos_3d[v][2], None])

    edge_trace = go.Scatter3d(
        x=edge_x, y=edge_y, z=edge_z,
        mode='lines',
        line=dict(color='cyan', width=2),  # Bright cyan for visibility
        hoverinfo='none',
        showlegend=False,
        name='Edges'
    )

    print(f"  ✓ Created {len([x for x in edge_x if x is not None])} edge segments")

    # Create nodes
    node_x, node_y, node_z = [], [], []
    node_colors, node_texts = [], []

    zone_color_map = {
        'dmz': '#ff6b6b',
        'internal': '#4ecdc4',
        'trusted': '#45b7d1',
        'database': '#574b90',
        'unknown': '#95a5a6',
    }

    for node in G.nodes():
        if node in pos_3d:
            node_data = G.nodes[node]
            zone = node_data.get('zone', 'unknown').lower()
            node_type = node_data.get('type', 'unknown')

            x, y, z = pos_3d[node]
            node_x.append(x)
            node_y.append(y)
            node_z.append(z)

            color = zone_color_map.get(zone, '#95a5a6')
            node_colors.append(color)

            node_texts.append(
                f"<b>{node}</b><br>"
                f"Type: {node_type}<br>"
                f"Zone: {zone.upper()}<br>"
                f"Position: ({x:.2f}, {y:.2f}, {z:.2f})"
            )

    node_trace = go.Scatter3d(
        x=node_x, y=node_y, z=node_z,
        mode='markers+text',
        marker=dict(
            size=15,  # Large for visibility
            color=node_colors,
            line=dict(width=2, color='white'),
            opacity=1.0
        ),
        text=[str(i) for i in range(len(node_x))],  # Show numbers
        textposition='top center',
        textfont=dict(color='white', size=10),
        hovertext=node_texts,
        hoverinfo='text',
        showlegend=False,
        name='Nodes'
    )

    print(f"  ✓ Created {len(node_x)} node markers")

    # Create figure
    fig = go.Figure(data=[edge_trace, node_trace])

    fig.update_layout(
        title=dict(
            text="🔍 DEBUG: Static 3D Visualization<br><sub>If you see this title but no graph, check console</sub>",
            font=dict(size=20, color='white'),
            x=0.5,
            xanchor='center'
        ),
        width=1600,
        height=1000,
        showlegend=False,
        scene=dict(
            camera=dict(
                eye=dict(x=1.5, y=1.5, z=1.5),  # Good viewing angle
                center=dict(x=0, y=0, z=6)
            ),
            xaxis=dict(
                showgrid=True,
                gridcolor='rgba(255,255,255,0.2)',
                showbackground=True,
                backgroundcolor='rgba(50,50,50,0.5)',
                title=dict(text='X', font=dict(color='white'))
            ),
            yaxis=dict(
                showgrid=True,
                gridcolor='rgba(255,255,255,0.2)',
                showbackground=True,
                backgroundcolor='rgba(50,50,50,0.5)',
                title=dict(text='Y', font=dict(color='white'))
            ),
            zaxis=dict(
                showgrid=True,
                gridcolor='rgba(255,255,255,0.2)',
                showbackground=True,
                backgroundcolor='rgba(50,50,50,0.5)',
                title=dict(text='Security Layers', font=dict(color='white'))
            ),
            bgcolor='rgba(20,20,40,1)'  # Dark blue, not pure black
        ),
        paper_bgcolor='rgb(30,30,50)',  # Slightly lighter background
        font=dict(color='white')
    )

    output = "$OUTPUT_DIR/debug_static.html"
    fig.write_html(output)

    print(f"\n✅ Static visualization saved!")
    print(f"\n📁 Output: {output}")
    print(f"\n🔍 What to check:")
    print(f"  1. Open the file in your browser")
    print(f"  2. You should see a 3D graph with colored nodes")
    print(f"  3. Try rotating with mouse/trackpad")
    print(f"  4. If it's still black, open browser DevTools (F12)")
    print(f"  5. Check Console tab for JavaScript errors")
    print(f"\n📊 Graph stats saved to debug-info.txt")

    # Save debug info
    with open("$OUTPUT_DIR/debug-info.txt", "w") as f:
        f.write(f"Graph File: $GRAPH\n")
        f.write(f"Nodes: {G.number_of_nodes()}\n")
        f.write(f"Edges: {G.number_of_edges()}\n")
        f.write(f"Position ranges:\n")
        f.write(f"  X: {min(all_x):.2f} to {max(all_x):.2f}\n")
        f.write(f"  Y: {min(all_y):.2f} to {max(all_y):.2f}\n")
        f.write(f"  Z: {min(all_z):.2f} to {max(all_z):.2f}\n")
        f.write(f"\nNode types:\n")
        types = {}
        for node, data in G.nodes(data=True):
            node_type = data.get('type', 'unknown')
            types[node_type] = types.get(node_type, 0) + 1
        for t, count in sorted(types.items()):
            f.write(f"  {t}: {count}\n")

except Exception as e:
    print(f"\n❌ ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

EOFPYTHON

python3 /tmp/debug_viz.py

if [ $? -eq 0 ]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "✅ Debug visualization created!"
    echo ""
    echo "Next steps:"
    echo "  1. Open: $OUTPUT_DIR/debug_static.html"
    echo "  2. Check: $OUTPUT_DIR/debug-info.txt"
    echo ""
    echo "If the static version works, the issue is with animation."
    echo "If the static version is also black, the issue is with data/rendering."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fi

rm -f /tmp/debug_viz.py
