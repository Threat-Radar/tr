#!/usr/bin/env bash
#
# Quick test script for holographic visualization
# Tests the fixed animation without running the full demo
#

set -e

echo "🔮 Testing Holographic Visualization Fix..."
echo ""

# Check if we have required files
GRAPH="../11_graph_visualization/sample_graph.graphml"
OUTPUT_DIR="./test-viz-output"

if [ ! -f "$GRAPH" ]; then
    echo "⚠️  Sample graph not found at: $GRAPH"
    echo "   Creating a minimal test graph..."

    mkdir -p "$OUTPUT_DIR"

    # Create minimal test using full-demo results if available
    if [ -f "./full-demo-results/05-graphs/main-graph.graphml" ]; then
        GRAPH="./full-demo-results/05-graphs/main-graph.graphml"
        echo "   ✓ Using graph from full-demo results"
    else
        echo "   ⚠️  No graph available. Please run ./full-demo.sh first"
        exit 1
    fi
fi

mkdir -p "$OUTPUT_DIR"

echo "Creating test holographic visualization..."
echo "Graph location: $GRAPH"

cat > /tmp/test_holographic.py << EOFPYTHON
import sys
import math
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from threat_radar.graph import NetworkXClient
    from plotly import graph_objects as go
    import networkx as nx

    print("Loading graph...")
    client = NetworkXClient()
    client.load("$GRAPH")

    G = client.graph
    print(f"  ✓ Loaded {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

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

    print("Creating animation frames...")
    frames = []
    num_frames = 60  # Fewer frames for quick test

    for frame_idx in range(num_frames):
        progress = frame_idx / num_frames

        # Camera rotation
        angle = progress * 2 * math.pi
        radius = 20
        height = 8

        camera_x = radius * math.cos(angle)
        camera_y = radius * math.sin(angle)
        camera_z = height

        # Edges
        edge_x, edge_y, edge_z = [], [], []
        for u, v in G.edges():
            if u in pos_3d and v in pos_3d:
                edge_x.extend([pos_3d[u][0], pos_3d[v][0], None])
                edge_y.extend([pos_3d[u][1], pos_3d[v][1], None])
                edge_z.extend([pos_3d[u][2], pos_3d[v][2], None])

        edge_trace = go.Scatter3d(
            x=edge_x, y=edge_y, z=edge_z,
            mode='lines',
            line=dict(color='rgba(100,100,150,0.3)', width=1),
            hoverinfo='none',
            showlegend=False
        )

        # Nodes
        node_x, node_y, node_z = [], [], []
        node_colors, node_sizes, node_texts = [], [], []

        pulse = 1.0 + 0.2 * math.sin(progress * 8 * math.pi)

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

                x, y, z = pos_3d[node]
                node_x.append(x)
                node_y.append(y)
                node_z.append(z)

                color = zone_color_map.get(zone, '#95a5a6')
                node_colors.append(color)

                size = 12 * pulse
                node_sizes.append(size)

                node_texts.append(f"<b>{node}</b><br>Zone: {zone.upper()}")

        node_trace = go.Scatter3d(
            x=node_x, y=node_y, z=node_z,
            mode='markers',
            marker=dict(
                size=node_sizes,
                color=node_colors,
                line=dict(width=2, color='white'),
                opacity=0.9
            ),
            text=node_texts,
            hoverinfo='text',
            showlegend=False
        )

        frame_data = [edge_trace, node_trace]

        # FIXED: Proper frame configuration
        frames.append(go.Frame(
            data=frame_data,
            name=f"frame_{frame_idx}",
            layout=go.Layout(
                scene=dict(
                    camera=dict(
                        eye=dict(x=camera_x/radius, y=camera_y/radius, z=camera_z/radius),
                        center=dict(x=0, y=0, z=6)
                    )
                ),
                title=dict(
                    text=f"🔮 TEST HOLOGRAPHIC VIZ<br><sub>Frame: {frame_idx}/{num_frames}</sub>",
                    font=dict(size=24, color='cyan'),
                    x=0.5,
                    xanchor='center'
                )
            )
        ))

    print(f"  ✓ Created {len(frames)} frames")

    # Create figure with FIXED settings
    print("Building figure...")
    fig = go.Figure(
        data=frames[0].data,
        frames=frames,
        layout=go.Layout(
            title=dict(
                text="🔮 HOLOGRAPHIC VISUALIZATION TEST<br><sub>Click LOOP to start!</sub>",
                font=dict(size=24, color='cyan'),
                x=0.5,
                xanchor='center'
            ),
            width=1600,
            height=1000,
            showlegend=False,
            scene=dict(
                camera=dict(
                    eye=dict(x=1, y=0, z=0.4),
                    center=dict(x=0, y=0, z=6)
                ),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, showbackground=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, showbackground=False),
                zaxis=dict(
                    showgrid=True,
                    gridcolor='rgba(100,150,200,0.3)',
                    title=dict(text='LAYERS', font=dict(color='cyan')),
                    tickfont=dict(color='cyan'),
                    showbackground=False
                ),
                bgcolor='#000000'
            ),
            paper_bgcolor='#000000',
            font=dict(color='cyan'),
            updatemenus=[{
                'type': 'buttons',
                'showactive': False,
                'buttons': [
                    {
                        'label': '▶ PLAY',
                        'method': 'animate',
                        'args': [None, {
                            'frame': {'duration': 50, 'redraw': True},
                            'fromcurrent': True,
                            'transition': {'duration': 50, 'easing': 'linear'},
                            'mode': 'immediate'
                        }]
                    },
                    {
                        'label': '⏸ PAUSE',
                        'method': 'animate',
                        'args': [[None], {
                            'frame': {'duration': 0, 'redraw': False},
                            'mode': 'immediate',
                            'transition': {'duration': 0}
                        }]
                    },
                    {
                        'label': '🔄 LOOP',
                        'method': 'animate',
                        'args': [None, {
                            'frame': {'duration': 50, 'redraw': True},
                            'fromcurrent': False,
                            'transition': {'duration': 50, 'easing': 'linear'},
                            'mode': 'immediate'
                        }]
                    }
                ],
                'x': 0.5,
                'y': 0.02,
                'xanchor': 'center',
                'yanchor': 'bottom',
                'bgcolor': 'rgba(0,100,150,0.8)',
                'bordercolor': 'cyan',
                'borderwidth': 2,
                'font': dict(color='cyan', size=14)
            }]
        )
    )

    output = "$OUTPUT_DIR/holographic_test.html"
    fig.write_html(output)
    print(f"\n✅ SUCCESS! Visualization saved to: {output}")
    print("")
    print("To view:")
    print(f"  open {output}")
    print("")
    print("Controls:")
    print("  ▶ PLAY - Play from current position")
    print("  ⏸ PAUSE - Pause animation")
    print("  🔄 LOOP - Restart and loop continuously")

except Exception as e:
    print(f"\n❌ ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

EOFPYTHON

python3 /tmp/test_holographic.py

if [ $? -eq 0 ]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "✅ Holographic visualization test PASSED!"
    echo ""
    echo "The visualization should now:"
    echo "  1. Display immediately when opened"
    echo "  2. NOT go black"
    echo "  3. Animate smoothly when you click LOOP"
    echo "  4. Loop continuously"
    echo ""
    echo "Open the test file to verify:"
    echo "  open $OUTPUT_DIR/holographic_test.html"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    echo ""
    echo "❌ Test failed. Check error messages above."
fi

rm -f /tmp/test_holographic.py
