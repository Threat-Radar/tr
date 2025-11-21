#!/usr/bin/env python3
"""Debug script to test 3D visualization step by step."""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import plotly.graph_objects as go
import networkx as nx
from threat_radar.graph import NetworkXClient

print("=" * 60)
print("STEP 1: Test basic Plotly 3D rendering")
print("=" * 60)

# Create a simple 3D scatter plot
fig = go.Figure(data=[
    go.Scatter3d(
        x=[0, 1, 2],
        y=[0, 1, 0],
        z=[0, 1, 2],
        mode='markers+lines',
        marker=dict(size=10, color='red'),
        line=dict(color='blue', width=5)
    )
])

fig.update_layout(
    title="Test 1: Simple 3D Plot",
    scene=dict(
        xaxis=dict(title='X'),
        yaxis=dict(title='Y'),
        zaxis=dict(title='Z')
    ),
    width=800,
    height=600
)

test1_file = "full-demo-results/07-visualizations/3d/test1_simple.html"
fig.write_html(test1_file)
print(f"✓ Created test file: {test1_file}")
print("  → Open this file. Do you see a simple 3D plot with red dots and blue line?")

print("\n" + "=" * 60)
print("STEP 2: Load graph and check data")
print("=" * 60)

graph_file = "full-demo-results/05-graphs/main-graph-with-contains.graphml"
print(f"Loading graph from: {graph_file}")

client = NetworkXClient()
client.load(graph_file)
graph = client.graph

print(f"✓ Graph loaded successfully")
print(f"  - Nodes: {graph.number_of_nodes()}")
print(f"  - Edges: {graph.number_of_edges()}")

# Check node types
node_types = {}
for node in graph.nodes():
    node_type = graph.nodes[node].get('node_type', 'unknown')
    node_types[node_type] = node_types.get(node_type, 0) + 1

print(f"\nNode types:")
for ntype, count in sorted(node_types.items()):
    print(f"  - {ntype}: {count}")

print("\n" + "=" * 60)
print("STEP 3: Test simple graph visualization")
print("=" * 60)

# Create simple 2D layout first
print("Creating layout...")
pos_2d = nx.spring_layout(graph, k=3.0, iterations=50, seed=42)
print(f"✓ Layout created for {len(pos_2d)} nodes")

# Convert to 3D
pos_3d = {}
for node, (x, y) in pos_2d.items():
    pos_3d[node] = (x * 10, y * 10, 0)  # All at z=0 for simplicity

print(f"✓ 3D positions created")

# Check if positions are valid
print("\nSample positions:")
sample_nodes = list(pos_3d.keys())[:3]
for node in sample_nodes:
    x, y, z = pos_3d[node]
    print(f"  - {node[:40]}: x={x:.2f}, y={y:.2f}, z={z:.2f}")

print("\n" + "=" * 60)
print("STEP 4: Create simple node visualization")
print("=" * 60)

# Just plot nodes, no edges
node_x = []
node_y = []
node_z = []
node_text = []

for node in list(graph.nodes())[:50]:  # Just first 50 nodes
    if node in pos_3d:
        x, y, z = pos_3d[node]
        node_x.append(x)
        node_y.append(y)
        node_z.append(z)
        node_text.append(f"{node[:30]}")

print(f"Plotting {len(node_x)} nodes...")

node_trace = go.Scatter3d(
    x=node_x,
    y=node_y,
    z=node_z,
    mode='markers',
    marker=dict(
        size=10,
        color='red',
        opacity=0.8
    ),
    text=node_text,
    hoverinfo='text',
    name='Nodes'
)

fig2 = go.Figure(data=[node_trace])
fig2.update_layout(
    title="Test 2: Graph Nodes Only (first 50)",
    scene=dict(
        camera=dict(
            eye=dict(x=1.5, y=1.5, z=1.5)
        ),
        xaxis=dict(title='X'),
        yaxis=dict(title='Y'),
        zaxis=dict(title='Z')
    ),
    width=1200,
    height=800
)

test2_file = "full-demo-results/07-visualizations/3d/test2_nodes_only.html"
fig2.write_html(test2_file)
print(f"✓ Created test file: {test2_file}")
print("  → Open this file. Do you see red dots in 3D space?")

print("\n" + "=" * 60)
print("STEP 5: Add edges")
print("=" * 60)

# Add some edges
edge_x = []
edge_y = []
edge_z = []

edge_count = 0
for u, v in list(graph.edges())[:30]:  # Just first 30 edges
    if u in pos_3d and v in pos_3d:
        edge_x.extend([pos_3d[u][0], pos_3d[v][0], None])
        edge_y.extend([pos_3d[u][1], pos_3d[v][1], None])
        edge_z.extend([pos_3d[u][2], pos_3d[v][2], None])
        edge_count += 1

print(f"Plotting {edge_count} edges...")

edge_trace = go.Scatter3d(
    x=edge_x,
    y=edge_y,
    z=edge_z,
    mode='lines',
    line=dict(color='blue', width=2),
    hoverinfo='skip',
    name='Edges'
)

fig3 = go.Figure(data=[edge_trace, node_trace])
fig3.update_layout(
    title="Test 3: Nodes + Edges",
    scene=dict(
        camera=dict(
            eye=dict(x=1.5, y=1.5, z=1.5)
        ),
        xaxis=dict(title='X'),
        yaxis=dict(title='Y'),
        zaxis=dict(title='Z')
    ),
    width=1200,
    height=800
)

test3_file = "full-demo-results/07-visualizations/3d/test3_nodes_and_edges.html"
fig3.write_html(test3_file)
print(f"✓ Created test file: {test3_file}")
print("  → Open this file. Do you see red dots connected by blue lines?")

print("\n" + "=" * 60)
print("STEP 6: Full graph with all nodes and edges")
print("=" * 60)

# All nodes
node_x = []
node_y = []
node_z = []
node_text = []
node_colors = []

for node in graph.nodes():
    if node in pos_3d:
        x, y, z = pos_3d[node]
        node_x.append(x)
        node_y.append(y)
        node_z.append(z)

        node_type = graph.nodes[node].get('node_type', 'unknown')
        node_text.append(f"{node[:30]}<br>Type: {node_type}")

        # Color by type
        type_colors = {
            'asset': 'gold',
            'container': 'gold',
            'package': 'cyan',
            'vulnerability': 'red',
        }
        node_colors.append(type_colors.get(node_type, 'grey'))

print(f"Plotting {len(node_x)} nodes...")

# All edges
edge_x = []
edge_y = []
edge_z = []

for u, v in graph.edges():
    if u in pos_3d and v in pos_3d:
        edge_x.extend([pos_3d[u][0], pos_3d[v][0], None])
        edge_y.extend([pos_3d[u][1], pos_3d[v][1], None])
        edge_z.extend([pos_3d[u][2], pos_3d[v][2], None])

print(f"Plotting {graph.number_of_edges()} edges...")

edge_trace = go.Scatter3d(
    x=edge_x,
    y=edge_y,
    z=edge_z,
    mode='lines',
    line=dict(color='lightgrey', width=1),
    hoverinfo='skip',
    name='Edges',
    showlegend=False
)

node_trace = go.Scatter3d(
    x=node_x,
    y=node_y,
    z=node_z,
    mode='markers',
    marker=dict(
        size=8,
        color=node_colors,
        opacity=0.8,
        line=dict(width=1, color='white')
    ),
    text=node_text,
    hoverinfo='text',
    name='Nodes'
)

fig4 = go.Figure(data=[edge_trace, node_trace])
fig4.update_layout(
    title="Test 4: Full Graph",
    scene=dict(
        camera=dict(
            eye=dict(x=1.5, y=1.5, z=1.5)
        ),
        xaxis=dict(showgrid=True),
        yaxis=dict(showgrid=True),
        zaxis=dict(showgrid=True)
    ),
    width=1400,
    height=900,
    showlegend=True
)

test4_file = "full-demo-results/07-visualizations/3d/test4_full_graph.html"
fig4.write_html(test4_file)
print(f"✓ Created test file: {test4_file}")
print("  → Open this file. Do you see the full graph with colored nodes?")

print("\n" + "=" * 60)
print("DEBUG SUMMARY")
print("=" * 60)
print("\nCreated 4 test files in order of complexity:")
print(f"1. {test1_file}")
print(f"2. {test2_file}")
print(f"3. {test3_file}")
print(f"4. {test4_file}")
print("\nPlease open each file and report:")
print("  - Which files show content?")
print("  - Which files show only title?")
print("  - Any JavaScript errors in browser console?")
print("\nThis will help identify where the problem occurs.")
