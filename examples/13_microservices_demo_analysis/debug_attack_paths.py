#!/usr/bin/env python3
"""Debug attack paths visualization step by step."""

import sys
import json
from pathlib import Path

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import plotly.graph_objects as go
import networkx as nx
from threat_radar.graph import NetworkXClient
from threat_radar.graph.models import EdgeType, NodeType

print("=" * 60)
print("Loading data...")
print("=" * 60)

# Load graph
graph_file = "full-demo-results/05-graphs/main-graph-with-contains.graphml"
client = NetworkXClient()
client.load(graph_file)
graph = client.graph

print(f"✓ Graph loaded: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")

# Load attack paths
paths_file = "full-demo-results/06-attack-paths/attack-paths.json"
with open(paths_file) as f:
    data = json.load(f)
attack_paths = data.get('attack_paths', [])

print(f"✓ Attack paths loaded: {len(attack_paths)} paths")

# Extract attack path nodes
path_nodes = set()
for path in attack_paths:
    for step in path.get('steps', []):
        path_nodes.add(step.get('node_id'))

print(f"✓ Attack path nodes: {len(path_nodes)} nodes")

# Create 3D positions
zone_levels = {
    'dmz': 0.0, 'public': 0.0, 'internet': 0.0,
    'internal': 5.0, 'trusted': 10.0,
    'database': 15.0, 'pci': 15.0, 'unknown': 2.5,
}

pos_2d = nx.spring_layout(graph, k=3.0, iterations=50, seed=42)
pos_3d = {}
for node, (x, y) in pos_2d.items():
    zone = graph.nodes[node].get('zone', 'unknown')
    if isinstance(zone, str):
        zone = zone.lower()
    z = zone_levels.get(zone, 2.5)
    pos_3d[node] = (x * 10, y * 10, z)

print(f"✓ 3D positions created")

# Find CONTAINS and HAS_VULNERABILITY edges
contains_edges = set()
has_vuln_edges = set()

assets_in_paths = {
    node for node in path_nodes
    if graph.nodes[node].get('node_type') in ['asset', 'container']
}

print(f"\n✓ Assets in paths: {len(assets_in_paths)}")

connected_packages = set()
for asset in assets_in_paths:
    for successor in graph.successors(asset):
        edge_data = graph.get_edge_data(asset, successor)
        successor_type = graph.nodes[successor].get('node_type')
        if (edge_data and edge_data.get('edge_type') == EdgeType.CONTAINS.value) or \
           (successor_type == NodeType.PACKAGE.value):
            contains_edges.add((asset, successor))
            connected_packages.add(successor)

print(f"✓ CONTAINS edges: {len(contains_edges)}")
print(f"✓ Connected packages: {len(connected_packages)}")

connected_vulns = set()
for package in connected_packages:
    for successor in graph.successors(package):
        edge_data = graph.get_edge_data(package, successor)
        successor_type = graph.nodes[successor].get('node_type')
        if (edge_data and edge_data.get('edge_type') == EdgeType.HAS_VULNERABILITY.value) or \
           (successor_type == NodeType.VULNERABILITY.value):
            has_vuln_edges.add((package, successor))
            connected_vulns.add(successor)

print(f"✓ HAS_VULNERABILITY edges: {len(has_vuln_edges)}")
print(f"✓ Connected vulnerabilities: {len(connected_vulns)}")

print("\n" + "=" * 60)
print("TEST 5: Base graph + CONTAINS edges")
print("=" * 60)

traces = []

# Base edges
edge_x, edge_y, edge_z = [], [], []
for u, v in graph.edges():
    if u in pos_3d and v in pos_3d:
        edge_x.extend([pos_3d[u][0], pos_3d[v][0], None])
        edge_y.extend([pos_3d[u][1], pos_3d[v][1], None])
        edge_z.extend([pos_3d[u][2], pos_3d[v][2], None])

base_trace = go.Scatter3d(
    x=edge_x, y=edge_y, z=edge_z,
    mode='lines',
    line=dict(color='rgba(180, 180, 180, 0.4)', width=1),
    hoverinfo='skip',
    name='Infrastructure',
    showlegend=True
)
traces.append(base_trace)

# CONTAINS edges (green)
if contains_edges:
    cont_x, cont_y, cont_z = [], [], []
    for u, v in contains_edges:
        if u in pos_3d and v in pos_3d:
            cont_x.extend([pos_3d[u][0], pos_3d[v][0], None])
            cont_y.extend([pos_3d[u][1], pos_3d[v][1], None])
            cont_z.extend([pos_3d[u][2], pos_3d[v][2], None])

    contains_trace = go.Scatter3d(
        x=cont_x, y=cont_y, z=cont_z,
        mode='lines',
        line=dict(color='rgba(0, 255, 0, 0.8)', width=4),
        hoverinfo='skip',
        name='CONTAINS (Asset → Package)',
        showlegend=True
    )
    traces.append(contains_trace)
    print(f"Added CONTAINS trace with {len(contains_edges)} edges")

# Nodes
node_x, node_y, node_z, node_text, node_colors = [], [], [], [], []
for node in graph.nodes():
    if node in pos_3d:
        x, y, z = pos_3d[node]
        node_x.append(x)
        node_y.append(y)
        node_z.append(z)
        node_type = graph.nodes[node].get('node_type', 'unknown')
        node_text.append(f"{node[:40]}<br>Type: {node_type}")

        if node in assets_in_paths:
            node_colors.append('gold')
        elif node in connected_packages:
            node_colors.append('cyan')
        else:
            node_colors.append('grey')

nodes_trace = go.Scatter3d(
    x=node_x, y=node_y, z=node_z,
    mode='markers',
    marker=dict(size=8, color=node_colors, opacity=0.8, line=dict(width=1, color='white')),
    text=node_text,
    hoverinfo='text',
    name='Nodes',
    showlegend=True
)
traces.append(nodes_trace)

print(f"Total traces: {len(traces)}")

fig5 = go.Figure(data=traces)
fig5.update_layout(
    title="Test 5: Graph + CONTAINS edges (green)",
    scene=dict(
        camera=dict(eye=dict(x=1.5, y=1.5, z=1.0)),
        xaxis=dict(showgrid=True),
        yaxis=dict(showgrid=True),
        zaxis=dict(showgrid=True, title='Security Layers')
    ),
    width=1400,
    height=900,
    showlegend=True
)

test5_file = "full-demo-results/07-visualizations/3d/test5_contains_edges.html"
fig5.write_html(test5_file)
print(f"✓ Created: {test5_file}")

print("\n" + "=" * 60)
print("TEST 6: Add HAS_VULNERABILITY edges")
print("=" * 60)

# Add HAS_VULNERABILITY edges (red)
if has_vuln_edges:
    vuln_x, vuln_y, vuln_z = [], [], []
    for u, v in has_vuln_edges:
        if u in pos_3d and v in pos_3d:
            vuln_x.extend([pos_3d[u][0], pos_3d[v][0], None])
            vuln_y.extend([pos_3d[u][1], pos_3d[v][1], None])
            vuln_z.extend([pos_3d[u][2], pos_3d[v][2], None])

    vuln_trace = go.Scatter3d(
        x=vuln_x, y=vuln_y, z=vuln_z,
        mode='lines',
        line=dict(color='rgba(255, 50, 50, 0.9)', width=4),
        hoverinfo='skip',
        name='HAS_VULNERABILITY (Package → Vuln)',
        showlegend=True
    )
    traces.append(vuln_trace)
    print(f"Added HAS_VULNERABILITY trace with {len(has_vuln_edges)} edges")

# Update node colors to show vulnerabilities
node_colors = []
for node in graph.nodes():
    if node in assets_in_paths:
        node_colors.append('gold')
    elif node in connected_packages:
        node_colors.append('cyan')
    elif node in connected_vulns:
        node_colors.append('orangered')
    else:
        node_colors.append('lightgrey')

traces[-1] = go.Scatter3d(
    x=node_x, y=node_y, z=node_z,
    mode='markers',
    marker=dict(size=8, color=node_colors, opacity=0.8, line=dict(width=1, color='white')),
    text=node_text,
    hoverinfo='text',
    name='Nodes',
    showlegend=True
)

print(f"Total traces: {len(traces)}")

fig6 = go.Figure(data=traces)
fig6.update_layout(
    title="Test 6: Graph + CONTAINS (green) + HAS_VULNERABILITY (red)",
    scene=dict(
        camera=dict(eye=dict(x=1.5, y=1.5, z=1.0)),
        xaxis=dict(showgrid=True),
        yaxis=dict(showgrid=True),
        zaxis=dict(showgrid=True, title='Security Layers')
    ),
    width=1400,
    height=900,
    showlegend=True
)

test6_file = "full-demo-results/07-visualizations/3d/test6_full_chains.html"
fig6.write_html(test6_file)
print(f"✓ Created: {test6_file}")

print("\n" + "=" * 60)
print("TEST 7: Add attack path routes (purple)")
print("=" * 60)

# Add attack path edges
attack_path_edges = set()
for path in attack_paths:
    steps = path.get('steps', [])
    for i in range(len(steps) - 1):
        u = steps[i].get('node_id')
        v = steps[i + 1].get('node_id')
        if u and v:
            attack_path_edges.add((u, v))

print(f"Attack path edges: {len(attack_path_edges)}")

if attack_path_edges:
    ap_x, ap_y, ap_z = [], [], []
    for u, v in attack_path_edges:
        if u in pos_3d and v in pos_3d:
            ap_x.extend([pos_3d[u][0], pos_3d[v][0], None])
            ap_y.extend([pos_3d[u][1], pos_3d[v][1], None])
            ap_z.extend([pos_3d[u][2], pos_3d[v][2], None])

    ap_trace = go.Scatter3d(
        x=ap_x, y=ap_y, z=ap_z,
        mode='lines',
        line=dict(color='rgba(255, 0, 255, 1.0)', width=6),
        hoverinfo='skip',
        name='Attack Path Routes',
        showlegend=True
    )
    traces.append(ap_trace)
    print(f"Added Attack Path trace")

print(f"Total traces: {len(traces)}")

fig7 = go.Figure(data=traces)
fig7.update_layout(
    title="Test 7: Complete - CONTAINS (green) + HAS_VULNERABILITY (red) + Attack Paths (purple)",
    scene=dict(
        camera=dict(eye=dict(x=1.5, y=1.5, z=1.0)),
        xaxis=dict(showgrid=True),
        yaxis=dict(showgrid=True),
        zaxis=dict(showgrid=True, title='Security Layers')
    ),
    width=1400,
    height=900,
    showlegend=True,
    paper_bgcolor='white'
)

test7_file = "full-demo-results/07-visualizations/3d/test7_complete.html"
fig7.write_html(test7_file)
print(f"✓ Created: {test7_file}")

print("\n" + "=" * 60)
print("DEBUG SUMMARY")
print("=" * 60)
print("\nCreated 3 progressive test files:")
print(f"5. {test5_file}")
print(f"   → Should show: Grey graph + GREEN CONTAINS edges + gold/cyan nodes")
print(f"\n6. {test6_file}")
print(f"   → Should show: Above + RED HAS_VULNERABILITY edges + orange vulnerability nodes")
print(f"\n7. {test7_file}")
print(f"   → Should show: Above + PURPLE attack path routes")
print("\nPlease check which files work and which don't!")
print(f"\nTrace counts:")
print(f"  Test 5: {3} traces (base + contains + nodes)")
print(f"  Test 6: {4} traces (base + contains + has_vuln + nodes)")
print(f"  Test 7: {5} traces (base + contains + has_vuln + attack_paths + nodes)")
