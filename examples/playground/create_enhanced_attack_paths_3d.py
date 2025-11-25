#!/usr/bin/env python3
"""
Enhanced 3D Attack Path Visualization with Asset → Package → Vulnerability Connections

This script creates a 3D visualization that shows:
1. The full infrastructure graph
2. Attack paths overlaid
3. Detailed CONTAINS edges (Asset → Package)
4. Detailed HAS_VULNERABILITY edges (Package → Vulnerability)

All connections related to attack paths are highlighted.
"""

import sys
import json
import math
from pathlib import Path
from collections import defaultdict

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import plotly.graph_objects as go
import networkx as nx
from threat_radar.graph import NetworkXClient, GraphAnalyzer
from threat_radar.graph.models import NodeType, EdgeType

def load_attack_paths(paths_file):
    """Load attack paths from JSON file."""
    with open(paths_file) as f:
        data = json.load(f)
    return data.get('attack_paths', [])

def extract_attack_path_nodes(attack_paths):
    """Extract all nodes involved in attack paths."""
    path_nodes = set()
    for path in attack_paths:
        for step in path.get('steps', []):
            path_nodes.add(step.get('node_id'))
    return path_nodes

def find_asset_package_vuln_connections(graph, path_nodes):
    """
    Find all Asset → Package → Vulnerability connections related to attack paths.

    Returns:
        - contains_edges: set of (asset, package) tuples
        - has_vuln_edges: set of (package, vuln) tuples
        - connected_packages: set of package nodes
        - connected_vulns: set of vulnerability nodes
    """
    contains_edges = set()
    has_vuln_edges = set()
    connected_packages = set()
    connected_vulns = set()

    # Find all assets in attack paths
    assets_in_paths = {
        node for node in path_nodes
        if graph.nodes[node].get('node_type') in ['asset', 'container']
    }

    print(f"Found {len(assets_in_paths)} assets in attack paths")

    # For each asset, find CONTAINS edges to packages
    for asset in assets_in_paths:
        for successor in graph.successors(asset):
            edge_data = graph.get_edge_data(asset, successor)
            successor_type = graph.nodes[successor].get('node_type')

            if (edge_data and edge_data.get('edge_type') == EdgeType.CONTAINS.value) or \
               (successor_type == NodeType.PACKAGE.value):
                contains_edges.add((asset, successor))
                connected_packages.add(successor)

    print(f"Found {len(contains_edges)} CONTAINS edges (Asset → Package)")
    print(f"Found {len(connected_packages)} packages connected to assets in attack paths")

    # For each package, find HAS_VULNERABILITY edges to vulnerabilities
    for package in connected_packages:
        for successor in graph.successors(package):
            edge_data = graph.get_edge_data(package, successor)
            successor_type = graph.nodes[successor].get('node_type')

            if (edge_data and edge_data.get('edge_type') == EdgeType.HAS_VULNERABILITY.value) or \
               (successor_type == NodeType.VULNERABILITY.value):
                has_vuln_edges.add((package, successor))
                connected_vulns.add(successor)

    print(f"Found {len(has_vuln_edges)} HAS_VULNERABILITY edges (Package → Vulnerability)")
    print(f"Found {len(connected_vulns)} vulnerabilities connected to packages")

    return contains_edges, has_vuln_edges, connected_packages, connected_vulns

def create_3d_positions(graph):
    """Create 3D positions for nodes based on zones."""
    # Zone-based z-levels
    zone_levels = {
        'dmz': 0.0,
        'public': 0.0,
        'internet': 0.0,
        'internal': 5.0,
        'trusted': 10.0,
        'database': 15.0,
        'pci': 15.0,
        'unknown': 2.5,
    }

    # Create 2D layout
    pos_2d = nx.spring_layout(graph, k=3.0, iterations=50, seed=42)

    # Convert to 3D with z based on zone
    pos_3d = {}
    for node, (x, y) in pos_2d.items():
        zone = graph.nodes[node].get('zone', 'unknown')
        if isinstance(zone, str):
            zone = zone.lower()
        z = zone_levels.get(zone, 2.5)
        pos_3d[node] = (x * 10, y * 10, z)

    return pos_3d

def create_edge_trace_3d(edges, pos_3d, color, width, name, opacity=0.8):
    """Create a 3D scatter trace for edges."""
    x_coords = []
    y_coords = []
    z_coords = []

    for u, v in edges:
        if u in pos_3d and v in pos_3d:
            x_coords.extend([pos_3d[u][0], pos_3d[v][0], None])
            y_coords.extend([pos_3d[u][1], pos_3d[v][1], None])
            z_coords.extend([pos_3d[u][2], pos_3d[v][2], None])

    return go.Scatter3d(
        x=x_coords,
        y=y_coords,
        z=z_coords,
        mode='lines',
        line=dict(color=color, width=width),
        opacity=opacity,
        hoverinfo='skip',
        name=name,
        showlegend=True
    )

def create_node_trace_3d(nodes, graph, pos_3d, color, size, name, marker_symbol='circle'):
    """Create a 3D scatter trace for nodes."""
    x_coords = []
    y_coords = []
    z_coords = []
    hover_texts = []

    for node in nodes:
        if node in pos_3d:
            node_data = graph.nodes[node]
            x, y, z = pos_3d[node]

            x_coords.append(x)
            y_coords.append(y)
            z_coords.append(z)

            # Create hover text
            node_type = node_data.get('node_type', 'unknown')
            zone = node_data.get('zone', 'unknown')
            hover_text = f"<b>{node}</b><br>Type: {node_type}<br>Zone: {zone}"

            # Add severity for vulnerabilities
            if node_type == 'vulnerability':
                severity = node_data.get('severity', 'unknown')
                cvss = node_data.get('cvss_score', 'N/A')
                hover_text += f"<br>Severity: {severity}<br>CVSS: {cvss}"

            hover_texts.append(hover_text)

    return go.Scatter3d(
        x=x_coords,
        y=y_coords,
        z=z_coords,
        mode='markers',
        marker=dict(
            size=size,
            color=color,
            symbol=marker_symbol,
            line=dict(width=2, color='white'),
            opacity=0.9
        ),
        text=hover_texts,
        hoverinfo='text',
        name=name,
        showlegend=True
    )

def create_enhanced_3d_visualization(graph_file, attack_paths_file, output_file):
    """Create enhanced 3D visualization with full attack path connections."""

    print("Loading graph...")
    client = NetworkXClient()
    client.load(graph_file)
    graph = client.graph

    print(f"Graph loaded: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")

    print("\nLoading attack paths...")
    attack_paths = load_attack_paths(attack_paths_file)
    print(f"Loaded {len(attack_paths)} attack paths")

    print("\nExtracting attack path nodes...")
    path_nodes = extract_attack_path_nodes(attack_paths)
    print(f"Found {len(path_nodes)} nodes in attack paths")

    print("\nFinding Asset → Package → Vulnerability connections...")
    contains_edges, has_vuln_edges, connected_packages, connected_vulns = \
        find_asset_package_vuln_connections(graph, path_nodes)

    print("\nCreating 3D positions...")
    pos_3d = create_3d_positions(graph)

    print("\nBuilding visualization traces...")
    traces = []

    # 1. Base graph edges (dimmed)
    all_edges = list(graph.edges())
    base_edges_trace = create_edge_trace_3d(
        all_edges, pos_3d,
        color='rgba(180, 180, 180, 0.4)',
        width=1,
        name='Infrastructure',
        opacity=0.4
    )
    traces.append(base_edges_trace)

    # 2. CONTAINS edges (Asset → Package) - GREEN
    if contains_edges:
        contains_trace = create_edge_trace_3d(
            contains_edges, pos_3d,
            color='rgba(0, 255, 0, 0.8)',  # Bright green
            width=4,
            name='🔗 CONTAINS (Asset → Package)',
            opacity=0.8
        )
        traces.append(contains_trace)

    # 3. HAS_VULNERABILITY edges (Package → Vulnerability) - RED
    if has_vuln_edges:
        vuln_trace = create_edge_trace_3d(
            has_vuln_edges, pos_3d,
            color='rgba(255, 50, 50, 0.9)',  # Bright red
            width=4,
            name='⚠️ HAS_VULNERABILITY (Package → Vuln)',
            opacity=0.9
        )
        traces.append(vuln_trace)

    # 4. Attack path edges (conceptual paths) - PURPLE
    attack_path_edges = set()
    for path in attack_paths:
        steps = path.get('steps', [])
        for i in range(len(steps) - 1):
            u = steps[i].get('node_id')
            v = steps[i + 1].get('node_id')
            if u and v:
                attack_path_edges.add((u, v))

    if attack_path_edges:
        attack_trace = create_edge_trace_3d(
            attack_path_edges, pos_3d,
            color='rgba(255, 0, 255, 1.0)',  # Bright purple
            width=6,
            name='🚨 Attack Path Routes',
            opacity=1.0
        )
        traces.append(attack_trace)

    # 5. Nodes - categorized
    all_highlighted_nodes = path_nodes | connected_packages | connected_vulns
    other_nodes = set(graph.nodes()) - all_highlighted_nodes

    # Assets in attack paths - YELLOW
    assets_in_paths = {
        node for node in path_nodes
        if graph.nodes[node].get('node_type') in ['asset', 'container']
    }
    if assets_in_paths:
        assets_trace = create_node_trace_3d(
            assets_in_paths, graph, pos_3d,
            color='rgba(255, 215, 0, 1.0)',  # Gold
            size=15,
            name='🎯 Assets in Attack Paths',
            marker_symbol='diamond'
        )
        traces.append(assets_trace)

    # Packages connected to attack paths - CYAN
    if connected_packages:
        packages_trace = create_node_trace_3d(
            connected_packages, graph, pos_3d,
            color='rgba(0, 255, 255, 0.9)',  # Cyan
            size=10,
            name='📦 Packages (in attack chain)',
            marker_symbol='square'
        )
        traces.append(packages_trace)

    # Vulnerabilities connected to attack paths - ORANGE/RED gradient
    if connected_vulns:
        vulns_trace = create_node_trace_3d(
            connected_vulns, graph, pos_3d,
            color='rgba(255, 100, 0, 1.0)',  # Orange-red
            size=12,
            name='🔴 Vulnerabilities (exploitable)',
            marker_symbol='circle'
        )
        traces.append(vulns_trace)

    # Other nodes (dimmed)
    if other_nodes:
        other_trace = create_node_trace_3d(
            other_nodes, graph, pos_3d,
            color='rgba(150, 150, 150, 0.6)',
            size=6,
            name='Other Nodes',
            marker_symbol='circle'
        )
        traces.append(other_trace)

    # Create figure
    print("\nCreating figure...")
    fig = go.Figure(data=traces)

    # Update layout - minimal styling, all backgrounds transparent/white
    fig.update_layout(
        title=dict(
            text="Enhanced Attack Path Visualization with Full Vulnerability Chains<br>" +
                 f"<sub>Assets → Packages → Vulnerabilities | {len(attack_paths)} Attack Paths</sub>",
            font=dict(size=20, color='#000000'),
            x=0.5,
            xanchor='center'
        ),
        width=1800,
        height=1200,
        showlegend=True,
        legend=dict(
            x=0.02,
            y=0.98,
            xanchor='left',
            yanchor='top',
            bgcolor='rgba(255, 255, 255, 0.95)',
            bordercolor='#999999',
            borderwidth=1,
            font=dict(color='#000000', size=10)
        ),
        scene=dict(
            camera=dict(
                eye=dict(x=1.5, y=1.5, z=1.0),
                center=dict(x=0, y=0, z=7.5)
            ),
            xaxis=dict(
                showgrid=True,
                gridcolor='rgba(200, 200, 200, 0.3)',
                zeroline=False,
                showticklabels=False,
                showbackground=False
            ),
            yaxis=dict(
                showgrid=True,
                gridcolor='rgba(200, 200, 200, 0.3)',
                zeroline=False,
                showticklabels=False,
                showbackground=False
            ),
            zaxis=dict(
                showgrid=True,
                gridcolor='rgba(200, 200, 200, 0.3)',
                title=dict(text='SECURITY LAYERS', font=dict(color='#000000')),
                ticktext=['EXPOSED', 'INTERNAL', 'SECURE', 'CRITICAL'],
                tickvals=[0, 5, 10, 15],
                tickfont=dict(color='#000000'),
                showbackground=False
            ),
            bgcolor='rgba(0, 0, 0, 0)'  # Transparent background
        ),
        paper_bgcolor='#ffffff',  # White paper background
        plot_bgcolor='#ffffff',   # White plot background
        font=dict(color='#000000')  # Black text
    )

    # Save
    print(f"\nSaving to {output_file}...")
    fig.write_html(output_file)

    print("\n✓ Enhanced 3D visualization created successfully!")
    print(f"\nVisualization includes:")
    print(f"  - {len(contains_edges)} CONTAINS edges (Asset → Package)")
    print(f"  - {len(has_vuln_edges)} HAS_VULNERABILITY edges (Package → Vulnerability)")
    print(f"  - {len(attack_path_edges)} attack path route edges")
    print(f"  - {len(assets_in_paths)} assets in attack paths")
    print(f"  - {len(connected_packages)} packages in attack chain")
    print(f"  - {len(connected_vulns)} exploitable vulnerabilities")

if __name__ == "__main__":
    # Default paths
    graph_file = "full-demo-results/05-graphs/main-graph-with-contains.graphml"
    attack_paths_file = "full-demo-results/06-attack-analysis/attack-paths.json"
    output_file = "full-demo-results/07-visualizations/3d/attack_paths_overlay_3d_enhanced.html"

    # Allow command line overrides
    if len(sys.argv) > 1:
        graph_file = sys.argv[1]
    if len(sys.argv) > 2:
        attack_paths_file = sys.argv[2]
    if len(sys.argv) > 3:
        output_file = sys.argv[3]

    create_enhanced_3d_visualization(graph_file, attack_paths_file, output_file)
