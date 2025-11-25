#!/usr/bin/env python3
"""
Nervous System 3D Visualization - Even 3D Distribution
Uses true 3D spring layout for even spatial distribution across all dimensions
"""

import sys
import json
from pathlib import Path

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import plotly.graph_objects as go
import networkx as nx
from threat_radar.graph import NetworkXClient

def load_attack_paths(paths_file):
    """Load attack paths from JSON file."""
    with open(paths_file) as f:
        data = json.load(f)
    return data.get('attack_paths', [])

def extract_attack_path_components(graph, attack_paths):
    """Extract all nodes and edges involved in attack paths and their connected components."""
    # Get all nodes in attack paths
    attack_nodes = set()
    for path in attack_paths:
        for step in path.get('steps', []):
            attack_nodes.add(step.get('node_id'))

    # Get attack path edges
    attack_edges = set()
    for path in attack_paths:
        steps = path.get('steps', [])
        for i in range(len(steps) - 1):
            node1 = steps[i].get('node_id')
            node2 = steps[i + 1].get('node_id')
            if node1 and node2:
                attack_edges.add((node1, node2))
                attack_edges.add((node2, node1))  # Both directions

    # Find assets in attack paths
    attack_assets = {
        node for node in attack_nodes
        if graph.nodes[node].get('node_type') in ['asset', 'container']
    }

    # Find all packages connected to attack assets first
    all_packages = set()
    for asset in attack_assets:
        for neighbor in graph.neighbors(asset):
            edge_data = graph.get_edge_data(asset, neighbor)
            neighbor_type = graph.nodes[neighbor].get('node_type')

            if edge_data and (edge_data.get('edge_type') == 'CONTAINS' or neighbor_type == 'package'):
                all_packages.add(neighbor)

    # Find HIGH SEVERITY vulnerabilities (CVSS > 8) and the packages that have them
    connected_vulnerabilities = set()
    has_vuln_edges = set()
    packages_with_high_severity = set()

    for package in all_packages:
        package_has_high_severity = False
        for neighbor in graph.neighbors(package):
            edge_data = graph.get_edge_data(package, neighbor)
            neighbor_type = graph.nodes[neighbor].get('node_type')

            if edge_data and (edge_data.get('edge_type') == 'HAS_VULNERABILITY' or neighbor_type == 'vulnerability'):
                # Only include CVEs with CVSS > 8
                neighbor_data = graph.nodes[neighbor]
                cvss_score = neighbor_data.get('cvss_score', 0)
                if isinstance(cvss_score, (int, float)) and cvss_score > 8:
                    connected_vulnerabilities.add(neighbor)
                    has_vuln_edges.add((package, neighbor))
                    package_has_high_severity = True

        if package_has_high_severity:
            packages_with_high_severity.add(package)

    # Now only create CONTAINS edges for packages with high-severity CVEs
    connected_packages = packages_with_high_severity
    contains_edges = set()

    for asset in attack_assets:
        for neighbor in graph.neighbors(asset):
            if neighbor in connected_packages:
                edge_data = graph.get_edge_data(asset, neighbor)
                neighbor_type = graph.nodes[neighbor].get('node_type')

                if edge_data and (edge_data.get('edge_type') == 'CONTAINS' or neighbor_type == 'package'):
                    contains_edges.add((asset, neighbor))

    return {
        'attack_nodes': attack_nodes,
        'attack_edges': attack_edges,
        'attack_assets': attack_assets,
        'connected_packages': connected_packages,
        'connected_vulnerabilities': connected_vulnerabilities,
        'contains_edges': contains_edges,
        'has_vuln_edges': has_vuln_edges,
    }

def create_3d_even_layout(graph):
    """Create true 3D layout with even distribution across all dimensions."""
    # Use 3D spring layout for even spatial distribution
    print("Creating 3D spring layout (this may take a moment)...")
    pos_3d_raw = nx.spring_layout(
        graph,
        dim=3,  # TRUE 3D LAYOUT
        k=2.5,  # Optimal distance between nodes
        iterations=150,  # More iterations for better distribution
        seed=42
    )

    # Scale positions for better visibility
    pos_3d = {}
    for node, (x, y, z) in pos_3d_raw.items():
        pos_3d[node] = (x * 25, y * 25, z * 25)

    return pos_3d

def create_visualization(graph_file, attack_paths_file, output_file):
    """Create nervous system visualization with even 3D distribution."""

    print("Loading graph...")
    client = NetworkXClient()
    client.load(graph_file)
    graph = client.graph

    print(f"✓ Graph: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")

    print("Loading attack paths...")
    attack_paths = load_attack_paths(attack_paths_file)
    print(f"✓ Attack paths: {len(attack_paths)}")

    print("Analyzing attack components...")
    components = extract_attack_path_components(graph, attack_paths)

    print(f"✓ Attack assets: {len(components['attack_assets'])}")
    print(f"✓ Connected packages: {len(components['connected_packages'])}")
    print(f"✓ Connected vulnerabilities: {len(components['connected_vulnerabilities'])}")
    print(f"✓ Attack path edges: {len(components['attack_edges'])}")
    print(f"✓ CONTAINS edges: {len(components['contains_edges'])}")
    print(f"✓ HAS_VULNERABILITY edges: {len(components['has_vuln_edges'])}")

    print("Creating even 3D layout...")
    pos_3d = create_3d_even_layout(graph)

    print("Building neural traces...")

    # Identify all highlighted nodes and edges
    highlighted_nodes = (
        components['attack_assets'] |
        components['connected_packages'] |
        components['connected_vulnerabilities']
    )

    all_attack_edges = (
        components['attack_edges'] |
        components['contains_edges'] |
        components['has_vuln_edges']
    )

    # TRACE 1: Background network edges (NOT in attack chain)
    inactive_edge_x, inactive_edge_y, inactive_edge_z = [], [], []
    for u, v in graph.edges():
        if (u, v) not in all_attack_edges and (v, u) not in all_attack_edges:
            if u in pos_3d and v in pos_3d:
                x0, y0, z0 = pos_3d[u]
                x1, y1, z1 = pos_3d[v]
                inactive_edge_x.extend([x0, x1, None])
                inactive_edge_y.extend([y0, y1, None])
                inactive_edge_z.extend([z0, z1, None])

    inactive_edge_trace = go.Scatter3d(
        x=inactive_edge_x, y=inactive_edge_y, z=inactive_edge_z,
        mode='lines',
        line=dict(color='rgba(100, 120, 180, 0.4)', width=1),
        hoverinfo='skip',
        name='🧠 Neural Network',
        showlegend=True
    )

    # TRACE 2: Attack chain edges (ALL CYAN)
    attack_chain_x, attack_chain_y, attack_chain_z = [], [], []
    for u, v in all_attack_edges:
        if u in pos_3d and v in pos_3d:
            x0, y0, z0 = pos_3d[u]
            x1, y1, z1 = pos_3d[v]
            attack_chain_x.extend([x0, x1, None])
            attack_chain_y.extend([y0, y1, None])
            attack_chain_z.extend([z0, z1, None])

    attack_chain_trace = go.Scatter3d(
        x=attack_chain_x, y=attack_chain_y, z=attack_chain_z,
        mode='lines',
        line=dict(color='rgba(0, 255, 255, 1.0)', width=5),
        hoverinfo='skip',
        name='⚡ Attack Path Telemetry',
        showlegend=True
    )

    # TRACE 3: Background nodes (not highlighted)
    background_nodes = set(graph.nodes()) - highlighted_nodes
    bg_x, bg_y, bg_z, bg_texts = [], [], [], []

    for node in background_nodes:
        if node in pos_3d:
            x, y, z = pos_3d[node]
            bg_x.append(x)
            bg_y.append(y)
            bg_z.append(z)
            node_data = graph.nodes[node]
            node_type = node_data.get('node_type', 'unknown')
            bg_texts.append(f"<b>{node[:40]}</b><br>Type: {node_type}")

    background_trace = go.Scatter3d(
        x=bg_x, y=bg_y, z=bg_z,
        mode='markers',
        marker=dict(
            size=8,
            color='rgba(150, 150, 180, 0.4)',
            symbol='circle',
            opacity=0.4
        ),
        text=bg_texts,
        hoverinfo='text',
        name='Background Nodes',
        showlegend=True
    )

    # TRACE 4: Assets (magenta diamonds)
    asset_x, asset_y, asset_z, asset_texts = [], [], [], []

    for node in components['attack_assets']:
        if node in pos_3d:
            x, y, z = pos_3d[node]
            asset_x.append(x)
            asset_y.append(y)
            asset_z.append(z)
            node_data = graph.nodes[node]
            asset_texts.append(f"<b>{node[:50]}</b><br>Type: Asset<br>Zone: {node_data.get('zone', 'unknown')}")

    asset_trace = go.Scatter3d(
        x=asset_x, y=asset_y, z=asset_z,
        mode='markers',
        marker=dict(
            size=8,
            color='rgba(255, 0, 255, 1.0)',  # Magenta - distinct from cyan edges
            symbol='diamond',
            opacity=1.0,
            line=dict(width=2, color='rgba(255, 255, 255, 0.8)')
        ),
        text=asset_texts,
        hoverinfo='text',
        name='🎯 Assets (Entry Points)',
        showlegend=True
    )

    # TRACE 5: Packages (gold squares)
    pkg_x, pkg_y, pkg_z, pkg_texts = [], [], [], []

    for node in components['connected_packages']:
        if node in pos_3d:
            x, y, z = pos_3d[node]
            pkg_x.append(x)
            pkg_y.append(y)
            pkg_z.append(z)
            node_data = graph.nodes[node]
            pkg_texts.append(f"<b>{node[:50]}</b><br>Type: Package")

    package_trace = go.Scatter3d(
        x=pkg_x, y=pkg_y, z=pkg_z,
        mode='markers',
        marker=dict(
            size=8,
            color='rgba(255, 200, 0, 1.0)',  # Gold
            symbol='square',
            opacity=1.0,
            line=dict(width=2, color='rgba(255, 255, 255, 0.8)')
        ),
        text=pkg_texts,
        hoverinfo='text',
        name='📦 Vulnerable Packages',
        showlegend=True
    )

    # TRACE 6: Vulnerabilities (orange circles)
    vuln_x, vuln_y, vuln_z, vuln_texts = [], [], [], []

    for node in components['connected_vulnerabilities']:
        if node in pos_3d:
            x, y, z = pos_3d[node]
            vuln_x.append(x)
            vuln_y.append(y)
            vuln_z.append(z)

            node_data = graph.nodes[node]
            severity = node_data.get('severity', 'unknown')
            cvss = node_data.get('cvss_score', 'N/A')
            vuln_texts.append(f"<b>{node}</b><br>Severity: {severity}<br>CVSS: {cvss}")

    vuln_trace = go.Scatter3d(
        x=vuln_x, y=vuln_y, z=vuln_z,
        mode='markers',
        marker=dict(
            size=8,
            color='rgba(255, 100, 0, 1.0)',  # Orange
            symbol='circle',
            opacity=1.0,
            line=dict(width=2, color='rgba(255, 255, 255, 0.8)')
        ),
        text=vuln_texts,
        hoverinfo='text',
        name='🔴 High-Severity CVEs (>8)',
        showlegend=True
    )

    traces = [
        inactive_edge_trace,
        attack_chain_trace,
        background_trace,
        asset_trace,
        package_trace,
        vuln_trace
    ]

    print(f"✓ Created {len(traces)} traces")

    # Create figure with dark theme
    fig = go.Figure(data=traces)

    fig.update_layout(
        title=dict(
            text="<b>🧠 NERVOUS SYSTEM ATTACK PATH ANALYSIS</b><br>" +
                 "<sub style='font-size: 14px;'>Even 3D Spatial Distribution • High-Severity CVEs (CVSS > 8)</sub>",
            font=dict(size=24, color='#00ffff'),
            x=0.5,
            xanchor='center'
        ),
        width=1600,
        height=1000,
        showlegend=True,
        legend=dict(
            x=0.02,
            y=0.98,
            bgcolor='rgba(10, 10, 30, 0.85)',
            bordercolor='#00ffff',
            borderwidth=2,
            font=dict(color='#ffffff', size=11)
        ),
        scene=dict(
            camera=dict(
                eye=dict(x=1.3, y=1.3, z=1.3),
                center=dict(x=0, y=0, z=0)
            ),
            xaxis=dict(
                showgrid=True,
                gridcolor='rgba(100, 150, 200, 0.15)',
                showbackground=True,
                backgroundcolor='rgba(10, 10, 30, 0.3)',
                showticklabels=False
            ),
            yaxis=dict(
                showgrid=True,
                gridcolor='rgba(100, 150, 200, 0.15)',
                showbackground=True,
                backgroundcolor='rgba(10, 10, 30, 0.3)',
                showticklabels=False
            ),
            zaxis=dict(
                showgrid=True,
                gridcolor='rgba(100, 150, 200, 0.15)',
                showbackground=True,
                backgroundcolor='rgba(10, 10, 30, 0.3)',
                showticklabels=False
            ),
            bgcolor='#0a0a1e'
        ),
        paper_bgcolor='#000000',
        plot_bgcolor='#000000'
    )

    print(f"Saving to {output_file}...")
    fig.write_html(output_file)

    print("\n✅ Even 3D nervous system visualization created successfully!")
    print(f"\n🧠 NERVOUS SYSTEM NETWORK:")
    print(f"  • {graph.number_of_nodes()} total neurons")
    print(f"  • {graph.number_of_edges()} total synapses")
    print(f"  • {len(background_nodes)} background nodes (visible)")

    print(f"\n⚡ ATTACK PATH TELEMETRY HIGHLIGHTED:")
    print(f"  • {len(components['attack_assets'])} Assets (magenta diamonds)")
    print(f"  • {len(components['connected_packages'])} Packages (gold squares)")
    print(f"  • {len(components['connected_vulnerabilities'])} Vulnerabilities (orange circles)")
    print(f"  • {len(all_attack_edges)} Attack chain connections (cyan edges)")

    print(f"\n🎯 3D LAYOUT:")
    print(f"  • True 3D spring algorithm (dim=3)")
    print(f"  • Even spatial distribution across X, Y, Z")
    print(f"  • Optimized node spacing (k=2.5)")

if __name__ == "__main__":
    graph_file = "full-demo-results/05-graphs/microservices-graph.graphml"
    attack_paths_file = "full-demo-results/06-attack-paths/microservices-attack-paths.json"
    output_file = "full-demo-results/07-visualizations/3d/nervous_system_3d_even.html"

    if len(sys.argv) > 1:
        graph_file = sys.argv[1]
    if len(sys.argv) > 2:
        attack_paths_file = sys.argv[2]
    if len(sys.argv) > 3:
        output_file = sys.argv[3]

    create_visualization(graph_file, attack_paths_file, output_file)
