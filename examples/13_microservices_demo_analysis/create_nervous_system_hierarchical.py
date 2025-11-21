#!/usr/bin/env python3
"""
Variation 1: Hierarchical Layered Layout
Nodes arranged in distinct vertical layers: Assets → Packages → Vulnerabilities
Deep space theme with vertical energy flow
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
    with open(paths_file) as f:
        data = json.load(f)
    return data.get('attack_paths', [])

def extract_attack_path_components(graph, attack_paths):
    attack_nodes = set()
    for path in attack_paths:
        for step in path.get('steps', []):
            attack_nodes.add(step.get('node_id'))

    attack_edges = set()
    for path in attack_paths:
        steps = path.get('steps', [])
        for i in range(len(steps) - 1):
            node1 = steps[i].get('node_id')
            node2 = steps[i + 1].get('node_id')
            if node1 and node2:
                attack_edges.add((node1, node2))
                attack_edges.add((node2, node1))

    attack_assets = {
        node for node in attack_nodes
        if graph.nodes[node].get('node_type') in ['asset', 'container']
    }

    all_packages = set()
    for asset in attack_assets:
        for neighbor in graph.neighbors(asset):
            edge_data = graph.get_edge_data(asset, neighbor)
            neighbor_type = graph.nodes[neighbor].get('node_type')
            if edge_data and (edge_data.get('edge_type') == 'CONTAINS' or neighbor_type == 'package'):
                all_packages.add(neighbor)

    connected_vulnerabilities = set()
    has_vuln_edges = set()
    packages_with_high_severity = set()

    for package in all_packages:
        package_has_high_severity = False
        for neighbor in graph.neighbors(package):
            edge_data = graph.get_edge_data(package, neighbor)
            neighbor_type = graph.nodes[neighbor].get('node_type')
            if edge_data and (edge_data.get('edge_type') == 'HAS_VULNERABILITY' or neighbor_type == 'vulnerability'):
                neighbor_data = graph.nodes[neighbor]
                cvss_score = neighbor_data.get('cvss_score', 0)
                if isinstance(cvss_score, (int, float)) and cvss_score > 8:
                    connected_vulnerabilities.add(neighbor)
                    has_vuln_edges.add((package, neighbor))
                    package_has_high_severity = True
        if package_has_high_severity:
            packages_with_high_severity.add(package)

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

def create_hierarchical_layout(graph, components):
    """Create hierarchical layout with distinct vertical layers."""
    print("Creating hierarchical layered layout...")

    # Assign nodes to layers
    node_layers = {}
    for node in graph.nodes():
        node_type = graph.nodes[node].get('node_type')
        if node_type in ['asset', 'container']:
            node_layers[node] = 0  # Bottom layer
        elif node_type == 'package':
            node_layers[node] = 1  # Middle layer
        elif node_type == 'vulnerability':
            node_layers[node] = 2  # Top layer
        else:
            node_layers[node] = 0.5  # Between layers

    # Create 2D layout within each layer
    pos_2d = nx.spring_layout(graph, k=3.0, iterations=100, seed=42)

    pos_3d = {}
    for node, (x, y) in pos_2d.items():
        layer = node_layers.get(node, 0)
        z = layer * 30  # 30 units between layers
        pos_3d[node] = (x * 25, y * 25, z)

    return pos_3d

def create_visualization(graph_file, attack_paths_file, output_file):
    print("Loading graph...")
    client = NetworkXClient()
    client.load(graph_file)
    graph = client.graph
    print(f"✓ Graph: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")

    print("Loading attack paths...")
    attack_paths = load_attack_paths(attack_paths_file)
    print(f"✓ Attack paths: {len(attack_paths)}")

    components = extract_attack_path_components(graph, attack_paths)
    pos_3d = create_hierarchical_layout(graph, components)

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

    # Background edges - deep purple
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
        line=dict(color='rgba(80, 60, 120, 0.3)', width=1),
        hoverinfo='skip',
        name='Neural Network',
        showlegend=True
    )

    # Attack edges - electric blue with glow
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
        line=dict(color='rgba(0, 200, 255, 1.0)', width=6),
        hoverinfo='skip',
        name='⚡ Energy Flow',
        showlegend=True
    )

    # Background nodes
    background_nodes = set(graph.nodes()) - highlighted_nodes
    bg_x, bg_y, bg_z, bg_texts = [], [], [], []
    for node in background_nodes:
        if node in pos_3d:
            x, y, z = pos_3d[node]
            bg_x.append(x)
            bg_y.append(y)
            bg_z.append(z)
            bg_texts.append(f"<b>{node[:40]}</b>")

    background_trace = go.Scatter3d(
        x=bg_x, y=bg_y, z=bg_z,
        mode='markers',
        marker=dict(size=8, color='rgba(100, 80, 140, 0.35)', opacity=0.35),
        text=bg_texts,
        hoverinfo='text',
        name='Background',
        showlegend=True
    )

    # Assets - bright cyan
    asset_x, asset_y, asset_z, asset_texts = [], [], [], []
    for node in components['attack_assets']:
        if node in pos_3d:
            x, y, z = pos_3d[node]
            asset_x.append(x)
            asset_y.append(y)
            asset_z.append(z)
            asset_texts.append(f"<b>{node[:50]}</b>")

    asset_trace = go.Scatter3d(
        x=asset_x, y=asset_y, z=asset_z,
        mode='markers',
        marker=dict(size=8, color='rgba(0, 255, 255, 1.0)', symbol='diamond', opacity=1.0,
                    line=dict(width=3, color='rgba(255, 255, 255, 0.9)')),
        text=asset_texts,
        hoverinfo='text',
        name='⬇️ Layer 1: Assets',
        showlegend=True
    )

    # Packages - electric green
    pkg_x, pkg_y, pkg_z, pkg_texts = [], [], [], []
    for node in components['connected_packages']:
        if node in pos_3d:
            x, y, z = pos_3d[node]
            pkg_x.append(x)
            pkg_y.append(y)
            pkg_z.append(z)
            pkg_texts.append(f"<b>{node[:50]}</b>")

    package_trace = go.Scatter3d(
        x=pkg_x, y=pkg_y, z=pkg_z,
        mode='markers',
        marker=dict(size=8, color='rgba(0, 255, 150, 1.0)', symbol='square', opacity=1.0,
                    line=dict(width=3, color='rgba(255, 255, 255, 0.9)')),
        text=pkg_texts,
        hoverinfo='text',
        name='⬆️ Layer 2: Packages',
        showlegend=True
    )

    # Vulnerabilities - hot pink
    vuln_x, vuln_y, vuln_z, vuln_texts = [], [], [], []
    for node in components['connected_vulnerabilities']:
        if node in pos_3d:
            x, y, z = pos_3d[node]
            vuln_x.append(x)
            vuln_y.append(y)
            vuln_z.append(z)
            node_data = graph.nodes[node]
            vuln_texts.append(f"<b>{node}</b><br>CVSS: {node_data.get('cvss_score', 'N/A')}")

    vuln_trace = go.Scatter3d(
        x=vuln_x, y=vuln_y, z=vuln_z,
        mode='markers',
        marker=dict(size=8, color='rgba(255, 0, 200, 1.0)', symbol='circle', opacity=1.0,
                    line=dict(width=3, color='rgba(255, 255, 255, 0.9)')),
        text=vuln_texts,
        hoverinfo='text',
        name='⬆️ Layer 3: CVEs',
        showlegend=True
    )

    traces = [inactive_edge_trace, attack_chain_trace, background_trace, asset_trace, package_trace, vuln_trace]

    fig = go.Figure(data=traces)
    fig.update_layout(
        title=dict(
            text="<b>🌌 HIERARCHICAL ENERGY FLOW</b><br><sub>Vertical Attack Path Layers</sub>",
            font=dict(size=24, color='#00ccff'),
            x=0.5, xanchor='center'
        ),
        width=1600, height=1000,
        showlegend=True,
        legend=dict(x=0.02, y=0.98, bgcolor='rgba(5, 5, 20, 0.9)', bordercolor='#00ccff', borderwidth=2,
                    font=dict(color='#ffffff', size=11)),
        scene=dict(
            camera=dict(eye=dict(x=1.5, y=1.5, z=1.2)),
            xaxis=dict(showgrid=True, gridcolor='rgba(0, 150, 200, 0.1)', showbackground=True,
                      backgroundcolor='rgba(5, 5, 20, 0.4)', showticklabels=False),
            yaxis=dict(showgrid=True, gridcolor='rgba(0, 150, 200, 0.1)', showbackground=True,
                      backgroundcolor='rgba(5, 5, 20, 0.4)', showticklabels=False),
            zaxis=dict(showgrid=True, gridcolor='rgba(0, 200, 255, 0.3)', showbackground=True,
                      backgroundcolor='rgba(5, 5, 20, 0.4)', showticklabels=False,
                      title=dict(text='<b>LAYERS ↑</b>', font=dict(color='#00ccff', size=12))),
            bgcolor='#000515'
        ),
        paper_bgcolor='#000000',
        plot_bgcolor='#000000'
    )

    print(f"Saving to {output_file}...")
    fig.write_html(output_file)
    print("✅ Hierarchical layered visualization complete!")

if __name__ == "__main__":
    graph_file = "full-demo-results/05-graphs/microservices-graph.graphml"
    attack_paths_file = "full-demo-results/06-attack-paths/microservices-attack-paths.json"
    output_file = "full-demo-results/07-visualizations/3d/nervous_system_hierarchical.html"
    create_visualization(graph_file, attack_paths_file, output_file)
