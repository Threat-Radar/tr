#!/usr/bin/env python3
"""
Variation 4: Spectral/Kamada-Kawai Layout
Energy-minimized optimal positioning with minimal edge crossings
Quantum field theme with harmonic resonance
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

def create_spectral_layout(graph):
    """Create energy-minimized spectral layout."""
    print("Creating spectral energy-minimized layout...")

    # Use Kamada-Kawai for energy minimization (spectral alternative)
    try:
        pos_2d = nx.kamada_kawai_layout(graph, scale=1.0)
        print("Using Kamada-Kawai energy minimization")
    except:
        # Fallback to spectral if Kamada-Kawai fails
        pos_2d = nx.spectral_layout(graph, dim=2)
        print("Using spectral layout")

    # Create 3D by adding z-dimension based on graph centrality
    centrality = nx.betweenness_centrality(graph)
    max_centrality = max(centrality.values()) if centrality else 1

    pos_3d = {}
    for node, (x, y) in pos_2d.items():
        # Z-axis represents network importance (centrality)
        node_centrality = centrality.get(node, 0)
        z = (node_centrality / max_centrality) * 35 if max_centrality > 0 else 0
        pos_3d[node] = (x * 35, y * 35, z)

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
    pos_3d = create_spectral_layout(graph)

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

    # Background edges - quantum violet
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
        line=dict(color='rgba(120, 80, 180, 0.2)', width=1),
        hoverinfo='skip',
        name='Quantum Field',
        showlegend=True
    )

    # Attack edges - neon violet/pink
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
        line=dict(color='rgba(200, 100, 255, 1.0)', width=6),
        hoverinfo='skip',
        name='⚛️ Energy Pathways',
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
        marker=dict(size=8, color='rgba(140, 120, 180, 0.25)', opacity=0.25),
        text=bg_texts,
        hoverinfo='text',
        name='Background',
        showlegend=True
    )

    # Assets - neon cyan
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
        marker=dict(size=8, color='rgba(100, 255, 255, 1.0)', symbol='diamond', opacity=1.0,
                    line=dict(width=4, color='rgba(200, 255, 255, 1.0)')),
        text=asset_texts,
        hoverinfo='text',
        name='◆ Quantum States: Assets',
        showlegend=True
    )

    # Packages - neon purple
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
        marker=dict(size=8, color='rgba(180, 120, 255, 1.0)', symbol='square', opacity=1.0,
                    line=dict(width=4, color='rgba(220, 180, 255, 1.0)')),
        text=pkg_texts,
        hoverinfo='text',
        name='◼ Wave Functions: Packages',
        showlegend=True
    )

    # Vulnerabilities - hot magenta
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
        marker=dict(size=8, color='rgba(255, 50, 200, 1.0)', symbol='circle', opacity=1.0,
                    line=dict(width=4, color='rgba(255, 150, 230, 1.0)')),
        text=vuln_texts,
        hoverinfo='text',
        name='● Resonance Points: CVEs',
        showlegend=True
    )

    traces = [inactive_edge_trace, attack_chain_trace, background_trace, asset_trace, package_trace, vuln_trace]

    fig = go.Figure(data=traces)
    fig.update_layout(
        title=dict(
            text="<b>⚛️ QUANTUM RESONANCE FIELD</b><br><sub>Energy-Optimized Harmonic Layout</sub>",
            font=dict(size=24, color='#c88cff'),
            x=0.5, xanchor='center'
        ),
        width=1600, height=1000,
        showlegend=True,
        legend=dict(x=0.02, y=0.98, bgcolor='rgba(15, 10, 25, 0.9)', bordercolor='#c88cff', borderwidth=2,
                    font=dict(color='#ffffff', size=11)),
        scene=dict(
            camera=dict(eye=dict(x=1.6, y=1.6, z=1.3)),
            xaxis=dict(showgrid=True, gridcolor='rgba(150, 100, 200, 0.12)', showbackground=True,
                      backgroundcolor='rgba(15, 10, 25, 0.35)', showticklabels=False),
            yaxis=dict(showgrid=True, gridcolor='rgba(150, 100, 200, 0.12)', showbackground=True,
                      backgroundcolor='rgba(15, 10, 25, 0.35)', showticklabels=False),
            zaxis=dict(showgrid=True, gridcolor='rgba(200, 150, 255, 0.25)', showbackground=True,
                      backgroundcolor='rgba(15, 10, 25, 0.35)', showticklabels=False,
                      title=dict(text='<b>CENTRALITY ↑</b>', font=dict(color='#c88cff', size=12))),
            bgcolor='#0f0a19'
        ),
        paper_bgcolor='#000000',
        plot_bgcolor='#000000'
    )

    print(f"Saving to {output_file}...")
    fig.write_html(output_file)
    print("✅ Quantum resonance visualization complete!")

if __name__ == "__main__":
    graph_file = "full-demo-results/05-graphs/microservices-graph.graphml"
    attack_paths_file = "full-demo-results/06-attack-paths/microservices-attack-paths.json"
    output_file = "full-demo-results/07-visualizations/3d/nervous_system_spectral.html"
    create_visualization(graph_file, attack_paths_file, output_file)
