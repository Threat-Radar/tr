#!/usr/bin/env python3
"""
Nervous System Attack Path Visualization
Creates a biological nervous system aesthetic with attack paths as electrical signals
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
    """Extract nodes and edges involved in attack paths, plus connected packages and vulnerabilities."""
    attack_nodes = set()
    attack_edges = set()

    for path in attack_paths:
        steps = path.get('steps', [])
        for step in steps:
            attack_nodes.add(step.get('node_id'))

        # Extract edges between consecutive steps
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
        'has_vuln_edges': has_vuln_edges
    }

def create_organic_3d_positions(graph):
    """Create organic 3D positions with depth-based layering."""
    # Use spring layout for organic feel
    pos_2d = nx.spring_layout(graph, k=2.0, iterations=100, seed=42)

    # Calculate node "depth" based on connections (like neural layers)
    depths = {}
    for node in graph.nodes():
        # Depth based on number of connections (more = deeper in network)
        depth = len(list(graph.neighbors(node)))
        depths[node] = depth

    max_depth = max(depths.values()) if depths else 1

    pos_3d = {}
    for node, (x, y) in pos_2d.items():
        depth = depths.get(node, 0)
        # Normalize depth to 0-20 range for z-axis
        z = (depth / max_depth) * 20 if max_depth > 0 else 10
        pos_3d[node] = (x * 15, y * 15, z)

    return pos_3d

def create_visualization(graph_file, attack_paths_file, output_file):
    """Create nervous system visualization."""

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

    print("Creating organic 3D layout...")
    pos_3d = create_organic_3d_positions(graph)

    print("Building simplified neural traces...")
    traces = []

    # Get all highlighted edges (attack chain)
    all_highlight_edges = components['attack_edges'] | components['contains_edges'] | components['has_vuln_edges']

    # 1. BACKGROUND NETWORK - Visible blue-purple nervous system
    inactive_edge_x, inactive_edge_y, inactive_edge_z = [], [], []
    for u, v in graph.edges():
        if u in pos_3d and v in pos_3d:
            if (u, v) not in all_highlight_edges and (v, u) not in all_highlight_edges:
                inactive_edge_x.extend([pos_3d[u][0], pos_3d[v][0], None])
                inactive_edge_y.extend([pos_3d[u][1], pos_3d[v][1], None])
                inactive_edge_z.extend([pos_3d[u][2], pos_3d[v][2], None])

    inactive_edge_trace = go.Scatter3d(
        x=inactive_edge_x, y=inactive_edge_y, z=inactive_edge_z,
        mode='lines',
        line=dict(color='rgba(100, 120, 180, 0.3)', width=1),  # Visible blue
        hoverinfo='skip',
        name='Neural Network',
        showlegend=True
    )
    traces.append(inactive_edge_trace)

    # 2. ATTACK PATH TELEMETRY - All edges in attack chain (ONE COLOR)
    attack_chain_x, attack_chain_y, attack_chain_z = [], [], []
    for u, v in all_highlight_edges:
        if u in pos_3d and v in pos_3d:
            attack_chain_x.extend([pos_3d[u][0], pos_3d[v][0], None])
            attack_chain_y.extend([pos_3d[u][1], pos_3d[v][1], None])
            attack_chain_z.extend([pos_3d[u][2], pos_3d[v][2], None])

    attack_chain_trace = go.Scatter3d(
        x=attack_chain_x, y=attack_chain_y, z=attack_chain_z,
        mode='lines',
        line=dict(color='rgba(0, 255, 255, 1.0)', width=5),  # Bright cyan
        hoverinfo='skip',
        name='⚡ Attack Path Telemetry',
        showlegend=True
    )
    traces.append(attack_chain_trace)

    # 3. BACKGROUND NODES - Visible nervous system nodes
    all_highlight_nodes = (components['attack_nodes'] | components['connected_packages'] |
                           components['connected_vulnerabilities'])
    inactive_nodes = set(graph.nodes()) - all_highlight_nodes
    inactive_node_x, inactive_node_y, inactive_node_z = [], [], []
    inactive_texts = []

    for node in inactive_nodes:
        if node in pos_3d:
            x, y, z = pos_3d[node]
            inactive_node_x.append(x)
            inactive_node_y.append(y)
            inactive_node_z.append(z)

            node_data = graph.nodes[node]
            node_type = node_data.get('node_type', 'unknown')
            inactive_texts.append(f"<b>{node[:50]}</b><br>Type: {node_type}")

    inactive_node_trace = go.Scatter3d(
        x=inactive_node_x, y=inactive_node_y, z=inactive_node_z,
        mode='markers',
        marker=dict(
            size=6,
            color='rgba(150, 160, 200, 0.4)',  # Visible muted blue
            symbol='circle',
            opacity=0.4,
            line=dict(width=1, color='rgba(200, 200, 255, 0.3)')
        ),
        text=inactive_texts,
        hoverinfo='text',
        name='Background Neurons',
        showlegend=True
    )
    traces.append(inactive_node_trace)

    # 4. ATTACK PATH NODES - Simplified by type with same shapes
    # Assets (entry points) - Cyan diamonds
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
            size=18,
            color='rgba(255, 0, 255, 1.0)',  # Magenta - distinct from cyan edges
            symbol='diamond',
            opacity=1.0,
            line=dict(width=2, color='rgba(255, 255, 255, 0.8)')
        ),
        text=asset_texts,
        hoverinfo='text',
        name='Assets (Entry Points)',
        showlegend=True
    )
    traces.append(asset_trace)

    # Packages - Yellow squares
    package_x, package_y, package_z, package_texts = [], [], [], []
    for node in components['connected_packages']:
        if node in pos_3d:
            x, y, z = pos_3d[node]
            package_x.append(x)
            package_y.append(y)
            package_z.append(z)
            package_texts.append(f"<b>{node[:50]}</b><br>Type: Package")

    package_trace = go.Scatter3d(
        x=package_x, y=package_y, z=package_z,
        mode='markers',
        marker=dict(
            size=12,
            color='rgba(255, 200, 0, 1.0)',  # Gold
            symbol='square',
            opacity=1.0,
            line=dict(width=2, color='rgba(255, 255, 255, 0.8)')
        ),
        text=package_texts,
        hoverinfo='text',
        name='Packages',
        showlegend=True
    )
    traces.append(package_trace)

    # Vulnerabilities - Orange circles (varying size by severity)
    vuln_x, vuln_y, vuln_z, vuln_texts, vuln_sizes = [], [], [], [], []
    for node in components['connected_vulnerabilities']:
        if node in pos_3d:
            x, y, z = pos_3d[node]
            vuln_x.append(x)
            vuln_y.append(y)
            vuln_z.append(z)

            node_data = graph.nodes[node]
            severity = node_data.get('severity', 'unknown').upper()
            cvss = node_data.get('cvss_score', 'N/A')

            # Size based on severity
            if severity == 'CRITICAL':
                size = 16
            elif severity == 'HIGH':
                size = 14
            else:
                size = 10

            vuln_sizes.append(size)
            vuln_texts.append(
                f"<b>{node[:50]}</b><br>"
                f"Type: Vulnerability<br>"
                f"Severity: {severity}<br>"
                f"CVSS: {cvss}"
            )

    vuln_trace = go.Scatter3d(
        x=vuln_x, y=vuln_y, z=vuln_z,
        mode='markers',
        marker=dict(
            size=vuln_sizes,
            color='rgba(255, 100, 0, 1.0)',  # Orange
            symbol='circle',
            opacity=1.0,
            line=dict(width=2, color='rgba(255, 255, 255, 0.8)')
        ),
        text=vuln_texts,
        hoverinfo='text',
        name='Vulnerabilities',
        showlegend=True
    )
    traces.append(vuln_trace)

    print(f"✓ Created {len(traces)} traces")

    # Create figure with simplified neural theme
    fig = go.Figure(data=traces)

    fig.update_layout(
        title=dict(
            text="<b>🧠 NEURAL ATTACK PATH VISUALIZATION</b><br>" +
                 "<sub style='font-size: 14px; color: #a0a0ff;'>" +
                 f"Highlighting {len(components['attack_assets'])} Entry Points • " +
                 f"{len(components['connected_packages'])} Packages • " +
                 f"{len(components['connected_vulnerabilities'])} CVEs in Attack Chain</sub>",
            font=dict(size=26, color='#00ccff', family='Arial'),
            x=0.5,
            xanchor='center',
            y=0.97,
            yanchor='top'
        ),
        width=1800,
        height=1100,
        showlegend=True,
        legend=dict(
            x=0.02,
            y=0.95,
            xanchor='left',
            yanchor='top',
            bgcolor='rgba(10, 10, 30, 0.9)',
            bordercolor='#00ffff',
            borderwidth=2,
            font=dict(color='#ffffff', size=12, family='Courier New')
        ),
        scene=dict(
            camera=dict(
                eye=dict(x=1.8, y=1.8, z=1.2),
                center=dict(x=0, y=0, z=0),
                projection=dict(type='perspective')
            ),
            aspectmode='auto',
            xaxis=dict(
                showgrid=False,
                zeroline=False,
                showticklabels=False,
                showbackground=True,
                backgroundcolor='rgba(5, 5, 20, 0.5)'
            ),
            yaxis=dict(
                showgrid=False,
                zeroline=False,
                showticklabels=False,
                showbackground=True,
                backgroundcolor='rgba(5, 5, 20, 0.5)'
            ),
            zaxis=dict(
                showgrid=True,
                gridcolor='rgba(100, 150, 200, 0.2)',
                gridwidth=1,
                title=dict(
                    text='<b>NETWORK DEPTH</b>',
                    font=dict(color='#00ffff', size=14, family='Arial Black')
                ),
                tickfont=dict(color='#00ffff', size=10),
                showbackground=True,
                backgroundcolor='rgba(5, 5, 20, 0.5)'
            ),
            bgcolor='#0a0a1e'  # Dark blue-purple background
        ),
        paper_bgcolor='#000000',
        plot_bgcolor='#000000',
        font=dict(color='#ccccff', family='Arial'),
        annotations=[
            dict(
                text="<b>ATTACK PATH TELEMETRY</b><br><br>" +
                     "💠 Diamonds = Assets<br>" +
                     "📦 Squares = Packages<br>" +
                     "⭕ Circles = Vulnerabilities<br>" +
                     "💠 Cyan = Attack Chain",
                xref="paper", yref="paper",
                x=0.98, y=0.65,
                xanchor="right", yanchor="middle",
                showarrow=False,
                font=dict(size=12, color="#bbbbff", family="Arial"),
                bgcolor="rgba(20,20,40,0.8)",
                bordercolor="#6666ff",
                borderwidth=2,
                borderpad=10
            )
        ]
    )

    print(f"Saving to {output_file}...")
    fig.write_html(output_file)

    print("\n✅ Neural network visualization created successfully!")
    print(f"\n🧠 NERVOUS SYSTEM NETWORK:")
    print(f"  • {graph.number_of_nodes()} total neurons")
    print(f"  • {graph.number_of_edges()} total synapses")
    print(f"  • {len(inactive_nodes)} background nodes (visible at 40% opacity)")
    print(f"\n⚡ ATTACK PATH TELEMETRY HIGHLIGHTED:")
    print(f"  • {len(components['attack_assets'])} Assets (cyan diamonds)")
    print(f"  • {len(components['connected_packages'])} Packages (gold squares)")
    print(f"  • {len(components['connected_vulnerabilities'])} Vulnerabilities (orange circles)")
    print(f"  • {len(all_highlight_edges)} Attack chain connections (cyan edges)")
    print(f"\n🎨 SIMPLIFIED COLOR SCHEME:")
    print(f"  • Blue-purple: Background nervous system (visible)")
    print(f"  • Cyan: Attack path telemetry (all edges in attack chain)")
    print(f"  • Cyan diamonds: Entry point assets")
    print(f"  • Gold squares: Vulnerable packages")
    print(f"  • Orange circles: CVEs (size varies by severity)")

if __name__ == "__main__":
    graph_file = "full-demo-results/05-graphs/microservices-graph.graphml"
    attack_paths_file = "full-demo-results/06-attack-paths/microservices-attack-paths.json"
    output_file = "full-demo-results/07-visualizations/3d/nervous_system_attack_paths.html"

    if len(sys.argv) > 1:
        graph_file = sys.argv[1]
    if len(sys.argv) > 2:
        attack_paths_file = sys.argv[2]
    if len(sys.argv) > 3:
        output_file = sys.argv[3]

    create_visualization(graph_file, attack_paths_file, output_file)
