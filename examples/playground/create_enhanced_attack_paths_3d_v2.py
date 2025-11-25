#!/usr/bin/env python3
"""
Enhanced 3D Attack Path Visualization - Version 2
With prominent vulnerability highlighting in attack chains
"""

import sys
import json
from pathlib import Path

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import plotly.graph_objects as go
import networkx as nx
from threat_radar.graph import NetworkXClient
from threat_radar.graph.models import EdgeType, NodeType

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

def find_attack_chain_components(graph, path_nodes):
    """
    Find all components of the attack chain:
    - Assets in paths
    - Packages connected to those assets
    - Vulnerabilities connected to those packages
    """
    # Assets
    assets_in_paths = {
        node for node in path_nodes
        if graph.nodes[node].get('node_type') in ['asset', 'container']
    }

    # Packages (via CONTAINS edges)
    contains_edges = set()
    connected_packages = set()

    for asset in assets_in_paths:
        for successor in graph.successors(asset):
            edge_data = graph.get_edge_data(asset, successor)
            successor_type = graph.nodes[successor].get('node_type')

            if (edge_data and edge_data.get('edge_type') == EdgeType.CONTAINS.value) or \
               (successor_type == NodeType.PACKAGE.value):
                contains_edges.add((asset, successor))
                connected_packages.add(successor)

    # Vulnerabilities (via HAS_VULNERABILITY edges)
    has_vuln_edges = set()
    connected_vulns = set()

    for package in connected_packages:
        for successor in graph.successors(package):
            edge_data = graph.get_edge_data(package, successor)
            successor_type = graph.nodes[successor].get('node_type')

            if (edge_data and edge_data.get('edge_type') == EdgeType.HAS_VULNERABILITY.value) or \
               (successor_type == NodeType.VULNERABILITY.value):
                has_vuln_edges.add((package, successor))
                connected_vulns.add(successor)

    return {
        'assets': assets_in_paths,
        'packages': connected_packages,
        'vulnerabilities': connected_vulns,
        'contains_edges': contains_edges,
        'has_vuln_edges': has_vuln_edges
    }

def create_3d_positions(graph):
    """Create 3D positions with spatial separation by node type and zone."""
    # Zone levels within each node type band
    zone_levels = {
        'dmz': 0.0, 'public': 0.0, 'internet': 0.0,
        'internal': 5.0, 'trusted': 10.0,
        'database': 15.0, 'pci': 15.0, 'unknown': 2.5,
    }

    # Node type base levels (completely separate vertical zones)
    type_base_levels = {
        'asset': 0.0,           # Assets: z = 0 to 20
        'container': 0.0,       # Containers: z = 0 to 20
        'scan_result': 0.0,     # Scan results: z = 0 to 20
        'package': 30.0,        # Packages: z = 30 to 50 (separate zone)
        'vulnerability': 60.0,  # Vulnerabilities: z = 60 to 80 (separate zone)
        'unknown': 0.0
    }

    # Create 2D layout with more spacing
    pos_2d = nx.spring_layout(graph, k=4.0, iterations=100, seed=42)

    pos_3d = {}
    for node, (x, y) in pos_2d.items():
        node_data = graph.nodes[node]

        # Get node type for base vertical zone
        node_type = node_data.get('node_type', 'unknown')
        type_base = type_base_levels.get(node_type, 0.0)

        # Get zone for offset within type zone
        zone = node_data.get('zone', 'unknown')
        if isinstance(zone, str):
            zone = zone.lower()
        zone_offset = zone_levels.get(zone, 2.5)

        # Final Z position = type base + zone offset
        z = type_base + zone_offset

        # Spread out X and Y more
        pos_3d[node] = (x * 15, y * 15, z)

    return pos_3d

def create_edge_trace(edges, pos_3d, color, width, name, opacity=0.8):
    """Create a 3D edge trace."""
    x, y, z = [], [], []
    for u, v in edges:
        if u in pos_3d and v in pos_3d:
            x.extend([pos_3d[u][0], pos_3d[v][0], None])
            y.extend([pos_3d[u][1], pos_3d[v][1], None])
            z.extend([pos_3d[u][2], pos_3d[v][2], None])

    return go.Scatter3d(
        x=x, y=y, z=z,
        mode='lines',
        line=dict(color=color, width=width),
        opacity=opacity,
        hoverinfo='skip',
        name=name,
        showlegend=True
    )

def create_node_trace(nodes, graph, pos_3d, color, size, name, marker_symbol='circle', opacity=0.9):
    """Create a 3D node trace."""
    x, y, z, texts = [], [], [], []

    for node in nodes:
        if node in pos_3d:
            node_data = graph.nodes[node]
            px, py, pz = pos_3d[node]

            x.append(px)
            y.append(py)
            z.append(pz)

            node_type = node_data.get('node_type', 'unknown')
            zone = node_data.get('zone', 'unknown')
            text = f"<b>{node[:50]}</b><br>Type: {node_type}<br>Zone: {zone}"

            # Add severity for vulnerabilities
            if node_type == 'vulnerability':
                severity = node_data.get('severity', 'unknown')
                cvss = node_data.get('cvss_score', 'N/A')
                text += f"<br>Severity: {severity}<br>CVSS: {cvss}"

            texts.append(text)

    return go.Scatter3d(
        x=x, y=y, z=z,
        mode='markers',
        marker=dict(
            size=size,
            color=color,
            symbol=marker_symbol,
            opacity=opacity,
            line=dict(width=2, color='white')
        ),
        text=texts,
        hoverinfo='text',
        name=name,
        showlegend=True
    )

def create_visualization(graph_file, attack_paths_file, output_file):
    """Create enhanced 3D visualization."""

    print("Loading graph...")
    client = NetworkXClient()
    client.load(graph_file)
    graph = client.graph

    print(f"✓ Graph: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")

    print("Loading attack paths...")
    attack_paths = load_attack_paths(attack_paths_file)
    print(f"✓ Attack paths: {len(attack_paths)}")

    print("Analyzing attack chain...")
    path_nodes = extract_attack_path_nodes(attack_paths)
    chain = find_attack_chain_components(graph, path_nodes)

    print(f"✓ Assets in paths: {len(chain['assets'])}")
    print(f"✓ Packages in chain: {len(chain['packages'])}")
    print(f"✓ Vulnerabilities in chain: {len(chain['vulnerabilities'])}")
    print(f"✓ CONTAINS edges: {len(chain['contains_edges'])}")
    print(f"✓ HAS_VULNERABILITY edges: {len(chain['has_vuln_edges'])}")

    print("Creating 3D positions...")
    pos_3d = create_3d_positions(graph)

    print("Building traces...")
    traces = []

    # 1. Base infrastructure edges (dark blue, subtle)
    all_edges = list(graph.edges())
    base_trace = create_edge_trace(
        all_edges, pos_3d,
        color='rgba(50, 80, 120, 0.15)',
        width=0.5,
        name='⚡ Infrastructure',
        opacity=0.15
    )
    traces.append(base_trace)

    # 2. CONTAINS edges (neon green glow)
    if chain['contains_edges']:
        contains_trace = create_edge_trace(
            chain['contains_edges'], pos_3d,
            color='rgba(0, 255, 100, 1.0)',  # Bright neon green
            width=6,
            name='🔗 CONTAINS (Asset → Package)',
            opacity=1.0
        )
        traces.append(contains_trace)

    # 3. HAS_VULNERABILITY edges (neon red glow) - HIGHLIGHTED
    if chain['has_vuln_edges']:
        vuln_trace = create_edge_trace(
            chain['has_vuln_edges'], pos_3d,
            color='rgba(255, 0, 80, 1.0)',  # Bright neon red/pink
            width=7,
            name='⚠️ HAS_VULNERABILITY (Package → CVE)',
            opacity=1.0
        )
        traces.append(vuln_trace)

    # 4. Attack path routes (neon purple/magenta glow)
    attack_edges = set()
    for path in attack_paths:
        steps = path.get('steps', [])
        for i in range(len(steps) - 1):
            u = steps[i].get('node_id')
            v = steps[i + 1].get('node_id')
            if u and v:
                attack_edges.add((u, v))

    if attack_edges:
        attack_trace = create_edge_trace(
            attack_edges, pos_3d,
            color='rgba(255, 0, 255, 1.0)',  # Bright neon magenta
            width=8,
            name='🚨 Attack Path Routes',
            opacity=1.0
        )
        traces.append(attack_trace)

    # 5. Nodes - categorized by role in attack chain

    # Other nodes (dark, subtle)
    all_highlighted = chain['assets'] | chain['packages'] | chain['vulnerabilities']
    other_nodes = set(graph.nodes()) - all_highlighted

    if other_nodes:
        other_trace = create_node_trace(
            other_nodes, graph, pos_3d,
            color='rgba(100, 120, 140, 0.2)',  # Dark blue-grey
            size=4,
            name='⚙️ Infrastructure',
            opacity=0.2
        )
        traces.append(other_trace)

    # Assets in attack paths (neon gold/yellow glow)
    if chain['assets']:
        assets_trace = create_node_trace(
            chain['assets'], graph, pos_3d,
            color='rgba(255, 220, 0, 1.0)',  # Bright neon gold
            size=20,
            name='🎯 ATTACK ENTRY POINTS',
            marker_symbol='diamond',
            opacity=1.0
        )
        traces.append(assets_trace)

    # Packages in attack chain (neon cyan glow)
    if chain['packages']:
        packages_trace = create_node_trace(
            chain['packages'], graph, pos_3d,
            color='rgba(0, 255, 255, 1.0)',  # Bright neon cyan
            size=14,
            name='📦 VULNERABLE PACKAGES',
            marker_symbol='square',
            opacity=1.0
        )
        traces.append(packages_trace)

    # VULNERABILITIES IN ATTACK CHAIN (bright orange glow, large, prominent!)
    if chain['vulnerabilities']:
        vulns_trace = create_node_trace(
            chain['vulnerabilities'], graph, pos_3d,
            color='rgba(255, 140, 0, 1.0)',  # Bright neon orange
            size=16,
            name='🔴 EXPLOITABLE CVES',
            marker_symbol='circle',
            opacity=1.0
        )
        traces.append(vulns_trace)

    print(f"✓ Created {len(traces)} traces")

    # Create figure with professional dark theme
    fig = go.Figure(data=traces)

    fig.update_layout(
        title=dict(
            text=f"<b>🔮 ATTACK PATH SECURITY VISUALIZATION</b><br>" +
                 f"<sub style='font-size: 14px; color: #00ffff;'>" +
                 f"Threat Intelligence Analysis • {len(chain['assets'])} Assets → " +
                 f"{len(chain['packages'])} Packages → {len(chain['vulnerabilities'])} Exploitable CVEs</sub>",
            font=dict(size=26, color='#00ffff', family='Arial Black'),
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
                eye=dict(x=1.5, y=1.5, z=0.8),
                center=dict(x=0, y=0, z=0),
                projection=dict(type='perspective')
            ),
            aspectmode='auto',
            xaxis=dict(
                showgrid=True,
                gridcolor='rgba(0, 100, 150, 0.3)',
                gridwidth=1,
                zeroline=False,
                showticklabels=False,
                showbackground=True,
                backgroundcolor='rgba(10, 10, 30, 0.3)'
            ),
            yaxis=dict(
                showgrid=True,
                gridcolor='rgba(0, 100, 150, 0.3)',
                gridwidth=1,
                zeroline=False,
                showticklabels=False,
                showbackground=True,
                backgroundcolor='rgba(10, 10, 30, 0.3)'
            ),
            zaxis=dict(
                showgrid=True,
                gridcolor='rgba(0, 200, 255, 0.4)',
                gridwidth=2,
                title=dict(
                    text='<b>ATTACK CHAIN LAYERS</b>',
                    font=dict(color='#00ffff', size=14, family='Arial Black')
                ),
                ticktext=['<b>ASSETS</b>', '<b>PACKAGES</b>', '<b>VULNERABILITIES</b>'],
                tickvals=[10, 40, 70],
                tickfont=dict(color='#00ffff', size=11, family='Courier New'),
                showbackground=True,
                backgroundcolor='rgba(10, 10, 30, 0.3)'
            ),
            bgcolor='#0a0a1e'  # Deep dark blue background
        ),
        paper_bgcolor='#000000',  # Black paper background
        plot_bgcolor='#000000',   # Black plot background
        font=dict(color='#00ffff', family='Arial')
    )

    print(f"Saving to {output_file}...")
    fig.write_html(output_file)

    print("\n✅ Visualization created successfully!")
    print(f"\nHighlighted components:")
    print(f"  - {len(chain['assets'])} Assets (gold diamonds)")
    print(f"  - {len(chain['packages'])} Packages (cyan squares)")
    print(f"  - {len(chain['vulnerabilities'])} Vulnerabilities (BRIGHT RED circles)")
    print(f"  - {len(chain['contains_edges'])} CONTAINS edges (green)")
    print(f"  - {len(chain['has_vuln_edges'])} HAS_VULNERABILITY edges (RED)")
    print(f"  - {len(attack_edges)} Attack path routes (purple)")

if __name__ == "__main__":
    graph_file = "full-demo-results/05-graphs/microservices-graph.graphml"
    attack_paths_file = "full-demo-results/06-attack-paths/microservices-attack-paths.json"
    output_file = "full-demo-results/07-visualizations/3d/microservices_attack_paths_3d.html"

    if len(sys.argv) > 1:
        graph_file = sys.argv[1]
    if len(sys.argv) > 2:
        attack_paths_file = sys.argv[2]
    if len(sys.argv) > 3:
        output_file = sys.argv[3]

    create_visualization(graph_file, attack_paths_file, output_file)
