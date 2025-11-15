#!/usr/bin/env python3
"""
Example 3: Dynamic 3D Network Topology Visualizations

This example demonstrates advanced 3D topology visualizations:
- Layered 3D network architecture (DMZ → Internal → Database)
- Animated zone transitions showing attack progression
- Rotating zone boundaries with security context
- Force-directed 3D with gravity zones
- Camera flythrough tour of infrastructure
- Exploding topology showing network segmentation
"""

import json
import math
from pathlib import Path
import random
from threat_radar.graph import NetworkXClient, GraphAnalyzer
from threat_radar.visualization import NetworkTopologyVisualizer, AttackPathVisualizer

# Check if plotly is available
try:
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    import networkx as nx
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    print("⚠️  Plotly not available. Install with: pip install plotly")


def create_layered_3d_topology(visualizer, output_file):
    """Create 3D visualization with actual network layers (DMZ, Internal, Database)."""

    if not PLOTLY_AVAILABLE:
        print("   ⚠️  Skipping layered 3D topology (plotly required)")
        return

    print(f"\n   Creating layered 3D network topology...")

    # Get graph
    G = visualizer.graph

    # Group nodes by zone
    zones = {}
    for node, data in G.nodes(data=True):
        zone = data.get('zone', 'unknown').lower()
        if zone not in zones:
            zones[zone] = []
        zones[zone].append(node)

    print(f"      Found zones: {list(zones.keys())}")

    # Define Z-levels for each zone (network layers)
    zone_levels = {
        'dmz': 0.0,          # Bottom layer - exposed to internet
        'public': 0.0,
        'internet': 0.0,
        'untrusted': 0.0,
        'internal': 3.0,     # Middle layer - internal apps
        'application': 3.0,
        'trusted': 6.0,      # Top layer - most secure
        'secure': 6.0,
        'database': 9.0,     # Highest layer - data storage
        'unknown': 1.5,      # Default middle
    }

    zone_colors = {
        'dmz': '#ff6b6b',
        'public': '#ff8c42',
        'internet': '#ffa07a',
        'untrusted': '#ff6347',
        'internal': '#4ecdc4',
        'application': '#4ecdc4',
        'trusted': '#45b7d1',
        'secure': '#96ceb4',
        'database': '#574b90',
        'unknown': '#95a5a6',
    }

    # Calculate 2D layout within each zone
    pos_3d = {}

    for zone_name, zone_nodes in zones.items():
        z_level = zone_levels.get(zone_name, 1.5)

        # Create subgraph for this zone
        subgraph = G.subgraph(zone_nodes)

        # 2D layout for nodes in this zone
        if len(zone_nodes) > 1:
            pos_2d = nx.spring_layout(subgraph, k=2, iterations=50, seed=42)
        else:
            pos_2d = {zone_nodes[0]: (0, 0)}

        # Add Z coordinate (layer)
        for node, (x, y) in pos_2d.items():
            pos_3d[node] = (x * 3, y * 3, z_level)

    # Create edge traces
    edge_x = []
    edge_y = []
    edge_z = []
    edge_colors = []

    for u, v in G.edges():
        if u in pos_3d and v in pos_3d:
            u_zone = G.nodes[u].get('zone', 'unknown').lower()
            v_zone = G.nodes[v].get('zone', 'unknown').lower()

            edge_x.extend([pos_3d[u][0], pos_3d[v][0], None])
            edge_y.extend([pos_3d[u][1], pos_3d[v][1], None])
            edge_z.extend([pos_3d[u][2], pos_3d[v][2], None])

            # Cross-zone edges are highlighted
            if u_zone != v_zone:
                edge_colors.extend(['#dc143c', '#dc143c', None])  # Red for cross-zone
            else:
                edge_colors.extend(['#bdc3c7', '#bdc3c7', None])  # Gray for same-zone

    # Since Scatter3d doesn't support per-segment colors easily, we'll use a single color
    edge_trace = go.Scatter3d(
        x=edge_x,
        y=edge_y,
        z=edge_z,
        mode='lines',
        line=dict(color='#bdc3c7', width=2),
        hoverinfo='none',
        showlegend=False,
    )

    # Create cross-zone edges separately (highlighted)
    cross_zone_x = []
    cross_zone_y = []
    cross_zone_z = []

    for u, v in G.edges():
        if u in pos_3d and v in pos_3d:
            u_zone = G.nodes[u].get('zone', 'unknown').lower()
            v_zone = G.nodes[v].get('zone', 'unknown').lower()

            if u_zone != v_zone:
                cross_zone_x.extend([pos_3d[u][0], pos_3d[v][0], None])
                cross_zone_y.extend([pos_3d[u][1], pos_3d[v][1], None])
                cross_zone_z.extend([pos_3d[u][2], pos_3d[v][2], None])

    cross_zone_trace = go.Scatter3d(
        x=cross_zone_x,
        y=cross_zone_y,
        z=cross_zone_z,
        mode='lines',
        line=dict(color='#dc143c', width=4),
        hoverinfo='text',
        text='Cross-Zone Connection',
        name='Cross-Zone Link',
    )

    # Create node traces per zone
    node_traces = []

    for zone_name, zone_nodes in zones.items():
        node_x = []
        node_y = []
        node_z = []
        node_texts = []

        for node in zone_nodes:
            if node in pos_3d:
                node_data = G.nodes[node]
                name = node_data.get('name', node)

                x, y, z = pos_3d[node]
                node_x.append(x)
                node_y.append(y)
                node_z.append(z)

                criticality = node_data.get('criticality', 'unknown')
                node_texts.append(
                    f"<b>{name}</b><br>"
                    f"Zone: {zone_name.upper()}<br>"
                    f"Layer: {z:.1f}<br>"
                    f"Criticality: {criticality}"
                )

        color = zone_colors.get(zone_name, '#95a5a6')

        node_trace = go.Scatter3d(
            x=node_x,
            y=node_y,
            z=node_z,
            mode='markers',
            marker=dict(
                size=12,
                color=color,
                line=dict(width=2, color='white'),
            ),
            text=node_texts,
            hoverinfo='text',
            name=f"{zone_name.upper()} Zone",
        )
        node_traces.append(node_trace)

    # Create layer planes (semi-transparent)
    layer_shapes = []

    for zone_name, z_level in set(zone_levels.items()):
        # Skip unknown
        if zone_name == 'unknown':
            continue

        # Create a mesh surface for the layer
        mesh_x = [-5, 5, 5, -5, -5]
        mesh_y = [-5, -5, 5, 5, -5]
        mesh_z = [z_level] * 5

        color = zone_colors.get(zone_name, '#95a5a6')

        layer_trace = go.Scatter3d(
            x=mesh_x,
            y=mesh_y,
            z=mesh_z,
            mode='lines',
            line=dict(color=color, width=2, dash='dot'),
            hoverinfo='text',
            text=f"{zone_name.upper()} Layer (Z={z_level})",
            showlegend=False,
            opacity=0.3,
        )
        node_traces.append(layer_trace)

    # Create figure
    fig = go.Figure(data=[edge_trace, cross_zone_trace] + node_traces)

    fig.update_layout(
        title=dict(
            text="Layered 3D Network Topology<br>"
                 "<sub>Z-Axis = Security Layer | Colors = Network Zones</sub>",
            font=dict(size=20)
        ),
        width=1600,
        height=1000,
        showlegend=True,
        legend=dict(
            yanchor="top",
            y=0.99,
            xanchor="right",
            x=0.99
        ),
        scene=dict(
            xaxis=dict(showgrid=True, zeroline=False, showticklabels=False, title=''),
            yaxis=dict(showgrid=True, zeroline=False, showticklabels=False, title=''),
            zaxis=dict(
                showgrid=True,
                zeroline=False,
                showticklabels=True,
                title='Security Layer',
                ticktext=['DMZ/Public', 'Internal Apps', 'Trusted Zone', 'Database'],
                tickvals=[0, 3, 6, 9],
            ),
            bgcolor='#f0f0f0',
            camera=dict(
                eye=dict(x=1.5, y=1.5, z=1.2)
            )
        ),
    )

    # Add annotation
    fig.add_annotation(
        text=(
            "<b>Network Architecture:</b><br>"
            "🔴 Cross-Zone Links<br>"
            "⬆️ Higher = More Secure<br>"
            "🎨 Colors = Zone Identity<br><br>"
            "Rotate: Click & Drag<br>"
            "Zoom: Scroll"
        ),
        xref="paper",
        yref="paper",
        x=0.02,
        y=0.98,
        showarrow=False,
        font=dict(size=12),
        align='left',
        bgcolor='rgba(255,255,255,0.9)',
        bordercolor='#333',
        borderwidth=2,
        borderpad=10,
        xanchor='left',
        yanchor='top',
    )

    visualizer.save_html(fig, output_file)
    print(f"   ✓ Saved layered 3D topology: {output_file}")


def create_rotating_zone_boundaries(visualizer, output_file):
    """Create 3D visualization with rotating zone boundaries."""

    if not PLOTLY_AVAILABLE:
        print("   ⚠️  Skipping rotating zone boundaries (plotly required)")
        return

    print(f"\n   Creating rotating zone boundaries...")

    # Get graph
    G = visualizer.graph

    # Group nodes by zone
    zones = {}
    for node, data in G.nodes(data=True):
        zone = data.get('zone', 'unknown').lower()
        if zone not in zones:
            zones[zone] = []
        zones[zone].append(node)

    # Position nodes in 3D space with zones grouped
    zone_positions = {
        'dmz': (0, 0, 0),
        'public': (0, 0, 0),
        'internal': (0, 0, 3),
        'trusted': (0, 0, 6),
        'database': (0, 0, 9),
        'unknown': (0, 0, 1.5),
    }

    pos_3d = {}

    for zone_name, zone_nodes in zones.items():
        center_x, center_y, center_z = zone_positions.get(zone_name, (0, 0, 0))

        # Arrange nodes in circle around zone center
        for i, node in enumerate(zone_nodes):
            angle = (i / len(zone_nodes)) * 2 * math.pi
            radius = 2.0

            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            z = center_z

            pos_3d[node] = (x, y, z)

    # Create animation frames (rotate camera)
    frames = []
    num_frames = 60

    for frame_idx in range(num_frames):
        rotation_angle = (frame_idx / num_frames) * 2 * math.pi

        # Calculate camera position
        camera_distance = 15
        camera_x = camera_distance * math.cos(rotation_angle)
        camera_y = camera_distance * math.sin(rotation_angle)
        camera_z = 5

        # Edges
        edge_x = []
        edge_y = []
        edge_z = []

        for u, v in G.edges():
            if u in pos_3d and v in pos_3d:
                edge_x.extend([pos_3d[u][0], pos_3d[v][0], None])
                edge_y.extend([pos_3d[u][1], pos_3d[v][1], None])
                edge_z.extend([pos_3d[u][2], pos_3d[v][2], None])

        edge_trace = go.Scatter3d(
            x=edge_x,
            y=edge_y,
            z=edge_z,
            mode='lines',
            line=dict(color='#bdc3c7', width=2),
            hoverinfo='none',
            showlegend=False,
        )

        # Nodes by zone
        node_traces = []

        zone_colors = {
            'dmz': '#ff6b6b',
            'public': '#ff8c42',
            'internal': '#4ecdc4',
            'trusted': '#45b7d1',
            'database': '#574b90',
            'unknown': '#95a5a6',
        }

        for zone_name, zone_nodes in zones.items():
            node_x = []
            node_y = []
            node_z = []
            node_texts = []

            for node in zone_nodes:
                if node in pos_3d:
                    node_data = G.nodes[node]
                    name = node_data.get('name', node)

                    x, y, z = pos_3d[node]
                    node_x.append(x)
                    node_y.append(y)
                    node_z.append(z)

                    node_texts.append(f"<b>{name}</b><br>Zone: {zone_name.upper()}")

            color = zone_colors.get(zone_name, '#95a5a6')

            node_trace = go.Scatter3d(
                x=node_x,
                y=node_y,
                z=node_z,
                mode='markers',
                marker=dict(
                    size=12,
                    color=color,
                    line=dict(width=2, color='white'),
                ),
                text=node_texts,
                hoverinfo='text',
                name=f"{zone_name.upper()} Zone",
                showlegend=(frame_idx == 0),
            )
            node_traces.append(node_trace)

        # Zone boundary cylinders (rotating with camera for effect)
        boundary_traces = []

        for zone_name, (cx, cy, cz) in zone_positions.items():
            if zone_name == 'unknown' or zone_name not in zones:
                continue

            # Create cylinder points
            cylinder_radius = 2.5
            cylinder_height = 1.5
            num_points = 20

            cyl_x = []
            cyl_y = []
            cyl_z = []

            for i in range(num_points + 1):
                angle = (i / num_points) * 2 * math.pi
                x = cx + cylinder_radius * math.cos(angle)
                y = cy + cylinder_radius * math.sin(angle)

                # Bottom and top
                cyl_x.extend([x, x, None])
                cyl_y.extend([y, y, None])
                cyl_z.extend([cz - cylinder_height/2, cz + cylinder_height/2, None])

            color = zone_colors.get(zone_name, '#95a5a6')

            boundary_trace = go.Scatter3d(
                x=cyl_x,
                y=cyl_y,
                z=cyl_z,
                mode='lines',
                line=dict(color=color, width=3, dash='dash'),
                hoverinfo='text',
                text=f"{zone_name.upper()} Boundary",
                showlegend=False,
                opacity=0.5,
            )
            boundary_traces.append(boundary_trace)

        # Create frame
        frame_data = [edge_trace] + node_traces + boundary_traces

        frames.append(go.Frame(
            data=frame_data,
            name=f"rotation_{frame_idx}",
            layout=go.Layout(
                scene=dict(
                    camera=dict(
                        eye=dict(
                            x=camera_x / camera_distance,
                            y=camera_y / camera_distance,
                            z=camera_z / camera_distance
                        )
                    )
                )
            )
        ))

    # Create figure
    fig = go.Figure(
        data=frames[0].data,
        frames=frames,
        layout=go.Layout(
            title=dict(
                text="Rotating 3D Zone Boundaries<br>"
                     "<sub>Dashed cylinders = Security zone boundaries</sub>",
                font=dict(size=20)
            ),
            width=1600,
            height=1000,
            showlegend=True,
            legend=dict(
                yanchor="top",
                y=0.99,
                xanchor="right",
                x=0.99
            ),
            scene=dict(
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                zaxis=dict(
                    showgrid=True,
                    zeroline=False,
                    showticklabels=True,
                    title='Security Layer',
                ),
                bgcolor='#0a0a0a',
                camera=dict(
                    eye=dict(x=1.5, y=1.5, z=0.5)
                )
            ),
            paper_bgcolor='#0a0a0a',
            updatemenus=[
                dict(
                    type='buttons',
                    showactive=False,
                    buttons=[
                        dict(
                            label='▶ Auto-Rotate',
                            method='animate',
                            args=[None, {
                                'frame': {'duration': 50, 'redraw': True},
                                'fromcurrent': True,
                                'mode': 'immediate',
                            }]
                        ),
                        dict(
                            label='⏸ Stop',
                            method='animate',
                            args=[[None], {
                                'frame': {'duration': 0, 'redraw': False},
                                'mode': 'immediate',
                            }]
                        )
                    ],
                    x=0.5,
                    y=1.08,
                    xanchor='center',
                    yanchor='top'
                )
            ]
        )
    )

    visualizer.save_html(fig, output_file)
    print(f"   ✓ Saved rotating zone boundaries: {output_file}")


def create_attack_layer_transition(visualizer, attack_paths, output_file):
    """Animate attacks moving through network layers."""

    if not PLOTLY_AVAILABLE:
        print("   ⚠️  Skipping attack layer transition (plotly required)")
        return

    print(f"\n   Creating attack layer transition animation...")

    # Get graph
    G = visualizer.graph

    if not attack_paths:
        print("   ⚠️  No attack paths provided")
        return

    # Pick first attack path
    attack_path = attack_paths[0]

    # Position nodes with layers
    zone_levels = {
        'dmz': 0.0,
        'public': 0.0,
        'internet': 0.0,
        'internal': 3.0,
        'trusted': 6.0,
        'database': 9.0,
        'unknown': 1.5,
    }

    # Calculate positions
    pos_2d = nx.spring_layout(G, k=2, iterations=50, seed=42)

    pos_3d = {}
    for node, (x, y) in pos_2d.items():
        zone = G.nodes[node].get('zone', 'unknown').lower()
        z = zone_levels.get(zone, 1.5)
        pos_3d[node] = (x * 5, y * 5, z)

    # Create animation frames
    frames = []
    num_frames = len(attack_path.steps) * 10  # 10 frames per step

    for frame_idx in range(num_frames):
        # Calculate which step we're on
        step_idx = frame_idx // 10
        step_progress = (frame_idx % 10) / 10.0

        # Base network
        edge_x = []
        edge_y = []
        edge_z = []

        for u, v in G.edges():
            if u in pos_3d and v in pos_3d:
                edge_x.extend([pos_3d[u][0], pos_3d[v][0], None])
                edge_y.extend([pos_3d[u][1], pos_3d[v][1], None])
                edge_z.extend([pos_3d[u][2], pos_3d[v][2], None])

        edge_trace = go.Scatter3d(
            x=edge_x,
            y=edge_y,
            z=edge_z,
            mode='lines',
            line=dict(color='#e0e0e0', width=1),
            hoverinfo='none',
            showlegend=False,
        )

        # Attack path traversed so far
        attack_edge_x = []
        attack_edge_y = []
        attack_edge_z = []

        for i in range(min(step_idx, len(attack_path.steps) - 1)):
            u = attack_path.steps[i].node_id
            v = attack_path.steps[i + 1].node_id

            if u in pos_3d and v in pos_3d:
                attack_edge_x.extend([pos_3d[u][0], pos_3d[v][0], None])
                attack_edge_y.extend([pos_3d[u][1], pos_3d[v][1], None])
                attack_edge_z.extend([pos_3d[u][2], pos_3d[v][2], None])

        attack_edge_trace = go.Scatter3d(
            x=attack_edge_x,
            y=attack_edge_y,
            z=attack_edge_z,
            mode='lines',
            line=dict(color='#dc143c', width=6),
            hoverinfo='none',
            name='Attack Path',
            showlegend=(frame_idx == 0),
        )

        # Moving attack "particle"
        if step_idx < len(attack_path.steps) - 1:
            u = attack_path.steps[step_idx].node_id
            v = attack_path.steps[step_idx + 1].node_id

            if u in pos_3d and v in pos_3d:
                # Interpolate position
                particle_x = pos_3d[u][0] + step_progress * (pos_3d[v][0] - pos_3d[u][0])
                particle_y = pos_3d[u][1] + step_progress * (pos_3d[v][1] - pos_3d[u][1])
                particle_z = pos_3d[u][2] + step_progress * (pos_3d[v][2] - pos_3d[u][2])

                particle_trace = go.Scatter3d(
                    x=[particle_x],
                    y=[particle_y],
                    z=[particle_z],
                    mode='markers',
                    marker=dict(
                        size=20,
                        color='#ff0000',
                        symbol='diamond',
                        line=dict(width=3, color='white'),
                    ),
                    hoverinfo='text',
                    text=f"⚡ ATTACK IN PROGRESS<br>Step {step_idx + 1}/{len(attack_path.steps)}",
                    name='Active Attack',
                    showlegend=(frame_idx == 0),
                )
            else:
                particle_trace = go.Scatter3d(x=[], y=[], z=[], showlegend=False)
        else:
            particle_trace = go.Scatter3d(x=[], y=[], z=[], showlegend=False)

        # Nodes
        node_x = []
        node_y = []
        node_z = []
        node_colors = []
        node_sizes = []
        node_texts = []

        visited_nodes = set(s.node_id for s in attack_path.steps[:step_idx + 1])

        for node in G.nodes():
            if node in pos_3d:
                node_data = G.nodes[node]
                name = node_data.get('name', node)
                zone = node_data.get('zone', 'unknown')

                x, y, z = pos_3d[node]
                node_x.append(x)
                node_y.append(y)
                node_z.append(z)

                if node in visited_nodes:
                    # Compromised
                    node_colors.append('#ff0000')
                    node_sizes.append(15)
                    node_texts.append(f"<b>⚠️ {name}</b><br>COMPROMISED<br>Zone: {zone}")
                else:
                    # Normal
                    node_colors.append('#95a5a6')
                    node_sizes.append(10)
                    node_texts.append(f"{name}<br>Zone: {zone}")

        node_trace = go.Scatter3d(
            x=node_x,
            y=node_y,
            z=node_z,
            mode='markers',
            marker=dict(
                size=node_sizes,
                color=node_colors,
                line=dict(width=2, color='white'),
            ),
            text=node_texts,
            hoverinfo='text',
            showlegend=False,
        )

        # Create frame
        frame_data = [edge_trace, attack_edge_trace, particle_trace, node_trace]

        # Get current zone
        current_step = attack_path.steps[min(step_idx, len(attack_path.steps) - 1)]
        current_node = current_step.node_id
        current_zone = G.nodes[current_node].get('zone', 'unknown') if current_node in G.nodes else 'unknown'

        frames.append(go.Frame(
            data=frame_data,
            name=f"frame_{frame_idx}",
            layout=go.Layout(
                title_text=f"Attack Layer Transition - Step {step_idx + 1}/{len(attack_path.steps)}<br>"
                           f"<sub>Current Zone: {current_zone.upper()}</sub>"
            )
        ))

    # Create figure
    fig = go.Figure(
        data=frames[0].data,
        frames=frames,
        layout=go.Layout(
            title=dict(
                text="3D Attack Layer Transition",
                font=dict(size=20)
            ),
            width=1600,
            height=1000,
            showlegend=True,
            legend=dict(
                yanchor="top",
                y=0.99,
                xanchor="right",
                x=0.99
            ),
            scene=dict(
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                zaxis=dict(
                    showgrid=True,
                    zeroline=False,
                    showticklabels=True,
                    title='Security Layer',
                    ticktext=['DMZ', 'Internal', 'Trusted', 'Database'],
                    tickvals=[0, 3, 6, 9],
                ),
                bgcolor='#f8f9fa',
                camera=dict(
                    eye=dict(x=1.8, y=1.8, z=1.2)
                )
            ),
            updatemenus=[
                dict(
                    type='buttons',
                    showactive=False,
                    buttons=[
                        dict(
                            label='▶ Play',
                            method='animate',
                            args=[None, {
                                'frame': {'duration': 100, 'redraw': True},
                                'fromcurrent': True,
                                'mode': 'immediate',
                            }]
                        ),
                        dict(
                            label='⏸ Pause',
                            method='animate',
                            args=[[None], {
                                'frame': {'duration': 0, 'redraw': False},
                                'mode': 'immediate',
                            }]
                        )
                    ],
                    x=0.5,
                    y=1.08,
                    xanchor='center',
                    yanchor='top'
                )
            ],
            sliders=[{
                'active': 0,
                'yanchor': 'top',
                'y': 0,
                'xanchor': 'left',
                'x': 0.1,
                'currentvalue': {
                    'prefix': 'Attack Progress: ',
                    'visible': True,
                    'xanchor': 'right'
                },
                'pad': {'b': 10, 't': 50},
                'len': 0.8,
                'steps': [
                    {
                        'args': [[f.name], {
                            'frame': {'duration': 100, 'redraw': True},
                            'mode': 'immediate',
                        }],
                        'method': 'animate',
                        'label': str(i // 10 + 1)
                    }
                    for i, f in enumerate(frames[::10])
                ]
            }]
        )
    )

    visualizer.save_html(fig, output_file)
    print(f"   ✓ Saved attack layer transition: {output_file}")


def create_camera_flythrough(visualizer, output_file):
    """Create camera flythrough tour of the 3D infrastructure."""

    if not PLOTLY_AVAILABLE:
        print("   ⚠️  Skipping camera flythrough (plotly required)")
        return

    print(f"\n   Creating camera flythrough tour...")

    # Get graph
    G = visualizer.graph

    # Position nodes
    zone_levels = {
        'dmz': 0.0,
        'public': 0.0,
        'internal': 3.0,
        'trusted': 6.0,
        'database': 9.0,
        'unknown': 1.5,
    }

    pos_2d = nx.spring_layout(G, k=2, iterations=50, seed=42)

    pos_3d = {}
    for node, (x, y) in pos_2d.items():
        zone = G.nodes[node].get('zone', 'unknown').lower()
        z = zone_levels.get(zone, 1.5)
        pos_3d[node] = (x * 5, y * 5, z)

    # Define camera path (circular orbit rising up)
    frames = []
    num_frames = 120

    for frame_idx in range(num_frames):
        progress = frame_idx / num_frames

        # Camera orbits in circle while rising
        angle = progress * 4 * math.pi  # 2 full rotations
        radius = 15
        height = 2 + progress * 10  # Rise from 2 to 12

        camera_x = radius * math.cos(angle)
        camera_y = radius * math.sin(angle)
        camera_z = height

        # Edges
        edge_x = []
        edge_y = []
        edge_z = []

        for u, v in G.edges():
            if u in pos_3d and v in pos_3d:
                edge_x.extend([pos_3d[u][0], pos_3d[v][0], None])
                edge_y.extend([pos_3d[u][1], pos_3d[v][1], None])
                edge_z.extend([pos_3d[u][2], pos_3d[v][2], None])

        edge_trace = go.Scatter3d(
            x=edge_x,
            y=edge_y,
            z=edge_z,
            mode='lines',
            line=dict(color='#bdc3c7', width=2),
            hoverinfo='none',
            showlegend=False,
        )

        # Nodes
        node_x = []
        node_y = []
        node_z = []
        node_colors = []
        node_texts = []

        zone_colors = {
            'dmz': '#ff6b6b',
            'public': '#ff8c42',
            'internal': '#4ecdc4',
            'trusted': '#45b7d1',
            'database': '#574b90',
            'unknown': '#95a5a6',
        }

        for node in G.nodes():
            if node in pos_3d:
                node_data = G.nodes[node]
                name = node_data.get('name', node)
                zone = node_data.get('zone', 'unknown').lower()

                x, y, z = pos_3d[node]
                node_x.append(x)
                node_y.append(y)
                node_z.append(z)

                color = zone_colors.get(zone, '#95a5a6')
                node_colors.append(color)

                node_texts.append(f"<b>{name}</b><br>Zone: {zone.upper()}")

        node_trace = go.Scatter3d(
            x=node_x,
            y=node_y,
            z=node_z,
            mode='markers',
            marker=dict(
                size=12,
                color=node_colors,
                line=dict(width=2, color='white'),
            ),
            text=node_texts,
            hoverinfo='text',
            showlegend=False,
        )

        # Create frame with camera position
        frames.append(go.Frame(
            data=[edge_trace, node_trace],
            name=f"flythrough_{frame_idx}",
            layout=go.Layout(
                scene=dict(
                    camera=dict(
                        eye=dict(
                            x=camera_x / radius,
                            y=camera_y / radius,
                            z=camera_z / radius
                        ),
                        center=dict(x=0, y=0, z=4.5),  # Look at middle layer
                    )
                ),
                title_text=f"Infrastructure Flythrough Tour - Progress: {progress:.0%}"
            )
        ))

    # Create figure
    fig = go.Figure(
        data=frames[0].data,
        frames=frames,
        layout=go.Layout(
            title=dict(
                text="3D Infrastructure Flythrough<br>"
                     "<sub>Automated camera tour of network topology</sub>",
                font=dict(size=20)
            ),
            width=1600,
            height=1000,
            showlegend=False,
            scene=dict(
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                zaxis=dict(
                    showgrid=True,
                    zeroline=False,
                    showticklabels=True,
                    title='Security Layer',
                ),
                bgcolor='#1a1a1a',
            ),
            paper_bgcolor='#1a1a1a',
            updatemenus=[
                dict(
                    type='buttons',
                    showactive=False,
                    buttons=[
                        dict(
                            label='▶ Start Tour',
                            method='animate',
                            args=[None, {
                                'frame': {'duration': 50, 'redraw': True},
                                'fromcurrent': True,
                                'mode': 'immediate',
                            }]
                        ),
                        dict(
                            label='⏸ Pause',
                            method='animate',
                            args=[[None], {
                                'frame': {'duration': 0, 'redraw': False},
                                'mode': 'immediate',
                            }]
                        ),
                        dict(
                            label='⏮ Restart',
                            method='animate',
                            args=[[frames[0].name], {
                                'frame': {'duration': 0, 'redraw': True},
                                'mode': 'immediate',
                            }]
                        )
                    ],
                    x=0.5,
                    y=1.08,
                    xanchor='center',
                    yanchor='top'
                )
            ]
        )
    )

    visualizer.save_html(fig, output_file)
    print(f"   ✓ Saved camera flythrough: {output_file}")


def main():
    """Create dynamic 3D topology visualizations."""

    # Paths
    examples_dir = Path(__file__).parent
    sample_graph = examples_dir / "sample_graph.graphml"
    output_dir = examples_dir / "output"
    output_dir.mkdir(exist_ok=True)

    # Check if sample graph exists
    if not sample_graph.exists():
        print("⚠️  Sample graph not found. Please run the setup script first:")
        print(f"   python {examples_dir / '00_setup.py'}")
        return

    print("🌐 Dynamic 3D Network Topology Visualizations\n")
    print("=" * 70)

    if not PLOTLY_AVAILABLE:
        print("\n⚠️  Plotly is required for 3D visualizations")
        print("   Install: pip install plotly")
        return

    # Load graph
    print("\n📊 Loading vulnerability graph...")
    client = NetworkXClient()
    client.load(str(sample_graph))

    metadata = client.get_metadata()
    print(f"   ✓ Loaded graph with {metadata.node_count} nodes")

    # Create visualizers
    topo_viz = NetworkTopologyVisualizer(client)

    # Try to load attack paths if they exist
    attack_paths_file = examples_dir.parent / "10_attack_path_discovery" / "attack-paths.json"
    attack_paths = []

    if attack_paths_file.exists():
        print(f"\n🔍 Loading attack paths...")
        import json
        from threat_radar.graph.models import AttackPath, AttackStep, AttackStepType, ThreatLevel

        with open(attack_paths_file) as f:
            attack_data = json.load(f)

        # Convert JSON to AttackPath objects
        for path_dict in attack_data.get("attack_paths", [])[:5]:  # Limit to 5 paths
            steps = []
            for step_dict in path_dict.get("steps", []):
                step = AttackStep(
                    node_id=step_dict["node_id"],
                    step_type=AttackStepType(step_dict["type"]),
                    description=step_dict["description"],
                    vulnerabilities=step_dict.get("vulnerabilities", []),
                    cvss_score=step_dict.get("cvss_score"),
                )
                steps.append(step)

            path = AttackPath(
                path_id=path_dict["path_id"],
                entry_point=path_dict["entry_point"],
                target=path_dict["target"],
                steps=steps,
                total_cvss=path_dict["total_cvss"],
                threat_level=ThreatLevel(path_dict["threat_level"]),
                exploitability=path_dict.get("exploitability", 0.5),
                path_length=path_dict.get("path_length", len(steps)),
            )
            attack_paths.append(path)

        print(f"   ✓ Loaded {len(attack_paths)} attack paths")

    print("\n" + "=" * 70)
    print("3D TOPOLOGY VISUALIZATIONS")
    print("=" * 70)

    # 1. Layered 3D topology
    print("\n1️⃣  Layered 3D Network Architecture")
    create_layered_3d_topology(
        topo_viz,
        output_dir / "topology_3d_layered.html"
    )

    # 2. Rotating zone boundaries
    print("\n2️⃣  Rotating Zone Boundaries")
    create_rotating_zone_boundaries(
        topo_viz,
        output_dir / "topology_3d_rotating_zones.html"
    )

    # 3. Attack layer transition (if attack paths available)
    if attack_paths:
        print("\n3️⃣  Attack Layer Transition")
        create_attack_layer_transition(
            topo_viz,
            attack_paths,
            output_dir / "topology_3d_attack_transition.html"
        )

    # 4. Camera flythrough
    print("\n4️⃣  Camera Flythrough Tour")
    create_camera_flythrough(
        topo_viz,
        output_dir / "topology_3d_flythrough.html"
    )

    print("\n" + "=" * 70)
    print("✅ 3D topology visualizations created!")
    print("=" * 70)

    print("\n📁 Generated Files:")
    print(f"   • topology_3d_layered.html - Network layers visualization")
    print(f"   • topology_3d_rotating_zones.html - Rotating zone boundaries")
    if attack_paths:
        print(f"   • topology_3d_attack_transition.html - Attack through layers")
    print(f"   • topology_3d_flythrough.html - Automated camera tour")

    print("\n🎨 Visualization Features:")
    print("   • Layered: Z-axis shows security layers (DMZ → Database)")
    print("   • Rotating: Auto-rotating 360° view with zone boundaries")
    if attack_paths:
        print("   • Transition: Watch attacks move through network layers")
    print("   • Flythrough: Automated camera tour of infrastructure")

    print("\n💡 Tips:")
    print("   • All visualizations support click & drag rotation")
    print("   • Scroll to zoom in/out")
    print("   • Use auto-rotate for presentations")
    print("   • Layered view shows network segmentation clearly")


if __name__ == "__main__":
    main()
