#!/usr/bin/env python3
"""
Example 2C: Advanced Dynamic Attack Path Visualizations

This example demonstrates cutting-edge, highly interactive visualizations:
- Animated network flow with moving particles
- Multi-attack simultaneous simulation
- Force-directed live network with attack pressure
- Rotating 3D sphere layout
- Interactive path builder/explorer
- Exploding detail view
"""

import json
import math
from pathlib import Path
import random
from threat_radar.graph import NetworkXClient, GraphAnalyzer
from threat_radar.visualization import AttackPathVisualizer

# Check if plotly is available
try:
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    import networkx as nx
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    print("⚠️  Plotly not available. Install with: pip install plotly")


def create_network_flow_animation(visualizer, attack_paths, output_file):
    """Create animated network flow showing attacks as moving particles."""

    if not PLOTLY_AVAILABLE:
        print("   ⚠️  Skipping network flow animation (plotly required)")
        return

    print(f"\n   Creating network flow animation with particles...")

    # Get graph
    G = visualizer.graph

    # Calculate layout
    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

    # Take first few paths for visualization
    paths_to_animate = attack_paths[:5]

    # Create frames for particle animation
    frames = []
    num_frames = 60  # Animation frames

    for frame_idx in range(num_frames):
        # Calculate particle positions along each path
        progress = frame_idx / num_frames

        # Base edges (network)
        edge_x = []
        edge_y = []

        for u, v in G.edges():
            if u in pos and v in pos:
                edge_x.extend([pos[u][0], pos[v][0], None])
                edge_y.extend([pos[u][1], pos[v][1], None])

        edge_trace = go.Scatter(
            x=edge_x,
            y=edge_y,
            mode='lines',
            line=dict(color='#e0e0e0', width=1),
            hoverinfo='none',
            showlegend=False,
        )

        # Base nodes
        node_x = []
        node_y = []
        node_colors = []
        node_sizes = []

        for node in G.nodes():
            if node in pos:
                node_x.append(pos[node][0])
                node_y.append(pos[node][1])
                node_colors.append('#95a5a6')
                node_sizes.append(10)

        node_trace = go.Scatter(
            x=node_x,
            y=node_y,
            mode='markers',
            marker=dict(
                size=node_sizes,
                color=node_colors,
                line=dict(width=1, color='white'),
            ),
            hoverinfo='none',
            showlegend=False,
        )

        # Animated particles (attack flows)
        particle_traces = []

        threat_colors = {
            'critical': '#ff0000',
            'high': '#ff6347',
            'medium': '#ffa500',
            'low': '#4682b4',
        }

        for path_idx, path in enumerate(paths_to_animate):
            # Calculate particle position along path
            # Use modulo to loop the animation
            loop_progress = (progress + (path_idx * 0.2)) % 1.0

            # Number of particles per path
            num_particles = 5

            for particle_num in range(num_particles):
                # Stagger particles along the path
                particle_progress = (loop_progress + (particle_num / num_particles)) % 1.0

                # Find which segment we're on
                segment_length = 1.0 / (len(path.steps) - 1) if len(path.steps) > 1 else 1.0
                segment_idx = int(particle_progress / segment_length)
                segment_idx = min(segment_idx, len(path.steps) - 2)

                if segment_idx >= 0 and segment_idx < len(path.steps) - 1:
                    u = path.steps[segment_idx].node_id
                    v = path.steps[segment_idx + 1].node_id

                    if u in pos and v in pos:
                        # Interpolate position between nodes
                        local_progress = (particle_progress - segment_idx * segment_length) / segment_length

                        particle_x = pos[u][0] + local_progress * (pos[v][0] - pos[u][0])
                        particle_y = pos[u][1] + local_progress * (pos[v][1] - pos[u][1])

                        color = threat_colors.get(path.threat_level.value, '#999')

                        # Create particle trace
                        particle_trace = go.Scatter(
                            x=[particle_x],
                            y=[particle_y],
                            mode='markers',
                            marker=dict(
                                size=12,
                                color=color,
                                symbol='circle',
                                line=dict(width=2, color='white'),
                            ),
                            hoverinfo='text',
                            text=f"Attack Path {path.path_id}<br>Threat: {path.threat_level.value.upper()}",
                            showlegend=False,
                        )
                        particle_traces.append(particle_trace)

        # Combine all traces for this frame
        frame_data = [edge_trace, node_trace] + particle_traces

        frames.append(go.Frame(
            data=frame_data,
            name=f"frame_{frame_idx}",
        ))

    # Create figure with first frame
    fig = go.Figure(
        data=frames[0].data,
        frames=frames,
        layout=go.Layout(
            title=dict(
                text=f"Network Flow Animation - {len(paths_to_animate)} Active Attack Paths<br>"
                     f"<sub>Colored particles represent attack traffic</sub>",
                font=dict(size=20)
            ),
            width=1400,
            height=900,
            showlegend=False,
            hovermode='closest',
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='#0a0a0a',  # Dark background for glow effect
            paper_bgcolor='#0a0a0a',
            updatemenus=[
                dict(
                    type='buttons',
                    showactive=False,
                    buttons=[
                        dict(
                            label='▶ Play',
                            method='animate',
                            args=[None, {
                                'frame': {'duration': 50, 'redraw': True},
                                'fromcurrent': True,
                                'mode': 'immediate',
                                'transition': {'duration': 0}
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
                    y=1.1,
                    xanchor='center',
                    yanchor='top'
                )
            ]
        )
    )

    # Add legend
    fig.add_annotation(
        text=(
            "<b>Network Flow Legend:</b><br>"
            "🔴 Critical Attack<br>"
            "🟠 High Severity<br>"
            "🟡 Medium Severity<br>"
            "🔵 Low Severity<br><br>"
            "Moving particles = Active attacks"
        ),
        xref="paper",
        yref="paper",
        x=0.02,
        y=0.98,
        showarrow=False,
        font=dict(size=12, color='white'),
        align='left',
        bgcolor='rgba(20,20,20,0.8)',
        bordercolor='#666',
        borderwidth=2,
        borderpad=10,
        xanchor='left',
        yanchor='top',
    )

    visualizer.save_html(fig, output_file)
    print(f"   ✓ Saved network flow animation: {output_file}")


def create_multi_attack_simulation(visualizer, attack_paths, output_file):
    """Simulate multiple attacks happening simultaneously over time."""

    if not PLOTLY_AVAILABLE:
        print("   ⚠️  Skipping multi-attack simulation (plotly required)")
        return

    print(f"\n   Creating multi-attack simultaneous simulation...")

    # Get graph
    G = visualizer.graph

    # Calculate layout
    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

    # Select paths to simulate (different start times)
    paths_to_simulate = attack_paths[:6]

    # Create timeline (0-100 time units)
    frames = []
    time_steps = 100

    for time in range(time_steps):
        # Base network
        edge_x = []
        edge_y = []

        for u, v in G.edges():
            if u in pos and v in pos:
                edge_x.extend([pos[u][0], pos[v][0], None])
                edge_y.extend([pos[u][1], pos[v][1], None])

        edge_trace = go.Scatter(
            x=edge_x,
            y=edge_y,
            mode='lines',
            line=dict(color='#e0e0e0', width=0.5, dash='dot'),
            hoverinfo='none',
            showlegend=False,
        )

        # Track which nodes are under attack at this time
        attacked_nodes = set()
        current_attacks = []

        threat_colors = {
            'critical': '#8b0000',
            'high': '#dc143c',
            'medium': '#ffa500',
            'low': '#4682b4',
        }

        # Simulate each path with different start times
        for idx, path in enumerate(paths_to_simulate):
            start_time = idx * 15  # Stagger starts
            duration = len(path.steps) * 8  # Each step takes 8 time units

            if time >= start_time and time < start_time + duration:
                # Attack is active
                progress = (time - start_time) / duration
                step_idx = int(progress * len(path.steps))
                step_idx = min(step_idx, len(path.steps) - 1)

                # Draw attack path up to current step
                attack_edge_x = []
                attack_edge_y = []

                for i in range(step_idx):
                    u = path.steps[i].node_id
                    v = path.steps[i + 1].node_id if i + 1 < len(path.steps) else path.steps[i].node_id

                    if u in pos and v in pos:
                        attack_edge_x.extend([pos[u][0], pos[v][0], None])
                        attack_edge_y.extend([pos[u][1], pos[v][1], None])
                        attacked_nodes.add(u)
                        attacked_nodes.add(v)

                color = threat_colors.get(path.threat_level.value, '#999')

                attack_trace = go.Scatter(
                    x=attack_edge_x,
                    y=attack_edge_y,
                    mode='lines',
                    line=dict(color=color, width=4),
                    hoverinfo='text',
                    text=f"Attack {idx + 1}: {path.threat_level.value.upper()}",
                    name=f"Attack {idx + 1}",
                    showlegend=(time == 0),  # Only show legend on first frame
                )
                current_attacks.append(attack_trace)

        # Draw nodes (highlight attacked ones)
        node_x = []
        node_y = []
        node_colors = []
        node_sizes = []
        node_texts = []

        for node in G.nodes():
            if node in pos:
                node_data = G.nodes[node]
                name = node_data.get('name', node)

                node_x.append(pos[node][0])
                node_y.append(pos[node][1])

                if node in attacked_nodes:
                    # Under attack - red and pulsing
                    node_colors.append('#ff0000')
                    node_sizes.append(20)
                    node_texts.append(f"<b>⚠️ {name}</b><br>UNDER ATTACK!")
                else:
                    # Normal
                    node_colors.append('#95a5a6')
                    node_sizes.append(10)
                    node_texts.append(name)

        node_trace = go.Scatter(
            x=node_x,
            y=node_y,
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
        frame_data = [edge_trace] + current_attacks + [node_trace]

        frames.append(go.Frame(
            data=frame_data,
            name=f"t={time}",
            layout=go.Layout(
                title_text=f"Multi-Attack Simulation - Time: {time}/{time_steps}<br>"
                           f"<sub>Active Attacks: {len(current_attacks)}</sub>"
            )
        ))

    # Create figure
    fig = go.Figure(
        data=frames[0].data,
        frames=frames,
        layout=go.Layout(
            title=dict(
                text="Multi-Attack Simulation - Timeline View",
                font=dict(size=20)
            ),
            width=1600,
            height=900,
            showlegend=True,
            legend=dict(
                yanchor="top",
                y=0.99,
                xanchor="right",
                x=0.99
            ),
            hovermode='closest',
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='#f8f9fa',
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
                        ),
                        dict(
                            label='⏮ Reset',
                            method='animate',
                            args=[[frames[0].name], {
                                'frame': {'duration': 0, 'redraw': True},
                                'mode': 'immediate',
                            }]
                        )
                    ],
                    x=0.5,
                    y=1.12,
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
                    'prefix': 'Time: ',
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
                        'label': str(i)
                    }
                    for i, f in enumerate(frames[::5])  # Show every 5th frame in slider
                ]
            }]
        )
    )

    visualizer.save_html(fig, output_file)
    print(f"   ✓ Saved multi-attack simulation: {output_file}")


def create_rotating_3d_sphere(visualizer, attack_paths, output_file):
    """Create attack paths mapped onto a rotating 3D sphere."""

    if not PLOTLY_AVAILABLE:
        print("   ⚠️  Skipping 3D sphere (plotly required)")
        return

    print(f"\n   Creating rotating 3D sphere visualization...")

    # Get graph
    G = visualizer.graph

    # Map nodes to sphere surface using spherical coordinates
    nodes_list = list(G.nodes())
    num_nodes = len(nodes_list)

    # Fibonacci sphere algorithm for even distribution
    pos_3d = {}
    golden_ratio = (1 + math.sqrt(5)) / 2

    for i, node in enumerate(nodes_list):
        # Fibonacci spiral on sphere
        theta = 2 * math.pi * i / golden_ratio
        phi = math.acos(1 - 2 * (i + 0.5) / num_nodes)

        radius = 5.0  # Sphere radius

        x = radius * math.sin(phi) * math.cos(theta)
        y = radius * math.sin(phi) * math.sin(theta)
        z = radius * math.cos(phi)

        pos_3d[node] = (x, y, z)

    # Create frames for rotation
    frames = []
    num_frames = 60

    for frame_idx in range(num_frames):
        rotation_angle = (frame_idx / num_frames) * 2 * math.pi

        # Rotate positions
        rotated_pos = {}
        for node, (x, y, z) in pos_3d.items():
            # Rotate around Z-axis
            new_x = x * math.cos(rotation_angle) - y * math.sin(rotation_angle)
            new_y = x * math.sin(rotation_angle) + y * math.cos(rotation_angle)
            new_z = z
            rotated_pos[node] = (new_x, new_y, new_z)

        # Attack path edges
        path_traces = []

        threat_colors = {
            'critical': '#8b0000',
            'high': '#dc143c',
            'medium': '#ffa500',
            'low': '#4682b4',
        }

        for path in attack_paths[:10]:
            edge_x = []
            edge_y = []
            edge_z = []

            for i in range(len(path.steps) - 1):
                u = path.steps[i].node_id
                v = path.steps[i + 1].node_id

                if u in rotated_pos and v in rotated_pos:
                    edge_x.extend([rotated_pos[u][0], rotated_pos[v][0], None])
                    edge_y.extend([rotated_pos[u][1], rotated_pos[v][1], None])
                    edge_z.extend([rotated_pos[u][2], rotated_pos[v][2], None])

            color = threat_colors.get(path.threat_level.value, '#999')

            path_trace = go.Scatter3d(
                x=edge_x,
                y=edge_y,
                z=edge_z,
                mode='lines',
                line=dict(color=color, width=6),
                hoverinfo='text',
                text=f"Path: {path.threat_level.value.upper()}",
                showlegend=(frame_idx == 0),
                name=path.threat_level.value.upper(),
            )
            path_traces.append(path_trace)

        # Nodes on sphere
        node_x = []
        node_y = []
        node_z = []
        node_colors = []
        node_texts = []

        for node in G.nodes():
            if node in rotated_pos:
                node_data = G.nodes[node]
                name = node_data.get('name', node)

                x, y, z = rotated_pos[node]
                node_x.append(x)
                node_y.append(y)
                node_z.append(z)

                # Color by criticality
                criticality = node_data.get('criticality', 'low')
                criticality_colors = {
                    'critical': '#c0392b',
                    'high': '#e74c3c',
                    'medium': '#f39c12',
                    'low': '#3498db',
                }
                node_colors.append(criticality_colors.get(criticality, '#95a5a6'))

                node_texts.append(f"<b>{name}</b><br>Criticality: {criticality}")

        node_trace = go.Scatter3d(
            x=node_x,
            y=node_y,
            z=node_z,
            mode='markers',
            marker=dict(
                size=8,
                color=node_colors,
                line=dict(width=1, color='white'),
            ),
            text=node_texts,
            hoverinfo='text',
            showlegend=False,
        )

        # Create frame
        frame_data = path_traces + [node_trace]

        frames.append(go.Frame(
            data=frame_data,
            name=f"rotation_{frame_idx}",
        ))

    # Create figure
    fig = go.Figure(
        data=frames[0].data,
        frames=frames,
        layout=go.Layout(
            title=dict(
                text=f"3D Sphere Attack Path Visualization<br>"
                     f"<sub>Auto-rotating view - {len(attack_paths)} paths</sub>",
                font=dict(size=20)
            ),
            width=1400,
            height=1000,
            showlegend=True,
            legend=dict(
                yanchor="top",
                y=0.99,
                xanchor="left",
                x=0.01
            ),
            scene=dict(
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, showbackground=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, showbackground=False),
                zaxis=dict(showgrid=False, zeroline=False, showticklabels=False, showbackground=False),
                bgcolor='#0a0a0a',
                camera=dict(
                    eye=dict(x=1.5, y=1.5, z=1.5)
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
                                'transition': {'duration': 0}
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
    print(f"   ✓ Saved rotating 3D sphere: {output_file}")


def create_force_directed_attack(visualizer, attack_paths, output_file):
    """Create force-directed animation showing attack pressure on network."""

    if not PLOTLY_AVAILABLE:
        print("   ⚠️  Skipping force-directed attack (plotly required)")
        return

    print(f"\n   Creating force-directed attack pressure visualization...")

    # Get graph
    G = visualizer.graph

    # Initial layout
    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

    # Calculate "attack pressure" on each node
    node_pressure = {}
    for node in G.nodes():
        pressure = 0
        for path in attack_paths:
            if any(s.node_id == node for s in path.steps):
                # Add pressure based on threat level
                threat_weights = {
                    'critical': 4.0,
                    'high': 3.0,
                    'medium': 2.0,
                    'low': 1.0,
                }
                pressure += threat_weights.get(path.threat_level.value, 1.0)
        node_pressure[node] = pressure

    # Create animation frames showing nodes "repelling" from attack pressure
    frames = []
    num_frames = 50

    for frame_idx in range(num_frames):
        progress = frame_idx / num_frames

        # Apply displacement based on pressure (nodes move away from high-pressure areas)
        displaced_pos = {}

        for node in G.nodes():
            pressure = node_pressure.get(node, 0)

            # Displacement amount (oscillates over time for pulse effect)
            displacement = 0.3 * pressure * math.sin(progress * 4 * math.pi) * (1 - progress)

            # Random direction for displacement
            angle = hash(node) % 360 * (math.pi / 180)
            dx = displacement * math.cos(angle)
            dy = displacement * math.sin(angle)

            original_x, original_y = pos[node]
            displaced_pos[node] = (original_x + dx, original_y + dy)

        # Draw network with displaced positions
        edge_x = []
        edge_y = []
        edge_colors = []
        edge_widths = []

        for u, v in G.edges():
            if u in displaced_pos and v in displaced_pos:
                edge_x.extend([displaced_pos[u][0], displaced_pos[v][0], None])
                edge_y.extend([displaced_pos[u][1], displaced_pos[v][1], None])

                # Edge tension based on endpoint pressure
                avg_pressure = (node_pressure.get(u, 0) + node_pressure.get(v, 0)) / 2

                if avg_pressure > 5:
                    edge_colors.extend(['#ff0000', '#ff0000', None])
                    edge_widths.extend([3, 3, None])
                elif avg_pressure > 3:
                    edge_colors.extend(['#ffa500', '#ffa500', None])
                    edge_widths.extend([2, 2, None])
                else:
                    edge_colors.extend(['#e0e0e0', '#e0e0e0', None])
                    edge_widths.extend([1, 1, None])

        # Since we can't have varying widths in a single trace easily, use average
        edge_trace = go.Scatter(
            x=edge_x,
            y=edge_y,
            mode='lines',
            line=dict(color='#e0e0e0', width=1),
            hoverinfo='none',
            showlegend=False,
        )

        # Draw nodes
        node_x = []
        node_y = []
        node_colors = []
        node_sizes = []
        node_texts = []

        for node in G.nodes():
            if node in displaced_pos:
                node_data = G.nodes[node]
                name = node_data.get('name', node)
                pressure = node_pressure.get(node, 0)

                x, y = displaced_pos[node]
                node_x.append(x)
                node_y.append(y)

                # Color and size based on pressure
                if pressure > 8:
                    node_colors.append('#8b0000')  # Dark red - extreme pressure
                    node_sizes.append(25)
                elif pressure > 5:
                    node_colors.append('#dc143c')  # Red - high pressure
                    node_sizes.append(20)
                elif pressure > 2:
                    node_colors.append('#ffa500')  # Orange - medium pressure
                    node_sizes.append(15)
                else:
                    node_colors.append('#95a5a6')  # Gray - low/no pressure
                    node_sizes.append(10)

                node_texts.append(
                    f"<b>{name}</b><br>"
                    f"Attack Pressure: {pressure:.1f}<br>"
                    f"Status: {'⚠️ UNDER ATTACK' if pressure > 5 else '✓ Normal'}"
                )

        node_trace = go.Scatter(
            x=node_x,
            y=node_y,
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
        frames.append(go.Frame(
            data=[edge_trace, node_trace],
            name=f"pressure_{frame_idx}",
            layout=go.Layout(
                title_text=f"Force-Directed Attack Pressure - Frame {frame_idx + 1}/{num_frames}<br>"
                           f"<sub>Node size/color = Attack intensity</sub>"
            )
        ))

    # Create figure
    fig = go.Figure(
        data=frames[0].data,
        frames=frames,
        layout=go.Layout(
            title=dict(
                text="Force-Directed Attack Pressure Visualization",
                font=dict(size=20)
            ),
            width=1400,
            height=900,
            showlegend=False,
            hovermode='closest',
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='#f8f9fa',
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
                    y=1.1,
                    xanchor='center',
                    yanchor='top'
                )
            ]
        )
    )

    # Add legend
    fig.add_annotation(
        text=(
            "<b>Attack Pressure Legend:</b><br>"
            "🔴 Dark Red: Extreme<br>"
            "🟠 Red: High<br>"
            "🟡 Orange: Medium<br>"
            "⚪ Gray: Normal<br><br>"
            "Nodes pulse under attack pressure"
        ),
        xref="paper",
        yref="paper",
        x=0.02,
        y=0.98,
        showarrow=False,
        font=dict(size=12),
        align='left',
        bgcolor='rgba(255,255,255,0.95)',
        bordercolor='#333',
        borderwidth=2,
        borderpad=10,
        xanchor='left',
        yanchor='top',
    )

    visualizer.save_html(fig, output_file)
    print(f"   ✓ Saved force-directed attack pressure: {output_file}")


def create_exploding_path_view(visualizer, attack_path, output_file):
    """Create 'exploding' view where nodes expand to show internal details."""

    if not PLOTLY_AVAILABLE:
        print("   ⚠️  Skipping exploding path view (plotly required)")
        return

    print(f"\n   Creating exploding path detail view...")

    # Get graph
    G = visualizer.graph

    # Calculate layout for main nodes
    main_pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

    # Create animation frames showing nodes "exploding" to reveal details
    frames = []
    num_frames = 60

    path_nodes = set(s.node_id for s in attack_path.steps)

    for frame_idx in range(num_frames):
        progress = frame_idx / num_frames

        # Explosion factor (grows then shrinks)
        explosion = math.sin(progress * math.pi) * 2.0

        # Base edges
        edge_x = []
        edge_y = []

        for u, v in G.edges():
            if u in main_pos and v in main_pos:
                edge_x.extend([main_pos[u][0], main_pos[v][0], None])
                edge_y.extend([main_pos[u][1], main_pos[v][1], None])

        edge_trace = go.Scatter(
            x=edge_x,
            y=edge_y,
            mode='lines',
            line=dict(color='#e0e0e0', width=1),
            hoverinfo='none',
            showlegend=False,
        )

        # Main nodes and "exploded" detail nodes
        main_node_x = []
        main_node_y = []
        main_node_colors = []
        main_node_sizes = []
        main_node_texts = []

        detail_node_x = []
        detail_node_y = []
        detail_node_colors = []
        detail_node_texts = []

        for node in G.nodes():
            if node in main_pos:
                node_data = G.nodes[node]
                name = node_data.get('name', node)

                main_x, main_y = main_pos[node]
                main_node_x.append(main_x)
                main_node_y.append(main_y)

                in_path = node in path_nodes

                if in_path:
                    main_node_colors.append('#dc143c')
                    main_node_sizes.append(20)
                    main_node_texts.append(f"<b>{name}</b><br>⚡ IN ATTACK PATH")

                    # Create "exploded" detail nodes around main node
                    if explosion > 0.5:  # Only show details when sufficiently exploded
                        # CVE details as satellite nodes
                        num_details = 4  # Simulated detail points
                        for i in range(num_details):
                            angle = (i / num_details) * 2 * math.pi
                            detail_distance = 0.3 * explosion

                            detail_x = main_x + detail_distance * math.cos(angle)
                            detail_y = main_y + detail_distance * math.sin(angle)

                            detail_node_x.append(detail_x)
                            detail_node_y.append(detail_y)
                            detail_node_colors.append('#ffa500')
                            detail_node_texts.append(f"Detail {i+1}<br>for {name}")
                else:
                    main_node_colors.append('#95a5a6')
                    main_node_sizes.append(10)
                    main_node_texts.append(name)

        main_node_trace = go.Scatter(
            x=main_node_x,
            y=main_node_y,
            mode='markers',
            marker=dict(
                size=main_node_sizes,
                color=main_node_colors,
                line=dict(width=2, color='white'),
            ),
            text=main_node_texts,
            hoverinfo='text',
            showlegend=False,
        )

        # Detail nodes trace
        if detail_node_x:
            detail_trace = go.Scatter(
                x=detail_node_x,
                y=detail_node_y,
                mode='markers',
                marker=dict(
                    size=8,
                    color=detail_node_colors,
                    symbol='diamond',
                    line=dict(width=1, color='white'),
                ),
                text=detail_node_texts,
                hoverinfo='text',
                showlegend=False,
            )
            frame_data = [edge_trace, main_node_trace, detail_trace]
        else:
            frame_data = [edge_trace, main_node_trace]

        # Create frame
        frames.append(go.Frame(
            data=frame_data,
            name=f"explosion_{frame_idx}",
            layout=go.Layout(
                title_text=f"Exploding Path View - Explosion: {explosion:.1f}x"
            )
        ))

    # Create figure
    fig = go.Figure(
        data=frames[0].data,
        frames=frames,
        layout=go.Layout(
            title=dict(
                text=f"Exploding Attack Path Detail View<br>"
                     f"<sub>Path: {attack_path.path_id} - {attack_path.threat_level.value.upper()}</sub>",
                font=dict(size=20)
            ),
            width=1400,
            height=900,
            showlegend=False,
            hovermode='closest',
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='#f8f9fa',
            updatemenus=[
                dict(
                    type='buttons',
                    showactive=False,
                    buttons=[
                        dict(
                            label='▶ Explode',
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
                        )
                    ],
                    x=0.5,
                    y=1.1,
                    xanchor='center',
                    yanchor='top'
                )
            ]
        )
    )

    visualizer.save_html(fig, output_file)
    print(f"   ✓ Saved exploding path view: {output_file}")


def main():
    """Create advanced dynamic attack path visualizations."""

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

    print("🚀 Advanced Dynamic Attack Path Visualizations\n")
    print("=" * 70)

    if not PLOTLY_AVAILABLE:
        print("\n⚠️  Plotly is required for advanced visualizations")
        print("   Install: pip install plotly")
        return

    # Load graph
    print("\n📊 Loading vulnerability graph...")
    client = NetworkXClient()
    client.load(str(sample_graph))

    metadata = client.get_metadata()
    print(f"   ✓ Loaded graph with {metadata.node_count} nodes")

    # Create analyzer
    print("\n🔍 Analyzing attack paths...")
    analyzer = GraphAnalyzer(client)

    # Identify entry points and targets
    entry_points = analyzer.identify_entry_points()
    targets = analyzer.identify_high_value_targets()

    print(f"   ✓ Found {len(entry_points)} entry points")
    print(f"   ✓ Found {len(targets)} high-value targets")

    if not entry_points or not targets:
        print("\n⚠️  No entry points or targets found in this graph.")
        print("   Try using a graph with environment configuration.")
        return

    # Find attack paths
    print("\n🛤️  Finding attack paths...")
    attack_paths = analyzer.find_shortest_attack_paths(
        entry_points=entry_points,
        targets=targets,
        max_length=10,
        max_paths=20,
    )

    if not attack_paths:
        print("   ⚠️  No attack paths found")
        return

    print(f"   ✓ Found {len(attack_paths)} attack paths")

    # Create visualizer
    visualizer = AttackPathVisualizer(client)

    print("\n" + "=" * 70)
    print("ADVANCED DYNAMIC VISUALIZATIONS")
    print("=" * 70)

    # 1. Network flow animation
    print("\n1️⃣  Network Flow with Moving Particles")
    create_network_flow_animation(
        visualizer,
        attack_paths,
        output_dir / "attack_flow_particles.html"
    )

    # 2. Multi-attack simulation
    print("\n2️⃣  Multi-Attack Simultaneous Simulation")
    create_multi_attack_simulation(
        visualizer,
        attack_paths,
        output_dir / "multi_attack_timeline.html"
    )

    # 3. Rotating 3D sphere
    print("\n3️⃣  Rotating 3D Sphere Layout")
    create_rotating_3d_sphere(
        visualizer,
        attack_paths,
        output_dir / "attack_sphere_3d.html"
    )

    # 4. Force-directed attack pressure
    print("\n4️⃣  Force-Directed Attack Pressure")
    create_force_directed_attack(
        visualizer,
        attack_paths,
        output_dir / "attack_pressure_force.html"
    )

    # 5. Exploding path view
    print("\n5️⃣  Exploding Path Detail View")
    most_critical = max(attack_paths, key=lambda p: (
        p.threat_level.value == 'critical',
        p.total_cvss
    ))
    create_exploding_path_view(
        visualizer,
        most_critical,
        output_dir / "attack_path_exploding.html"
    )

    print("\n" + "=" * 70)
    print("✅ Advanced dynamic visualizations created!")
    print("=" * 70)

    print("\n📁 Generated Files:")
    print(f"   • attack_flow_particles.html - Animated network flow with particles")
    print(f"   • multi_attack_timeline.html - Multiple simultaneous attacks")
    print(f"   • attack_sphere_3d.html - Auto-rotating 3D sphere")
    print(f"   • attack_pressure_force.html - Force-directed pressure animation")
    print(f"   • attack_path_exploding.html - Exploding detail view")

    print("\n🎨 Visualization Features:")
    print("   • Particles: Smooth attack flow animation")
    print("   • Timeline: See attacks overlap in time")
    print("   • Sphere: Nodes distributed on 3D sphere surface")
    print("   • Pressure: Nodes react to attack intensity")
    print("   • Exploding: Nodes expand to show details")

    print("\n💡 Tips:")
    print("   • All visualizations have play/pause controls")
    print("   • Dark backgrounds enhance glow effects")
    print("   • Sphere auto-rotates for full 360° view")
    print("   • Pressure shows real-time attack intensity")
    print("   • Use Chrome/Firefox for best performance")


if __name__ == "__main__":
    main()
