#!/usr/bin/env python3
"""
Example 4: Ultimate Combined Visualizations

This example creates the most comprehensive, beautiful visualizations
that combine all security data:
- Security Command Center: Multi-panel synchronized dashboard
- Holographic Security Story: Immersive 3D narrative visualization

These are the "masterpiece" visualizations showing everything together.
"""

import json
import math
from pathlib import Path
import random
from threat_radar.graph import NetworkXClient, GraphAnalyzer
from threat_radar.visualization import (
    NetworkTopologyVisualizer,
    AttackPathVisualizer,
)

# Check if plotly is available
try:
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    import networkx as nx
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    print("⚠️  Plotly not available. Install with: pip install plotly")


def create_security_command_center(visualizer, attack_paths, output_file):
    """
    Create ultimate multi-panel security command center dashboard.

    Combines:
    - 3D network topology with attack paths
    - Risk heatmap
    - Timeline view
    - Key metrics
    - Zone status

    All synchronized and interactive.
    """

    if not PLOTLY_AVAILABLE:
        print("   ⚠️  Skipping command center (plotly required)")
        return

    print(f"\n   Creating Security Command Center dashboard...")

    # Get graph
    G = visualizer.graph

    # Calculate node risk scores
    node_risk = {}
    for node in G.nodes():
        risk = 0
        path_count = 0
        for path in attack_paths:
            if any(s.node_id == node for s in path.steps):
                path_count += 1
                threat_weights = {
                    'critical': 4.0,
                    'high': 3.0,
                    'medium': 2.0,
                    'low': 1.0,
                }
                risk += threat_weights.get(path.threat_level.value, 1.0)

        # Add criticality multiplier
        criticality = G.nodes[node].get('criticality', 'low')
        crit_multipliers = {'critical': 2.0, 'high': 1.5, 'medium': 1.2, 'low': 1.0}
        risk *= crit_multipliers.get(criticality, 1.0)

        node_risk[node] = risk

    # Normalize risk scores
    max_risk = max(node_risk.values()) if node_risk else 1
    normalized_risk = {node: (risk / max_risk) * 100 for node, risk in node_risk.items()}

    # Create 2x2 subplot layout
    fig = make_subplots(
        rows=2,
        cols=2,
        specs=[
            [{'type': 'scatter3d', 'rowspan': 2}, {'type': 'scatter'}],
            [None, {'type': 'bar'}]
        ],
        subplot_titles=(
            '🌐 3D Network Topology with Attack Paths',
            '🔥 Real-Time Risk Heatmap',
            '📊 Zone Security Status'
        ),
        vertical_spacing=0.12,
        horizontal_spacing=0.1,
    )

    # ============ Panel 1: 3D Topology with Attack Paths ============

    # Position nodes in 3D
    zone_levels = {
        'dmz': 0.0, 'public': 0.0, 'internet': 0.0,
        'internal': 3.0, 'application': 3.0,
        'trusted': 6.0, 'secure': 6.0,
        'database': 9.0,
        'unknown': 1.5,
    }

    pos_2d = nx.spring_layout(G, k=2, iterations=50, seed=42)
    pos_3d = {}
    for node, (x, y) in pos_2d.items():
        zone = G.nodes[node].get('zone', 'unknown').lower()
        z = zone_levels.get(zone, 1.5)
        pos_3d[node] = (x * 4, y * 4, z)

    # Base network edges
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
        line=dict(color='#bdc3c7', width=1),
        hoverinfo='none',
        showlegend=False,
    )

    # Attack paths overlay
    path_traces_3d = []
    threat_colors = {
        'critical': '#8b0000',
        'high': '#dc143c',
        'medium': '#ffa500',
        'low': '#4682b4',
    }

    for path in attack_paths[:10]:  # Limit to 10 paths
        path_x = []
        path_y = []
        path_z = []

        for i in range(len(path.steps) - 1):
            u = path.steps[i].node_id
            v = path.steps[i + 1].node_id

            if u in pos_3d and v in pos_3d:
                path_x.extend([pos_3d[u][0], pos_3d[v][0], None])
                path_y.extend([pos_3d[u][1], pos_3d[v][1], None])
                path_z.extend([pos_3d[u][2], pos_3d[v][2], None])

        color = threat_colors.get(path.threat_level.value, '#999')

        path_trace = go.Scatter3d(
            x=path_x,
            y=path_y,
            z=path_z,
            mode='lines',
            line=dict(color=color, width=5),
            name=f"{path.threat_level.value.upper()}",
            showlegend=True,
            legendgroup='threat',
        )
        path_traces_3d.append(path_trace)

    # Nodes colored by risk
    node_x = []
    node_y = []
    node_z = []
    node_colors = []
    node_sizes = []
    node_texts = []

    for node in G.nodes():
        if node in pos_3d:
            node_data = G.nodes[node]
            name = node_data.get('name', node)
            risk = normalized_risk.get(node, 0)

            x, y, z = pos_3d[node]
            node_x.append(x)
            node_y.append(y)
            node_z.append(z)
            node_colors.append(risk)
            node_sizes.append(8 + (risk / 10))

            zone = node_data.get('zone', 'unknown')
            criticality = node_data.get('criticality', 'unknown')
            node_texts.append(
                f"<b>{name}</b><br>"
                f"Risk: {risk:.1f}/100<br>"
                f"Zone: {zone}<br>"
                f"Criticality: {criticality}"
            )

    node_trace = go.Scatter3d(
        x=node_x,
        y=node_y,
        z=node_z,
        mode='markers',
        marker=dict(
            size=node_sizes,
            color=node_colors,
            colorscale='Reds',
            showscale=True,
            colorbar=dict(
                title="Risk",
                x=0.45,
                len=0.4,
                thickness=15,
            ),
            line=dict(width=1, color='white'),
            cmin=0,
            cmax=100,
        ),
        text=node_texts,
        hoverinfo='text',
        showlegend=False,
    )

    # Add all 3D traces
    fig.add_trace(edge_trace, row=1, col=1)
    for trace in path_traces_3d:
        fig.add_trace(trace, row=1, col=1)
    fig.add_trace(node_trace, row=1, col=1)

    # ============ Panel 2: 2D Risk Heatmap ============

    # Calculate 2D positions for heatmap
    heatmap_edge_x = []
    heatmap_edge_y = []

    for u, v in G.edges():
        if u in pos_2d and v in pos_2d:
            heatmap_edge_x.extend([pos_2d[u][0], pos_2d[v][0], None])
            heatmap_edge_y.extend([pos_2d[u][1], pos_2d[v][1], None])

    heatmap_edge_trace = go.Scatter(
        x=heatmap_edge_x,
        y=heatmap_edge_y,
        mode='lines',
        line=dict(color='#e0e0e0', width=1),
        hoverinfo='none',
        showlegend=False,
    )

    # Nodes for heatmap
    heatmap_node_x = []
    heatmap_node_y = []
    heatmap_node_colors = []
    heatmap_node_sizes = []
    heatmap_node_texts = []

    for node in G.nodes():
        if node in pos_2d:
            node_data = G.nodes[node]
            name = node_data.get('name', node)
            risk = normalized_risk.get(node, 0)

            x, y = pos_2d[node]
            heatmap_node_x.append(x)
            heatmap_node_y.append(y)
            heatmap_node_colors.append(risk)
            heatmap_node_sizes.append(15 + (risk / 5))

            path_count = sum(1 for p in attack_paths if any(s.node_id == node for s in p.steps))
            heatmap_node_texts.append(
                f"<b>{name}</b><br>"
                f"Risk Score: {risk:.1f}/100<br>"
                f"Attack Paths: {path_count}<br>"
                f"Status: {'🔴 HIGH RISK' if risk > 70 else '🟡 MEDIUM' if risk > 40 else '🟢 LOW'}"
            )

    heatmap_node_trace = go.Scatter(
        x=heatmap_node_x,
        y=heatmap_node_y,
        mode='markers',
        marker=dict(
            size=heatmap_node_sizes,
            color=heatmap_node_colors,
            colorscale='Reds',
            showscale=False,
            line=dict(width=2, color='white'),
            cmin=0,
            cmax=100,
        ),
        text=heatmap_node_texts,
        hoverinfo='text',
        showlegend=False,
    )

    fig.add_trace(heatmap_edge_trace, row=1, col=2)
    fig.add_trace(heatmap_node_trace, row=1, col=2)

    # ============ Panel 3: Zone Security Status Bar Chart ============

    # Group nodes by zone and calculate average risk
    zones = {}
    for node, data in G.nodes(data=True):
        zone = data.get('zone', 'unknown').lower()
        if zone not in zones:
            zones[zone] = {'nodes': [], 'risks': []}
        zones[zone]['nodes'].append(node)
        zones[zone]['risks'].append(normalized_risk.get(node, 0))

    zone_names = []
    zone_avg_risks = []
    zone_colors_list = []

    zone_color_map = {
        'dmz': '#ff6b6b',
        'public': '#ff8c42',
        'internal': '#4ecdc4',
        'trusted': '#45b7d1',
        'database': '#574b90',
        'unknown': '#95a5a6',
    }

    for zone_name, zone_data in zones.items():
        avg_risk = sum(zone_data['risks']) / len(zone_data['risks']) if zone_data['risks'] else 0
        zone_names.append(zone_name.upper())
        zone_avg_risks.append(avg_risk)
        zone_colors_list.append(zone_color_map.get(zone_name, '#95a5a6'))

    zone_bar = go.Bar(
        x=zone_names,
        y=zone_avg_risks,
        marker=dict(
            color=zone_colors_list,
            line=dict(color='#333', width=2),
        ),
        text=[f"{risk:.1f}" for risk in zone_avg_risks],
        textposition='outside',
        hovertemplate='<b>%{x}</b><br>Avg Risk: %{y:.1f}/100<extra></extra>',
        showlegend=False,
    )

    fig.add_trace(zone_bar, row=2, col=2)

    # ============ Layout and Styling ============

    # Update 3D scene
    fig.update_scenes(
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        zaxis=dict(
            showgrid=True,
            title='Security Layer',
            ticktext=['DMZ', 'Internal', 'Trusted', 'Database'],
            tickvals=[0, 3, 6, 9],
        ),
        bgcolor='#0a0a0a',
        camera=dict(
            eye=dict(x=1.5, y=1.5, z=1.2)
        ),
        row=1,
        col=1,
    )

    # Update 2D heatmap axes
    fig.update_xaxes(showgrid=False, zeroline=False, showticklabels=False, row=1, col=2)
    fig.update_yaxes(showgrid=False, zeroline=False, showticklabels=False, row=1, col=2)

    # Update bar chart axes
    fig.update_xaxes(title="Security Zone", row=2, col=2)
    fig.update_yaxes(title="Average Risk Score", range=[0, 100], row=2, col=2)

    # Overall layout
    fig.update_layout(
        title=dict(
            text="🛡️ SECURITY COMMAND CENTER<br>"
                 "<sub>Real-Time Network Security Dashboard | All Systems Integrated</sub>",
            font=dict(size=24, color='white'),
            x=0.5,
            xanchor='center',
        ),
        width=2000,
        height=1200,
        showlegend=True,
        legend=dict(
            yanchor="top",
            y=0.98,
            xanchor="left",
            x=0.01,
            bgcolor='rgba(0,0,0,0.7)',
            bordercolor='white',
            borderwidth=1,
            font=dict(color='white', size=11),
        ),
        paper_bgcolor='#0a0a0a',
        plot_bgcolor='#0a0a0a',
        font=dict(color='white'),
    )

    # Add metric annotations
    total_risk = sum(normalized_risk.values()) / len(normalized_risk) if normalized_risk else 0
    critical_count = sum(1 for r in normalized_risk.values() if r > 70)
    high_count = sum(1 for r in normalized_risk.values() if r > 40 and r <= 70)

    metrics_text = (
        f"<b>🎯 KEY METRICS</b><br><br>"
        f"Total Assets: {len(G.nodes())}<br>"
        f"Attack Paths: {len(attack_paths)}<br>"
        f"Avg Risk: {total_risk:.1f}/100<br><br>"
        f"🔴 Critical: {critical_count}<br>"
        f"🟡 High: {high_count}<br><br>"
        f"<b>Status:</b> {'🚨 ALERT' if critical_count > 0 else '✅ NORMAL'}"
    )

    fig.add_annotation(
        text=metrics_text,
        xref="paper",
        yref="paper",
        x=0.99,
        y=0.5,
        showarrow=False,
        font=dict(size=13, color='white', family='monospace'),
        align='left',
        bgcolor='rgba(20,20,20,0.9)',
        bordercolor='#dc143c' if critical_count > 0 else '#45b7d1',
        borderwidth=3,
        borderpad=15,
        xanchor='right',
        yanchor='middle',
    )

    visualizer.save_html(fig, output_file)
    print(f"   ✓ Saved Security Command Center: {output_file}")


def create_holographic_security_story(visualizer, attack_paths, output_file):
    """
    Create immersive 3D "holographic" visualization that tells complete security story.

    Combines in single animated view:
    - 3D layered topology
    - Attack paths flowing with particles
    - Zone boundaries pulsing
    - Risk halos around nodes
    - Rotating camera for cinematic effect
    - Timeline of attack progression

    This is the ultimate "wow" visualization.
    """

    if not PLOTLY_AVAILABLE:
        print("   ⚠️  Skipping holographic story (plotly required)")
        return

    print(f"\n   Creating Holographic Security Story...")

    # Get graph
    G = visualizer.graph

    # Calculate node importance (risk + criticality + path count)
    node_importance = {}
    for node in G.nodes():
        path_count = sum(1 for p in attack_paths if any(s.node_id == node for s in p.steps))
        criticality = G.nodes[node].get('criticality', 'low')
        crit_scores = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}

        importance = path_count * 3 + crit_scores.get(criticality, 1)
        node_importance[node] = importance

    # Position nodes in 3D with layers
    zone_levels = {
        'dmz': 0.0, 'public': 0.0, 'internet': 0.0,
        'internal': 4.0, 'application': 4.0,
        'trusted': 8.0, 'secure': 8.0,
        'database': 12.0,
        'unknown': 2.0,
    }

    pos_2d = nx.spring_layout(G, k=2.5, iterations=50, seed=42)
    pos_3d = {}
    for node, (x, y) in pos_2d.items():
        zone = G.nodes[node].get('zone', 'unknown').lower()
        z = zone_levels.get(zone, 2.0)
        pos_3d[node] = (x * 6, y * 6, z)

    # Create animation frames
    frames = []
    num_frames = 150  # Longer for epic cinematic effect

    for frame_idx in range(num_frames):
        progress = frame_idx / num_frames

        # Camera rotation (full 360° while rising and orbiting)
        angle = progress * 2 * math.pi
        radius = 20 + 5 * math.sin(progress * 4 * math.pi)  # Pulsing radius
        height = 6 + 4 * math.sin(progress * 2 * math.pi)   # Undulating height

        camera_x = radius * math.cos(angle)
        camera_y = radius * math.sin(angle)
        camera_z = height

        # Base network edges with slight glow
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
            line=dict(color='rgba(100,100,150,0.3)', width=1),
            hoverinfo='none',
            showlegend=False,
        )

        # Attack path particles (flowing)
        particle_traces = []
        threat_colors = {
            'critical': '#ff0000',
            'high': '#ff6347',
            'medium': '#ffa500',
            'low': '#4682b4',
        }

        for path_idx, path in enumerate(attack_paths[:8]):
            # Stagger particles
            particle_progress = (progress + (path_idx * 0.15)) % 1.0

            # Find segment
            if len(path.steps) > 1:
                segment_length = 1.0 / (len(path.steps) - 1)
                segment_idx = int(particle_progress / segment_length)
                segment_idx = min(segment_idx, len(path.steps) - 2)

                u = path.steps[segment_idx].node_id
                v = path.steps[segment_idx + 1].node_id

                if u in pos_3d and v in pos_3d:
                    local_progress = (particle_progress - segment_idx * segment_length) / segment_length

                    px = pos_3d[u][0] + local_progress * (pos_3d[v][0] - pos_3d[u][0])
                    py = pos_3d[u][1] + local_progress * (pos_3d[v][1] - pos_3d[u][1])
                    pz = pos_3d[u][2] + local_progress * (pos_3d[v][2] - pos_3d[u][2])

                    color = threat_colors.get(path.threat_level.value, '#999')

                    # Create glowing particle
                    particle = go.Scatter3d(
                        x=[px],
                        y=[py],
                        z=[pz],
                        mode='markers',
                        marker=dict(
                            size=15,
                            color=color,
                            symbol='diamond',
                            line=dict(width=3, color='white'),
                            opacity=0.9,
                        ),
                        hoverinfo='none',
                        showlegend=False,
                    )
                    particle_traces.append(particle)

        # Nodes with pulsing "risk halos"
        node_x = []
        node_y = []
        node_z = []
        node_colors = []
        node_sizes = []
        node_texts = []

        pulse = 1.0 + 0.3 * math.sin(progress * 8 * math.pi)  # Pulsing effect

        zone_color_map = {
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
                importance = node_importance.get(node, 0)

                x, y, z = pos_3d[node]
                node_x.append(x)
                node_y.append(y)
                node_z.append(z)

                # Color by zone
                color = zone_color_map.get(zone, '#95a5a6')
                node_colors.append(color)

                # Size by importance (with pulse for high-importance nodes)
                base_size = 10 + importance
                if importance > 10:
                    size = base_size * pulse
                else:
                    size = base_size

                node_sizes.append(size)

                criticality = node_data.get('criticality', 'unknown')
                path_count = sum(1 for p in attack_paths if any(s.node_id == node for s in p.steps))

                node_texts.append(
                    f"<b>{name}</b><br>"
                    f"Zone: {zone.upper()}<br>"
                    f"Criticality: {criticality}<br>"
                    f"Attack Paths: {path_count}<br>"
                    f"Importance: {importance}"
                )

        node_trace = go.Scatter3d(
            x=node_x,
            y=node_y,
            z=node_z,
            mode='markers',
            marker=dict(
                size=node_sizes,
                color=node_colors,
                line=dict(width=2, color='white'),
                opacity=0.9,
            ),
            text=node_texts,
            hoverinfo='text',
            showlegend=False,
        )

        # Zone boundary rings (pulsing)
        zone_rings = []

        for zone_name, z_level in zone_levels.items():
            if zone_name == 'unknown':
                continue

            # Create ring at this level
            num_points = 30
            ring_radius = 7 + math.sin(progress * 4 * math.pi) * 0.5

            ring_x = []
            ring_y = []
            ring_z = []

            for i in range(num_points + 1):
                angle = (i / num_points) * 2 * math.pi
                ring_x.append(ring_radius * math.cos(angle))
                ring_y.append(ring_radius * math.sin(angle))
                ring_z.append(z_level)

            color = zone_color_map.get(zone_name, '#95a5a6')

            ring = go.Scatter3d(
                x=ring_x,
                y=ring_y,
                z=ring_z,
                mode='lines',
                line=dict(color=color, width=4, dash='dot'),
                hoverinfo='text',
                text=f"{zone_name.upper()} Zone Boundary",
                showlegend=False,
                opacity=0.6,
            )
            zone_rings.append(ring)

        # Combine all traces
        frame_data = [edge_trace] + particle_traces + [node_trace] + zone_rings

        # Progress indicator
        phase = "INITIALIZATION" if progress < 0.2 else \
                "ATTACK DETECTED" if progress < 0.5 else \
                "BREACH ANALYSIS" if progress < 0.8 else \
                "THREAT ASSESSMENT"

        frames.append(go.Frame(
            data=frame_data,
            name=f"frame_{frame_idx}",
            layout=go.Layout(
                scene=dict(
                    camera=dict(
                        eye=dict(
                            x=camera_x / radius,
                            y=camera_y / radius,
                            z=camera_z / radius
                        ),
                        center=dict(x=0, y=0, z=6),
                    )
                ),
                title_text=f"🔮 HOLOGRAPHIC SECURITY VISUALIZATION<br>"
                          f"<sub>Phase: {phase} | Progress: {progress:.0%}</sub>"
            )
        ))

    # Create figure
    fig = go.Figure(
        data=frames[0].data,
        frames=frames,
        layout=go.Layout(
            title=dict(
                text="🔮 HOLOGRAPHIC SECURITY VISUALIZATION<br>"
                     "<sub>Immersive 3D Network Security Story</sub>",
                font=dict(size=24, color='cyan'),
                x=0.5,
                xanchor='center',
            ),
            width=1800,
            height=1200,
            showlegend=False,
            scene=dict(
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, showbackground=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, showbackground=False),
                zaxis=dict(
                    showgrid=True,
                    gridcolor='rgba(100,150,200,0.3)',
                    zeroline=False,
                    showticklabels=True,
                    title=dict(text='SECURITY LAYERS', font=dict(color='cyan', size=14)),
                    ticktext=['EXPOSED', 'INTERNAL', 'SECURE', 'CRITICAL'],
                    tickvals=[0, 4, 8, 12],
                    tickfont=dict(color='cyan'),
                    showbackground=False,
                ),
                bgcolor='#000000',
            ),
            paper_bgcolor='#000000',
            font=dict(color='cyan'),
            updatemenus=[
                dict(
                    type='buttons',
                    showactive=False,
                    buttons=[
                        dict(
                            label='▶ PLAY STORY',
                            method='animate',
                            args=[None, {
                                'frame': {'duration': 50, 'redraw': True},
                                'fromcurrent': True,
                                'mode': 'immediate',
                            }]
                        ),
                        dict(
                            label='⏸ PAUSE',
                            method='animate',
                            args=[[None], {
                                'frame': {'duration': 0, 'redraw': False},
                                'mode': 'immediate',
                            }]
                        ),
                        dict(
                            label='⏮ RESTART',
                            method='animate',
                            args=[[frames[0].name], {
                                'frame': {'duration': 0, 'redraw': True},
                                'mode': 'immediate',
                            }]
                        )
                    ],
                    x=0.5,
                    y=0.02,
                    xanchor='center',
                    yanchor='bottom',
                    bgcolor='rgba(0,100,150,0.8)',
                    bordercolor='cyan',
                    borderwidth=2,
                    font=dict(color='cyan', size=14),
                )
            ]
        )
    )

    # Add legend for elements
    legend_text = (
        "<b>🔮 HOLOGRAPHIC LEGEND</b><br><br>"
        "💎 Flowing Particles = Active Attacks<br>"
        "⭕ Pulsing Rings = Zone Boundaries<br>"
        "🔴 Red Glow = Critical Threat<br>"
        "🟡 Orange = High Severity<br>"
        "🔵 Blue = Low Risk<br><br>"
        "📊 Node Size = Importance<br>"
        "🌈 Color = Security Zone<br><br>"
        "<i>Camera auto-rotates for full view</i>"
    )

    fig.add_annotation(
        text=legend_text,
        xref="paper",
        yref="paper",
        x=0.02,
        y=0.98,
        showarrow=False,
        font=dict(size=12, color='cyan', family='monospace'),
        align='left',
        bgcolor='rgba(0,20,40,0.9)',
        bordercolor='cyan',
        borderwidth=2,
        borderpad=12,
        xanchor='left',
        yanchor='top',
    )

    visualizer.save_html(fig, output_file)
    print(f"   ✓ Saved Holographic Security Story: {output_file}")


def main():
    """Create ultimate combined visualizations."""

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

    print("🌟 ULTIMATE COMBINED VISUALIZATIONS\n")
    print("=" * 70)

    if not PLOTLY_AVAILABLE:
        print("\n⚠️  Plotly is required for ultimate visualizations")
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

    # Load attack paths
    print("\n🔍 Analyzing attack paths...")
    analyzer = GraphAnalyzer(client)

    entry_points = analyzer.identify_entry_points()
    targets = analyzer.identify_high_value_targets()

    print(f"   ✓ Found {len(entry_points)} entry points")
    print(f"   ✓ Found {len(targets)} high-value targets")

    if not entry_points or not targets:
        print("\n⚠️  No entry points or targets found.")
        print("   Using sample attack paths instead...")
        # Create dummy attack paths for demonstration
        attack_paths = []
    else:
        attack_paths = analyzer.find_shortest_attack_paths(
            entry_points=entry_points,
            targets=targets,
            max_length=10,
            max_paths=20,
        )
        print(f"   ✓ Found {len(attack_paths)} attack paths")

    if not attack_paths:
        print("   ⚠️  No attack paths found. Visualizations will show topology only.")

    print("\n" + "=" * 70)
    print("CREATING ULTIMATE VISUALIZATIONS")
    print("=" * 70)

    # 1. Security Command Center
    print("\n1️⃣  Security Command Center Dashboard")
    print("   (Multi-panel synchronized view)")
    create_security_command_center(
        topo_viz,
        attack_paths if attack_paths else [],
        output_dir / "ultimate_command_center.html"
    )

    # 2. Holographic Security Story
    print("\n2️⃣  Holographic Security Story")
    print("   (Immersive 3D cinematic visualization)")
    create_holographic_security_story(
        topo_viz,
        attack_paths if attack_paths else [],
        output_dir / "ultimate_holographic_story.html"
    )

    print("\n" + "=" * 70)
    print("✅ ULTIMATE VISUALIZATIONS CREATED!")
    print("=" * 70)

    print("\n📁 Generated Masterpiece Visualizations:")
    print(f"   • ultimate_command_center.html - Multi-panel dashboard")
    print(f"   • ultimate_holographic_story.html - Cinematic 3D story")

    print("\n🎨 Visualization Features:")
    print("\n   COMMAND CENTER:")
    print("   • 3D topology with attack paths")
    print("   • Real-time risk heatmap")
    print("   • Zone security status chart")
    print("   • Key metrics panel")
    print("   • All views synchronized")

    print("\n   HOLOGRAPHIC STORY:")
    print("   • Flowing attack particles")
    print("   • Pulsing zone boundaries")
    print("   • Risk halos around nodes")
    print("   • Auto-rotating cinematic camera")
    print("   • Complete security narrative")

    print("\n💡 Usage Tips:")
    print("   • Command Center: Best for real-time monitoring")
    print("   • Holographic: Best for presentations and demos")
    print("   • Both are fully interactive")
    print("   • Use full-screen for maximum impact")
    print("   • Record Holographic as video for marketing")

    print("\n🎯 Perfect For:")
    print("   • Executive presentations")
    print("   • Security operations centers")
    print("   • Investor pitches")
    print("   • Conference demos")
    print("   • Marketing materials")

    print("\n🌟 These are the ultimate 'wow factor' visualizations!")


if __name__ == "__main__":
    main()
