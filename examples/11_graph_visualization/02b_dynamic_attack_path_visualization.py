#!/usr/bin/env python3
"""
Example 2B: Dynamic Attack Path Visualization

This example demonstrates advanced, interactive attack path visualizations:
- Animated step-by-step attack progression
- Interactive controls and filtering
- Comparison views
- 3D visualization
- Risk heatmaps
- Path selection and exploration
"""

import json
from pathlib import Path
from threat_radar.graph import NetworkXClient, GraphAnalyzer
from threat_radar.visualization import AttackPathVisualizer, GraphExporter

# Check if plotly is available for animations
try:
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    print("⚠️  Plotly not available. Install with: pip install plotly")


def create_animated_attack_path(visualizer, attack_path, output_file):
    """Create animated step-by-step attack path visualization."""

    if not PLOTLY_AVAILABLE:
        print("   ⚠️  Skipping animation (plotly required)")
        return

    print(f"\n   Creating animated attack path: {attack_path.path_id}")

    # Get graph
    G = visualizer.graph

    # Calculate layout
    import networkx as nx
    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

    # Create frames for animation (one per step)
    frames = []

    for step_idx in range(len(attack_path.steps) + 1):
        # Nodes and edges visible up to this step
        visible_steps = attack_path.steps[:step_idx]
        visible_nodes = set(s.node_id for s in visible_steps)

        # Edge trace (attack path edges up to this step)
        edge_x = []
        edge_y = []

        for i in range(len(visible_steps) - 1):
            u = visible_steps[i].node_id
            v = visible_steps[i + 1].node_id

            if u in pos and v in pos:
                edge_x.extend([pos[u][0], pos[v][0], None])
                edge_y.extend([pos[u][1], pos[v][1], None])

        edge_trace = go.Scatter(
            x=edge_x,
            y=edge_y,
            mode='lines',
            line=dict(color='#dc143c', width=4),
            hoverinfo='none',
            showlegend=False,
        )

        # Node trace (all nodes, but highlight visited)
        node_x = []
        node_y = []
        node_colors = []
        node_sizes = []
        node_texts = []

        for node in G.nodes():
            if node in pos:
                node_x.append(pos[node][0])
                node_y.append(pos[node][1])

                node_data = G.nodes[node]
                node_name = node_data.get('name', node)

                if node in visible_nodes:
                    # Visited node
                    step_num = next((i for i, s in enumerate(visible_steps) if s.node_id == node), -1)
                    if step_num == len(visible_steps) - 1:
                        # Current step - pulse effect
                        node_colors.append('#ff0000')
                        node_sizes.append(25)
                        node_texts.append(f"<b>CURRENT: {node_name}</b><br>Step {step_num + 1}")
                    else:
                        # Previous step
                        node_colors.append('#ff6347')
                        node_sizes.append(18)
                        node_texts.append(f"<b>{node_name}</b><br>Step {step_num + 1}")
                else:
                    # Not yet visited
                    node_colors.append('#bdc3c7')
                    node_sizes.append(12)
                    node_texts.append(node_name)

        node_trace = go.Scatter(
            x=node_x,
            y=node_y,
            mode='markers+text',
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
        frame_name = f"Step {step_idx}" if step_idx > 0 else "Start"
        frames.append(go.Frame(
            data=[edge_trace, node_trace],
            name=frame_name,
            layout=go.Layout(
                title_text=f"Attack Path Animation - {frame_name}/{len(attack_path.steps)}"
            )
        ))

    # Create initial figure
    fig = go.Figure(
        data=[frames[0].data[0], frames[0].data[1]],
        frames=frames,
        layout=go.Layout(
            title=dict(
                text=f"Attack Path Animation: {attack_path.path_id}<br>Threat: {attack_path.threat_level.value.upper()}",
                font=dict(size=20)
            ),
            width=1400,
            height=900,
            showlegend=False,
            hovermode='closest',
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='#f8f9fa',
            # Animation controls
            updatemenus=[
                dict(
                    type='buttons',
                    showactive=False,
                    buttons=[
                        dict(
                            label='▶ Play',
                            method='animate',
                            args=[None, {
                                'frame': {'duration': 1500, 'redraw': True},
                                'fromcurrent': True,
                                'mode': 'immediate',
                                'transition': {'duration': 500}
                            }]
                        ),
                        dict(
                            label='⏸ Pause',
                            method='animate',
                            args=[[None], {
                                'frame': {'duration': 0, 'redraw': False},
                                'mode': 'immediate',
                                'transition': {'duration': 0}
                            }]
                        ),
                        dict(
                            label='⏮ Reset',
                            method='animate',
                            args=[[frames[0].name], {
                                'frame': {'duration': 0, 'redraw': True},
                                'mode': 'immediate',
                                'transition': {'duration': 0}
                            }]
                        )
                    ],
                    x=0.1,
                    y=1.15,
                    xanchor='left',
                    yanchor='top'
                )
            ],
            # Slider
            sliders=[{
                'active': 0,
                'yanchor': 'top',
                'y': 0,
                'xanchor': 'left',
                'x': 0.1,
                'currentvalue': {
                    'prefix': 'Attack Step: ',
                    'visible': True,
                    'xanchor': 'right'
                },
                'pad': {'b': 10, 't': 50},
                'len': 0.9,
                'steps': [
                    {
                        'args': [[f.name], {
                            'frame': {'duration': 500, 'redraw': True},
                            'mode': 'immediate',
                            'transition': {'duration': 300}
                        }],
                        'method': 'animate',
                        'label': f.name
                    }
                    for f in frames
                ]
            }]
        )
    )

    # Add step information annotation
    fig.add_annotation(
        text=f"<b>Attack Path Details:</b><br>"
             f"Entry: {attack_path.entry_point}<br>"
             f"Target: {attack_path.target}<br>"
             f"Total Steps: {len(attack_path.steps)}<br>"
             f"CVSS Score: {attack_path.total_cvss:.1f}<br>"
             f"Exploitability: {attack_path.exploitability:.0%}",
        xref="paper",
        yref="paper",
        x=0.98,
        y=0.98,
        showarrow=False,
        font=dict(size=12),
        align='left',
        bgcolor='rgba(255,255,255,0.9)',
        bordercolor='#333',
        borderwidth=2,
        borderpad=10,
        xanchor='right',
        yanchor='top',
    )

    visualizer.save_html(fig, output_file)
    print(f"   ✓ Saved animated visualization: {output_file}")


def create_3d_attack_paths(visualizer, attack_paths, output_file):
    """Create 3D visualization of multiple attack paths."""

    if not PLOTLY_AVAILABLE:
        print("   ⚠️  Skipping 3D visualization (plotly required)")
        return

    print(f"\n   Creating 3D attack path visualization...")

    # Get graph
    G = visualizer.graph

    # Calculate 3D layout
    import networkx as nx
    pos_2d = nx.spring_layout(G, k=2, iterations=50, seed=42)

    # Convert to 3D by adding z-coordinate based on criticality
    pos_3d = {}
    for node, (x, y) in pos_2d.items():
        node_data = G.nodes[node]
        # Z-coordinate based on criticality or severity
        criticality = node_data.get('criticality', 'low')
        criticality_z = {
            'critical': 3.0,
            'high': 2.0,
            'medium': 1.0,
            'low': 0.0,
        }.get(criticality, 0.5)

        pos_3d[node] = (x, y, criticality_z)

    # Create traces for each attack path
    path_traces = []

    threat_colors = {
        'critical': '#8b0000',
        'high': '#dc143c',
        'medium': '#ffa500',
        'low': '#4682b4',
    }

    for path in attack_paths[:10]:  # Limit to 10 paths for clarity
        edge_x = []
        edge_y = []
        edge_z = []

        for i in range(len(path.steps) - 1):
            u = path.steps[i].node_id
            v = path.steps[i + 1].node_id

            if u in pos_3d and v in pos_3d:
                edge_x.extend([pos_3d[u][0], pos_3d[v][0], None])
                edge_y.extend([pos_3d[u][1], pos_3d[v][1], None])
                edge_z.extend([pos_3d[u][2], pos_3d[v][2], None])

        color = threat_colors.get(path.threat_level.value, '#999')

        edge_trace = go.Scatter3d(
            x=edge_x,
            y=edge_y,
            z=edge_z,
            mode='lines',
            line=dict(color=color, width=5),
            hoverinfo='text',
            text=f"Path {path.path_id}: {path.threat_level.value.upper()}",
            name=f"{path.threat_level.value.upper()} Path",
        )
        path_traces.append(edge_trace)

    # Node trace
    node_x = []
    node_y = []
    node_z = []
    node_colors = []
    node_texts = []

    for node, (x, y, z) in pos_3d.items():
        node_data = G.nodes[node]
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

        name = node_data.get('name', node)
        node_type = node_data.get('node_type', 'unknown')
        node_texts.append(f"<b>{name}</b><br>Type: {node_type}<br>Criticality: {criticality}")

    node_trace = go.Scatter3d(
        x=node_x,
        y=node_y,
        z=node_z,
        mode='markers',
        marker=dict(
            size=8,
            color=node_colors,
            line=dict(width=2, color='white'),
        ),
        text=node_texts,
        hoverinfo='text',
        name='Assets',
    )

    # Create figure
    fig = go.Figure(data=[node_trace] + path_traces)

    fig.update_layout(
        title=dict(
            text=f"3D Attack Path Visualization<br>{len(attack_paths)} Paths Analyzed",
            font=dict(size=20)
        ),
        width=1400,
        height=900,
        showlegend=True,
        scene=dict(
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, title=''),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, title=''),
            zaxis=dict(
                showgrid=True,
                zeroline=False,
                showticklabels=True,
                title='Criticality Level',
                ticktext=['Low', 'Medium', 'High', 'Critical'],
                tickvals=[0, 1, 2, 3],
            ),
            bgcolor='#f8f9fa',
        ),
        legend=dict(
            yanchor="top",
            y=0.99,
            xanchor="left",
            x=0.01
        )
    )

    visualizer.save_html(fig, output_file)
    print(f"   ✓ Saved 3D visualization: {output_file}")


def create_comparison_view(visualizer, attack_paths, output_file):
    """Create side-by-side comparison of multiple attack paths."""

    if not PLOTLY_AVAILABLE:
        print("   ⚠️  Skipping comparison view (plotly required)")
        return

    print(f"\n   Creating attack path comparison view...")

    # Select top 4 paths by different criteria
    if len(attack_paths) < 4:
        print(f"   ⚠️  Need at least 4 paths for comparison (found {len(attack_paths)})")
        return

    # Sort by different criteria
    most_critical = max(attack_paths, key=lambda p: (p.threat_level.value == 'critical', p.total_cvss))
    shortest = min(attack_paths, key=lambda p: p.path_length)
    most_exploitable = max(attack_paths, key=lambda p: p.exploitability)
    longest = max(attack_paths, key=lambda p: p.path_length)

    paths_to_compare = [
        ("Most Critical", most_critical),
        ("Shortest Path", shortest),
        ("Most Exploitable", most_exploitable),
        ("Longest Path", longest),
    ]

    # Create 2x2 subplot
    from plotly.subplots import make_subplots

    fig = make_subplots(
        rows=2,
        cols=2,
        subplot_titles=[title for title, _ in paths_to_compare],
        specs=[[{"type": "scatter"}, {"type": "scatter"}],
               [{"type": "scatter"}, {"type": "scatter"}]],
        horizontal_spacing=0.1,
        vertical_spacing=0.15,
    )

    # Get graph
    G = visualizer.graph

    # Calculate layout
    import networkx as nx
    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

    # Add each path to a subplot
    for idx, (title, path) in enumerate(paths_to_compare):
        row = (idx // 2) + 1
        col = (idx % 2) + 1

        # Extract subgraph for this path
        path_nodes = set(s.node_id for s in path.steps)

        # Edge trace
        edge_x = []
        edge_y = []

        for i in range(len(path.steps) - 1):
            u = path.steps[i].node_id
            v = path.steps[i + 1].node_id

            if u in pos and v in pos:
                edge_x.extend([pos[u][0], pos[v][0], None])
                edge_y.extend([pos[u][1], pos[v][1], None])

        threat_colors = {
            'critical': '#8b0000',
            'high': '#dc143c',
            'medium': '#ffa500',
            'low': '#4682b4',
        }
        color = threat_colors.get(path.threat_level.value, '#999')

        edge_trace = go.Scatter(
            x=edge_x,
            y=edge_y,
            mode='lines',
            line=dict(color=color, width=3),
            hoverinfo='none',
            showlegend=False,
        )

        # Node trace
        node_x = []
        node_y = []
        node_colors = []
        node_sizes = []
        node_texts = []

        for node in G.nodes():
            if node in pos:
                node_x.append(pos[node][0])
                node_y.append(pos[node][1])

                node_data = G.nodes[node]
                name = node_data.get('name', node)

                if node in path_nodes:
                    # Part of path
                    step_num = next((i for i, s in enumerate(path.steps) if s.node_id == node), -1)
                    node_colors.append(color)
                    node_sizes.append(15)
                    node_texts.append(f"<b>{name}</b><br>Step {step_num + 1}")
                else:
                    # Not in path
                    node_colors.append('#e0e0e0')
                    node_sizes.append(8)
                    node_texts.append(name)

        node_trace = go.Scatter(
            x=node_x,
            y=node_y,
            mode='markers',
            marker=dict(
                size=node_sizes,
                color=node_colors,
                line=dict(width=1, color='white'),
            ),
            text=node_texts,
            hoverinfo='text',
            showlegend=False,
        )

        fig.add_trace(edge_trace, row=row, col=col)
        fig.add_trace(node_trace, row=row, col=col)

        # Add metrics annotation
        metrics_text = (
            f"Threat: {path.threat_level.value.upper()}<br>"
            f"Steps: {path.path_length}<br>"
            f"CVSS: {path.total_cvss:.1f}<br>"
            f"Exploit: {path.exploitability:.0%}"
        )

        fig.add_annotation(
            text=metrics_text,
            xref=f"x{idx+1}",
            yref=f"y{idx+1}",
            x=0.95,
            y=0.95,
            xanchor='right',
            yanchor='top',
            showarrow=False,
            font=dict(size=10),
            bgcolor='rgba(255,255,255,0.8)',
            bordercolor='#333',
            borderwidth=1,
            borderpad=5,
            row=row,
            col=col,
        )

        # Update axes
        fig.update_xaxes(showgrid=False, zeroline=False, showticklabels=False, row=row, col=col)
        fig.update_yaxes(showgrid=False, zeroline=False, showticklabels=False, row=row, col=col)

    fig.update_layout(
        title=dict(
            text="Attack Path Comparison - Different Strategies",
            font=dict(size=20)
        ),
        width=1600,
        height=1200,
        plot_bgcolor='#f8f9fa',
    )

    visualizer.save_html(fig, output_file)
    print(f"   ✓ Saved comparison view: {output_file}")


def create_risk_heatmap(visualizer, attack_paths, output_file):
    """Create risk heatmap showing vulnerability density."""

    if not PLOTLY_AVAILABLE:
        print("   ⚠️  Skipping risk heatmap (plotly required)")
        return

    print(f"\n   Creating risk heatmap...")

    # Get graph
    G = visualizer.graph

    # Calculate layout
    import networkx as nx
    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

    # Calculate risk score for each node
    # (based on number of paths passing through and their threat levels)
    node_risk = {}

    for node in G.nodes():
        risk_score = 0
        path_count = 0

        for path in attack_paths:
            if any(s.node_id == node for s in path.steps):
                path_count += 1

                # Add risk based on threat level
                threat_weights = {
                    'critical': 4.0,
                    'high': 3.0,
                    'medium': 2.0,
                    'low': 1.0,
                }
                risk_score += threat_weights.get(path.threat_level.value, 1.0)

        node_risk[node] = risk_score

    # Normalize risk scores
    max_risk = max(node_risk.values()) if node_risk else 1
    normalized_risk = {node: (risk / max_risk) * 100 for node, risk in node_risk.items()}

    # Create heatmap visualization
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

    # Node trace with risk-based coloring
    node_x = []
    node_y = []
    node_colors = []
    node_sizes = []
    node_texts = []

    for node in G.nodes():
        if node in pos:
            node_data = G.nodes[node]
            name = node_data.get('name', node)
            risk = normalized_risk.get(node, 0)

            node_x.append(pos[node][0])
            node_y.append(pos[node][1])
            node_colors.append(risk)
            node_sizes.append(10 + (risk / 10))  # Size based on risk

            path_count = sum(1 for p in attack_paths if any(s.node_id == node for s in p.steps))
            node_texts.append(
                f"<b>{name}</b><br>"
                f"Risk Score: {risk:.1f}/100<br>"
                f"Attack Paths: {path_count}<br>"
                f"Type: {node_data.get('node_type', 'unknown')}"
            )

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode='markers',
        marker=dict(
            size=node_sizes,
            color=node_colors,
            colorscale='Reds',
            showscale=True,
            colorbar=dict(
                title="Risk Score",
                thickness=20,
                len=0.7,
            ),
            line=dict(width=2, color='white'),
            cmin=0,
            cmax=100,
        ),
        text=node_texts,
        hoverinfo='text',
        showlegend=False,
    )

    fig = go.Figure(data=[edge_trace, node_trace])

    fig.update_layout(
        title=dict(
            text=f"Attack Surface Risk Heatmap<br>{len(attack_paths)} Attack Paths Analyzed",
            font=dict(size=20)
        ),
        width=1400,
        height=900,
        showlegend=False,
        hovermode='closest',
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor='#f8f9fa',
    )

    # Add legend
    fig.add_annotation(
        text=(
            "<b>Risk Heatmap Legend:</b><br>"
            "🔴 Dark Red: High Risk<br>"
            "🟠 Orange: Medium Risk<br>"
            "⚪ White: Low Risk<br><br>"
            "Node size = Risk level<br>"
            "Color intensity = Attack path density"
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
    print(f"   ✓ Saved risk heatmap: {output_file}")


def main():
    """Create dynamic attack path visualizations."""

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

    print("🎯 Dynamic Attack Path Visualization Examples\n")
    print("=" * 70)

    if not PLOTLY_AVAILABLE:
        print("\n⚠️  Plotly is required for dynamic visualizations")
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

    # Show threat distribution
    threat_counts = {}
    for path in attack_paths:
        level = path.threat_level.value
        threat_counts[level] = threat_counts.get(level, 0) + 1

    print(f"\n   Threat Level Distribution:")
    for level in ["critical", "high", "medium", "low"]:
        count = threat_counts.get(level, 0)
        if count > 0:
            print(f"      • {level.upper()}: {count} path(s)")

    # Create visualizer
    visualizer = AttackPathVisualizer(client)

    print("\n" + "=" * 70)
    print("DYNAMIC VISUALIZATIONS")
    print("=" * 70)

    # 1. Animated step-by-step attack path
    print("\n1️⃣  Animated Attack Path Progression")
    most_critical = max(attack_paths, key=lambda p: (
        p.threat_level.value == 'critical',
        p.total_cvss
    ))
    create_animated_attack_path(
        visualizer,
        most_critical,
        output_dir / "attack_path_animated.html"
    )

    # 2. 3D visualization
    print("\n2️⃣  3D Attack Path Visualization")
    create_3d_attack_paths(
        visualizer,
        attack_paths,
        output_dir / "attack_paths_3d.html"
    )

    # 3. Comparison view
    print("\n3️⃣  Attack Path Comparison")
    create_comparison_view(
        visualizer,
        attack_paths,
        output_dir / "attack_paths_comparison.html"
    )

    # 4. Risk heatmap
    print("\n4️⃣  Risk Heatmap")
    create_risk_heatmap(
        visualizer,
        attack_paths,
        output_dir / "attack_surface_heatmap.html"
    )

    print("\n" + "=" * 70)
    print("✅ Dynamic visualizations created successfully!")
    print("=" * 70)

    print("\n📁 Generated Files:")
    print(f"   • attack_path_animated.html - Step-by-step attack progression")
    print(f"   • attack_paths_3d.html - Interactive 3D view")
    print(f"   • attack_paths_comparison.html - Side-by-side comparison")
    print(f"   • attack_surface_heatmap.html - Risk density heatmap")

    print("\n🎨 Interactive Features:")
    print("   • Animated: Use play/pause controls and slider")
    print("   • 3D: Click and drag to rotate, scroll to zoom")
    print("   • Comparison: Hover for details on each path")
    print("   • Heatmap: Color intensity shows attack concentration")

    print("\n💡 Tips:")
    print("   • Open HTML files in a modern browser (Chrome, Firefox, Safari)")
    print("   • Animations work best with the play button")
    print("   • 3D view can be rotated for different perspectives")
    print("   • Heatmap shows which assets are most targeted")


if __name__ == "__main__":
    main()
