"""Attack path visualization with highlighted routes."""

import logging
from typing import List, Dict, Set, Tuple, Optional
from pathlib import Path

try:
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

from ..graph.graph_client import NetworkXClient
from ..graph.models import AttackPath, AttackStep, ThreatLevel
from .graph_visualizer import NetworkGraphVisualizer

logger = logging.getLogger(__name__)


class AttackPathVisualizer(NetworkGraphVisualizer):
    """Specialized visualizer for attack paths."""

    THREAT_LEVEL_COLORS = {
        ThreatLevel.CRITICAL: "#8b0000",  # Dark red
        ThreatLevel.HIGH: "#dc143c",      # Crimson
        ThreatLevel.MEDIUM: "#ffa500",    # Orange
        ThreatLevel.LOW: "#4682b4",       # Steel blue
    }

    PATH_EDGE_WIDTH = 5
    PATH_NODE_SIZE = 20

    def __init__(self, client: NetworkXClient):
        """
        Initialize attack path visualizer.

        Args:
            client: NetworkXClient instance with loaded graph
        """
        super().__init__(client)

    def visualize_attack_paths(
        self,
        attack_paths: List[AttackPath],
        layout: str = "hierarchical",
        title: str = "Attack Path Analysis",
        width: int = 1400,
        height: int = 900,
        show_all_paths: bool = False,
        max_paths_display: int = 5,
    ) -> go.Figure:
        """
        Visualize attack paths with highlighted routes.

        Args:
            attack_paths: List of AttackPath objects to visualize
            layout: Layout algorithm
            title: Figure title
            width: Figure width
            height: Figure height
            show_all_paths: Show all paths or just the most critical
            max_paths_display: Maximum number of paths to display

        Returns:
            Plotly figure with highlighted attack paths
        """
        if not attack_paths:
            logger.warning("No attack paths provided for visualization")
            return go.Figure()

        # Sort paths by threat level and CVSS
        sorted_paths = sorted(
            attack_paths,
            key=lambda p: (
                p.threat_level == ThreatLevel.CRITICAL,
                p.threat_level == ThreatLevel.HIGH,
                -p.total_cvss
            ),
            reverse=True
        )

        # Limit paths if not showing all
        if not show_all_paths:
            sorted_paths = sorted_paths[:max_paths_display]

        logger.info(f"Visualizing {len(sorted_paths)} attack paths")

        # Extract nodes and edges from paths
        path_nodes = set()
        path_edges = set()

        for path in sorted_paths:
            for step in path.steps:
                path_nodes.add(step.node_id)

            # Create edges between consecutive steps
            for i in range(len(path.steps) - 1):
                u = path.steps[i].node_id
                v = path.steps[i + 1].node_id
                path_edges.add((u, v))

        # Calculate layout
        pos = self._calculate_layout(layout, three_d=False)

        # Create base visualization
        fig = self._create_path_figure(
            pos=pos,
            attack_paths=sorted_paths,
            path_nodes=path_nodes,
            path_edges=path_edges,
            title=title,
            width=width,
            height=height,
        )

        return fig

    def visualize_single_path(
        self,
        attack_path: AttackPath,
        layout: str = "hierarchical",
        title: Optional[str] = None,
        width: int = 1200,
        height: int = 800,
        show_step_details: bool = True,
    ) -> go.Figure:
        """
        Visualize a single attack path in detail.

        Args:
            attack_path: AttackPath object to visualize
            layout: Layout algorithm
            title: Figure title (auto-generated if None)
            width: Figure width
            height: Figure height
            show_step_details: Show detailed step information

        Returns:
            Plotly figure focused on single path
        """
        if not title:
            title = f"Attack Path: {attack_path.entry_point} → {attack_path.target}"

        # Extract path nodes and edges
        path_nodes = {step.node_id for step in attack_path.steps}
        path_edges = set()

        for i in range(len(attack_path.steps) - 1):
            u = attack_path.steps[i].node_id
            v = attack_path.steps[i + 1].node_id
            path_edges.add((u, v))

        # Filter graph to show only relevant nodes (path + immediate neighbors)
        relevant_nodes = self._get_relevant_nodes(path_nodes)

        # Calculate layout
        pos = self._calculate_layout(layout, three_d=False)

        # Create figure
        fig = self._create_single_path_figure(
            pos=pos,
            attack_path=attack_path,
            path_nodes=path_nodes,
            path_edges=path_edges,
            relevant_nodes=relevant_nodes,
            title=title,
            width=width,
            height=height,
            show_step_details=show_step_details,
        )

        return fig

    def _create_path_figure(
        self,
        pos: Dict[str, Tuple[float, float]],
        attack_paths: List[AttackPath],
        path_nodes: Set[str],
        path_edges: Set[Tuple[str, str]],
        title: str,
        width: int,
        height: int,
    ) -> go.Figure:
        """Create figure with multiple attack paths highlighted."""
        # Create base edges (dimmed)
        edge_traces = self._create_dimmed_edges(pos)

        # Create highlighted path edges (one trace per path)
        for i, path in enumerate(attack_paths):
            path_edge_trace = self._create_path_edge_trace(pos, path, i)
            edge_traces.append(path_edge_trace)

        # Create node traces
        path_node_trace = self._create_path_node_trace(pos, path_nodes, attack_paths)
        other_node_trace = self._create_other_node_trace(pos, path_nodes)

        # Combine all traces
        data = edge_traces + [other_node_trace, path_node_trace]

        # Create layout
        layout = go.Layout(
            title=dict(
                text=title,
                font=dict(size=20, color='#333')
            ),
            width=width,
            height=height,
            showlegend=True,
            hovermode='closest',
            margin=dict(b=50, l=50, r=50, t=80),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='#f8f9fa',
        )

        fig = go.Figure(data=data, layout=layout)

        # Add legend for threat levels
        self._add_threat_level_legend(fig, attack_paths)

        return fig

    def _create_single_path_figure(
        self,
        pos: Dict[str, Tuple[float, float]],
        attack_path: AttackPath,
        path_nodes: Set[str],
        path_edges: Set[Tuple[str, str]],
        relevant_nodes: Set[str],
        title: str,
        width: int,
        height: int,
        show_step_details: bool,
    ) -> go.Figure:
        """Create figure for single path visualization."""
        # Create edge trace for the path
        path_edge_trace = self._create_path_edge_trace(
            pos,
            attack_path,
            path_index=0,
        )

        # Create node traces
        path_node_trace = self._create_path_node_trace(
            pos,
            path_nodes,
            [attack_path],
        )

        # Create trace for nearby nodes (dimmed)
        nearby_nodes = relevant_nodes - path_nodes
        nearby_trace = self._create_nearby_node_trace(pos, nearby_nodes)

        # Combine traces
        data = [path_edge_trace, nearby_trace, path_node_trace]

        # Create layout with step annotations
        layout = go.Layout(
            title=dict(
                text=title,
                font=dict(size=20, color='#333')
            ),
            width=width,
            height=height,
            showlegend=True,
            hovermode='closest',
            margin=dict(b=50, l=50, r=50, t=100),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='#f8f9fa',
        )

        fig = go.Figure(data=data, layout=layout)

        # Add step annotations if requested
        if show_step_details:
            self._add_step_annotations(fig, pos, attack_path)

        # Add path info box
        self._add_path_info_box(fig, attack_path)

        return fig

    def _create_dimmed_edges(
        self,
        pos: Dict[str, Tuple[float, float]]
    ) -> List[go.Scatter]:
        """Create dimmed background edges."""
        x_coords = []
        y_coords = []

        for u, v in self.graph.edges():
            if u not in pos or v not in pos:
                continue

            x_coords.extend([pos[u][0], pos[v][0], None])
            y_coords.extend([pos[u][1], pos[v][1], None])

        trace = go.Scatter(
            x=x_coords,
            y=y_coords,
            mode='lines',
            line=dict(color='#e0e0e0', width=0.5),
            hoverinfo='none',
            showlegend=False,
        )

        return [trace]

    def _create_path_edge_trace(
        self,
        pos: Dict[str, Tuple[float, float]],
        attack_path: AttackPath,
        path_index: int,
    ) -> go.Scatter:
        """Create edge trace for an attack path."""
        x_coords = []
        y_coords = []

        for i in range(len(attack_path.steps) - 1):
            u = attack_path.steps[i].node_id
            v = attack_path.steps[i + 1].node_id

            if u not in pos or v not in pos:
                continue

            x_coords.extend([pos[u][0], pos[v][0], None])
            y_coords.extend([pos[u][1], pos[v][1], None])

        color = self.THREAT_LEVEL_COLORS[attack_path.threat_level]

        trace = go.Scatter(
            x=x_coords,
            y=y_coords,
            mode='lines',
            line=dict(
                color=color,
                width=self.PATH_EDGE_WIDTH,
            ),
            hoverinfo='text',
            text=f"Path {path_index + 1}: {attack_path.threat_level.value.upper()}",
            name=f"Path {path_index + 1} ({attack_path.threat_level.value})",
        )

        return trace

    def _create_path_node_trace(
        self,
        pos: Dict[str, Tuple[float, float]],
        path_nodes: Set[str],
        attack_paths: List[AttackPath],
    ) -> go.Scatter:
        """Create node trace for path nodes."""
        x_coords = []
        y_coords = []
        colors = []
        sizes = []
        hover_texts = []

        # Build node to path mapping for coloring
        node_threats = {}
        for path in attack_paths:
            for step in path.steps:
                if step.node_id not in node_threats:
                    node_threats[step.node_id] = path.threat_level
                elif path.threat_level.value == "critical":
                    # Override with critical if any path through node is critical
                    node_threats[step.node_id] = path.threat_level

        for node in path_nodes:
            if node not in pos:
                continue

            node_data = self.graph.nodes[node]
            x_coords.append(pos[node][0])
            y_coords.append(pos[node][1])

            # Color by threat level
            threat_level = node_threats.get(node, ThreatLevel.LOW)
            colors.append(self.THREAT_LEVEL_COLORS[threat_level])

            # Larger size for entry/target points
            is_entry_or_target = any(
                node == path.entry_point or node == path.target
                for path in attack_paths
            )
            sizes.append(self.PATH_NODE_SIZE * 1.5 if is_entry_or_target else self.PATH_NODE_SIZE)

            # Create hover text
            hover_text = self._create_path_node_hover(node, node_data, attack_paths)
            hover_texts.append(hover_text)

        trace = go.Scatter(
            x=x_coords,
            y=y_coords,
            mode='markers',
            marker=dict(
                size=sizes,
                color=colors,
                line=dict(width=2, color='white'),
            ),
            text=hover_texts,
            hoverinfo='text',
            name="Attack Path Nodes",
        )

        return trace

    def _create_other_node_trace(
        self,
        pos: Dict[str, Tuple[float, float]],
        path_nodes: Set[str],
    ) -> go.Scatter:
        """Create trace for non-path nodes (dimmed)."""
        x_coords = []
        y_coords = []
        hover_texts = []

        for node in self.graph.nodes():
            if node in path_nodes or node not in pos:
                continue

            node_data = self.graph.nodes[node]
            x_coords.append(pos[node][0])
            y_coords.append(pos[node][1])
            hover_texts.append(self._create_hover_text(node, node_data))

        trace = go.Scatter(
            x=x_coords,
            y=y_coords,
            mode='markers',
            marker=dict(
                size=8,
                color='#bdc3c7',
                opacity=0.3,
                line=dict(width=1, color='white'),
            ),
            text=hover_texts,
            hoverinfo='text',
            showlegend=False,
        )

        return trace

    def _create_nearby_node_trace(
        self,
        pos: Dict[str, Tuple[float, float]],
        nearby_nodes: Set[str],
    ) -> go.Scatter:
        """Create trace for nodes near the path."""
        x_coords = []
        y_coords = []
        hover_texts = []

        for node in nearby_nodes:
            if node not in pos:
                continue

            node_data = self.graph.nodes[node]
            x_coords.append(pos[node][0])
            y_coords.append(pos[node][1])
            hover_texts.append(self._create_hover_text(node, node_data))

        trace = go.Scatter(
            x=x_coords,
            y=y_coords,
            mode='markers',
            marker=dict(
                size=10,
                color='#95a5a6',
                opacity=0.5,
                line=dict(width=1, color='white'),
            ),
            text=hover_texts,
            hoverinfo='text',
            name="Related Nodes",
        )

        return trace

    def _create_path_node_hover(
        self,
        node_id: str,
        node_data: Dict,
        attack_paths: List[AttackPath],
    ) -> str:
        """Create hover text for path nodes with attack context."""
        lines = [f"<b>{node_id}</b>"]

        # Add role in attack paths
        roles = []
        for path in attack_paths:
            if node_id == path.entry_point:
                roles.append("🚪 Entry Point")
            elif node_id == path.target:
                roles.append("🎯 Target")
            else:
                for step in path.steps:
                    if step.node_id == node_id:
                        roles.append(f"⚡ {step.step_type.value.replace('_', ' ').title()}")
                        break

        if roles:
            lines.append("<br>".join(roles))

        # Add node info
        node_type = node_data.get("node_type", "unknown")
        lines.append(f"Type: {node_type}")

        # Add vulnerabilities if present
        for path in attack_paths:
            for step in path.steps:
                if step.node_id == node_id and step.vulnerabilities:
                    lines.append(f"CVEs: {', '.join(step.vulnerabilities[:3])}")
                    if step.cvss_score:
                        lines.append(f"CVSS: {step.cvss_score:.1f}")
                    break

        return "<br>".join(lines)

    def _get_relevant_nodes(self, path_nodes: Set[str]) -> Set[str]:
        """Get nodes relevant to the path (path + immediate neighbors)."""
        relevant = set(path_nodes)

        for node in path_nodes:
            # Add predecessors and successors
            relevant.update(self.graph.predecessors(node))
            relevant.update(self.graph.successors(node))

        return relevant

    def _add_step_annotations(
        self,
        fig: go.Figure,
        pos: Dict[str, Tuple[float, float]],
        attack_path: AttackPath,
    ) -> None:
        """Add step number annotations to the path."""
        annotations = []

        for i, step in enumerate(attack_path.steps):
            if step.node_id not in pos:
                continue

            x, y = pos[step.node_id]

            annotations.append(
                dict(
                    x=x,
                    y=y,
                    text=f"<b>{i + 1}</b>",
                    showarrow=False,
                    font=dict(size=12, color='white'),
                    bgcolor='rgba(0,0,0,0.7)',
                    borderpad=4,
                    xanchor='center',
                    yanchor='middle',
                )
            )

        fig.update_layout(annotations=annotations)

    def _add_path_info_box(
        self,
        fig: go.Figure,
        attack_path: AttackPath,
    ) -> None:
        """Add information box about the attack path."""
        info_text = (
            f"<b>Attack Path Analysis</b><br>"
            f"Threat Level: {attack_path.threat_level.value.upper()}<br>"
            f"Total CVSS: {attack_path.total_cvss:.1f}<br>"
            f"Path Length: {attack_path.path_length} steps<br>"
            f"Exploitability: {attack_path.exploitability:.0%}<br>"
            f"Requires Privileges: {'Yes' if attack_path.requires_privileges else 'No'}"
        )

        fig.add_annotation(
            xref="paper",
            yref="paper",
            x=0.02,
            y=0.98,
            text=info_text,
            showarrow=False,
            font=dict(size=11, color='#333'),
            align='left',
            bgcolor='rgba(255,255,255,0.9)',
            bordercolor='#333',
            borderwidth=1,
            borderpad=10,
            xanchor='left',
            yanchor='top',
        )

    def _add_threat_level_legend(
        self,
        fig: go.Figure,
        attack_paths: List[AttackPath],
    ) -> None:
        """Add legend showing threat levels."""
        # Count paths by threat level
        threat_counts = {}
        for path in attack_paths:
            level = path.threat_level.value
            threat_counts[level] = threat_counts.get(level, 0) + 1

        # Create legend text
        legend_lines = ["<b>Threat Levels:</b>"]
        for level, color in self.THREAT_LEVEL_COLORS.items():
            count = threat_counts.get(level.value, 0)
            if count > 0:
                legend_lines.append(
                    f"<span style='color:{color}'>●</span> "
                    f"{level.value.upper()}: {count} path(s)"
                )

        legend_text = "<br>".join(legend_lines)

        fig.add_annotation(
            xref="paper",
            yref="paper",
            x=0.98,
            y=0.98,
            text=legend_text,
            showarrow=False,
            font=dict(size=11),
            align='left',
            bgcolor='rgba(255,255,255,0.9)',
            bordercolor='#333',
            borderwidth=1,
            borderpad=10,
            xanchor='right',
            yanchor='top',
        )
