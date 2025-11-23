"""Core graph visualization engine using Plotly."""

import logging
from typing import Dict, List, Optional, Tuple, Any, Set
from pathlib import Path
import networkx as nx

try:
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

from ..graph.graph_client import NetworkXClient
from ..graph.models import NodeType, EdgeType

logger = logging.getLogger(__name__)


class NetworkGraphVisualizer:
    """
    Interactive graph visualizer using Plotly.

    Provides interactive web-based visualizations of vulnerability graphs with
    customizable layouts, colors, and styling. Supports both 2D and 3D visualizations
    with intelligent z-axis spacing for improved node visibility.

    Color Schemes:
        - Node colors by type: Container (blue), Package (green), Vulnerability (red), etc.
        - Severity colors: Critical (dark red) → Negligible (light green)
        - Edge colors by relationship type

    Supported Layout Algorithms (2D and 3D):
        - spring: Force-directed layout (3D: native NetworkX 3D spring algorithm)
        - kamada_kawai: Energy-based layout (3D: native NetworkX 3D algorithm)
        - circular: Circular layout (3D: spiral/helix pattern along z-axis)
        - spectral: Spectral layout (3D: z-position based on node connectivity)
        - shell: Shell layout (3D: concentric shells at different z-levels)
        - hierarchical: Custom layered layout (3D: z-axis layers by node type)

    3D Visualization Improvements:
        - Spring/Kamada-Kawai: Use native 3D algorithms for natural spatial distribution
        - Circular: Creates spiral pattern for even z-axis distribution
        - Spectral: Z-position based on node degree (hubs at higher levels)
        - Shell: Inner shells at higher z, outer shells at lower z
        - Hierarchical: Node types separated along z-axis (vulnerabilities highest)

    Example:
        >>> client = NetworkXClient()
        >>> client.load("vulnerability_graph.graphml")
        >>> visualizer = NetworkGraphVisualizer(client)
        >>> # 2D visualization
        >>> fig = visualizer.visualize(layout="hierarchical", color_by="severity")
        >>> # 3D visualization with proper z-spacing
        >>> fig_3d = visualizer.visualize(layout="spring", three_d=True)
        >>> visualizer.save_html(fig_3d, "output.html", auto_open=True)
    """

    # Color schemes
    NODE_COLORS = {
        NodeType.CONTAINER.value: "#3498db",  # Blue
        NodeType.PACKAGE.value: "#2ecc71",    # Green
        NodeType.VULNERABILITY.value: "#e74c3c",  # Red
        NodeType.SERVICE.value: "#f39c12",    # Orange
        NodeType.HOST.value: "#9b59b6",       # Purple
        NodeType.SCAN_RESULT.value: "#95a5a6",  # Gray
    }

    SEVERITY_COLORS = {
        "critical": "#8b0000",    # Dark red
        "high": "#dc143c",        # Crimson
        "medium": "#ffa500",      # Orange
        "low": "#ffd700",         # Gold
        "negligible": "#90ee90",  # Light green
        "unknown": "#808080",     # Gray
    }

    EDGE_COLORS = {
        EdgeType.CONTAINS.value: "#bdc3c7",
        EdgeType.HAS_VULNERABILITY.value: "#e74c3c",
        EdgeType.DEPENDS_ON.value: "#3498db",
        EdgeType.FIXED_BY.value: "#2ecc71",
    }

    def __init__(self, client: NetworkXClient):
        """
        Initialize graph visualizer.

        Args:
            client: NetworkXClient instance with loaded graph
        """
        if not PLOTLY_AVAILABLE:
            raise ImportError(
                "Plotly is required for visualization. "
                "Install with: pip install plotly"
            )

        self.client = client
        self.graph = client.graph
        logger.info(f"Initialized visualizer for graph with {self.graph.number_of_nodes()} nodes")

    def visualize(
        self,
        layout: str = "spring",
        title: str = "Vulnerability Graph",
        width: int = 1200,
        height: int = 800,
        show_labels: bool = True,
        highlight_nodes: Optional[Set[str]] = None,
        highlight_edges: Optional[Set[Tuple[str, str]]] = None,
        node_size: int = 10,
        edge_width: int = 1,
        color_by: str = "node_type",  # or "severity"
        three_d: bool = False,
    ) -> go.Figure:
        """
        Create interactive graph visualization.

        Args:
            layout: Layout algorithm (spring, kamada_kawai, circular, spectral, shell)
            title: Graph title
            width: Figure width in pixels
            height: Figure height in pixels
            show_labels: Whether to show node labels
            highlight_nodes: Set of node IDs to highlight
            highlight_edges: Set of edge tuples to highlight
            node_size: Base node size
            edge_width: Base edge width
            color_by: Color nodes by "node_type" or "severity"
            three_d: Use 3D layout

        Returns:
            Plotly Figure object
        """
        logger.info(f"Creating {layout} layout visualization")

        # Calculate layout
        pos = self._calculate_layout(layout, three_d=three_d)

        # Create figure
        fig = self._create_figure(
            pos,
            title=title,
            width=width,
            height=height,
            show_labels=show_labels,
            highlight_nodes=highlight_nodes or set(),
            highlight_edges=highlight_edges or set(),
            node_size=node_size,
            edge_width=edge_width,
            color_by=color_by,
            three_d=three_d,
        )

        return fig

    def _calculate_layout(
        self,
        layout: str,
        three_d: bool = False,
        seed: int = 42
    ) -> Dict[str, Tuple[float, ...]]:
        """
        Calculate node positions using NetworkX layout algorithms.

        Args:
            layout: Layout algorithm name
            three_d: Use 3D positions with proper z-axis spacing
            seed: Random seed for reproducible layouts

        Returns:
            Dictionary mapping node IDs to (x, y) or (x, y, z) positions
        """
        logger.debug(f"Calculating {layout} layout ({'3D' if three_d else '2D'})")

        # Choose layout algorithm
        if layout == "spring":
            if three_d:
                # Use native 3D spring layout for proper z-axis distribution
                pos_raw = nx.spring_layout(self.graph, seed=seed, dim=3)
                # Convert numpy arrays to tuples
                pos = {node: tuple(coords) for node, coords in pos_raw.items()}
            else:
                pos_raw = nx.spring_layout(self.graph, seed=seed, dim=2)
                # Convert numpy arrays to tuples
                pos = {node: tuple(coords) for node, coords in pos_raw.items()}

        elif layout == "kamada_kawai":
            if three_d:
                # Use native 3D kamada-kawai layout
                pos_raw = nx.kamada_kawai_layout(self.graph, dim=3)
                # Convert numpy arrays to tuples
                pos = {node: tuple(coords) for node, coords in pos_raw.items()}
            else:
                pos_raw = nx.kamada_kawai_layout(self.graph, dim=2)
                # Convert numpy arrays to tuples
                pos = {node: tuple(coords) for node, coords in pos_raw.items()}

        elif layout == "circular":
            pos_2d_raw = nx.circular_layout(self.graph)
            # Convert numpy arrays to tuples
            pos_2d = {node: tuple(coords) for node, coords in pos_2d_raw.items()}
            if three_d:
                # Create 3D spiral/helix pattern from circular layout
                pos = self._add_spiral_z_dimension(pos_2d)
            else:
                pos = pos_2d

        elif layout == "spectral":
            pos_2d_raw = nx.spectral_layout(self.graph)
            # Convert numpy arrays to tuples
            pos_2d = {node: tuple(coords) for node, coords in pos_2d_raw.items()}
            if three_d:
                # Add z-dimension based on node degree (connectivity)
                pos = self._add_degree_based_z_dimension(pos_2d)
            else:
                pos = pos_2d

        elif layout == "shell":
            pos_2d_raw = nx.shell_layout(self.graph)
            # Convert numpy arrays to tuples
            pos_2d = {node: tuple(coords) for node, coords in pos_2d_raw.items()}
            if three_d:
                # Add z-dimension based on shell layers
                pos = self._add_shell_z_dimension(pos_2d)
            else:
                pos = pos_2d

        elif layout == "hierarchical":
            # Custom hierarchical layout based on node types
            pos = self._hierarchical_layout(three_d=three_d)

        else:
            logger.warning(f"Unknown layout '{layout}', using spring layout")
            if three_d:
                pos_raw = nx.spring_layout(self.graph, seed=seed, dim=3)
                # Convert numpy arrays to tuples
                pos = {node: tuple(coords) for node, coords in pos_raw.items()}
            else:
                pos_raw = nx.spring_layout(self.graph, seed=seed, dim=2)
                # Convert numpy arrays to tuples
                pos = {node: tuple(coords) for node, coords in pos_raw.items()}

        return pos

    def _hierarchical_layout(self, three_d: bool = False) -> Dict[str, Tuple[float, ...]]:
        """
        Create hierarchical layout with vulnerability nodes at top.

        In 3D mode, uses z-axis for vertical layering instead of y-axis,
        providing better visibility and separation between node types.

        Returns:
            Position dictionary
        """
        # Group nodes by type
        node_types = {}
        for node, data in self.graph.nodes(data=True):
            node_type = data.get("node_type", "unknown")
            if node_type not in node_types:
                node_types[node_type] = []
            node_types[node_type].append(node)

        # Assign vertical layers
        type_order = [
            NodeType.VULNERABILITY.value,
            NodeType.PACKAGE.value,
            NodeType.CONTAINER.value,
            NodeType.SERVICE.value,
            NodeType.HOST.value,
        ]

        pos = {}
        layer_coord = 0.0
        layer_spacing = 2.0

        for node_type in type_order:
            nodes = node_types.get(node_type, [])
            if not nodes:
                continue

            # Distribute nodes horizontally
            num_nodes = len(nodes)
            x_spacing = 10.0 / max(num_nodes, 1)

            for i, node in enumerate(nodes):
                x = (i - num_nodes / 2) * x_spacing
                if three_d:
                    # In 3D, use z-axis for hierarchy (top to bottom)
                    # Spread nodes in a grid pattern on x-y plane
                    y = 0.0
                    z = -layer_coord  # Negative so top nodes are at higher z
                    pos[node] = (x, y, z)
                else:
                    # In 2D, use y-axis for hierarchy
                    y = layer_coord
                    pos[node] = (x, y)

            layer_coord += layer_spacing

        # Handle any remaining nodes not in type_order
        remaining_nodes = set(self.graph.nodes()) - set(pos.keys())
        if remaining_nodes:
            num_remaining = len(remaining_nodes)
            x_spacing = 10.0 / max(num_remaining, 1)
            for i, node in enumerate(remaining_nodes):
                x = (i - num_remaining / 2) * x_spacing
                if three_d:
                    y = 0.0
                    z = -layer_coord
                    pos[node] = (x, y, z)
                else:
                    y = layer_coord
                    pos[node] = (x, y)

        return pos

    def _add_spiral_z_dimension(self, pos_2d: Dict[str, Tuple[float, float]]) -> Dict[str, Tuple[float, float, float]]:
        """
        Add z-dimension to circular layout to create a 3D spiral/helix pattern.

        This distributes nodes along the z-axis based on their position in the circle,
        creating a visually appealing spiral that spreads nodes out in 3D space.

        Args:
            pos_2d: 2D circular layout positions

        Returns:
            3D positions with spiral z-coordinates
        """
        import math

        pos_3d = {}
        nodes = list(pos_2d.keys())
        num_nodes = len(nodes)

        for i, node in enumerate(nodes):
            x, y = pos_2d[node]
            # Create spiral: z varies smoothly from -1 to 1 based on position in circle
            # Using sine wave for smooth spiral
            z = math.sin(2 * math.pi * i / num_nodes) * 1.5
            pos_3d[node] = (x, y, z)

        return pos_3d

    def _add_degree_based_z_dimension(self, pos_2d: Dict[str, Tuple[float, float]]) -> Dict[str, Tuple[float, float, float]]:
        """
        Add z-dimension based on node degree (connectivity).

        Highly connected nodes appear at higher z-levels, making network hubs
        more visible in the 3D visualization.

        Args:
            pos_2d: 2D layout positions

        Returns:
            3D positions with degree-based z-coordinates
        """
        pos_3d = {}

        # Calculate node degrees
        degrees = dict(self.graph.degree())
        max_degree = max(degrees.values()) if degrees else 1

        for node, (x, y) in pos_2d.items():
            degree = degrees.get(node, 0)
            # Normalize degree to z-range [-1, 1]
            z = (degree / max_degree) * 2.0 - 1.0
            pos_3d[node] = (x, y, z)

        return pos_3d

    def _add_shell_z_dimension(self, pos_2d: Dict[str, Tuple[float, float]]) -> Dict[str, Tuple[float, float, float]]:
        """
        Add z-dimension to shell layout based on distance from center.

        Creates concentric shells at different z-levels, with inner shells
        at higher z-coordinates and outer shells at lower levels.

        Args:
            pos_2d: 2D shell layout positions

        Returns:
            3D positions with shell-based z-coordinates
        """
        import math

        pos_3d = {}

        # Calculate distance from center for each node
        distances = {}
        for node, (x, y) in pos_2d.items():
            distance = math.sqrt(x**2 + y**2)
            distances[node] = distance

        max_distance = max(distances.values()) if distances else 1

        for node, (x, y) in pos_2d.items():
            distance = distances[node]
            # Normalize distance to z-range [1, -1] (inner = high, outer = low)
            z = 1.0 - (distance / max_distance) * 2.0
            pos_3d[node] = (x, y, z)

        return pos_3d

    def _create_figure(
        self,
        pos: Dict[str, Tuple[float, ...]],
        title: str,
        width: int,
        height: int,
        show_labels: bool,
        highlight_nodes: Set[str],
        highlight_edges: Set[Tuple[str, str]],
        node_size: int,
        edge_width: int,
        color_by: str,
        three_d: bool,
    ) -> go.Figure:
        """Create Plotly figure from graph and positions."""
        # Create edge traces
        edge_traces = self._create_edge_traces(
            pos,
            highlight_edges=highlight_edges,
            edge_width=edge_width,
            three_d=three_d,
        )

        # Create node trace
        node_trace = self._create_node_trace(
            pos,
            highlight_nodes=highlight_nodes,
            node_size=node_size,
            color_by=color_by,
            three_d=three_d,
        )

        # Create figure
        data = edge_traces + [node_trace]

        if three_d:
            layout = go.Layout(
                title=title,
                width=width,
                height=height,
                showlegend=False,
                hovermode='closest',
                margin=dict(b=0, l=0, r=0, t=40),
                scene=dict(
                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    zaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                ),
            )
        else:
            layout = go.Layout(
                title=title,
                width=width,
                height=height,
                showlegend=False,
                hovermode='closest',
                margin=dict(b=0, l=0, r=0, t=40),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            )

        fig = go.Figure(data=data, layout=layout)

        # Add annotations for labels if requested
        if show_labels and not three_d:
            annotations = self._create_labels(pos)
            fig.update_layout(annotations=annotations)

        return fig

    def _create_edge_traces(
        self,
        pos: Dict[str, Tuple[float, ...]],
        highlight_edges: Set[Tuple[str, str]],
        edge_width: int,
        three_d: bool,
    ) -> List[go.Scatter]:
        """Create edge traces for the graph."""
        edge_traces = []

        # Group edges by type
        edges_by_type = {}
        for u, v, data in self.graph.edges(data=True):
            edge_type = data.get("edge_type", "unknown")
            if edge_type not in edges_by_type:
                edges_by_type[edge_type] = []

            is_highlighted = (u, v) in highlight_edges or (v, u) in highlight_edges
            edges_by_type[edge_type].append((u, v, is_highlighted))

        # Create trace for each edge type
        for edge_type, edges in edges_by_type.items():
            x_coords = []
            y_coords = []
            z_coords = [] if three_d else None

            for u, v, is_highlighted in edges:
                if u not in pos or v not in pos:
                    continue

                u_pos = pos[u]
                v_pos = pos[v]

                x_coords.extend([u_pos[0], v_pos[0], None])
                y_coords.extend([u_pos[1], v_pos[1], None])
                if three_d:
                    z_coords.extend([u_pos[2], v_pos[2], None])

            if three_d:
                trace = go.Scatter3d(
                    x=x_coords,
                    y=y_coords,
                    z=z_coords,
                    mode='lines',
                    line=dict(
                        color=self.EDGE_COLORS.get(edge_type, "#bdc3c7"),
                        width=edge_width,
                    ),
                    hoverinfo='none',
                    name=edge_type,
                )
            else:
                trace = go.Scatter(
                    x=x_coords,
                    y=y_coords,
                    mode='lines',
                    line=dict(
                        color=self.EDGE_COLORS.get(edge_type, "#bdc3c7"),
                        width=edge_width,
                    ),
                    hoverinfo='none',
                    name=edge_type,
                )

            edge_traces.append(trace)

        return edge_traces

    def _create_node_trace(
        self,
        pos: Dict[str, Tuple[float, ...]],
        highlight_nodes: Set[str],
        node_size: int,
        color_by: str,
        three_d: bool,
    ) -> go.Scatter:
        """Create node trace with colors and hover info."""
        x_coords = []
        y_coords = []
        z_coords = [] if three_d else None
        colors = []
        sizes = []
        hover_texts = []

        for node in self.graph.nodes():
            if node not in pos:
                continue

            node_pos = pos[node]
            node_data = self.graph.nodes[node]

            x_coords.append(node_pos[0])
            y_coords.append(node_pos[1])
            if three_d:
                z_coords.append(node_pos[2])

            # Determine color
            if node in highlight_nodes:
                color = "#ffff00"  # Yellow for highlighted
            elif color_by == "severity":
                severity = node_data.get("severity", "unknown")
                color = self.SEVERITY_COLORS.get(severity.lower(), "#808080")
            else:  # color_by == "node_type"
                node_type = node_data.get("node_type", "unknown")
                color = self.NODE_COLORS.get(node_type, "#808080")

            colors.append(color)

            # Determine size
            if node in highlight_nodes:
                sizes.append(node_size * 2)
            else:
                sizes.append(node_size)

            # Create hover text
            hover_text = self._create_hover_text(node, node_data)
            hover_texts.append(hover_text)

        if three_d:
            trace = go.Scatter3d(
                x=x_coords,
                y=y_coords,
                z=z_coords,
                mode='markers',
                marker=dict(
                    size=sizes,
                    color=colors,
                    line=dict(width=1, color='white'),
                ),
                text=hover_texts,
                hoverinfo='text',
            )
        else:
            trace = go.Scatter(
                x=x_coords,
                y=y_coords,
                mode='markers',
                marker=dict(
                    size=sizes,
                    color=colors,
                    line=dict(width=1, color='white'),
                ),
                text=hover_texts,
                hoverinfo='text',
            )

        return trace

    def _create_hover_text(self, node_id: str, node_data: Dict[str, Any]) -> str:
        """Create hover text for a node."""
        node_type = node_data.get("node_type", "unknown")
        lines = [f"<b>{node_id}</b>", f"Type: {node_type}"]

        # Add type-specific information
        if node_type == NodeType.VULNERABILITY.value:
            lines.append(f"Severity: {node_data.get('severity', 'N/A')}")
            cvss = node_data.get('cvss_score')
            if cvss:
                lines.append(f"CVSS: {cvss}")

        elif node_type == NodeType.PACKAGE.value:
            name = node_data.get('name', '')
            version = node_data.get('version', '')
            if name:
                lines.append(f"Package: {name}@{version}")

        elif node_type == NodeType.CONTAINER.value:
            name = node_data.get('name', '')
            if name:
                lines.append(f"Container: {name}")

        # Add business context if available
        if "criticality" in node_data:
            lines.append(f"Criticality: {node_data['criticality']}")

        if "zone" in node_data:
            lines.append(f"Zone: {node_data['zone']}")

        return "<br>".join(lines)

    def _create_labels(self, pos: Dict[str, Tuple[float, float]]) -> List[Dict]:
        """Create text annotations for node labels."""
        annotations = []

        for node, (x, y) in pos.items():
            node_data = self.graph.nodes[node]
            node_type = node_data.get("node_type", "")

            # Create short label
            if node_type == NodeType.VULNERABILITY.value:
                label = node_data.get("cve_id", node)
            elif node_type == NodeType.PACKAGE.value:
                label = node_data.get("name", node)
            else:
                label = node_data.get("name", node)

            # Truncate long labels
            if len(label) > 15:
                label = label[:12] + "..."

            annotations.append(
                dict(
                    x=x,
                    y=y,
                    text=label,
                    showarrow=False,
                    font=dict(size=8, color='#333'),
                    xanchor='center',
                    yanchor='bottom',
                )
            )

        return annotations

    def save_html(
        self,
        fig: go.Figure,
        output_path: Path,
        auto_open: bool = False,
        include_plotlyjs: str = 'inline',
    ) -> None:
        """
        Save figure as standalone HTML file.

        Args:
            fig: Plotly figure to save
            output_path: Output file path
            auto_open: Whether to open in browser after saving
            include_plotlyjs: How to include plotly.js library.
                'inline' (default): Embed full library in HTML (larger file, more secure, works offline)
                'cdn': Use CDN link (smaller file, requires internet, potential security risk)
                'directory': Save to separate file (advanced use)
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Validate include_plotlyjs value
        valid_options = ['inline', 'cdn', 'directory', True, False]
        if include_plotlyjs not in valid_options:
            logger.warning(
                f"Invalid include_plotlyjs value '{include_plotlyjs}', using 'inline'"
            )
            include_plotlyjs = 'inline'

        fig.write_html(
            str(output_path),
            auto_open=auto_open,
            include_plotlyjs=include_plotlyjs,
        )

        logger.info(f"Saved visualization to {output_path}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get graph statistics for visualization metadata."""
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "node_types": self._count_node_types(),
            "edge_types": self._count_edge_types(),
        }

    def _count_node_types(self) -> Dict[str, int]:
        """Count nodes by type."""
        counts = {}
        for _, data in self.graph.nodes(data=True):
            node_type = data.get("node_type", "unknown")
            counts[node_type] = counts.get(node_type, 0) + 1
        return counts

    def _count_edge_types(self) -> Dict[str, int]:
        """Count edges by type."""
        counts = {}
        for _, _, data in self.graph.edges(data=True):
            edge_type = data.get("edge_type", "unknown")
            counts[edge_type] = counts.get(edge_type, 0) + 1
        return counts
