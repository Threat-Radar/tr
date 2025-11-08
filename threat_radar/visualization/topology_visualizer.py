"""Network topology visualization with security overlays."""

import logging
from typing import Dict, List, Set, Tuple, Optional, Any
from pathlib import Path

try:
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

from ..graph.graph_client import NetworkXClient
from ..graph.models import NodeType
from .graph_visualizer import NetworkGraphVisualizer

logger = logging.getLogger(__name__)


class NetworkTopologyVisualizer(NetworkGraphVisualizer):
    """
    Visualizer for network topology with security context overlays.

    Extends NetworkGraphVisualizer to provide infrastructure topology visualization
    with security zone boundaries, compliance scope markers, and criticality levels.

    Features:
        - Security zone visualization with color-coded boundaries
        - Compliance scope highlighting (PCI-DSS, HIPAA, SOX, GDPR)
        - Criticality-based node coloring
        - Internet-facing asset identification
        - Zone-optimized layouts

    Security Zones:
        - DMZ: Demilitarized zone (red) - exposed services
        - Public: Public-facing zone (orange)
        - Internal: Internal application zone (teal)
        - Trusted: Trusted secure zone (sky blue)
        - Database: Database zone (purple)

    Criticality Levels:
        - Critical: Mission-critical assets (dark red)
        - High: High-importance assets (red)
        - Medium: Standard assets (orange)
        - Low: Low-priority assets (blue)

    Compliance Types:
        - PCI-DSS: Payment card industry data security (🔐)
        - HIPAA: Healthcare information protection (🏥)
        - SOX: Sarbanes-Oxley financial controls (📊)
        - GDPR: European data protection (🇪🇺)

    Example:
        >>> client = NetworkXClient()
        >>> client.load("production_environment.graphml")
        >>> visualizer = NetworkTopologyVisualizer(client)
        >>>
        >>> # Full topology view
        >>> fig = visualizer.visualize_topology(color_by="zone", show_zones=True)
        >>> visualizer.save_html(fig, "topology.html")
        >>>
        >>> # Security zones focus
        >>> zones_fig = visualizer.visualize_security_zones()
        >>> visualizer.save_html(zones_fig, "security_zones.html")
        >>>
        >>> # Compliance scope (PCI-DSS only)
        >>> pci_fig = visualizer.visualize_compliance_scope(compliance_type="pci")
        >>> visualizer.save_html(pci_fig, "pci_scope.html")
    """

    # Zone colors
    ZONE_COLORS = {
        "dmz": "#ff6b6b",           # Red
        "public": "#ff8c42",        # Orange
        "internet": "#ffa07a",      # Light salmon
        "untrusted": "#ff6347",     # Tomato
        "internal": "#4ecdc4",      # Teal
        "trusted": "#45b7d1",       # Sky blue
        "secure": "#96ceb4",        # Sage
        "database": "#574b90",      # Purple
        "unknown": "#95a5a6",       # Gray
    }

    # Criticality colors
    CRITICALITY_COLORS = {
        "critical": "#c0392b",      # Dark red
        "high": "#e74c3c",          # Red
        "medium": "#f39c12",        # Orange
        "low": "#3498db",           # Blue
        "unknown": "#95a5a6",       # Gray
    }

    # Compliance scope markers
    COMPLIANCE_MARKERS = {
        "pci": "🔐",
        "hipaa": "🏥",
        "sox": "📊",
        "gdpr": "🇪🇺",
    }

    def __init__(self, client: NetworkXClient):
        """
        Initialize topology visualizer.

        Args:
            client: NetworkXClient instance with loaded graph
        """
        super().__init__(client)

    def visualize_topology(
        self,
        layout: str = "hierarchical",
        title: str = "Network Topology",
        width: int = 1400,
        height: int = 900,
        color_by: str = "zone",  # zone, criticality, compliance
        show_zones: bool = True,
        show_compliance: bool = True,
        show_internet_facing: bool = True,
    ) -> go.Figure:
        """
        Visualize network topology with security context.

        Args:
            layout: Layout algorithm
            title: Figure title
            width: Figure width
            height: Figure height
            color_by: Color scheme (zone, criticality, compliance)
            show_zones: Show zone boundaries
            show_compliance: Show compliance scope markers
            show_internet_facing: Highlight internet-facing assets

        Returns:
            Plotly figure with topology visualization
        """
        logger.info(f"Creating topology visualization (color_by={color_by})")

        # Calculate layout
        pos = self._calculate_layout(layout, three_d=False)

        # Group nodes by zones
        zones = self._group_nodes_by_zone()

        # Create figure
        fig = self._create_topology_figure(
            pos=pos,
            zones=zones,
            title=title,
            width=width,
            height=height,
            color_by=color_by,
            show_zones=show_zones,
            show_compliance=show_compliance,
            show_internet_facing=show_internet_facing,
        )

        return fig

    def visualize_security_zones(
        self,
        title: str = "Security Zone Map",
        width: int = 1400,
        height: int = 900,
    ) -> go.Figure:
        """
        Create zone-focused visualization with clear boundaries.

        Args:
            title: Figure title
            width: Figure width
            height: Figure height

        Returns:
            Plotly figure showing security zones
        """
        logger.info("Creating security zone visualization")

        # Group nodes by zone
        zones = self._group_nodes_by_zone()

        # Create zone-optimized layout
        pos = self._create_zone_layout(zones)

        # Create figure with zone emphasis
        fig = self._create_zone_figure(
            pos=pos,
            zones=zones,
            title=title,
            width=width,
            height=height,
        )

        return fig

    def visualize_compliance_scope(
        self,
        compliance_type: Optional[str] = None,  # pci, hipaa, sox, gdpr
        title: str = "Compliance Scope Analysis",
        width: int = 1400,
        height: int = 900,
    ) -> go.Figure:
        """
        Visualize compliance scope across infrastructure.

        Args:
            compliance_type: Specific compliance type to highlight (None = all)
            title: Figure title
            width: Figure width
            height: Figure height

        Returns:
            Plotly figure showing compliance scope
        """
        logger.info(f"Creating compliance visualization (type={compliance_type})")

        # Find nodes in compliance scope
        compliance_nodes = self._find_compliance_nodes(compliance_type)

        # Calculate layout
        pos = self._calculate_layout("hierarchical", three_d=False)

        # Create figure
        fig = self._create_compliance_figure(
            pos=pos,
            compliance_nodes=compliance_nodes,
            compliance_type=compliance_type,
            title=title,
            width=width,
            height=height,
        )

        return fig

    def _group_nodes_by_zone(self) -> Dict[str, List[str]]:
        """Group nodes by their security zone."""
        zones = {}

        for node, data in self.graph.nodes(data=True):
            zone = data.get("zone", "unknown").lower()

            if zone not in zones:
                zones[zone] = []

            zones[zone].append(node)

        logger.debug(f"Found {len(zones)} security zones")
        return zones

    def _create_zone_layout(
        self,
        zones: Dict[str, List[str]]
    ) -> Dict[str, Tuple[float, float]]:
        """Create layout optimized for zone visualization."""
        pos = {}

        # Define zone positions (x offset)
        zone_order = ["internet", "dmz", "public", "untrusted", "internal", "trusted", "secure", "database"]
        zone_x_positions = {}

        defined_zones = [z for z in zone_order if z in zones]
        undefined_zones = [z for z in zones.keys() if z not in zone_order]

        all_zones = defined_zones + undefined_zones
        zone_width = 10.0 / max(len(all_zones), 1)

        for i, zone in enumerate(all_zones):
            zone_x_positions[zone] = (i - len(all_zones) / 2) * zone_width

        # Position nodes within each zone
        for zone, nodes in zones.items():
            zone_x = zone_x_positions.get(zone, 0.0)
            num_nodes = len(nodes)

            # Distribute vertically within zone
            y_spacing = 8.0 / max(num_nodes, 1)

            for i, node in enumerate(nodes):
                x = zone_x + (hash(node) % 100) / 500  # Small random x offset
                y = (i - num_nodes / 2) * y_spacing

                pos[node] = (x, y)

        return pos

    def _create_topology_figure(
        self,
        pos: Dict[str, Tuple[float, float]],
        zones: Dict[str, List[str]],
        title: str,
        width: int,
        height: int,
        color_by: str,
        show_zones: bool,
        show_compliance: bool,
        show_internet_facing: bool,
    ) -> go.Figure:
        """Create main topology figure."""
        data = []

        # Add zone backgrounds if requested
        if show_zones:
            zone_shapes = self._create_zone_shapes(pos, zones)
        else:
            zone_shapes = []

        # Create edges
        edge_trace = self._create_topology_edges(pos, show_internet_facing)
        data.append(edge_trace)

        # Create node traces grouped by property
        if color_by == "zone":
            node_traces = self._create_zone_colored_nodes(pos)
        elif color_by == "criticality":
            node_traces = self._create_criticality_colored_nodes(pos)
        elif color_by == "compliance":
            node_traces = self._create_compliance_colored_nodes(pos)
        else:
            # Default to type-based coloring
            node_traces = [self._create_node_trace(
                pos,
                highlight_nodes=set(),
                node_size=12,
                color_by="node_type",
                three_d=False,
            )]

        data.extend(node_traces)

        # Create layout
        layout = go.Layout(
            title=dict(text=title, font=dict(size=20)),
            width=width,
            height=height,
            showlegend=True,
            hovermode='closest',
            margin=dict(b=50, l=50, r=50, t=80),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='#f8f9fa',
            shapes=zone_shapes,
        )

        fig = go.Figure(data=data, layout=layout)

        # Add legends and annotations
        if show_compliance:
            self._add_compliance_legend(fig)

        return fig

    def _create_zone_figure(
        self,
        pos: Dict[str, Tuple[float, float]],
        zones: Dict[str, List[str]],
        title: str,
        width: int,
        height: int,
    ) -> go.Figure:
        """Create zone-focused figure with clear boundaries."""
        data = []

        # Create zone shapes (backgrounds)
        zone_shapes = self._create_zone_shapes(pos, zones, emphasize=True)

        # Create edges (dimmed)
        edge_trace = self._create_dimmed_edge_trace(pos)
        data.append(edge_trace)

        # Create node traces per zone
        for zone_name, zone_nodes in zones.items():
            zone_trace = self._create_zone_node_trace(pos, zone_name, zone_nodes)
            data.append(zone_trace)

        # Layout
        layout = go.Layout(
            title=dict(text=title, font=dict(size=20)),
            width=width,
            height=height,
            showlegend=True,
            hovermode='closest',
            margin=dict(b=50, l=50, r=50, t=80),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='#ffffff',
            shapes=zone_shapes,
        )

        fig = go.Figure(data=data, layout=layout)

        # Add zone labels
        self._add_zone_labels(fig, pos, zones)

        return fig

    def _create_compliance_figure(
        self,
        pos: Dict[str, Tuple[float, float]],
        compliance_nodes: Dict[str, Set[str]],
        compliance_type: Optional[str],
        title: str,
        width: int,
        height: int,
    ) -> go.Figure:
        """Create compliance-focused figure."""
        data = []

        # All nodes in any compliance scope
        all_compliance = set()
        for nodes in compliance_nodes.values():
            all_compliance.update(nodes)

        # Create edges
        edge_trace = self._create_dimmed_edge_trace(pos)
        data.append(edge_trace)

        # Non-compliance nodes (dimmed)
        non_compliance = set(self.graph.nodes()) - all_compliance
        non_compliance_trace = self._create_dimmed_node_trace(pos, non_compliance)
        data.append(non_compliance_trace)

        # Compliance nodes (highlighted)
        if compliance_type:
            # Single compliance type
            nodes = compliance_nodes.get(compliance_type, set())
            compliance_trace = self._create_compliance_node_trace(
                pos,
                nodes,
                compliance_type,
            )
            data.append(compliance_trace)
        else:
            # All compliance types
            for comp_type, nodes in compliance_nodes.items():
                compliance_trace = self._create_compliance_node_trace(
                    pos,
                    nodes,
                    comp_type,
                )
                data.append(compliance_trace)

        # Layout
        layout = go.Layout(
            title=dict(text=title, font=dict(size=20)),
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

        return fig

    def _create_zone_shapes(
        self,
        pos: Dict[str, Tuple[float, float]],
        zones: Dict[str, List[str]],
        emphasize: bool = False,
    ) -> List[Dict]:
        """Create background shapes for security zones."""
        shapes = []

        for zone_name, zone_nodes in zones.items():
            if not zone_nodes:
                continue

            # Get node positions in this zone
            zone_positions = [pos[node] for node in zone_nodes if node in pos]

            if not zone_positions:
                continue

            # Calculate bounding box
            xs = [p[0] for p in zone_positions]
            ys = [p[1] for p in zone_positions]

            x_min, x_max = min(xs), max(xs)
            y_min, y_max = min(ys), max(ys)

            # Add padding
            padding = 0.5
            x_min -= padding
            x_max += padding
            y_min -= padding
            y_max += padding

            # Create shape
            color = self.ZONE_COLORS.get(zone_name, "#e0e0e0")

            shapes.append(
                dict(
                    type="rect",
                    xref="x",
                    yref="y",
                    x0=x_min,
                    y0=y_min,
                    x1=x_max,
                    y1=y_max,
                    fillcolor=color,
                    opacity=0.2 if emphasize else 0.1,
                    line=dict(
                        color=color,
                        width=2 if emphasize else 1,
                    ),
                    layer="below",
                )
            )

        return shapes

    def _create_topology_edges(
        self,
        pos: Dict[str, Tuple[float, float]],
        show_internet_facing: bool,
    ) -> go.Scatter:
        """Create edge trace for topology."""
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
            line=dict(color='#bdc3c7', width=1),
            hoverinfo='none',
            showlegend=False,
        )

        return trace

    def _create_zone_colored_nodes(
        self,
        pos: Dict[str, Tuple[float, float]],
    ) -> List[go.Scatter]:
        """Create node traces colored by security zone."""
        zones = self._group_nodes_by_zone()
        traces = []

        for zone_name, zone_nodes in zones.items():
            zone_trace = self._create_zone_node_trace(pos, zone_name, zone_nodes)
            traces.append(zone_trace)

        return traces

    def _create_zone_node_trace(
        self,
        pos: Dict[str, Tuple[float, float]],
        zone_name: str,
        zone_nodes: List[str],
    ) -> go.Scatter:
        """Create node trace for a specific zone."""
        x_coords = []
        y_coords = []
        hover_texts = []

        for node in zone_nodes:
            if node not in pos:
                continue

            node_data = self.graph.nodes[node]
            x_coords.append(pos[node][0])
            y_coords.append(pos[node][1])

            hover_text = self._create_topology_hover(node, node_data)
            hover_texts.append(hover_text)

        color = self.ZONE_COLORS.get(zone_name, "#95a5a6")

        trace = go.Scatter(
            x=x_coords,
            y=y_coords,
            mode='markers',
            marker=dict(
                size=14,
                color=color,
                line=dict(width=2, color='white'),
            ),
            text=hover_texts,
            hoverinfo='text',
            name=f"{zone_name.upper()} Zone",
        )

        return trace

    def _create_criticality_colored_nodes(
        self,
        pos: Dict[str, Tuple[float, float]],
    ) -> List[go.Scatter]:
        """Create node traces colored by criticality."""
        by_criticality = {}

        for node, data in self.graph.nodes(data=True):
            criticality = data.get("criticality", "unknown").lower()
            if criticality not in by_criticality:
                by_criticality[criticality] = []
            by_criticality[criticality].append(node)

        traces = []

        for criticality, nodes in by_criticality.items():
            x_coords = []
            y_coords = []
            hover_texts = []

            for node in nodes:
                if node not in pos:
                    continue

                node_data = self.graph.nodes[node]
                x_coords.append(pos[node][0])
                y_coords.append(pos[node][1])

                hover_text = self._create_topology_hover(node, node_data)
                hover_texts.append(hover_text)

            color = self.CRITICALITY_COLORS.get(criticality, "#95a5a6")

            trace = go.Scatter(
                x=x_coords,
                y=y_coords,
                mode='markers',
                marker=dict(
                    size=16 if criticality == "critical" else 12,
                    color=color,
                    line=dict(width=2, color='white'),
                ),
                text=hover_texts,
                hoverinfo='text',
                name=f"{criticality.upper()} Criticality",
            )

            traces.append(trace)

        return traces

    def _create_compliance_colored_nodes(
        self,
        pos: Dict[str, Tuple[float, float]],
    ) -> List[go.Scatter]:
        """Create node traces colored by compliance scope."""
        compliance_nodes = self._find_compliance_nodes()

        traces = []

        for comp_type, nodes in compliance_nodes.items():
            trace = self._create_compliance_node_trace(pos, nodes, comp_type)
            traces.append(trace)

        # Non-compliance nodes
        all_compliance = set()
        for nodes in compliance_nodes.values():
            all_compliance.update(nodes)

        non_compliance = set(self.graph.nodes()) - all_compliance
        non_compliance_trace = self._create_dimmed_node_trace(pos, non_compliance)
        traces.append(non_compliance_trace)

        return traces

    def _create_compliance_node_trace(
        self,
        pos: Dict[str, Tuple[float, float]],
        nodes: Set[str],
        compliance_type: str,
    ) -> go.Scatter:
        """Create trace for nodes in compliance scope."""
        x_coords = []
        y_coords = []
        hover_texts = []

        for node in nodes:
            if node not in pos:
                continue

            node_data = self.graph.nodes[node]
            x_coords.append(pos[node][0])
            y_coords.append(pos[node][1])

            hover_text = self._create_topology_hover(node, node_data)
            hover_texts.append(hover_text)

        # Color based on compliance type
        colors = {
            "pci": "#e74c3c",
            "hipaa": "#3498db",
            "sox": "#f39c12",
            "gdpr": "#9b59b6",
        }

        color = colors.get(compliance_type, "#95a5a6")
        marker_symbol = self.COMPLIANCE_MARKERS.get(compliance_type, "●")

        trace = go.Scatter(
            x=x_coords,
            y=y_coords,
            mode='markers',
            marker=dict(
                size=16,
                color=color,
                line=dict(width=2, color='white'),
            ),
            text=hover_texts,
            hoverinfo='text',
            name=f"{marker_symbol} {compliance_type.upper()} Scope",
        )

        return trace

    def _create_dimmed_edge_trace(
        self,
        pos: Dict[str, Tuple[float, float]],
    ) -> go.Scatter:
        """Create dimmed edge trace."""
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

        return trace

    def _create_dimmed_node_trace(
        self,
        pos: Dict[str, Tuple[float, float]],
        nodes: Set[str],
    ) -> go.Scatter:
        """Create dimmed node trace."""
        x_coords = []
        y_coords = []
        hover_texts = []

        for node in nodes:
            if node not in pos:
                continue

            node_data = self.graph.nodes[node]
            x_coords.append(pos[node][0])
            y_coords.append(pos[node][1])

            hover_text = self._create_hover_text(node, node_data)
            hover_texts.append(hover_text)

        trace = go.Scatter(
            x=x_coords,
            y=y_coords,
            mode='markers',
            marker=dict(
                size=8,
                color='#bdc3c7',
                opacity=0.5,
                line=dict(width=1, color='white'),
            ),
            text=hover_texts,
            hoverinfo='text',
            name="Other Assets",
        )

        return trace

    def _create_topology_hover(self, node_id: str, node_data: Dict[str, Any]) -> str:
        """Create hover text with security context."""
        lines = [f"<b>{node_id}</b>"]

        # Node type
        node_type = node_data.get("node_type", "unknown")
        lines.append(f"Type: {node_type}")

        # Name
        name = node_data.get("name", "")
        if name and name != node_id:
            lines.append(f"Name: {name}")

        # Security context
        if "zone" in node_data:
            lines.append(f"🔒 Zone: {node_data['zone']}")

        if "criticality" in node_data:
            lines.append(f"⚠️ Criticality: {node_data['criticality']}")

        # Compliance markers
        compliance_markers = []
        if node_data.get("pci_scope"):
            compliance_markers.append("PCI-DSS")
        if node_data.get("hipaa_scope"):
            compliance_markers.append("HIPAA")
        if node_data.get("sox_scope"):
            compliance_markers.append("SOX")
        if node_data.get("gdpr_scope"):
            compliance_markers.append("GDPR")

        if compliance_markers:
            lines.append(f"📋 Compliance: {', '.join(compliance_markers)}")

        # Internet-facing
        if node_data.get("internet_facing"):
            lines.append("🌐 Internet-Facing")

        if node_data.get("customer_facing"):
            lines.append("👥 Customer-Facing")

        return "<br>".join(lines)

    def _find_compliance_nodes(
        self,
        compliance_type: Optional[str] = None
    ) -> Dict[str, Set[str]]:
        """Find nodes in compliance scope."""
        compliance_nodes = {
            "pci": set(),
            "hipaa": set(),
            "sox": set(),
            "gdpr": set(),
        }

        for node, data in self.graph.nodes(data=True):
            if data.get("pci_scope") or data.get("data_classification") == "pci":
                compliance_nodes["pci"].add(node)

            if data.get("hipaa_scope") or data.get("data_classification") == "hipaa":
                compliance_nodes["hipaa"].add(node)

            if data.get("sox_scope"):
                compliance_nodes["sox"].add(node)

            if data.get("gdpr_scope"):
                compliance_nodes["gdpr"].add(node)

        if compliance_type:
            return {compliance_type: compliance_nodes.get(compliance_type, set())}

        return compliance_nodes

    def _add_compliance_legend(self, fig: go.Figure) -> None:
        """Add compliance scope legend."""
        legend_text = (
            "<b>Compliance Scope:</b><br>"
            "🔐 PCI-DSS<br>"
            "🏥 HIPAA<br>"
            "📊 SOX<br>"
            "🇪🇺 GDPR"
        )

        fig.add_annotation(
            xref="paper",
            yref="paper",
            x=0.02,
            y=0.98,
            text=legend_text,
            showarrow=False,
            font=dict(size=11),
            align='left',
            bgcolor='rgba(255,255,255,0.9)',
            bordercolor='#333',
            borderwidth=1,
            borderpad=10,
            xanchor='left',
            yanchor='top',
        )

    def _add_zone_labels(
        self,
        fig: go.Figure,
        pos: Dict[str, Tuple[float, float]],
        zones: Dict[str, List[str]],
    ) -> None:
        """Add zone name labels to the figure."""
        annotations = []

        for zone_name, zone_nodes in zones.items():
            if not zone_nodes:
                continue

            # Calculate zone center
            zone_positions = [pos[node] for node in zone_nodes if node in pos]
            if not zone_positions:
                continue

            center_x = sum(p[0] for p in zone_positions) / len(zone_positions)
            center_y = max(p[1] for p in zone_positions) + 0.7

            annotations.append(
                dict(
                    x=center_x,
                    y=center_y,
                    text=f"<b>{zone_name.upper()} ZONE</b>",
                    showarrow=False,
                    font=dict(
                        size=14,
                        color=self.ZONE_COLORS.get(zone_name, "#333")
                    ),
                    bgcolor='rgba(255,255,255,0.8)',
                    borderpad=6,
                )
            )

        fig.update_layout(annotations=annotations)
