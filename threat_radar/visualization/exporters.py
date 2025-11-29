"""Export graph visualizations to various formats."""

import logging
import json
from pathlib import Path
from typing import Optional, Dict, Any

try:
    import plotly.graph_objects as go

    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

from ..graph.graph_client import NetworkXClient

logger = logging.getLogger(__name__)


class GraphExporter:
    """
    Export graph visualizations and data to multiple formats.

    Provides comprehensive export functionality for vulnerability graphs, supporting
    various output formats for different use cases including web visualization,
    static images, data exchange, and integration with external tools.

    Supported Export Formats:
        - HTML: Interactive web visualization (standalone, works offline with 'inline' mode)
        - PNG: High-resolution static image (requires kaleido)
        - SVG: Scalable vector graphics (requires kaleido)
        - PDF: PDF document for reports (requires kaleido)
        - JSON: Graph data with optional pre-calculated positions
        - DOT: Graphviz format (requires pydot)
        - Cytoscape: Cytoscape.js JSON format for web applications
        - GEXF: Gephi format for advanced graph analysis

    Use Cases:
        - HTML: Shareable interactive reports, documentation
        - PNG/SVG/PDF: Presentations, printed reports, documentation
        - JSON: Custom web dashboards, data processing
        - DOT: Graphviz rendering, custom layouts
        - Cytoscape: Web-based graph applications
        - GEXF: Advanced analysis in Gephi

    Example:
        >>> client = NetworkXClient()
        >>> client.load("vulnerability_graph.graphml")
        >>> exporter = GraphExporter(client)
        >>>
        >>> # Create visualization
        >>> visualizer = NetworkGraphVisualizer(client)
        >>> fig = visualizer.visualize(layout="hierarchical")
        >>>
        >>> # Export to multiple formats
        >>> outputs = exporter.export_all_formats(
        ...     fig=fig,
        ...     base_path="reports/vulnerability-graph",
        ...     formats=["html", "png", "json"]
        ... )
        >>> print(outputs)  # {'html': 'reports/vulnerability-graph.html', ...}
        >>>
        >>> # Export single format
        >>> exporter.export_html(fig, "viz.html", include_plotlyjs="inline")
        >>> exporter.export_image(fig, "viz.png", format="png", scale=2.0)
    """

    def __init__(self, client: NetworkXClient):
        """
        Initialize exporter.

        Args:
            client: NetworkXClient instance with loaded graph
        """
        self.client = client
        self.graph = client.graph
        logger.info("Initialized GraphExporter")

    def export_html(
        self,
        fig: go.Figure,
        output_path: Path,
        auto_open: bool = False,
        include_plotlyjs: str = "inline",
    ) -> None:
        """
        Export figure as standalone HTML file.

        Args:
            fig: Plotly figure to export
            output_path: Output file path
            auto_open: Open in browser after saving
            include_plotlyjs: How to include plotly.js library.
                'inline' (default): Embed full library in HTML (larger file, more secure, works offline)
                'cdn': Use CDN link (smaller file, requires internet, potential security risk)
                'directory': Save to separate file (advanced use)
        """
        if not PLOTLY_AVAILABLE:
            raise ImportError("Plotly is required for HTML export")

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Validate include_plotlyjs value
        valid_options = ["inline", "cdn", "directory", True, False]
        if include_plotlyjs not in valid_options:
            logger.warning(
                f"Invalid include_plotlyjs value '{include_plotlyjs}', using 'inline'"
            )
            include_plotlyjs = "inline"

        fig.write_html(
            str(output_path),
            auto_open=auto_open,
            include_plotlyjs=include_plotlyjs,
        )

        logger.info(f"Exported HTML to {output_path}")

    def export_image(
        self,
        fig: go.Figure,
        output_path: Path,
        format: str = "png",
        width: Optional[int] = None,
        height: Optional[int] = None,
        scale: float = 2.0,
    ) -> None:
        """
        Export figure as static image.

        Args:
            fig: Plotly figure to export
            output_path: Output file path
            format: Image format (png, jpg, svg, pdf)
            width: Image width in pixels
            height: Image height in pixels
            scale: Scale factor for resolution

        Note:
            Requires kaleido package: pip install kaleido
        """
        if not PLOTLY_AVAILABLE:
            raise ImportError("Plotly is required for image export")

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            fig.write_image(
                str(output_path),
                format=format,
                width=width,
                height=height,
                scale=scale,
            )
            logger.info(f"Exported {format.upper()} image to {output_path}")
        except Exception as e:
            logger.error(f"Image export failed: {e}")
            logger.info("Install kaleido for image export: pip install kaleido")
            raise

    def export_json(
        self,
        output_path: Path,
        include_positions: bool = True,
        layout_algorithm: str = "spring",
    ) -> None:
        """
        Export graph as JSON for web visualization.

        Creates a JSON representation of the graph suitable for custom web applications
        and JavaScript visualization libraries. Optionally includes pre-calculated node
        positions for consistent layout.

        Args:
            output_path: Output file path
            include_positions: Include pre-calculated node positions in JSON.
                If True, adds 'x' and 'y' coordinates to each node.
            layout_algorithm: Layout algorithm for position calculation.
                Options: 'spring', 'kamada_kawai', 'circular', 'spectral'

        Output Format:
            - nodes: List of node objects with id, attributes, and optional positions
            - links: List of edge objects with source, target, and attributes

        Example:
            >>> exporter = GraphExporter(client)
            >>> exporter.export_json(
            ...     "graph_data.json",
            ...     include_positions=True,
            ...     layout_algorithm="hierarchical"
            ... )
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Export NetworkX graph to dict
        from networkx.readwrite import json_graph

        graph_data = json_graph.node_link_data(self.graph)

        # Add positions if requested
        if include_positions:
            try:
                import networkx as nx

                pos = None

                if layout_algorithm == "spring":
                    pos = nx.spring_layout(self.graph, seed=42)
                elif layout_algorithm == "kamada_kawai":
                    pos = nx.kamada_kawai_layout(self.graph)
                elif layout_algorithm == "circular":
                    pos = nx.circular_layout(self.graph)
                elif layout_algorithm == "spectral":
                    pos = nx.spectral_layout(self.graph)

                if pos:
                    # Add positions to node data
                    for node_data in graph_data["nodes"]:
                        node_id = node_data["id"]
                        if node_id in pos:
                            x, y = pos[node_id]
                            node_data["x"] = float(x)
                            node_data["y"] = float(y)

            except Exception as e:
                logger.warning(f"Could not calculate positions: {e}")

        with open(output_path, "w") as f:
            json.dump(graph_data, f, indent=2)

        logger.info(f"Exported JSON to {output_path}")

    def export_dot(
        self,
        output_path: Path,
        node_attributes: Optional[list] = None,
        edge_attributes: Optional[list] = None,
    ) -> None:
        """
        Export graph as DOT format (Graphviz).

        Args:
            output_path: Output file path
            node_attributes: Node attributes to include
            edge_attributes: Edge attributes to include
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            import networkx as nx

            # Write DOT format
            nx.drawing.nx_pydot.write_dot(self.graph, str(output_path))

            logger.info(f"Exported DOT to {output_path}")
        except ImportError:
            logger.error("pydot is required for DOT export: pip install pydot")
            raise

    def export_cytoscape(
        self,
        output_path: Path,
    ) -> None:
        """
        Export graph in Cytoscape.js JSON format.

        Creates a JSON file compatible with Cytoscape.js for web-based graph visualization.
        Cytoscape.js is a popular JavaScript library for interactive graph visualization.

        Args:
            output_path: Output file path

        Output Format:
            - elements.nodes: Array of node objects with data properties
            - elements.edges: Array of edge objects with source/target references

        Use Cases:
            - Custom web dashboards
            - Interactive network visualization applications
            - Integration with React/Vue/Angular applications

        Example:
            >>> exporter = GraphExporter(client)
            >>> exporter.export_cytoscape("graph.cytoscape.json")

        More Info:
            https://js.cytoscape.org/
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Build Cytoscape.js format
        cytoscape_data = {
            "elements": {
                "nodes": [],
                "edges": [],
            }
        }

        # Add nodes
        for node, data in self.graph.nodes(data=True):
            node_elem = {"data": {"id": node, **data}}
            cytoscape_data["elements"]["nodes"].append(node_elem)

        # Add edges
        for u, v, data in self.graph.edges(data=True):
            edge_elem = {"data": {"id": f"{u}-{v}", "source": u, "target": v, **data}}
            cytoscape_data["elements"]["edges"].append(edge_elem)

        with open(output_path, "w") as f:
            json.dump(cytoscape_data, f, indent=2)

        logger.info(f"Exported Cytoscape.js format to {output_path}")

    def export_gexf(
        self,
        output_path: Path,
    ) -> None:
        """
        Export graph as GEXF format (Gephi).

        Creates a GEXF (Graph Exchange XML Format) file for use with Gephi,
        a powerful open-source network analysis and visualization platform.

        Args:
            output_path: Output file path

        Features:
            - Full node and edge attribute preservation
            - Compatible with Gephi 0.9+
            - Supports dynamic graph attributes

        Use Cases:
            - Advanced graph analysis in Gephi
            - Community detection and clustering
            - Large-scale network visualization
            - Statistical analysis and metrics calculation

        Example:
            >>> exporter = GraphExporter(client)
            >>> exporter.export_gexf("vulnerability_network.gexf")
            # Open in Gephi for advanced analysis

        More Info:
            https://gephi.org/
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            import networkx as nx

            # Clean None values (GEXF doesn't support them)
            clean_graph = self.graph.copy()
            for node, data in clean_graph.nodes(data=True):
                for key in list(data.keys()):
                    if data[key] is None:
                        del data[key]

            for u, v, data in clean_graph.edges(data=True):
                for key in list(data.keys()):
                    if data[key] is None:
                        del data[key]

            nx.write_gexf(clean_graph, str(output_path))

            logger.info(f"Exported GEXF to {output_path}")
        except Exception as e:
            logger.error(f"GEXF export failed: {e}")
            raise

    def export_visualization_data(
        self,
        output_path: Path,
        include_metadata: bool = True,
    ) -> None:
        """
        Export comprehensive visualization data package.

        Creates JSON file with graph data, statistics, and metadata.

        Args:
            output_path: Output file path
            include_metadata: Include graph statistics and metadata
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        from networkx.readwrite import json_graph

        data = {
            "graph": json_graph.node_link_data(self.graph),
        }

        if include_metadata:
            data["metadata"] = {
                "total_nodes": self.graph.number_of_nodes(),
                "total_edges": self.graph.number_of_edges(),
                "node_types": self._count_by_attribute("node_type"),
                "edge_types": self._count_edge_types(),
                "severities": self._count_by_attribute(
                    "severity", node_type="vulnerability"
                ),
                "zones": self._count_by_attribute("zone"),
                "criticalities": self._count_by_attribute("criticality"),
            }

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported visualization data to {output_path}")

    def export_attack_paths(
        self,
        attack_paths: list,
        output_path: Path,
    ) -> None:
        """
        Export attack path data as JSON.

        Args:
            attack_paths: List of AttackPath objects
            output_path: Output file path
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        paths_data = []
        for path in attack_paths:
            path_dict = {
                "path_id": path.path_id,
                "entry_point": path.entry_point,
                "target": path.target,
                "threat_level": path.threat_level.value,
                "total_cvss": path.total_cvss,
                "path_length": path.path_length,
                "exploitability": path.exploitability,
                "requires_privileges": path.requires_privileges,
                "description": path.description,
                "steps": [
                    {
                        "node_id": step.node_id,
                        "step_type": step.step_type.value,
                        "description": step.description,
                        "vulnerabilities": step.vulnerabilities,
                        "cvss_score": step.cvss_score,
                        "prerequisites": step.prerequisites,
                        "impact": step.impact,
                    }
                    for step in path.steps
                ],
            }
            paths_data.append(path_dict)

        with open(output_path, "w") as f:
            json.dump(
                {
                    "total_paths": len(attack_paths),
                    "attack_paths": paths_data,
                },
                f,
                indent=2,
            )

        logger.info(f"Exported {len(attack_paths)} attack paths to {output_path}")

    def _count_by_attribute(
        self,
        attribute: str,
        node_type: Optional[str] = None,
    ) -> Dict[str, int]:
        """Count nodes by attribute value."""
        counts = {}

        for node, data in self.graph.nodes(data=True):
            # Filter by node type if specified
            if node_type and data.get("node_type") != node_type:
                continue

            value = data.get(attribute, "unknown")
            if value:
                counts[value] = counts.get(value, 0) + 1

        return counts

    def _count_edge_types(self) -> Dict[str, int]:
        """Count edges by type."""
        counts = {}

        for _, _, data in self.graph.edges(data=True):
            edge_type = data.get("edge_type", "unknown")
            counts[edge_type] = counts.get(edge_type, 0) + 1

        return counts

    def export_all_formats(
        self,
        fig: go.Figure,
        base_path: Path,
        formats: Optional[list] = None,
    ) -> Dict[str, Path]:
        """
        Export visualization in multiple formats.

        Args:
            fig: Plotly figure to export
            base_path: Base output path (without extension)
            formats: List of formats to export (default: all)

        Returns:
            Dictionary mapping format to output path
        """
        if formats is None:
            formats = ["html", "png", "json", "dot"]

        base_path = Path(base_path)
        outputs = {}

        for fmt in formats:
            try:
                if fmt == "html":
                    output = base_path.with_suffix(".html")
                    self.export_html(fig, output)
                    outputs["html"] = output

                elif fmt == "png":
                    output = base_path.with_suffix(".png")
                    self.export_image(fig, output, format="png")
                    outputs["png"] = output

                elif fmt == "svg":
                    output = base_path.with_suffix(".svg")
                    self.export_image(fig, output, format="svg")
                    outputs["svg"] = output

                elif fmt == "pdf":
                    output = base_path.with_suffix(".pdf")
                    self.export_image(fig, output, format="pdf")
                    outputs["pdf"] = output

                elif fmt == "json":
                    output = base_path.with_suffix(".json")
                    self.export_json(output)
                    outputs["json"] = output

                elif fmt == "dot":
                    output = base_path.with_suffix(".dot")
                    self.export_dot(output)
                    outputs["dot"] = output

                elif fmt == "cytoscape":
                    output = base_path.with_suffix(".cytoscape.json")
                    self.export_cytoscape(output)
                    outputs["cytoscape"] = output

                elif fmt == "gexf":
                    output = base_path.with_suffix(".gexf")
                    self.export_gexf(output)
                    outputs["gexf"] = output

            except Exception as e:
                logger.error(f"Failed to export {fmt}: {e}")
                continue

        logger.info(f"Exported {len(outputs)} formats: {list(outputs.keys())}")
        return outputs
