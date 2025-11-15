"""Visualization CLI commands."""

import json
import logging
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.table import Table

from ..graph import NetworkXClient, GraphAnalyzer
from ..visualization import (
    NetworkGraphVisualizer,
    AttackPathVisualizer,
    NetworkTopologyVisualizer,
    GraphFilter,
    GraphExporter,
)

logger = logging.getLogger(__name__)
console = Console()
app = typer.Typer(help="Interactive graph visualization commands")

# Valid parameter values for input validation
VALID_LAYOUTS = ["spring", "kamada_kawai", "circular", "spectral", "shell", "hierarchical"]
VALID_COLOR_BY = ["node_type", "severity", "zone", "criticality", "compliance"]
VALID_VIEW_TYPES = ["topology", "zones", "compliance"]
VALID_COMPLIANCE_TYPES = ["pci", "hipaa", "sox", "gdpr"]
VALID_FILTER_TYPES = [
    "severity", "node_type", "cve", "package", "zone",
    "criticality", "compliance", "internet_facing", "search"
]
VALID_EXPORT_FORMATS = ["html", "png", "svg", "pdf", "json", "dot", "cytoscape", "gexf"]


def validate_path(path: Path, must_exist: bool = False) -> Path:
    """
    Validate and sanitize file path to prevent directory traversal.

    Args:
        path: Path to validate
        must_exist: Whether the path must already exist

    Returns:
        Validated absolute path

    Raises:
        typer.BadParameter: If path is invalid or contains directory traversal
    """
    try:
        # Convert to absolute path
        abs_path = path.resolve()

        # Check for directory traversal attempts
        if ".." in str(path):
            raise typer.BadParameter(
                f"Invalid path '{path}': directory traversal not allowed"
            )

        # Check if parent directory exists (for output files)
        if not must_exist and not abs_path.parent.exists():
            raise typer.BadParameter(
                f"Invalid path '{path}': parent directory does not exist"
            )

        # Check if file exists (for input files)
        if must_exist and not abs_path.exists():
            raise typer.BadParameter(
                f"File not found: {path}"
            )

        return abs_path

    except Exception as e:
        if isinstance(e, typer.BadParameter):
            raise
        raise typer.BadParameter(f"Invalid path '{path}': {e}")


def validate_enum_value(value: str, valid_values: List[str], param_name: str) -> str:
    """
    Validate that a parameter value is in the allowed set.

    Args:
        value: Value to validate
        valid_values: List of valid values
        param_name: Parameter name for error messages

    Returns:
        Validated value (lowercase)

    Raises:
        typer.BadParameter: If value is not valid
    """
    value_lower = value.lower()
    if value_lower not in valid_values:
        valid_str = ", ".join(valid_values)
        raise typer.BadParameter(
            f"Invalid {param_name}: '{value}'. Must be one of: {valid_str}"
        )
    return value_lower


@app.command()
def graph(
    graph_file: Path = typer.Argument(
        ...,
        help="Path to graph file (.graphml)",
        exists=True,
    ),
    output: Path = typer.Option(
        ...,
        "-o",
        "--output",
        help="Output HTML file path",
    ),
    layout: str = typer.Option(
        "spring",
        "--layout",
        "-l",
        help="Layout algorithm (spring, kamada_kawai, circular, spectral, hierarchical)",
    ),
    color_by: str = typer.Option(
        "node_type",
        "--color-by",
        help="Color scheme (node_type, severity)",
    ),
    width: int = typer.Option(
        1200,
        "--width",
        help="Figure width in pixels",
    ),
    height: int = typer.Option(
        800,
        "--height",
        help="Figure height in pixels",
    ),
    show_labels: bool = typer.Option(
        True,
        "--labels/--no-labels",
        help="Show node labels",
    ),
    three_d: bool = typer.Option(
        False,
        "--3d",
        help="Use 3D visualization",
    ),
    auto_open: bool = typer.Option(
        False,
        "--open",
        help="Open in browser after creating",
    ),
):
    """
    Create interactive graph visualization.

    Generates an interactive HTML visualization of the vulnerability graph
    with customizable layout, colors, and styling.
    """
    # Validate inputs
    graph_file = validate_path(graph_file, must_exist=True)
    output = validate_path(output, must_exist=False)
    layout = validate_enum_value(layout, VALID_LAYOUTS, "layout")
    color_by = validate_enum_value(color_by, VALID_COLOR_BY, "color_by")

    if width <= 0 or height <= 0:
        raise typer.BadParameter("Width and height must be positive integers")

    console.print(f"[cyan]Loading graph: {graph_file}[/cyan]")

    try:
        # Load graph
        client = NetworkXClient()
        client.load(str(graph_file))

        # Create visualizer
        visualizer = NetworkGraphVisualizer(client)

        # Create visualization
        with console.status("[bold green]Creating visualization..."):
            fig = visualizer.visualize(
                layout=layout,
                title=f"Vulnerability Graph - {graph_file.stem}",
                width=width,
                height=height,
                show_labels=show_labels,
                color_by=color_by,
                three_d=three_d,
            )

        # Save
        visualizer.save_html(fig, output, auto_open=auto_open)

        # Show stats
        stats = visualizer.get_statistics()
        console.print("[green]✓[/green] Visualization created successfully")
        console.print(f"  • Nodes: {stats['total_nodes']}")
        console.print(f"  • Edges: {stats['total_edges']}")
        console.print(f"  • Output: {output}")

        if auto_open:
            console.print("[dim]Opening in browser...[/dim]")

    except ImportError as e:
        console.print(f"[red]✗[/red] Missing dependency: {e}")
        console.print("[yellow]Install visualization dependencies:[/yellow]")
        console.print("  pip install plotly")
        raise typer.Exit(code=1)

    except Exception as e:
        console.print(f"[red]✗[/red] Error creating visualization: {e}")
        logger.exception("Error creating visualization")
        raise typer.Exit(code=1)


@app.command(name="attack-paths")
def visualize_attack_paths(
    graph_file: Path = typer.Argument(
        ...,
        help="Path to graph file (.graphml)",
        exists=True,
    ),
    output: Path = typer.Option(
        ...,
        "-o",
        "--output",
        help="Output HTML file path",
    ),
    attack_paths_file: Optional[Path] = typer.Option(
        None,
        "--paths",
        help="Path to attack paths JSON file (optional, will calculate if not provided)",
    ),
    max_paths: int = typer.Option(
        5,
        "--max-paths",
        help="Maximum number of paths to display",
    ),
    layout: str = typer.Option(
        "hierarchical",
        "--layout",
        "-l",
        help="Layout algorithm",
    ),
    width: int = typer.Option(
        1400,
        "--width",
        help="Figure width in pixels",
    ),
    height: int = typer.Option(
        900,
        "--height",
        help="Figure height in pixels",
    ),
    auto_open: bool = typer.Option(
        False,
        "--open",
        help="Open in browser after creating",
    ),
):
    """
    Visualize attack paths with highlighted routes.

    Creates an interactive visualization showing potential attack paths
    through the infrastructure with threat level highlighting.
    """
    # Validate inputs
    graph_file = validate_path(graph_file, must_exist=True)
    output = validate_path(output, must_exist=False)
    layout = validate_enum_value(layout, VALID_LAYOUTS, "layout")

    if attack_paths_file:
        attack_paths_file = validate_path(attack_paths_file, must_exist=True)

    if max_paths <= 0:
        raise typer.BadParameter("max_paths must be a positive integer")

    if width <= 0 or height <= 0:
        raise typer.BadParameter("Width and height must be positive integers")

    console.print(f"[cyan]Loading graph: {graph_file}[/cyan]")

    try:
        # Load graph
        client = NetworkXClient()
        client.load(str(graph_file))

        # Load or calculate attack paths
        if attack_paths_file:
            console.print(f"[cyan]Loading attack paths: {attack_paths_file}[/cyan]")
            with open(attack_paths_file) as f:
                paths_data = json.load(f)

            # Convert JSON to AttackPath objects
            from ..graph.models import AttackPath, AttackStep, AttackStepType, ThreatLevel

            attack_paths = []
            for path_data in paths_data.get("attack_paths", []):
                steps = [
                    AttackStep(
                        node_id=step["node_id"],
                        step_type=AttackStepType(step.get("step_type", step.get("type", "lateral_movement"))),
                        description=step["description"],
                        vulnerabilities=step.get("vulnerabilities", []),
                        cvss_score=step.get("cvss_score"),
                        prerequisites=step.get("prerequisites", []),
                        impact=step.get("impact"),
                    )
                    for step in path_data["steps"]
                ]

                attack_path = AttackPath(
                    path_id=path_data["path_id"],
                    entry_point=path_data["entry_point"],
                    target=path_data["target"],
                    steps=steps,
                    total_cvss=path_data["total_cvss"],
                    threat_level=ThreatLevel(path_data["threat_level"]),
                    exploitability=path_data.get("exploitability", 0.5),
                    requires_privileges=path_data.get("requires_privileges", False),
                    description=path_data.get("description", ""),
                )
                attack_paths.append(attack_path)

        else:
            # Calculate attack paths
            console.print("[cyan]Calculating attack paths...[/cyan]")
            analyzer = GraphAnalyzer(client)

            with console.status("[bold green]Finding attack paths..."):
                attack_paths = analyzer.find_shortest_attack_paths(
                    max_paths=max_paths * 2,  # Calculate more, display fewer
                    max_length=10,
                )

        if not attack_paths:
            console.print("[yellow]No attack paths found[/yellow]")
            return

        console.print(f"[green]✓[/green] Found {len(attack_paths)} attack paths")

        # Create visualizer
        visualizer = AttackPathVisualizer(client)

        # Create visualization
        with console.status("[bold green]Creating visualization..."):
            fig = visualizer.visualize_attack_paths(
                attack_paths=attack_paths,
                layout=layout,
                title=f"Attack Paths - {graph_file.stem}",
                width=width,
                height=height,
                max_paths_display=max_paths,
            )

        # Save
        visualizer.save_html(fig, output, auto_open=auto_open)

        console.print("[green]✓[/green] Attack path visualization created")
        console.print(f"  • Paths displayed: {min(len(attack_paths), max_paths)}")
        console.print(f"  • Output: {output}")

    except Exception as e:
        console.print(f"[red]✗[/red] Error creating visualization: {e}")
        logger.exception("Error creating attack path visualization")
        raise typer.Exit(code=1)


@app.command()
def topology(
    graph_file: Path = typer.Argument(
        ...,
        help="Path to graph file (.graphml)",
        exists=True,
    ),
    output: Path = typer.Option(
        ...,
        "-o",
        "--output",
        help="Output HTML file path",
    ),
    view: str = typer.Option(
        "topology",
        "--view",
        help="View type (topology, zones, compliance)",
    ),
    color_by: str = typer.Option(
        "zone",
        "--color-by",
        help="Color scheme (zone, criticality, compliance)",
    ),
    compliance_type: Optional[str] = typer.Option(
        None,
        "--compliance",
        help="Specific compliance type to highlight (pci, hipaa, sox, gdpr)",
    ),
    attack_paths_file: Optional[Path] = typer.Option(
        None,
        "--attack-paths",
        help="Path to attack paths JSON file (overlays attack paths on zones view)",
    ),
    layout: str = typer.Option(
        "hierarchical",
        "--layout",
        "-l",
        help="Layout algorithm",
    ),
    width: int = typer.Option(
        1400,
        "--width",
        help="Figure width in pixels",
    ),
    height: int = typer.Option(
        900,
        "--height",
        help="Figure height in pixels",
    ),
    auto_open: bool = typer.Option(
        False,
        "--open",
        help="Open in browser after creating",
    ),
):
    """
    Visualize network topology with security overlays.

    Creates visualization showing security zones, compliance scope,
    and network architecture with security context.

    Can overlay attack paths on zones view using --attack-paths option.
    """
    # Validate inputs
    graph_file = validate_path(graph_file, must_exist=True)
    output = validate_path(output, must_exist=False)
    view = validate_enum_value(view, VALID_VIEW_TYPES, "view")
    color_by = validate_enum_value(color_by, VALID_COLOR_BY, "color_by")
    layout = validate_enum_value(layout, VALID_LAYOUTS, "layout")

    if compliance_type:
        compliance_type = validate_enum_value(
            compliance_type, VALID_COMPLIANCE_TYPES, "compliance_type"
        )

    if attack_paths_file:
        attack_paths_file = validate_path(attack_paths_file, must_exist=True)

    if width <= 0 or height <= 0:
        raise typer.BadParameter("Width and height must be positive integers")

    console.print(f"[cyan]Loading graph: {graph_file}[/cyan]")

    try:
        # Load graph
        client = NetworkXClient()
        client.load(str(graph_file))

        # Load attack paths if provided
        attack_paths = None
        if attack_paths_file:
            console.print(f"[cyan]Loading attack paths: {attack_paths_file}[/cyan]")
            with open(attack_paths_file) as f:
                paths_data = json.load(f)

            # Convert JSON to AttackPath objects
            from ..graph.models import AttackPath, AttackStep, AttackStepType, ThreatLevel

            attack_paths = []
            for path_data in paths_data.get("attack_paths", []):
                steps = [
                    AttackStep(
                        node_id=step["node_id"],
                        step_type=AttackStepType(step.get("step_type", step.get("type", "lateral_movement"))),
                        description=step["description"],
                        vulnerabilities=step.get("vulnerabilities", []),
                        cvss_score=step.get("cvss_score"),
                        prerequisites=step.get("prerequisites", []),
                        impact=step.get("impact"),
                    )
                    for step in path_data["steps"]
                ]

                attack_path = AttackPath(
                    path_id=path_data["path_id"],
                    entry_point=path_data["entry_point"],
                    target=path_data["target"],
                    steps=steps,
                    total_cvss=path_data["total_cvss"],
                    threat_level=ThreatLevel(path_data["threat_level"]),
                    exploitability=path_data.get("exploitability", 0.5),
                    requires_privileges=path_data.get("requires_privileges", False),
                    description=path_data.get("description", ""),
                )
                attack_paths.append(attack_path)

            console.print(f"[green]✓[/green] Loaded {len(attack_paths)} attack paths")

        # Create visualizer
        visualizer = NetworkTopologyVisualizer(client)

        # Create visualization based on view type
        with console.status("[bold green]Creating visualization..."):
            if view == "zones":
                fig = visualizer.visualize_security_zones(
                    title=f"Security Zones - {graph_file.stem}",
                    width=width,
                    height=height,
                    attack_paths=attack_paths,
                )
            elif view == "compliance":
                fig = visualizer.visualize_compliance_scope(
                    compliance_type=compliance_type,
                    title=f"Compliance Scope - {graph_file.stem}",
                    width=width,
                    height=height,
                )
            else:  # topology
                fig = visualizer.visualize_topology(
                    layout=layout,
                    title=f"Network Topology - {graph_file.stem}",
                    width=width,
                    height=height,
                    color_by=color_by,
                )

        # Save
        visualizer.save_html(fig, output, auto_open=auto_open)

        console.print("[green]✓[/green] Topology visualization created")
        console.print(f"  • View: {view}")
        if attack_paths:
            console.print(f"  • Attack paths overlaid: {len(attack_paths)}")
        console.print(f"  • Output: {output}")

    except Exception as e:
        console.print(f"[red]✗[/red] Error creating visualization: {e}")
        logger.exception("Error creating topology visualization")
        raise typer.Exit(code=1)


@app.command()
def export(
    graph_file: Path = typer.Argument(
        ...,
        help="Path to graph file (.graphml)",
        exists=True,
    ),
    output: Path = typer.Option(
        ...,
        "-o",
        "--output",
        help="Output file path (without extension for multi-format)",
    ),
    formats: List[str] = typer.Option(
        ["html"],
        "--format",
        "-f",
        help="Export formats (html, png, svg, pdf, json, dot, cytoscape, gexf)",
    ),
    layout: str = typer.Option(
        "spring",
        "--layout",
        "-l",
        help="Layout algorithm for visualization formats",
    ),
):
    """
    Export graph visualization in multiple formats.

    Supports exporting to various formats for different use cases:
    - html: Interactive web visualization
    - png/svg/pdf: Static images for reports
    - json: Web-friendly data format
    - dot: Graphviz format
    - cytoscape: Cytoscape.js format
    - gexf: Gephi format
    """
    # Validate inputs
    graph_file = validate_path(graph_file, must_exist=True)
    output = validate_path(output, must_exist=False)
    layout = validate_enum_value(layout, VALID_LAYOUTS, "layout")

    # Validate formats
    for fmt in formats:
        if fmt.lower() not in VALID_EXPORT_FORMATS:
            valid_str = ", ".join(VALID_EXPORT_FORMATS)
            raise typer.BadParameter(
                f"Invalid format: '{fmt}'. Must be one of: {valid_str}"
            )

    console.print(f"[cyan]Loading graph: {graph_file}[/cyan]")

    try:
        # Load graph
        client = NetworkXClient()
        client.load(str(graph_file))

        # Create exporter
        exporter = GraphExporter(client)

        # Create visualization if needed for image formats
        needs_visualization = any(fmt in ['html', 'png', 'svg', 'pdf'] for fmt in formats)

        if needs_visualization:
            visualizer = NetworkGraphVisualizer(client)

            with console.status("[bold green]Creating visualization..."):
                fig = visualizer.visualize(
                    layout=layout,
                    title=f"Graph - {graph_file.stem}",
                )
        else:
            fig = None

        # Export formats
        with console.status("[bold green]Exporting formats..."):
            outputs = exporter.export_all_formats(
                fig=fig,
                base_path=output,
                formats=formats,
            )

        # Show results
        console.print("[green]✓[/green] Export completed")
        console.print(f"  • Formats exported: {len(outputs)}")

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Format", style="cyan")
        table.add_column("Output Path", style="yellow")

        for fmt, path in outputs.items():
            table.add_row(fmt.upper(), str(path))

        console.print(table)

    except Exception as e:
        console.print(f"[red]✗[/red] Error exporting: {e}")
        logger.exception("Error exporting visualization")
        raise typer.Exit(code=1)


@app.command()
def filter(
    graph_file: Path = typer.Argument(
        ...,
        help="Path to graph file (.graphml)",
        exists=True,
    ),
    output: Path = typer.Option(
        ...,
        "-o",
        "--output",
        help="Output file path for filtered visualization",
    ),
    filter_type: str = typer.Option(
        ...,
        "--type",
        "-t",
        help="Filter type (severity, node_type, cve, package, zone, criticality, compliance, internet_facing, search)",
    ),
    value: Optional[str] = typer.Option(
        None,
        "--value",
        "-v",
        help="Filter value (depends on filter type)",
    ),
    values: Optional[List[str]] = typer.Option(
        None,
        "--values",
        help="Multiple filter values (for list-based filters)",
    ),
    include_related: bool = typer.Option(
        True,
        "--related/--no-related",
        help="Include related nodes in filter",
    ),
    layout: str = typer.Option(
        "spring",
        "--layout",
        "-l",
        help="Layout algorithm",
    ),
    auto_open: bool = typer.Option(
        False,
        "--open",
        help="Open in browser after creating",
    ),
):
    """
    Filter and visualize specific graph subset.

    Apply filters to focus on specific aspects of the vulnerability graph,
    such as high-severity issues, specific packages, or security zones.
    """
    # Validate inputs
    graph_file = validate_path(graph_file, must_exist=True)
    output = validate_path(output, must_exist=False)
    filter_type = validate_enum_value(filter_type, VALID_FILTER_TYPES, "filter_type")
    layout = validate_enum_value(layout, VALID_LAYOUTS, "layout")

    console.print(f"[cyan]Loading graph: {graph_file}[/cyan]")

    try:
        # Load graph
        client = NetworkXClient()
        client.load(str(graph_file))

        # Create filter
        graph_filter = GraphFilter(client)

        # Apply filter based on type
        console.print(f"[cyan]Applying {filter_type} filter...[/cyan]")

        if filter_type == "severity":
            if not value:
                console.print("[red]Error: --value required for severity filter[/red]")
                raise typer.Exit(code=1)
            filtered_client = graph_filter.filter_by_severity(value, include_related)

        elif filter_type == "node_type":
            if not values:
                console.print("[red]Error: --values required for node_type filter[/red]")
                raise typer.Exit(code=1)
            filtered_client = graph_filter.filter_by_node_type(list(values), include_related)

        elif filter_type == "cve":
            if not values:
                console.print("[red]Error: --values required for cve filter[/red]")
                raise typer.Exit(code=1)
            filtered_client = graph_filter.filter_by_cve(list(values), include_related)

        elif filter_type == "package":
            if not values:
                console.print("[red]Error: --values required for package filter[/red]")
                raise typer.Exit(code=1)
            filtered_client = graph_filter.filter_by_package(list(values), include_related)

        elif filter_type == "zone":
            if not values:
                console.print("[red]Error: --values required for zone filter[/red]")
                raise typer.Exit(code=1)
            filtered_client = graph_filter.filter_by_zone(list(values), include_related)

        elif filter_type == "criticality":
            if not value:
                console.print("[red]Error: --value required for criticality filter[/red]")
                raise typer.Exit(code=1)
            filtered_client = graph_filter.filter_by_criticality(value, include_related)

        elif filter_type == "compliance":
            if not values:
                console.print("[red]Error: --values required for compliance filter[/red]")
                raise typer.Exit(code=1)
            filtered_client = graph_filter.filter_by_compliance(list(values), include_related)

        elif filter_type == "internet_facing":
            filtered_client = graph_filter.filter_by_internet_facing(include_related)

        elif filter_type == "search":
            if not value:
                console.print("[red]Error: --value required for search filter[/red]")
                raise typer.Exit(code=1)
            filtered_client = graph_filter.filter_by_search(value, include_related=include_related)

        else:
            console.print(f"[red]Error: Unknown filter type: {filter_type}[/red]")
            raise typer.Exit(code=1)

        # Show filter results
        filtered_stats = filtered_client.get_metadata()
        console.print(f"[green]✓[/green] Filtered graph:")
        console.print(f"  • Nodes: {filtered_stats.node_count} (from {client.graph.number_of_nodes()})")
        console.print(f"  • Edges: {filtered_stats.edge_count} (from {client.graph.number_of_edges()})")

        # Create visualization of filtered graph
        visualizer = NetworkGraphVisualizer(filtered_client)

        with console.status("[bold green]Creating visualization..."):
            fig = visualizer.visualize(
                layout=layout,
                title=f"Filtered Graph - {filter_type}",
            )

        # Save
        visualizer.save_html(fig, output, auto_open=auto_open)

        console.print("[green]✓[/green] Filtered visualization created")
        console.print(f"  • Output: {output}")

    except Exception as e:
        console.print(f"[red]✗[/red] Error creating filtered visualization: {e}")
        logger.exception("Error creating filtered visualization")
        raise typer.Exit(code=1)


@app.command()
def stats(
    graph_file: Path = typer.Argument(
        ...,
        help="Path to graph file (.graphml)",
        exists=True,
    ),
):
    """
    Show graph statistics for filtering.

    Displays available filter values and counts to help
    construct effective visualization filters.
    """
    # Validate input
    graph_file = validate_path(graph_file, must_exist=True)

    console.print(f"[cyan]Loading graph: {graph_file}[/cyan]")

    try:
        # Load graph
        client = NetworkXClient()
        client.load(str(graph_file))

        # Create filter
        graph_filter = GraphFilter(client)

        # Get statistics
        stats = graph_filter.get_filter_statistics()

        console.print("\n[bold]Graph Filter Statistics:[/bold]\n")

        # Overall stats
        console.print(f"Total Nodes: {stats['total_nodes']}")
        console.print(f"Total Edges: {stats['total_edges']}")

        # Node types
        if stats['node_types']:
            console.print("\n[bold cyan]Node Types:[/bold cyan]")
            table = Table(show_header=False)
            table.add_column("Type", style="yellow")
            table.add_column("Count", justify="right", style="cyan")

            for node_type, count in sorted(stats['node_types'].items(), key=lambda x: -x[1]):
                table.add_row(node_type, str(count))

            console.print(table)

        # Severities
        if stats['severities']:
            console.print("\n[bold cyan]Severities:[/bold cyan]")
            table = Table(show_header=False)
            table.add_column("Severity", style="yellow")
            table.add_column("Count", justify="right", style="cyan")

            for severity, count in sorted(stats['severities'].items(), key=lambda x: -x[1]):
                table.add_row(severity, str(count))

            console.print(table)

        # Zones
        if stats['zones']:
            console.print("\n[bold cyan]Security Zones:[/bold cyan]")
            table = Table(show_header=False)
            table.add_column("Zone", style="yellow")
            table.add_column("Count", justify="right", style="cyan")

            for zone, count in sorted(stats['zones'].items(), key=lambda x: -x[1]):
                table.add_row(zone, str(count))

            console.print(table)

        # Criticalities
        if stats['criticalities']:
            console.print("\n[bold cyan]Criticality Levels:[/bold cyan]")
            table = Table(show_header=False)
            table.add_column("Criticality", style="yellow")
            table.add_column("Count", justify="right", style="cyan")

            for criticality, count in sorted(stats['criticalities'].items(), key=lambda x: -x[1]):
                table.add_row(criticality, str(count))

            console.print(table)

        # Compliance
        if any(stats['compliance_scopes'].values()):
            console.print("\n[bold cyan]Compliance Scope:[/bold cyan]")
            table = Table(show_header=False)
            table.add_column("Type", style="yellow")
            table.add_column("Count", justify="right", style="cyan")

            for comp_type, count in stats['compliance_scopes'].items():
                if count > 0:
                    table.add_row(comp_type.upper(), str(count))

            console.print(table)

        # Internet-facing
        if stats['internet_facing'] > 0:
            console.print(f"\n[bold cyan]Internet-Facing Assets:[/bold cyan] {stats['internet_facing']}")

    except Exception as e:
        console.print(f"[red]✗[/red] Error loading statistics: {e}")
        logger.exception("Error loading graph statistics")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
