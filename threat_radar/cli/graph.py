"""Graph database CLI commands."""

import json
import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from ..graph import NetworkXClient, GraphBuilder, GraphAnalyzer
from ..core import GrypeScanResult, GrypeVulnerability
from ..core.container_analyzer import ContainerAnalyzer, ContainerAnalysis
from ..utils.graph_storage import GraphStorageManager

logger = logging.getLogger(__name__)
console = Console()
app = typer.Typer(help="Graph database operations for vulnerability modeling")


@app.command()
def build(
    scan_results: Path = typer.Argument(
        ...,
        help="Path to CVE scan results JSON file",
        exists=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "-o",
        "--output",
        help="Output graph file path",
    ),
    auto_save: bool = typer.Option(
        False,
        "--auto-save",
        "--as",
        help="Auto-save to storage/graph_storage/",
    ),
):
    """
    Build vulnerability graph from CVE scan results.

    This command converts flat scan data into a graph structure
    for relationship-based queries and analysis.
    """
    console.print(f"[cyan]Building graph from: {scan_results}[/cyan]")

    try:
        # Load scan results
        with open(scan_results) as f:
            scan_data = json.load(f)

        # Convert to GrypeScanResult
        vulnerabilities = []
        for vuln_data in scan_data.get("matches", []):
            vuln = GrypeVulnerability(
                id=vuln_data["vulnerability"]["id"],
                severity=vuln_data["vulnerability"].get("severity", "unknown"),
                package_name=vuln_data["artifact"]["name"],
                package_version=vuln_data["artifact"]["version"],
                package_type=vuln_data["artifact"].get("type", "unknown"),
                fixed_in_version=vuln_data["vulnerability"].get("fix", {}).get("versions", [None])[0],
                description=vuln_data["vulnerability"].get("description"),
                cvss_score=vuln_data["vulnerability"].get("cvss", [{}])[0].get("metrics", {}).get("baseScore"),
                urls=vuln_data["vulnerability"].get("urls", []),
                data_source=vuln_data["vulnerability"].get("dataSource"),
                namespace=vuln_data["vulnerability"].get("namespace"),
            )
            vulnerabilities.append(vuln)

        scan_result = GrypeScanResult(
            target=scan_data.get("source", {}).get("target", "unknown"),
            vulnerabilities=vulnerabilities,
        )

        # Create graph client and builder
        client = NetworkXClient()
        builder = GraphBuilder(client)

        # Build graph
        with console.status("[bold green]Building graph..."):
            builder.build_from_scan(scan_result)

        # Get metadata
        metadata = client.get_metadata()

        console.print("[green]✓[/green] Graph built successfully")
        console.print(f"  • Nodes: {metadata.node_count}")
        console.print(f"  • Edges: {metadata.edge_count}")
        console.print(f"  • Node types: {metadata.node_type_counts}")

        # Save graph
        if auto_save:
            storage = GraphStorageManager()
            target_name = scan_result.target.replace(":", "_").replace("/", "_")
            saved_path = storage.save_graph(
                client,
                target_name,
                metadata={
                    "source": str(scan_results),
                    "target": scan_result.target,
                    "vulnerability_count": scan_result.total_count,
                    **metadata.node_type_counts,
                }
            )
            console.print(f"[green]✓[/green] Saved to: {saved_path}")

        if output:
            client.save(str(output))
            console.print(f"[green]✓[/green] Saved to: {output}")

        if not auto_save and not output:
            console.print("[yellow]⚠[/yellow] Graph not saved (use --output or --auto-save)")

    except Exception as e:
        console.print(f"[red]✗[/red] Error building graph: {e}")
        logger.exception("Error building graph")
        raise typer.Exit(code=1)


@app.command()
def query(
    graph_file: Path = typer.Argument(
        ...,
        help="Path to graph file (.graphml)",
        exists=True,
    ),
    cve: Optional[str] = typer.Option(
        None,
        "--cve",
        help="Find containers affected by CVE",
    ),
    top_packages: Optional[int] = typer.Option(
        None,
        "--top-packages",
        help="Show top N most vulnerable packages",
    ),
    stats: bool = typer.Option(
        False,
        "--stats",
        help="Show vulnerability statistics",
    ),
):
    """
    Query the vulnerability graph.

    Supports various query types:
    - Find containers affected by a CVE
    - Show most vulnerable packages
    - Display vulnerability statistics
    """
    console.print(f"[cyan]Loading graph: {graph_file}[/cyan]")

    try:
        # Load graph
        client = NetworkXClient()
        client.load(str(graph_file))

        analyzer = GraphAnalyzer(client)

        # Execute queries
        if cve:
            console.print(f"\n[bold]Blast radius for {cve}:[/bold]")
            blast_radius = analyzer.blast_radius(cve)

            for asset_type, assets in blast_radius.items():
                if assets:
                    console.print(f"\n[cyan]{asset_type.capitalize()}:[/cyan]")
                    for asset in assets:
                        console.print(f"  • {asset}")

        if top_packages:
            console.print(f"\n[bold]Top {top_packages} Most Vulnerable Packages:[/bold]")
            vulnerable_pkgs = analyzer.most_vulnerable_packages(top_n=top_packages)

            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Package", style="yellow")
            table.add_column("Vulnerabilities", justify="right")
            table.add_column("Avg CVSS", justify="right")

            for pkg_id, vuln_count, avg_cvss in vulnerable_pkgs:
                table.add_row(
                    pkg_id,
                    str(vuln_count),
                    f"{avg_cvss:.1f}"
                )

            console.print(table)

        if stats:
            console.print("\n[bold]Vulnerability Statistics:[/bold]")
            statistics = analyzer.vulnerability_statistics()

            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", justify="right", style="yellow")

            table.add_row("Total Vulnerabilities", str(statistics["total_vulnerabilities"]))
            table.add_row("Critical", str(statistics["by_severity"]["critical"]))
            table.add_row("High", str(statistics["by_severity"]["high"]))
            table.add_row("Medium", str(statistics["by_severity"]["medium"]))
            table.add_row("Low", str(statistics["by_severity"]["low"]))
            table.add_row("With Fixes", str(statistics["with_fixes"]))
            table.add_row("Without Fixes", str(statistics["without_fixes"]))
            table.add_row("Avg CVSS Score", f"{statistics['avg_cvss_score']:.2f}")

            console.print(table)

    except Exception as e:
        console.print(f"[red]✗[/red] Error querying graph: {e}")
        logger.exception("Error querying graph")
        raise typer.Exit(code=1)


@app.command()
def list(
    limit: Optional[int] = typer.Option(
        None,
        "--limit",
        "-n",
        help="Limit number of results",
    ),
):
    """
    List all stored graphs.
    """
    storage = GraphStorageManager()
    graphs = storage.list_graphs()

    if not graphs:
        console.print("[yellow]No graphs found in storage[/yellow]")
        return

    if limit:
        graphs = graphs[:limit]

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Filename", style="cyan")
    table.add_column("Size", justify="right")
    table.add_column("Modified", style="dim")

    for graph_path in graphs:
        stat = graph_path.stat()
        size_mb = stat.st_size / (1024 * 1024)
        from datetime import datetime
        mod_time = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")

        table.add_row(
            graph_path.name,
            f"{size_mb:.2f} MB",
            mod_time
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(graphs)} graphs[/dim]")


@app.command()
def info(
    graph_file: Path = typer.Argument(
        ...,
        help="Path to graph file (.graphml)",
        exists=True,
    ),
):
    """
    Show detailed information about a graph.
    """
    console.print(f"[cyan]Loading graph: {graph_file}[/cyan]")

    try:
        # Load graph
        client = NetworkXClient()
        client.load(str(graph_file))

        metadata = client.get_metadata()

        console.print("\n[bold]Graph Information:[/bold]")

        # Basic stats
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right", style="yellow")

        table.add_row("Total Nodes", str(metadata.node_count))
        table.add_row("Total Edges", str(metadata.edge_count))

        console.print(table)

        # Node types
        if metadata.node_type_counts:
            console.print("\n[bold]Node Types:[/bold]")
            type_table = Table(show_header=True, header_style="bold cyan")
            type_table.add_column("Type", style="cyan")
            type_table.add_column("Count", justify="right", style="yellow")

            for node_type, count in sorted(metadata.node_type_counts.items()):
                type_table.add_row(node_type, str(count))

            console.print(type_table)

        # Edge types
        if metadata.edge_type_counts:
            console.print("\n[bold]Edge Types:[/bold]")
            edge_table = Table(show_header=True, header_style="bold cyan")
            edge_table.add_column("Type", style="cyan")
            edge_table.add_column("Count", justify="right", style="yellow")

            for edge_type, count in sorted(metadata.edge_type_counts.items()):
                edge_table.add_row(edge_type, str(count))

            console.print(edge_table)

    except Exception as e:
        console.print(f"[red]✗[/red] Error loading graph: {e}")
        logger.exception("Error loading graph info")
        raise typer.Exit(code=1)


@app.command()
def fixes(
    graph_file: Path = typer.Argument(
        ...,
        help="Path to graph file (.graphml)",
        exists=True,
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        help="Filter by severity (critical, high, medium, low)",
    ),
):
    """
    Find vulnerabilities with available fixes.
    """
    console.print(f"[cyan]Loading graph: {graph_file}[/cyan]")

    try:
        # Load graph
        client = NetworkXClient()
        client.load(str(graph_file))

        analyzer = GraphAnalyzer(client)

        console.print("\n[bold]Fix Candidates:[/bold]")
        fix_candidates = analyzer.find_fix_candidates(severity=severity)

        if not fix_candidates:
            console.print("[yellow]No fix candidates found[/yellow]")
            return

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("CVE", style="yellow")
        table.add_column("Severity")
        table.add_column("CVSS", justify="right")
        table.add_column("Affected Packages", justify="right")
        table.add_column("Fix Version", style="green")

        for fix in fix_candidates:
            severity_color = {
                "critical": "red",
                "high": "bright_red",
                "medium": "yellow",
                "low": "blue",
            }.get(fix["severity"], "white")

            table.add_row(
                fix["cve_id"],
                f"[{severity_color}]{fix['severity'].upper()}[/{severity_color}]",
                f"{fix['cvss_score']:.1f}" if fix['cvss_score'] else "N/A",
                str(len(fix["affected_packages"])),
                fix["fix_version"]
            )

        console.print(table)
        console.print(f"\n[dim]Total: {len(fix_candidates)} fix candidates[/dim]")

    except Exception as e:
        console.print(f"[red]✗[/red] Error finding fixes: {e}")
        logger.exception("Error finding fixes")
        raise typer.Exit(code=1)


@app.command()
def cleanup(
    days: int = typer.Option(
        30,
        "--days",
        help="Delete graphs older than this many days",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Skip confirmation prompt",
    ),
):
    """
    Clean up old graph files from storage.
    """
    storage = GraphStorageManager()

    if not force:
        confirm = typer.confirm(
            f"Delete all graphs older than {days} days?",
            abort=True
        )

    deleted = storage.cleanup_old_graphs(days=days)
    console.print(f"[green]✓[/green] Deleted {deleted} old graph(s)")


if __name__ == "__main__":
    app()
