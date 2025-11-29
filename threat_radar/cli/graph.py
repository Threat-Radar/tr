"""Graph database CLI commands."""

import json
import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from ..graph import (
    NetworkXClient,
    GraphBuilder,
    GraphAnalyzer,
    GraphAnalytics,
    GraphValidator,
    CentralityMetric,
    CommunityAlgorithm,
)
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

        # Detect format
        is_grype_raw_format = "matches" in scan_data
        is_threat_radar_format = (
            "vulnerabilities" in scan_data and "target" in scan_data
        )

        # Convert to GrypeScanResult
        vulnerabilities = []

        if is_grype_raw_format:
            # Parse raw Grype format (nested structure)
            for vuln_data in scan_data.get("matches", []):
                vuln = GrypeVulnerability(
                    id=vuln_data["vulnerability"]["id"],
                    severity=vuln_data["vulnerability"].get("severity", "unknown"),
                    package_name=vuln_data["artifact"]["name"],
                    package_version=vuln_data["artifact"]["version"],
                    package_type=vuln_data["artifact"].get("type", "unknown"),
                    fixed_in_version=vuln_data["vulnerability"]
                    .get("fix", {})
                    .get("versions", [None])[0],
                    description=vuln_data["vulnerability"].get("description"),
                    cvss_score=vuln_data["vulnerability"]
                    .get("cvss", [{}])[0]
                    .get("metrics", {})
                    .get("baseScore"),
                    urls=vuln_data["vulnerability"].get("urls", []),
                    data_source=vuln_data["vulnerability"].get("dataSource"),
                    namespace=vuln_data["vulnerability"].get("namespace"),
                )
                vulnerabilities.append(vuln)

        elif is_threat_radar_format:
            # Parse Threat Radar simplified format (flat structure)
            for vuln_data in scan_data.get("vulnerabilities", []):
                # Extract package name and version from "package" field
                # Format: "git@1:2.39.5-0+deb12u2" or "openssl@1.1.1"
                package_full = vuln_data.get("package", "unknown@unknown")
                if "@" in package_full:
                    package_name, package_version = package_full.split("@", 1)
                else:
                    package_name = package_full
                    package_version = "unknown"

                vuln = GrypeVulnerability(
                    id=vuln_data.get("id", "UNKNOWN"),
                    severity=vuln_data.get("severity", "unknown"),
                    package_name=package_name,
                    package_version=package_version,
                    package_type=vuln_data.get("package_type", "unknown"),
                    fixed_in_version=vuln_data.get("fixed_in"),
                    description=vuln_data.get("description"),
                    cvss_score=vuln_data.get("cvss_score"),
                    urls=vuln_data.get("urls", []),
                    data_source=vuln_data.get("data_source"),
                    namespace=vuln_data.get("namespace"),
                )
                vulnerabilities.append(vuln)

        else:
            # Unsupported format
            console.print("[red]✗[/red] Unsupported scan result format")
            console.print("[yellow]Expected either:[/yellow]")
            console.print("  • Raw Grype format (with 'matches' key)")
            console.print(
                "  • Threat Radar format (with 'vulnerabilities' and 'target' keys)"
            )
            raise typer.Exit(code=1)

        # Extract target based on format
        if is_grype_raw_format:
            target = scan_data.get("source", {}).get("target", "unknown")
        elif is_threat_radar_format:
            target = scan_data.get("target", "unknown")
        else:
            target = "unknown"

        scan_result = GrypeScanResult(
            target=target,
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

        # Show detected format
        if is_grype_raw_format:
            format_name = "Grype raw format"
        elif is_threat_radar_format:
            format_name = "Threat Radar format"
        else:
            format_name = "Unknown format"

        console.print(f"[dim]Format detected: {format_name}[/dim]")
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
                },
            )
            console.print(f"[green]✓[/green] Saved to: {saved_path}")

        if output:
            client.save(str(output))
            console.print(f"[green]✓[/green] Saved to: {output}")

        if not auto_save and not output:
            console.print(
                "[yellow]⚠[/yellow] Graph not saved (use --output or --auto-save)"
            )

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
            console.print(
                f"\n[bold]Top {top_packages} Most Vulnerable Packages:[/bold]"
            )
            vulnerable_pkgs = analyzer.most_vulnerable_packages(top_n=top_packages)

            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Package", style="yellow")
            table.add_column("Vulnerabilities", justify="right")
            table.add_column("Avg CVSS", justify="right")

            for pkg_id, vuln_count, avg_cvss in vulnerable_pkgs:
                table.add_row(pkg_id, str(vuln_count), f"{avg_cvss:.1f}")

            console.print(table)

        if stats:
            console.print("\n[bold]Vulnerability Statistics:[/bold]")
            statistics = analyzer.vulnerability_statistics()

            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", justify="right", style="yellow")

            table.add_row(
                "Total Vulnerabilities", str(statistics["total_vulnerabilities"])
            )
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


@app.command(name="list")
def list_graphs(
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

        table.add_row(graph_path.name, f"{size_mb:.2f} MB", mod_time)

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
                f"{fix['cvss_score']:.1f}" if fix["cvss_score"] else "N/A",
                str(len(fix["affected_packages"])),
                fix["fix_version"],
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
            f"Delete all graphs older than {days} days?", abort=True
        )

    deleted = storage.cleanup_old_graphs(days=days)
    console.print(f"[green]✓[/green] Deleted {deleted} old graph(s)")


@app.command(name="attack-paths")
def attack_paths(
    graph_file: Path = typer.Argument(
        ...,
        help="Path to graph file (.graphml)",
        exists=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "-o",
        "--output",
        help="Save results to JSON file",
    ),
    max_paths: int = typer.Option(
        20,
        "--max-paths",
        help="Maximum number of attack paths to find",
    ),
    max_length: int = typer.Option(
        10,
        "--max-length",
        help="Maximum path length to consider",
    ),
):
    """
    Find shortest attack paths from entry points to high-value targets.

    Identifies potential attack paths through the infrastructure by
    analyzing relationships between vulnerable assets.
    """
    console.print(f"[cyan]Loading graph: {graph_file}[/cyan]")

    try:
        # Load graph
        client = NetworkXClient()
        client.load(str(graph_file))

        analyzer = GraphAnalyzer(client)

        # Identify entry points and targets
        with console.status("[bold green]Identifying entry points and targets..."):
            entry_points = analyzer.identify_entry_points()
            targets = analyzer.identify_high_value_targets()

        console.print(f"[green]✓[/green] Found {len(entry_points)} entry points")
        console.print(f"[green]✓[/green] Found {len(targets)} high-value targets")

        if not entry_points or not targets:
            console.print("[yellow]⚠[/yellow] No entry points or targets found")
            return

        # Find attack paths
        with console.status("[bold green]Finding attack paths..."):
            attack_paths = analyzer.find_shortest_attack_paths(
                entry_points=entry_points, targets=targets, max_length=max_length
            )[:max_paths]

        if not attack_paths:
            console.print("[yellow]No attack paths found[/yellow]")
            return

        console.print(f"\n[bold]Found {len(attack_paths)} Attack Paths:[/bold]")

        # Display paths
        for i, path in enumerate(attack_paths[:10], 1):  # Show top 10 in console
            threat_color = {
                "critical": "red",
                "high": "bright_red",
                "medium": "yellow",
                "low": "blue",
            }.get(path.threat_level.value, "white")

            console.print(f"\n[bold cyan]Path {i}:[/bold cyan]")
            console.print(
                f"  Threat Level: [{threat_color}]{path.threat_level.value.upper()}[/{threat_color}]"
            )
            console.print(f"  Total CVSS: {path.total_cvss:.2f}")
            console.print(f"  Length: {path.path_length} steps")
            console.print(f"  Exploitability: {path.exploitability:.0%}")

            console.print(f"\n  [dim]Steps:[/dim]")
            for step in path.steps:
                console.print(f"    • {step.description}")
                if step.vulnerabilities:
                    console.print(f"      CVEs: {', '.join(step.vulnerabilities[:3])}")

        # Save to JSON
        if output:
            attack_paths_data = [
                {
                    "path_id": p.path_id,
                    "entry_point": p.entry_point,
                    "target": p.target,
                    "threat_level": p.threat_level.value,
                    "total_cvss": p.total_cvss,
                    "path_length": p.path_length,
                    "exploitability": p.exploitability,
                    "requires_privileges": p.requires_privileges,
                    "description": p.description,
                    "steps": [
                        {
                            "node_id": s.node_id,
                            "step_type": s.step_type.value,
                            "description": s.description,
                            "vulnerabilities": s.vulnerabilities,
                            "cvss_score": s.cvss_score,
                        }
                        for s in p.steps
                    ],
                }
                for p in attack_paths
            ]

            with open(output, "w") as f:
                json.dump(
                    {
                        "total_paths": len(attack_paths),
                        "entry_points": entry_points,
                        "targets": targets,
                        "attack_paths": attack_paths_data,
                    },
                    f,
                    indent=2,
                )

            console.print(
                f"\n[green]✓[/green] Saved {len(attack_paths)} paths to: {output}"
            )

    except Exception as e:
        console.print(f"[red]✗[/red] Error analyzing attack paths: {e}")
        logger.exception("Error analyzing attack paths")
        raise typer.Exit(code=1)


@app.command(name="privilege-escalation")
def privilege_escalation(
    graph_file: Path = typer.Argument(
        ...,
        help="Path to graph file (.graphml)",
        exists=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "-o",
        "--output",
        help="Save results to JSON file",
    ),
    max_paths: int = typer.Option(
        20,
        "--max-paths",
        help="Maximum number of paths to find",
    ),
):
    """
    Detect privilege escalation opportunities.

    Identifies paths where an attacker can escalate from lower to higher
    privilege levels (e.g., DMZ to internal zone, user to admin).
    """
    console.print(f"[cyan]Loading graph: {graph_file}[/cyan]")

    try:
        # Load graph
        client = NetworkXClient()
        client.load(str(graph_file))

        analyzer = GraphAnalyzer(client)

        # Detect privilege escalations
        with console.status("[bold green]Detecting privilege escalation paths..."):
            escalation_paths = analyzer.detect_privilege_escalation_paths(
                max_paths=max_paths
            )

        if not escalation_paths:
            console.print("[yellow]No privilege escalation paths found[/yellow]")
            return

        console.print(
            f"\n[bold]Found {len(escalation_paths)} Privilege Escalation Paths:[/bold]"
        )

        # Display paths
        for i, esc in enumerate(escalation_paths[:10], 1):  # Show top 10
            diff_color = {
                "easy": "red",
                "medium": "yellow",
                "hard": "green",
            }.get(esc.difficulty, "white")

            console.print(f"\n[bold cyan]Escalation {i}:[/bold cyan]")
            console.print(f"  From: {esc.from_privilege}")
            console.print(f"  To: {esc.to_privilege}")
            console.print(
                f"  Difficulty: [{diff_color}]{esc.difficulty.upper()}[/{diff_color}]"
            )
            console.print(f"  Path Length: {esc.path.path_length} steps")
            console.print(f"  CVEs: {', '.join(esc.vulnerabilities[:5])}")

            if esc.mitigation:
                console.print(f"\n  [dim]Mitigation:[/dim]")
                for mit in esc.mitigation[:3]:
                    console.print(f"    • {mit}")

        # Save to JSON
        if output:
            escalation_data = [
                {
                    "from_privilege": e.from_privilege,
                    "to_privilege": e.to_privilege,
                    "difficulty": e.difficulty,
                    "vulnerabilities": e.vulnerabilities,
                    "mitigation": e.mitigation,
                    "path": {
                        "entry_point": e.path.entry_point,
                        "target": e.path.target,
                        "length": e.path.path_length,
                        "total_cvss": e.path.total_cvss,
                        "steps": [
                            {
                                "node_id": s.node_id,
                                "type": s.step_type.value,
                                "description": s.description,
                            }
                            for s in e.path.steps
                        ],
                    },
                }
                for e in escalation_paths
            ]

            with open(output, "w") as f:
                json.dump(
                    {
                        "total_escalations": len(escalation_paths),
                        "privilege_escalations": escalation_data,
                    },
                    f,
                    indent=2,
                )

            console.print(
                f"\n[green]✓[/green] Saved {len(escalation_paths)} escalations to: {output}"
            )

    except Exception as e:
        console.print(f"[red]✗[/red] Error detecting privilege escalation: {e}")
        logger.exception("Error detecting privilege escalation")
        raise typer.Exit(code=1)


@app.command(name="lateral-movement")
def lateral_movement(
    graph_file: Path = typer.Argument(
        ...,
        help="Path to graph file (.graphml)",
        exists=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "-o",
        "--output",
        help="Save results to JSON file",
    ),
    max_opportunities: int = typer.Option(
        30,
        "--max-opportunities",
        help="Maximum number of opportunities to find",
    ),
):
    """
    Identify lateral movement opportunities.

    Finds ways an attacker could move between compromised assets within
    the same network zone or privilege level.
    """
    console.print(f"[cyan]Loading graph: {graph_file}[/cyan]")

    try:
        # Load graph
        client = NetworkXClient()
        client.load(str(graph_file))

        analyzer = GraphAnalyzer(client)

        # Identify lateral movements
        with console.status(
            "[bold green]Identifying lateral movement opportunities..."
        ):
            opportunities = analyzer.identify_lateral_movement_opportunities(
                max_opportunities=max_opportunities
            )

        if not opportunities:
            console.print("[yellow]No lateral movement opportunities found[/yellow]")
            return

        console.print(
            f"\n[bold]Found {len(opportunities)} Lateral Movement Opportunities:[/bold]"
        )

        # Display opportunities
        for i, opp in enumerate(opportunities[:10], 1):  # Show top 10
            detect_color = {
                "easy": "green",
                "medium": "yellow",
                "hard": "red",
            }.get(opp.detection_difficulty, "white")

            console.print(f"\n[bold cyan]Opportunity {i}:[/bold cyan]")
            console.print(f"  From: {opp.from_asset}")
            console.print(f"  To: {opp.to_asset}")
            console.print(f"  Type: {opp.movement_type}")
            console.print(
                f"  Detection: [{detect_color}]{opp.detection_difficulty.upper()}[/{detect_color}]"
            )
            console.print(f"  Path Length: {opp.path.path_length} steps")

            if opp.vulnerabilities:
                console.print(f"  CVEs: {', '.join(opp.vulnerabilities[:3])}")

        # Save to JSON
        if output:
            movement_data = [
                {
                    "from_asset": o.from_asset,
                    "to_asset": o.to_asset,
                    "movement_type": o.movement_type,
                    "detection_difficulty": o.detection_difficulty,
                    "vulnerabilities": o.vulnerabilities,
                    "network_requirements": o.network_requirements,
                    "prerequisites": o.prerequisites,
                    "path": {
                        "entry_point": o.path.entry_point,
                        "target": o.path.target,
                        "length": o.path.path_length,
                    },
                }
                for o in opportunities
            ]

            with open(output, "w") as f:
                json.dump(
                    {
                        "total_opportunities": len(opportunities),
                        "lateral_movements": movement_data,
                    },
                    f,
                    indent=2,
                )

            console.print(
                f"\n[green]✓[/green] Saved {len(opportunities)} opportunities to: {output}"
            )

    except Exception as e:
        console.print(f"[red]✗[/red] Error identifying lateral movement: {e}")
        logger.exception("Error identifying lateral movement")
        raise typer.Exit(code=1)


@app.command(name="attack-surface")
def attack_surface(
    graph_file: Path = typer.Argument(
        ...,
        help="Path to graph file (.graphml)",
        exists=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "-o",
        "--output",
        help="Save results to JSON file",
    ),
    max_paths: int = typer.Option(
        50,
        "--max-paths",
        help="Maximum paths to analyze",
    ),
):
    """
    Comprehensive attack surface analysis.

    Combines attack path discovery, privilege escalation detection, and
    lateral movement identification into a complete security assessment.
    """
    console.print(f"[cyan]Loading graph: {graph_file}[/cyan]")

    try:
        # Load graph
        client = NetworkXClient()
        client.load(str(graph_file))

        analyzer = GraphAnalyzer(client)

        # Analyze attack surface
        with console.status("[bold green]Analyzing attack surface..."):
            attack_surface = analyzer.analyze_attack_surface(max_paths=max_paths)

        # Display results
        console.print("\n[bold]Attack Surface Analysis Results:[/bold]")
        console.print(
            f"  Total Risk Score: [red]{attack_surface.total_risk_score:.1f}/100[/red]"
        )
        console.print(f"\n  Entry Points: {len(attack_surface.entry_points)}")
        console.print(f"  High-Value Targets: {len(attack_surface.high_value_targets)}")
        console.print(f"  Attack Paths: {len(attack_surface.attack_paths)}")
        console.print(
            f"  Privilege Escalations: {len(attack_surface.privilege_escalations)}"
        )
        console.print(f"  Lateral Movements: {len(attack_surface.lateral_movements)}")

        # Show threat distribution
        if attack_surface.attack_paths:
            console.print("\n[bold]Threat Distribution:[/bold]")
            threat_counts = {}
            for path in attack_surface.attack_paths:
                threat_counts[path.threat_level.value] = (
                    threat_counts.get(path.threat_level.value, 0) + 1
                )

            for level in ["critical", "high", "medium", "low"]:
                count = threat_counts.get(level, 0)
                if count > 0:
                    color = {
                        "critical": "red",
                        "high": "bright_red",
                        "medium": "yellow",
                        "low": "blue",
                    }.get(level, "white")
                    console.print(
                        f"  [{color}]{level.upper()}[/{color}]: {count} paths"
                    )

        # Show recommendations
        if attack_surface.recommendations:
            console.print("\n[bold]Security Recommendations:[/bold]")
            for i, rec in enumerate(attack_surface.recommendations[:10], 1):
                console.print(f"  {i}. {rec}")

        # Save to JSON
        if output:
            surface_data = {
                "total_risk_score": attack_surface.total_risk_score,
                "entry_points": attack_surface.entry_points,
                "high_value_targets": attack_surface.high_value_targets,
                "attack_paths": [
                    {
                        "path_id": p.path_id,
                        "threat_level": p.threat_level.value,
                        "total_cvss": p.total_cvss,
                        "path_length": p.path_length,
                        "exploitability": p.exploitability,
                        "entry_point": p.entry_point,
                        "target": p.target,
                    }
                    for p in attack_surface.attack_paths
                ],
                "privilege_escalations": [
                    {
                        "from_privilege": e.from_privilege,
                        "to_privilege": e.to_privilege,
                        "difficulty": e.difficulty,
                        "vulnerabilities": e.vulnerabilities,
                    }
                    for e in attack_surface.privilege_escalations
                ],
                "lateral_movements": [
                    {
                        "from_asset": m.from_asset,
                        "to_asset": m.to_asset,
                        "movement_type": m.movement_type,
                        "detection_difficulty": m.detection_difficulty,
                    }
                    for m in attack_surface.lateral_movements
                ],
                "recommendations": attack_surface.recommendations,
            }

            with open(output, "w") as f:
                json.dump(surface_data, f, indent=2)

            console.print(f"\n[green]✓[/green] Saved complete analysis to: {output}")

    except Exception as e:
        console.print(f"[red]✗[/red] Error analyzing attack surface: {e}")
        logger.exception("Error analyzing attack surface")
        raise typer.Exit(code=1)


@app.command()
def centrality(
    graph_file: Path = typer.Argument(
        ...,
        help="Path to graph file (.graphml)",
        exists=True,
    ),
    metric: str = typer.Option(
        "betweenness",
        "--metric",
        "-m",
        help="Centrality metric (degree, betweenness, closeness, pagerank, eigenvector)",
    ),
    top: int = typer.Option(
        10,
        "--top",
        "-n",
        help="Show top N nodes",
    ),
    node_type: Optional[str] = typer.Option(
        None,
        "--node-type",
        help="Filter by node type (package, vulnerability, container)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "-o",
        "--output",
        help="Save results to JSON file",
    ),
):
    """
    Calculate centrality metrics to identify critical nodes.

    Centrality metrics identify the most important or influential nodes
    in the vulnerability graph based on their position and connections.
    """
    console.print(f"[cyan]Loading graph: {graph_file}[/cyan]")

    try:
        # Load graph
        client = NetworkXClient()
        client.load(str(graph_file))

        # Initialize analytics engine
        analytics = GraphAnalytics(client)

        # Parse metric
        try:
            centrality_metric = CentralityMetric(metric.lower())
        except ValueError:
            console.print(f"[red]✗[/red] Invalid metric: {metric}")
            console.print(
                "[yellow]Valid metrics:[/yellow] degree, betweenness, closeness, pagerank, eigenvector"
            )
            raise typer.Exit(code=1)

        # Calculate centrality
        with console.status(f"[bold green]Calculating {metric} centrality..."):
            result = analytics.calculate_centrality(
                metric=centrality_metric,
                top_n=top,
                node_type_filter=node_type,
            )

        # Display results
        console.print(
            f"\n[bold]Top {len(result.nodes)} Nodes by {metric.capitalize()} Centrality:[/bold]"
        )
        console.print(f"[dim]Total nodes analyzed: {result.total_nodes}[/dim]")
        console.print(f"[dim]Average score: {result.avg_score:.4f}[/dim]\n")

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Rank", justify="right", style="dim")
        table.add_column("Node ID", style="yellow")
        table.add_column("Type", style="cyan")
        table.add_column("Score", justify="right", style="green")
        table.add_column("Details", style="dim")

        for node in result.nodes:
            # Extract useful details
            details_parts = []
            if node.node_type == "package":
                name = node.properties.get("name", "")
                version = node.properties.get("version", "")
                if name:
                    details_parts.append(f"{name}@{version}")
            elif node.node_type == "vulnerability":
                severity = node.properties.get("severity", "")
                cvss = node.properties.get("cvss_score")
                if severity:
                    details_parts.append(f"{severity.upper()}")
                if cvss:
                    details_parts.append(f"CVSS: {cvss}")

            details = " | ".join(details_parts) if details_parts else "-"

            table.add_row(
                str(node.rank),
                node.node_id,
                node.node_type,
                f"{node.score:.4f}",
                details,
            )

        console.print(table)

        # Show interpretation
        console.print("\n[bold]Interpretation:[/bold]")
        if centrality_metric == CentralityMetric.BETWEENNESS:
            console.print("  • High betweenness = critical 'bridge' nodes")
            console.print("  • Vulnerabilities here have wide blast radius")
        elif centrality_metric == CentralityMetric.DEGREE:
            console.print("  • High degree = highly connected nodes")
            console.print("  • Widely used packages or multi-package CVEs")
        elif centrality_metric == CentralityMetric.CLOSENESS:
            console.print("  • High closeness = can quickly reach other nodes")
            console.print("  • Vulnerabilities that spread rapidly")
        elif centrality_metric == CentralityMetric.PAGERANK:
            console.print(
                "  • High PageRank = important based on connections' importance"
            )
            console.print("  • Critical nodes in dependency chains")

        # Save to JSON if requested
        if output:
            output_data = {
                "metric": metric,
                "total_nodes": result.total_nodes,
                "avg_score": result.avg_score,
                "max_score": result.max_score,
                "min_score": result.min_score,
                "top_nodes": [
                    {
                        "rank": node.rank,
                        "node_id": node.node_id,
                        "node_type": node.node_type,
                        "score": node.score,
                        "properties": node.properties,
                    }
                    for node in result.nodes
                ],
            }

            with open(output, "w") as f:
                json.dump(output_data, f, indent=2)

            console.print(f"\n[green]✓[/green] Saved results to: {output}")

    except Exception as e:
        console.print(f"[red]✗[/red] Error calculating centrality: {e}")
        logger.exception("Error calculating centrality")
        raise typer.Exit(code=1)


@app.command()
def communities(
    graph_file: Path = typer.Argument(
        ...,
        help="Path to graph file (.graphml)",
        exists=True,
    ),
    algorithm: str = typer.Option(
        "greedy_modularity",
        "--algorithm",
        "-a",
        help="Community detection algorithm (greedy_modularity, label_propagation, louvain)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "-o",
        "--output",
        help="Save results to JSON file",
    ),
    top: int = typer.Option(
        10,
        "--top",
        "-n",
        help="Show top N largest communities",
    ),
):
    """
    Detect communities (clusters) of related nodes.

    Community detection identifies groups of nodes that are more densely
    connected to each other than to the rest of the graph.
    """
    console.print(f"[cyan]Loading graph: {graph_file}[/cyan]")

    try:
        # Load graph
        client = NetworkXClient()
        client.load(str(graph_file))

        # Initialize analytics engine
        analytics = GraphAnalytics(client)

        # Parse algorithm
        try:
            community_algorithm = CommunityAlgorithm(algorithm.lower())
        except ValueError:
            console.print(f"[red]✗[/red] Invalid algorithm: {algorithm}")
            console.print(
                "[yellow]Valid algorithms:[/yellow] greedy_modularity, label_propagation, louvain"
            )
            raise typer.Exit(code=1)

        # Detect communities
        with console.status(f"[bold green]Detecting communities using {algorithm}..."):
            result = analytics.detect_communities(algorithm=community_algorithm)

        # Display results
        console.print(
            f"\n[bold]Detected {result.total_communities} Communities:[/bold]"
        )
        console.print(f"[dim]Modularity score: {result.modularity:.3f}[/dim]")
        console.print(f"[dim]Coverage: {result.coverage:.1%}[/dim]\n")

        # Show top N communities
        top_communities = result.get_largest_communities(n=top)

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("ID", justify="right", style="cyan")
        table.add_column("Size", justify="right", style="yellow")
        table.add_column("Density", justify="right", style="green")
        table.add_column("Description", style="white")
        table.add_column("Avg CVSS", justify="right", style="red")
        table.add_column("Node Types", style="dim")

        for comm in top_communities:
            avg_cvss_str = f"{comm.avg_cvss:.1f}" if comm.avg_cvss else "N/A"

            # Format node types
            node_types_str = ", ".join(
                f"{k}: {v}"
                for k, v in sorted(
                    comm.node_types.items(), key=lambda x: x[1], reverse=True
                )
            )

            table.add_row(
                str(comm.community_id),
                str(comm.size),
                f"{comm.density:.2f}",
                comm.description,
                avg_cvss_str,
                node_types_str,
            )

        console.print(table)

        # Show interpretation
        console.print("\n[bold]Interpretation:[/bold]")
        console.print("  • Communities represent tightly coupled asset groups")
        console.print("  • High-risk communities have high avg CVSS scores")
        console.print("  • Vulnerabilities in same community spread easily")
        console.print("  • Fix entire communities together for maximum impact")

        # Save to JSON if requested
        if output:
            output_data = {
                "algorithm": algorithm,
                "total_communities": result.total_communities,
                "modularity": result.modularity,
                "coverage": result.coverage,
                "communities": [
                    {
                        "community_id": comm.community_id,
                        "size": comm.size,
                        "density": comm.density,
                        "description": comm.description,
                        "avg_cvss": comm.avg_cvss,
                        "node_types": comm.node_types,
                        "nodes": list(comm.nodes),
                    }
                    for comm in result.communities
                ],
            }

            with open(output, "w") as f:
                json.dump(output_data, f, indent=2)

            console.print(
                f"\n[green]✓[/green] Saved {len(result.communities)} communities to: {output}"
            )

    except Exception as e:
        console.print(f"[red]✗[/red] Error detecting communities: {e}")
        logger.exception("Error detecting communities")
        raise typer.Exit(code=1)


@app.command()
def propagation(
    graph_file: Path = typer.Argument(
        ...,
        help="Path to graph file (.graphml)",
        exists=True,
    ),
    cve: str = typer.Option(
        ...,
        "--cve",
        help="CVE ID to analyze (e.g., CVE-2023-1234)",
    ),
    max_depth: int = typer.Option(
        10,
        "--max-depth",
        help="Maximum propagation depth to trace",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "-o",
        "--output",
        help="Save results to JSON file",
    ),
):
    """
    Analyze how a vulnerability propagates through dependencies.

    Traces vulnerability propagation paths from the source CVE through
    affected packages and containers, showing the full infection chain.
    """
    console.print(f"[cyan]Loading graph: {graph_file}[/cyan]")

    try:
        # Load graph
        client = NetworkXClient()
        client.load(str(graph_file))

        # Initialize analytics engine
        analytics = GraphAnalytics(client)

        # Analyze propagation
        with console.status(f"[bold green]Tracing propagation for {cve}..."):
            result = analytics.analyze_vulnerability_propagation(
                cve, max_depth=max_depth
            )

        # Display results
        console.print(f"\n[bold]Vulnerability Propagation Analysis: {cve}[/bold]\n")

        # Summary stats
        stats_table = Table(show_header=False, box=None)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="yellow")

        stats_table.add_row("Total Affected Nodes", str(result.total_affected_nodes))
        stats_table.add_row("Affected Packages", str(len(result.affected_packages)))
        stats_table.add_row("Affected Containers", str(len(result.affected_containers)))
        stats_table.add_row("Max Propagation Depth", str(result.max_depth))
        stats_table.add_row("Infection Score", f"{result.infection_score:.1f}/100")

        console.print(stats_table)

        # Show direct vs transitive impact
        console.print(f"\n[bold]Impact Breakdown:[/bold]")
        console.print(f"  • Direct impact: {result.get_direct_impact()} packages")
        console.print(
            f"  • Transitive impact: {result.get_transitive_impact()} downstream nodes"
        )

        # Show critical path if found
        if result.critical_path:
            console.print(f"\n[bold]Critical Propagation Path:[/bold]")
            for step in result.critical_path[:5]:  # Show first 5 steps
                depth_prefix = "  " * step.depth
                cvss_str = f" (CVSS: {step.cvss_score})" if step.cvss_score else ""
                console.print(
                    f"{depth_prefix}→ {step.node_type}: {step.node_id}{cvss_str}"
                )

        # Show sample propagation paths
        if result.propagation_paths:
            console.print(
                f"\n[bold]Sample Propagation Paths ({len(result.propagation_paths)} total):[/bold]"
            )
            for i, path in enumerate(result.propagation_paths[:3], 1):
                console.print(f"\n  Path {i} ({len(path)} steps):")
                for step in path[:4]:  # Show first 4 steps of each path
                    console.print(f"    {step.depth}. {step.node_type}: {step.node_id}")
                if len(path) > 4:
                    console.print(f"    ... ({len(path) - 4} more steps)")

        # Risk assessment
        console.print(f"\n[bold]Risk Assessment:[/bold]")
        if result.infection_score > 75:
            console.print("  [red]CRITICAL[/red] - Very high propagation risk")
        elif result.infection_score > 50:
            console.print(
                "  [bright_red]HIGH[/bright_red] - Significant propagation risk"
            )
        elif result.infection_score > 25:
            console.print("  [yellow]MEDIUM[/yellow] - Moderate propagation risk")
        else:
            console.print("  [blue]LOW[/blue] - Limited propagation risk")

        # Save to JSON if requested
        if output:
            output_data = {
                "cve_id": result.cve_id,
                "total_affected_nodes": result.total_affected_nodes,
                "affected_packages": result.affected_packages,
                "affected_containers": result.affected_containers,
                "max_depth": result.max_depth,
                "infection_score": result.infection_score,
                "direct_impact": result.get_direct_impact(),
                "transitive_impact": result.get_transitive_impact(),
                "propagation_paths": [
                    [
                        {
                            "node_id": step.node_id,
                            "node_type": step.node_type,
                            "depth": step.depth,
                            "cvss_score": step.cvss_score,
                        }
                        for step in path
                    ]
                    for path in result.propagation_paths
                ],
            }

            with open(output, "w") as f:
                json.dump(output_data, f, indent=2)

            console.print(f"\n[green]✓[/green] Saved propagation analysis to: {output}")

    except ValueError as e:
        console.print(f"[red]✗[/red] {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]✗[/red] Error analyzing propagation: {e}")
        logger.exception("Error analyzing propagation")
        raise typer.Exit(code=1)


@app.command()
def metrics(
    graph_file: Path = typer.Argument(
        ...,
        help="Path to graph file (.graphml)",
        exists=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "-o",
        "--output",
        help="Save results to JSON file",
    ),
):
    """
    Calculate comprehensive graph topology and health metrics.

    Provides overall security posture assessment through various
    graph theory metrics and vulnerability distribution analysis.
    """
    console.print(f"[cyan]Loading graph: {graph_file}[/cyan]")

    try:
        # Load graph
        client = NetworkXClient()
        client.load(str(graph_file))

        # Initialize analytics engine
        analytics = GraphAnalytics(client)

        # Calculate metrics
        with console.status("[bold green]Calculating graph metrics..."):
            result = analytics.calculate_graph_metrics()

        # Display results
        console.print("\n[bold]Graph Topology Metrics:[/bold]\n")

        # Basic structure
        structure_table = Table(
            title="Graph Structure", show_header=True, header_style="bold cyan"
        )
        structure_table.add_column("Metric", style="cyan")
        structure_table.add_column("Value", justify="right", style="yellow")

        structure_table.add_row("Total Nodes", str(result.total_nodes))
        structure_table.add_row("Total Edges", str(result.total_edges))
        structure_table.add_row("Graph Density", f"{result.density:.3f}")
        structure_table.add_row("Avg Node Degree", f"{result.avg_degree:.2f}")
        structure_table.add_row("Avg Clustering", f"{result.avg_clustering:.3f}")

        console.print(structure_table)

        # Connectivity
        console.print()
        connectivity_table = Table(
            title="Connectivity", show_header=True, header_style="bold cyan"
        )
        connectivity_table.add_column("Metric", style="cyan")
        connectivity_table.add_column("Value", justify="right", style="yellow")

        connectivity_table.add_row(
            "Connected Components", str(result.connected_components)
        )
        connectivity_table.add_row(
            "Largest Component Size", str(result.largest_component_size)
        )
        connectivity_table.add_row("Avg Path Length", f"{result.avg_path_length:.2f}")
        connectivity_table.add_row("Graph Diameter", str(result.diameter))

        console.print(connectivity_table)

        # Security metrics
        console.print()
        security_table = Table(
            title="Security Metrics", show_header=True, header_style="bold cyan"
        )
        security_table.add_column("Metric", style="cyan")
        security_table.add_column("Value", justify="right", style="yellow")

        security_table.add_row(
            "Vulnerability Concentration", f"{result.vulnerability_concentration:.3f}"
        )
        security_table.add_row("Critical Node Count", str(result.critical_node_count))
        security_table.add_row(
            "Security Score", f"[bold]{result.security_score:.1f}/100[/bold]"
        )

        console.print(security_table)

        # Interpretation
        console.print("\n[bold]Interpretation:[/bold]")

        # Density interpretation
        if result.density > 0.5:
            console.print(
                "  • [yellow]High density[/yellow] - Highly interconnected (vulnerabilities spread easily)"
            )
        elif result.density > 0.2:
            console.print("  • [blue]Moderate density[/blue] - Balanced connectivity")
        else:
            console.print(
                "  • [green]Low density[/green] - Sparse connections (better isolation)"
            )

        # Clustering interpretation
        if result.avg_clustering > 0.5:
            console.print(
                "  • [yellow]High clustering[/yellow] - Assets form tight groups"
            )
        else:
            console.print(
                "  • [green]Low clustering[/green] - Assets are well distributed"
            )

        # Security score interpretation
        if result.security_score >= 70:
            console.print(
                "  • [green]Good security posture[/green] - Low risk of widespread impact"
            )
        elif result.security_score >= 50:
            console.print(
                "  • [yellow]Moderate security posture[/yellow] - Some isolation concerns"
            )
        else:
            console.print(
                "  • [red]Poor security posture[/red] - High risk of cascading failures"
            )

        # Recommendations
        console.print("\n[bold]Recommendations:[/bold]")
        if result.density > 0.5:
            console.print("  • Consider breaking tight dependencies")
        if result.critical_node_count > result.total_nodes * 0.1:
            console.print("  • Focus on securing critical bottleneck nodes")
        if result.vulnerability_concentration > 0.7:
            console.print(
                "  • Vulnerabilities are concentrated - target high-risk packages"
            )

        # Save to JSON if requested
        if output:
            with open(output, "w") as f:
                json.dump(result.to_dict(), f, indent=2)

            console.print(f"\n[green]✓[/green] Saved metrics to: {output}")

    except Exception as e:
        console.print(f"[red]✗[/red] Error calculating metrics: {e}")
        logger.exception("Error calculating metrics")
        raise typer.Exit(code=1)


@app.command()
def validate(
    graph_file: Path = typer.Argument(
        ...,
        help="Path to graph file (.graphml)",
        exists=True,
    ),
    show_all: bool = typer.Option(
        False,
        "--all",
        help="Show all issues including info-level",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "-o",
        "--output",
        help="Save validation report to JSON file",
    ),
):
    """
    Validate graph data quality and structure.

    Checks for common data quality issues:
    - Missing node types or edge types
    - Assets disconnected from packages (no CONTAINS edges)
    - Packages disconnected from vulnerabilities
    - Missing vulnerability attributes
    - Orphaned nodes
    - End-to-end connectivity issues

    Returns exit code 1 if critical issues are found.
    """
    console.print(f"[cyan]🔍 Validating graph: {graph_file}[/cyan]\n")

    try:
        # Load graph
        client = NetworkXClient()
        with console.status("[bold green]Loading graph..."):
            client.load(str(graph_file))

        # Run validation
        validator = GraphValidator(client)

        with console.status("[bold green]Running validation checks..."):
            report = validator.validate_all()

        # Display summary
        console.print(report.summary())
        console.print()

        # Display critical issues
        critical = report.get_issues_by_severity("critical")
        if critical:
            console.print("[red]❌ Critical Issues:[/red]\n")
            for issue in critical:
                console.print(f"{issue}\n")

        # Display warnings
        warnings = report.get_issues_by_severity("warning")
        if warnings:
            console.print("[yellow]⚠️  Warnings:[/yellow]\n")
            for issue in warnings:
                console.print(f"{issue}\n")

        # Display info if requested
        if show_all:
            info = report.get_issues_by_severity("info")
            if info:
                console.print("[cyan]ℹ️  Info:[/cyan]\n")
                for issue in info:
                    console.print(f"{issue}\n")

        # Display statistics
        console.print("\n[bold]Graph Statistics:[/bold]")

        stats_table = Table(show_header=False)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Count", justify="right", style="yellow")

        stats_table.add_row("Total Nodes", str(report.stats.get("total_nodes", 0)))
        stats_table.add_row("Total Edges", str(report.stats.get("total_edges", 0)))

        # Node counts
        for key, value in report.stats.items():
            if key.startswith("nodes_") and key != "nodes_unknown":
                node_type = key.replace("nodes_", "").replace("_", " ").title()
                stats_table.add_row(f"  {node_type}", str(value))

        stats_table.add_row("", "")  # Separator

        # Edge counts - highlight key edges
        for edge_type in [
            "CONTAINS",
            "HAS_VULNERABILITY",
            "COMMUNICATES_WITH",
            "DEPENDS_ON",
        ]:
            key = f"edges_{edge_type}"
            count = report.stats.get(key, 0)
            style = "green" if count > 0 else "red"
            stats_table.add_row(f"  {edge_type} Edges", f"[{style}]{count}[/{style}]")

        console.print(stats_table)

        # Save report if requested
        if output:
            report_data = {
                "graph_file": str(graph_file),
                "validation_summary": {
                    "critical": len(critical),
                    "warnings": len(warnings),
                    "info": len(report.get_issues_by_severity("info")),
                },
                "issues": [
                    {
                        "severity": issue.severity.value,
                        "category": issue.category,
                        "message": issue.message,
                        "affected_items": issue.affected_items,
                        "suggestion": issue.suggestion,
                    }
                    for issue in report.issues
                ],
                "stats": report.stats,
            }

            with open(output, "w") as f:
                json.dump(report_data, f, indent=2)

            console.print(f"\n[green]✓[/green] Validation report saved to: {output}")

        # Exit with error if critical issues found
        if report.has_critical_issues():
            console.print("\n[red]⚠️  Graph has critical data quality issues![/red]")
            console.print(
                "[yellow]These issues may prevent correct attack path analysis and vulnerability attribution.[/yellow]"
            )
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]✗[/red] Error validating graph: {e}")
        logger.exception("Error validating graph")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
