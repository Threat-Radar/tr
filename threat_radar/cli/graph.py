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
                entry_points=entry_points,
                targets=targets,
                max_length=max_length
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
            console.print(f"  Threat Level: [{threat_color}]{path.threat_level.value.upper()}[/{threat_color}]")
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
                            "type": s.step_type.value,
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
                json.dump({
                    "total_paths": len(attack_paths),
                    "entry_points": entry_points,
                    "targets": targets,
                    "attack_paths": attack_paths_data
                }, f, indent=2)

            console.print(f"\n[green]✓[/green] Saved {len(attack_paths)} paths to: {output}")

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

        console.print(f"\n[bold]Found {len(escalation_paths)} Privilege Escalation Paths:[/bold]")

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
            console.print(f"  Difficulty: [{diff_color}]{esc.difficulty.upper()}[/{diff_color}]")
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
                json.dump({
                    "total_escalations": len(escalation_paths),
                    "privilege_escalations": escalation_data
                }, f, indent=2)

            console.print(f"\n[green]✓[/green] Saved {len(escalation_paths)} escalations to: {output}")

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
        with console.status("[bold green]Identifying lateral movement opportunities..."):
            opportunities = analyzer.identify_lateral_movement_opportunities(
                max_opportunities=max_opportunities
            )

        if not opportunities:
            console.print("[yellow]No lateral movement opportunities found[/yellow]")
            return

        console.print(f"\n[bold]Found {len(opportunities)} Lateral Movement Opportunities:[/bold]")

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
            console.print(f"  Detection: [{detect_color}]{opp.detection_difficulty.upper()}[/{detect_color}]")
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
                json.dump({
                    "total_opportunities": len(opportunities),
                    "lateral_movements": movement_data
                }, f, indent=2)

            console.print(f"\n[green]✓[/green] Saved {len(opportunities)} opportunities to: {output}")

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
        console.print(f"  Total Risk Score: [red]{attack_surface.total_risk_score:.1f}/100[/red]")
        console.print(f"\n  Entry Points: {len(attack_surface.entry_points)}")
        console.print(f"  High-Value Targets: {len(attack_surface.high_value_targets)}")
        console.print(f"  Attack Paths: {len(attack_surface.attack_paths)}")
        console.print(f"  Privilege Escalations: {len(attack_surface.privilege_escalations)}")
        console.print(f"  Lateral Movements: {len(attack_surface.lateral_movements)}")

        # Show threat distribution
        if attack_surface.attack_paths:
            console.print("\n[bold]Threat Distribution:[/bold]")
            threat_counts = {}
            for path in attack_surface.attack_paths:
                threat_counts[path.threat_level.value] = threat_counts.get(path.threat_level.value, 0) + 1

            for level in ["critical", "high", "medium", "low"]:
                count = threat_counts.get(level, 0)
                if count > 0:
                    color = {
                        "critical": "red",
                        "high": "bright_red",
                        "medium": "yellow",
                        "low": "blue",
                    }.get(level, "white")
                    console.print(f"  [{color}]{level.upper()}[/{color}]: {count} paths")

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


if __name__ == "__main__":
    app()
