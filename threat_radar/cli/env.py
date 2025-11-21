"""Environment configuration CLI commands."""

import json
import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from pydantic import ValidationError

from ..environment import (
    EnvironmentParser,
    EnvironmentGraphBuilder,
    Environment,
)
from ..graph import NetworkXClient, GraphBuilder, GraphAnalyzer, GraphValidator, validate_asset_scan_matching
from ..core import GrypeScanResult, GrypeVulnerability
from ..utils.graph_storage import GraphStorageManager

logger = logging.getLogger(__name__)
console = Console()
app = typer.Typer(help="Environment configuration and business context management")


@app.command()
def validate(
    env_file: Path = typer.Argument(
        ...,
        help="Path to environment configuration file (JSON or YAML)",
        exists=True,
    ),
    show_errors: bool = typer.Option(
        True,
        "--errors/--no-errors",
        help="Show detailed validation errors",
    ),
):
    """
    Validate environment configuration file.

    Checks JSON/YAML syntax and validates against schema using Pydantic.
    """
    console.print(f"[cyan]Validating environment file: {env_file}[/cyan]")

    try:
        # Try to load and validate
        env = EnvironmentParser.load_from_file(env_file)

        console.print("[green]✓ Validation successful![/green]")
        console.print(f"\nEnvironment: {env.environment.name}")
        console.print(f"  Type: {env.environment.type.value}")
        console.print(f"  Assets: {len(env.assets)}")
        console.print(f"  Dependencies: {len(env.dependencies)}")

        # Show risk summary
        risk_scores = env.calculate_total_risk_score()
        console.print(f"\n[bold]Risk Summary:[/bold]")
        console.print(f"  Critical assets: {risk_scores['critical_assets']}")
        console.print(f"  Internet-facing: {risk_scores['internet_facing_assets']}")
        console.print(f"  PCI scope: {risk_scores['pci_scope_assets']}")
        console.print(f"  Risk level: {risk_scores['average_criticality']:.1f}/4.0")

    except ValidationError as e:
        console.print("[red]✗ Validation failed![/red]")

        if show_errors:
            console.print("\n[bold]Validation Errors:[/bold]")
            for error in e.errors():
                loc = " → ".join(str(l) for l in error['loc'])
                console.print(f"\n[yellow]  {loc}[/yellow]")
                console.print(f"    {error['msg']}")
                if 'input' in error:
                    console.print(f"    Input: {error['input']}")

        raise typer.Exit(code=1)

    except Exception as e:
        console.print(f"[red]✗ Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command()
def build_graph(
    env_file: Path = typer.Argument(
        ...,
        help="Path to environment configuration file",
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
    merge_scans: Optional[list[Path]] = typer.Option(
        None,
        "--merge-scan",
        help="Merge with CVE scan results (can be repeated)",
    ),
):
    """
    Build graph from environment configuration.

    Creates infrastructure topology graph with business context.
    Optionally merges with vulnerability scan data.
    """
    console.print(f"[cyan]Building graph from environment: {env_file}[/cyan]")

    try:
        # Load environment
        with console.status("[bold green]Loading environment..."):
            env = EnvironmentParser.load_from_file(env_file)

        console.print(f"[green]✓[/green] Loaded environment: {env.environment.name}")
        console.print(f"  • {len(env.assets)} assets")
        console.print(f"  • {len(env.dependencies)} dependencies")

        # Pre-flight validation: Check asset-scan matching
        if merge_scans:
            console.print(f"\n[cyan]🔍 Running pre-flight validation...[/cyan]")

            # Load environment as dict for validation
            with open(env_file) as f:
                env_dict = json.load(f)

            validation_report = validate_asset_scan_matching(
                env_dict,
                [str(scan) for scan in merge_scans]
            )

            # Display validation results
            for issue in validation_report.issues:
                console.print(f"  {issue}")

            if validation_report.has_critical_issues():
                console.print("\n[red]⚠️  CRITICAL VALIDATION ISSUES DETECTED[/red]")
                console.print("[yellow]The graph will be built but may have missing CONTAINS edges.[/yellow]")
                console.print("[yellow]Attack paths and vulnerability attribution may be incomplete.[/yellow]\n")

        # Build graph
        with console.status("[bold green]Building graph..."):
            client = NetworkXClient()
            builder = EnvironmentGraphBuilder(client)
            builder.build_from_environment(env)

        metadata = client.get_metadata()
        console.print(f"[green]✓[/green] Graph built successfully")
        console.print(f"  • Nodes: {metadata.node_count}")
        console.print(f"  • Edges: {metadata.edge_count}")

        # Merge with scan results if provided
        if merge_scans:
            console.print(f"\n[cyan]Merging with vulnerability scans...[/cyan]")
            vuln_builder = GraphBuilder(client)

            for scan_file in merge_scans:
                console.print(f"  • Loading {scan_file.name}")

                # Load scan JSON
                with open(scan_file) as f:
                    scan_data = json.load(f)

                # Parse into GrypeScanResult
                vulnerabilities = []

                # Support both Grype raw format and Threat Radar simplified format
                if "matches" in scan_data:
                    # Raw Grype format
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
                elif "vulnerabilities" in scan_data:
                    # Threat Radar simplified format
                    for vuln_data in scan_data.get("vulnerabilities", []):
                        # Parse package name and version from "package" field (e.g., "busybox@1.36.1-r7")
                        package_full = vuln_data.get("package", "")
                        if "@" in package_full:
                            package_name, package_version = package_full.split("@", 1)
                        else:
                            package_name = package_full
                            package_version = "unknown"

                        vuln = GrypeVulnerability(
                            id=vuln_data["id"],
                            severity=vuln_data.get("severity", "unknown"),
                            package_name=package_name,
                            package_version=package_version,
                            package_type=vuln_data.get("package_type", "unknown"),
                            fixed_in_version=vuln_data.get("fixed_in"),
                            description=vuln_data.get("description"),
                            cvss_score=vuln_data.get("cvss_score"),
                            urls=vuln_data.get("urls", []),
                            data_source=None,
                            namespace=None,
                        )
                        vulnerabilities.append(vuln)
                else:
                    console.print(f"    [yellow]⚠[/yellow] Unknown scan format in {scan_file.name}")
                    continue

                scan_result = GrypeScanResult(
                    target=scan_data.get("target") or scan_data.get("source", {}).get("target", scan_file.stem),
                    vulnerabilities=vulnerabilities,
                )

                # Merge into existing graph
                vuln_builder.build_from_scan(scan_result)

                # Link packages to assets by matching scan target to asset image
                scan_target = scan_result.target
                matched_assets = []

                for asset in env.assets:
                    if asset.software and asset.software.image:
                        # Match by exact image name or normalized target
                        asset_image = asset.software.image

                        # Normalize both for comparison (handle docker.io prefix, tags, etc.)
                        def normalize_image(img: str) -> str:
                            # Remove docker.io/ prefix
                            img = img.replace("docker.io/", "")
                            # Remove library/ prefix for official images
                            img = img.replace("library/", "")
                            return img.lower()

                        if normalize_image(asset_image) == normalize_image(scan_target):
                            matched_assets.append(asset)

                # Create CONTAINS edges from matched assets to packages
                if matched_assets:
                    for asset in matched_assets:
                        asset_node_id = f"asset:{asset.id}"

                        # Link asset to all packages from this scan
                        for vuln in vulnerabilities:
                            pkg_node_id = f"package:{vuln.package_name}@{vuln.package_version}"

                            # Check if package node exists
                            if client.get_node(pkg_node_id):
                                # Check if edge doesn't already exist
                                existing_edge = None
                                try:
                                    # Try to get existing edge (NetworkX specific)
                                    if hasattr(client.graph, 'get_edge_data'):
                                        existing_edge = client.graph.get_edge_data(asset_node_id, pkg_node_id)
                                except:
                                    pass

                                if not existing_edge:
                                    from ..graph import GraphEdge, EdgeType
                                    client.add_edge(GraphEdge(
                                        source_id=asset_node_id,
                                        target_id=pkg_node_id,
                                        edge_type=EdgeType.CONTAINS,
                                    ))

                    console.print(f"    [green]✓[/green] Linked to {len(matched_assets)} asset(s)")

                console.print(f"    [green]✓[/green] Merged {len(vulnerabilities)} vulnerabilities")

        # Post-build validation: Check graph data quality
        if merge_scans:
            console.print(f"\n[cyan]🔍 Running post-build validation...[/cyan]")

            validator = GraphValidator(client)
            validation_report = validator.validate_all()

            # Show critical issues and warnings
            critical_issues = validation_report.get_issues_by_severity("critical")
            warnings = validation_report.get_issues_by_severity("warning")

            if critical_issues:
                console.print(f"\n[red]❌ Critical Issues Found:[/red]")
                for issue in critical_issues:
                    console.print(f"  {issue}")

            if warnings:
                console.print(f"\n[yellow]⚠️  Warnings:[/yellow]")
                for issue in warnings[:3]:  # Show first 3 warnings
                    console.print(f"  {issue}")
                if len(warnings) > 3:
                    console.print(f"  ... and {len(warnings) - 3} more warnings")

            if not critical_issues and not warnings:
                console.print(f"  [green]✅ Graph validation passed - all data quality checks OK[/green]")

            # Show key stats
            contains_edges = validation_report.stats.get('edges_CONTAINS', 0)
            has_vuln_edges = validation_report.stats.get('edges_HAS_VULNERABILITY', 0)
            console.print(f"\n  Graph Quality Metrics:")
            console.print(f"    • CONTAINS edges: {contains_edges}")
            console.print(f"    • HAS_VULNERABILITY edges: {has_vuln_edges}")

        # Calculate risk scores
        console.print(f"\n[bold]Risk Assessment:[/bold]")
        risk_scores = builder.calculate_risk_scores(env)

        # Show top risk assets
        sorted_risks = sorted(
            risk_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]

        table = Table(title="Top Risk Assets")
        table.add_column("Asset", style="cyan")
        table.add_column("Risk Score", justify="right", style="yellow")

        for asset_id, score in sorted_risks:
            asset = env.get_asset(asset_id)
            risk_indicator = "🔴" if score >= 80 else "🟠" if score >= 60 else "🟡"
            table.add_row(
                f"{asset.name} ({asset.type.value})",
                f"{score:.0f}/100 {risk_indicator}"
            )

        console.print(table)

        # Save graph
        if auto_save:
            storage = GraphStorageManager()
            saved_path = storage.save_graph(
                client,
                f"{env.environment.name}-environment",
                metadata={
                    "source": str(env_file),
                    "environment": env.environment.name,
                    "environment_type": env.environment.type.value,
                    "asset_count": len(env.assets),
                    **metadata.node_type_counts,
                }
            )
            console.print(f"\n[green]✓[/green] Saved to storage: {saved_path.name}")

        if output:
            client.save(str(output))
            console.print(f"[green]✓[/green] Saved to: {output}")

        if not auto_save and not output:
            console.print("\n[yellow]⚠[/yellow] Graph not saved (use --output or --auto-save)")

    except Exception as e:
        console.print(f"[red]✗[/red] Error building graph: {e}")
        logger.exception("Error building graph from environment")
        raise typer.Exit(code=1)


@app.command()
def analyze(
    env_file: Path = typer.Argument(
        ...,
        help="Path to environment configuration file",
        exists=True,
    ),
):
    """
    Analyze environment risk and compliance posture.

    Shows business context, risk assessment, and compliance status.
    """
    console.print(f"[cyan]Analyzing environment: {env_file}[/cyan]\n")

    try:
        env = EnvironmentParser.load_from_file(env_file)

        # Environment summary
        console.print(f"[bold]Environment: {env.environment.name}[/bold]")
        console.print(f"  Type: {env.environment.type.value}")
        if env.environment.cloud_provider:
            console.print(f"  Provider: {env.environment.cloud_provider.value}")
        if env.environment.region:
            console.print(f"  Region: {env.environment.region}")

        # Asset summary
        console.print(f"\n[bold]Assets:[/bold]")
        console.print(f"  Total: {len(env.assets)}")

        asset_by_type = {}
        for asset in env.assets:
            asset_by_type[asset.type.value] = asset_by_type.get(asset.type.value, 0) + 1

        for asset_type, count in sorted(asset_by_type.items()):
            console.print(f"  • {asset_type}: {count}")

        # Criticality breakdown
        console.print(f"\n[bold]Criticality Breakdown:[/bold]")
        critical = len([a for a in env.assets if a.business_context.criticality.value == "critical"])
        high = len([a for a in env.assets if a.business_context.criticality.value == "high"])
        medium = len([a for a in env.assets if a.business_context.criticality.value == "medium"])
        low = len([a for a in env.assets if a.business_context.criticality.value == "low"])

        console.print(f"  🔴 Critical: {critical}")
        console.print(f"  🟠 High: {high}")
        console.print(f"  🟡 Medium: {medium}")
        console.print(f"  🟢 Low: {low}")

        # Exposure analysis
        console.print(f"\n[bold]Exposure Analysis:[/bold]")
        internet_facing = env.get_internet_facing_assets()
        console.print(f"  Internet-facing assets: {len(internet_facing)}")

        if internet_facing:
            console.print(f"\n  Exposed assets:")
            for asset in internet_facing[:5]:
                criticality_icon = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢"
                }.get(asset.business_context.criticality.value, "⚪")

                console.print(f"    {criticality_icon} {asset.name} ({asset.type.value})")

        # Compliance scope
        console.print(f"\n[bold]Compliance Scope:[/bold]")
        if env.environment.compliance_requirements:
            for req in env.environment.compliance_requirements:
                console.print(f"  • {req.value.upper()}")

        pci_scope = env.get_pci_scope_assets()
        if pci_scope:
            console.print(f"\n  PCI-DSS scope assets: {len(pci_scope)}")

        # Risk summary
        risk_scores = env.calculate_total_risk_score()
        console.print(f"\n[bold]Risk Assessment:[/bold]")
        console.print(f"  Average criticality: {risk_scores['average_criticality']:.2f}/4.0")
        console.print(f"  High-risk percentage: {risk_scores['high_risk_percentage']:.1f}%")

        # Business context
        if env.business_context:
            console.print(f"\n[bold]Business Context:[/bold]")
            if env.business_context.organization:
                console.print(f"  Organization: {env.business_context.organization}")
            if env.business_context.risk_tolerance:
                console.print(f"  Risk tolerance: {env.business_context.risk_tolerance.value}")

    except Exception as e:
        console.print(f"[red]✗[/red] Error analyzing environment: {e}")
        logger.exception("Error analyzing environment")
        raise typer.Exit(code=1)


@app.command()
def template(
    output: Path = typer.Option(
        "environment-template.json",
        "-o",
        "--output",
        help="Output file path",
    ),
):
    """
    Generate environment configuration template.

    Creates a minimal valid environment file to get started.
    """
    console.print("[cyan]Generating environment template...[/cyan]")

    template = EnvironmentParser.generate_template()

    with open(output, 'w') as f:
        json.dump(template, f, indent=2)

    console.print(f"[green]✓[/green] Template created: {output}")
    console.print("\n[bold]Next steps:[/bold]")
    console.print("  1. Edit the template with your infrastructure details")
    console.print(f"  2. Validate: threat-radar env validate {output}")
    console.print(f"  3. Build graph: threat-radar env build-graph {output} --auto-save")


@app.command()
def list_assets(
    env_file: Path = typer.Argument(
        ...,
        help="Path to environment configuration file",
        exists=True,
    ),
    criticality: Optional[str] = typer.Option(
        None,
        "--criticality",
        help="Filter by criticality (critical, high, medium, low)",
    ),
    internet_facing: bool = typer.Option(
        False,
        "--internet-facing",
        help="Show only internet-facing assets",
    ),
):
    """
    List assets in environment configuration.

    Supports filtering by criticality and exposure.
    """
    try:
        env = EnvironmentParser.load_from_file(env_file)

        assets = env.assets

        # Apply filters
        if criticality:
            assets = [
                a for a in assets
                if a.business_context.criticality.value == criticality.lower()
            ]

        if internet_facing:
            internet_facing_ids = {a.id for a in env.get_internet_facing_assets()}
            assets = [a for a in assets if a.id in internet_facing_ids]

        # Display table
        table = Table(title=f"Assets in {env.environment.name}")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Type")
        table.add_column("Criticality")
        table.add_column("Function")
        table.add_column("Exposed")

        for asset in assets:
            criticality_color = {
                "critical": "red",
                "high": "bright_red",
                "medium": "yellow",
                "low": "green",
            }.get(asset.business_context.criticality.value, "white")

            exposed = "✓" if (asset.network and asset.network.public_ip) else ""

            table.add_row(
                asset.id,
                asset.name,
                asset.type.value,
                f"[{criticality_color}]{asset.business_context.criticality.value.upper()}[/{criticality_color}]",
                asset.business_context.function or "",
                exposed
            )

        console.print(table)
        console.print(f"\n[dim]Total: {len(assets)} assets[/dim]")

    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
