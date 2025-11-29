"""SBOM generation and analysis commands using Syft."""

from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..core.sbom_operations import (
    SBOMGenerator,
    SBOMReader,
    SBOMComparator,
    SBOMAnalyzer,
    SBOMExporter,
    SBOMStorageManager,
)
from ..utils.sbom_utils import (
    display_sbom_summary,
    display_packages_table,
    display_components_summary,
    display_detailed_components,
    display_components_grouped_by_type,
    display_components_grouped_by_language,
)

app = typer.Typer(help="SBOM generation and analysis")
console = Console()


@app.command("generate")
def generate(
    path: Path = typer.Argument(..., help="Directory or file to scan"),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file path"
    ),
    format: str = typer.Option(
        "cyclonedx-json",
        "--format",
        "-f",
        help="SBOM format (cyclonedx-json, spdx-json, syft-json)",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output"),
    auto_save: bool = typer.Option(
        False, "--auto-save", help="Auto-save to sbom_storage/local/ with timestamp"
    ),
):
    """
    Generate SBOM from a local directory or file.

    Supports all major package ecosystems (Python, Node.js, Go, Rust, Java, etc.)
    """
    try:
        generator = SBOMGenerator()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Scanning {path}...", total=None)

            result = generator.generate_from_path(
                path=path,
                format=format,
                output=output,
                auto_save=auto_save,
            )

            progress.update(task, completed=True, description="Scan complete!")

        # Display results
        if isinstance(result.sbom_data, dict):
            display_sbom_summary(result.sbom_data, result.source, console)

            if result.output_path:
                console.print(f"\n[green]SBOM saved to {result.output_path}[/green]")
        else:
            # Text format output
            console.print(result.sbom_data)
            if result.output_path:
                console.print(f"\n[green]SBOM saved to {result.output_path}[/green]")

    except (ValueError, RuntimeError) as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("docker")
def docker_scan(
    image: str = typer.Argument(..., help="Docker image to scan (e.g., 'alpine:3.18')"),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file path"
    ),
    format: str = typer.Option("cyclonedx-json", "--format", "-f", help="SBOM format"),
    scope: str = typer.Option(
        "squashed", "--scope", "-s", help="Image scope (squashed, all-layers)"
    ),
    auto_save: bool = typer.Option(
        False, "--auto-save", help="Auto-save to sbom_storage/docker/ with timestamp"
    ),
):
    """
    Generate SBOM from a Docker image.

    Scans container images for all installed packages across all ecosystems.
    """
    try:
        generator = SBOMGenerator()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Scanning Docker image {image}...", total=None)

            result = generator.generate_from_docker(
                image=image,
                format=format,
                scope=scope,
                output=output,
                auto_save=auto_save,
            )

            progress.update(task, completed=True, description="Scan complete!")

        display_sbom_summary(result.sbom_data, result.source, console)

        if result.output_path:
            console.print(f"\n[green]SBOM saved to {result.output_path}[/green]")

    except RuntimeError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("read")
def read(
    sbom_path: Path = typer.Argument(..., exists=True, help="Path to SBOM file"),
    format: str = typer.Option(
        "table", "--format", "-f", help="Display format (table, json, summary)"
    ),
    filter: Optional[str] = typer.Option(
        None, "--filter", help="Filter packages by name"
    ),
):
    """
    Read and display an existing SBOM file.

    Supports CycloneDX, SPDX, and Syft JSON formats.
    """
    try:
        reader = SBOMReader()
        sbom_data = reader.read_sbom(sbom_path)

        if format == "json":
            console.print_json(data=sbom_data)
        elif format == "summary":
            display_sbom_summary(sbom_data, sbom_path.name, console)
        else:  # table
            packages = reader.get_packages(sbom_data, name_filter=filter)
            display_packages_table(
                packages, console, title=f"Packages in {sbom_path.name}"
            )

            if filter:
                console.print(f"\n[dim]Filtered by: {filter}[/dim]")

    except Exception as e:
        console.print(f"[red]Error reading SBOM: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("compare")
def compare(
    sbom1: Path = typer.Argument(..., exists=True, help="First SBOM file"),
    sbom2: Path = typer.Argument(..., exists=True, help="Second SBOM file"),
    show_versions: bool = typer.Option(
        False, "--versions", "-v", help="Show version changes"
    ),
):
    """
    Compare two SBOM files and show differences.

    Useful for tracking dependency changes between releases.
    """
    try:
        comparator = SBOMComparator()
        result = comparator.compare(sbom1, sbom2, include_versions=show_versions)

        console.print(f"\n[bold cyan]SBOM Comparison[/bold cyan]\n")
        console.print(f"SBOM 1: {result.sbom1_name}")
        console.print(f"SBOM 2: {result.sbom2_name}\n")

        # Summary table
        summary = Table(title="Summary")
        summary.add_column("Category", style="cyan")
        summary.add_column("Count", style="green")

        summary.add_row("Common packages", str(len(result.common)))
        summary.add_row("Added packages", str(len(result.added)))
        summary.add_row("Removed packages", str(len(result.removed)))

        console.print(summary)

        # Show added packages
        if result.added:
            console.print("\n[bold green]Added Packages:[/bold green]")
            for pkg in sorted(result.added):
                console.print(f"  [green]+[/green] {pkg}")

        # Show removed packages
        if result.removed:
            console.print("\n[bold red]Removed Packages:[/bold red]")
            for pkg in sorted(result.removed):
                console.print(f"  [red]-[/red] {pkg}")

        # Show version changes
        if show_versions and result.version_changes:
            console.print("\n[bold yellow]Version Changes:[/bold yellow]")
            for pkg, (old_ver, new_ver) in sorted(result.version_changes.items()):
                console.print(f"  {pkg}: {old_ver} → {new_ver}")

    except Exception as e:
        console.print(f"[red]Error comparing SBOMs: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("stats")
def statistics(
    sbom_path: Path = typer.Argument(..., exists=True, help="Path to SBOM file"),
):
    """
    Show statistics about packages in SBOM.

    Displays package counts by ecosystem and license information.
    """
    try:
        analyzer = SBOMAnalyzer()
        stats = analyzer.get_statistics(sbom_path)

        console.print(f"\n[bold cyan]SBOM Statistics: {sbom_path.name}[/bold cyan]\n")

        # Package type statistics
        table = Table(title="Packages by Type")
        table.add_column("Type", style="cyan")
        table.add_column("Count", style="green")

        for pkg_type, count in sorted(
            stats.package_stats.items(), key=lambda x: x[1], reverse=True
        ):
            table.add_row(pkg_type, str(count))

        console.print(table)

        # License statistics
        if stats.licenses:
            console.print(f"\n[bold]License Summary:[/bold]")
            console.print(f"Total unique licenses: {stats.total_licenses}\n")

            lic_table = Table(title="Top Licenses")
            lic_table.add_column("License", style="cyan")
            lic_table.add_column("Package Count", style="green")

            # Show top 10 licenses
            sorted_licenses = sorted(
                stats.licenses.items(), key=lambda x: len(x[1]), reverse=True
            )
            for lic_name, packages in sorted_licenses[:10]:
                lic_table.add_row(lic_name, str(len(packages)))

            console.print(lic_table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("export")
def export(
    sbom_path: Path = typer.Argument(..., exists=True, help="Path to SBOM file"),
    output: Path = typer.Option(..., "--output", "-o", help="Output file path"),
    format: str = typer.Option(
        "csv", "--format", "-f", help="Export format (csv, requirements)"
    ),
):
    """
    Export SBOM to different formats.

    Supported formats:
    - csv: Comma-separated values
    - requirements: Python requirements.txt format
    """
    try:
        exporter = SBOMExporter()
        exporter.export(sbom_path, output, format)

        console.print(f"[green]{format.upper()} exported to {output}[/green]")

    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("search")
def search(
    sbom_path: Path = typer.Argument(..., exists=True, help="Path to SBOM file"),
    query: str = typer.Argument(..., help="Search term"),
):
    """
    Search for packages in SBOM by name.
    """
    try:
        analyzer = SBOMAnalyzer()
        results = analyzer.search(sbom_path, query)

        if not results:
            console.print(f"[yellow]No packages found matching '{query}'[/yellow]")
            return

        display_packages_table(results, console, title=f"Search Results for '{query}'")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("list")
def list_sboms(
    category: str = typer.Option(
        "all",
        "--category",
        "-c",
        help="Category to list (docker, local, comparisons, archives, all)",
    ),
    limit: Optional[int] = typer.Option(
        None, "--limit", "-n", help="Limit number of results"
    ),
):
    """
    List all stored SBOMs in sbom_storage directory.

    Shows SBOMs organized by category with timestamps and sizes.
    """
    try:
        manager = SBOMStorageManager()
        sboms = manager.list_sboms(category, limit)

        if not sboms:
            console.print(f"[yellow]No SBOMs found in category '{category}'[/yellow]")
            return

        # Display table
        table = Table(title=f"Stored SBOMs ({category})")
        table.add_column("Filename", style="cyan", max_width=60)
        table.add_column("Category", style="magenta")
        table.add_column("Size", style="green")
        table.add_column("Modified", style="blue")

        for sbom_path in sboms:
            metadata = manager.get_sbom_metadata(sbom_path)
            table.add_row(
                metadata["filename"],
                metadata["category"],
                metadata["size_str"],
                metadata["modified"],
            )

        console.print(table)
        console.print(f"\n[dim]Total: {len(sboms)} SBOM(s)[/dim]")

        # Show if limited
        if limit:
            all_sboms = manager.list_sboms(category)
            if len(all_sboms) > limit:
                console.print(
                    f"[dim]Showing {limit} of {len(all_sboms)} total SBOMs[/dim]"
                )

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("components")
def components(
    sbom_path: Path = typer.Argument(..., exists=True, help="Path to SBOM file"),
    type: Optional[str] = typer.Option(
        None, "--type", "-t", help="Filter by type (library, file, os, application)"
    ),
    language: Optional[str] = typer.Option(
        None, "--language", "-l", help="Filter by language (python, javascript, go)"
    ),
    details: bool = typer.Option(
        False, "--details", "-d", help="Show detailed component information"
    ),
    group_by: Optional[str] = typer.Option(
        None, "--group-by", "-g", help="Group by (type, language)"
    ),
    limit: Optional[int] = typer.Option(
        None, "--limit", "-n", help="Limit number of components shown"
    ),
):
    """
    Display all components from SBOM with filtering and grouping options.

    Shows libraries, files, OS packages, and other component types.
    """
    try:
        analyzer = SBOMAnalyzer()
        components_list = analyzer.get_components(
            sbom_path,
            type_filter=type,
            language_filter=language,
            limit=limit,
        )

        if not components_list:
            console.print(f"[yellow]No components found matching the criteria[/yellow]")
            return

        # Display based on grouping
        if group_by == "type":
            from ..utils.sbom_utils import load_sbom

            sbom_data = load_sbom(sbom_path)
            display_components_grouped_by_type(
                sbom_data, components_list, details, console
            )
        elif group_by == "language":
            display_components_grouped_by_language(components_list, details, console)
        elif details:
            display_detailed_components(components_list, console)
        else:
            display_components_summary(components_list, sbom_path.name, console)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)
