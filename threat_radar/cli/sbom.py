"""SBOM generation and analysis commands using Syft."""
from pathlib import Path
from typing import Optional
import json
from datetime import datetime
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..core.syft_integration import SyftClient, SBOMFormat
from ..utils.sbom_utils import (
    save_sbom,
    load_sbom,
    extract_packages,
    compare_sboms,
    get_package_statistics,
    extract_licenses,
    convert_to_csv,
    convert_to_requirements,
    search_packages,
    get_version_changes,
    group_components_by_type,
    extract_component_metadata,
    get_files_by_category,
    get_component_details,
    filter_components_by_language,
    get_language_statistics,
    filter_packages_by_type
)
from ..utils.sbom_storage import (
    get_docker_sbom_path,
    get_local_sbom_path,
    get_comparison_path,
    get_format_extension,
    ensure_storage_directories,
    list_stored_sboms
)

app = typer.Typer(help="SBOM generation and analysis")
console = Console()


@app.command("generate")
def generate(
    path: Path = typer.Argument(..., help="Directory or file to scan"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: str = typer.Option("cyclonedx-json", "--format", "-f", help="SBOM format (cyclonedx-json, spdx-json, syft-json)"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output"),
    auto_save: bool = typer.Option(False, "--auto-save", help="Auto-save to sbom_storage/local/ with timestamp"),
):
    """
    Generate SBOM from a local directory or file.

    Supports all major package ecosystems (Python, Node.js, Go, Rust, Java, etc.)
    """
    if not path.exists():
        console.print(f"[red]Error: Path does not exist: {path}[/red]")
        raise typer.Exit(code=1)

    # Map format string to enum
    format_map = {
        "cyclonedx-json": SBOMFormat.CYCLONEDX_JSON,
        "cyclonedx-xml": SBOMFormat.CYCLONEDX_XML,
        "spdx-json": SBOMFormat.SPDX_JSON,
        "spdx-tag-value": SBOMFormat.SPDX_TAG_VALUE,
        "syft-json": SBOMFormat.SYFT_JSON,
        "table": SBOMFormat.TABLE,
    }

    sbom_format = format_map.get(format)
    if not sbom_format:
        console.print(f"[red]Error: Unsupported format '{format}'[/red]")
        console.print(f"Supported formats: {', '.join(format_map.keys())}")
        raise typer.Exit(code=1)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Scanning {path}...", total=None)

            client = SyftClient()
            sbom_data = client.scan(path, output_format=sbom_format, quiet=True)

            progress.update(task, completed=True, description="Scan complete!")

        # Display results
        if isinstance(sbom_data, dict):
            _display_sbom_summary(sbom_data, path)

            # Determine output path
            if auto_save:
                project_name = path.name if path.is_dir() else path.stem
                file_ext = get_format_extension(format)
                output_path = get_local_sbom_path(project_name, file_ext)
            elif output:
                output_path = output
            else:
                output_path = None

            # Save to file
            if output_path:
                save_sbom(sbom_data, output_path)
                console.print(f"\n[green]SBOM saved to {output_path}[/green]")
        else:
            # Text format output
            console.print(sbom_data)
            if output:
                output.write_text(sbom_data)
                console.print(f"\n[green]SBOM saved to {output}[/green]")

    except RuntimeError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("docker")
def docker_scan(
    image: str = typer.Argument(..., help="Docker image to scan (e.g., 'alpine:3.18')"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: str = typer.Option("cyclonedx-json", "--format", "-f", help="SBOM format"),
    scope: str = typer.Option("squashed", "--scope", "-s", help="Image scope (squashed, all-layers)"),
    auto_save: bool = typer.Option(False, "--auto-save", help="Auto-save to sbom_storage/docker/ with timestamp"),
):
    """
    Generate SBOM from a Docker image.

    Scans container images for all installed packages across all ecosystems.
    """
    format_map = {
        "cyclonedx-json": SBOMFormat.CYCLONEDX_JSON,
        "spdx-json": SBOMFormat.SPDX_JSON,
        "syft-json": SBOMFormat.SYFT_JSON,
    }

    sbom_format = format_map.get(format, SBOMFormat.CYCLONEDX_JSON)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Scanning Docker image {image}...", total=None)

            client = SyftClient()
            sbom_data = client.scan_docker_image(image, output_format=sbom_format, scope=scope)

            progress.update(task, completed=True, description="Scan complete!")

        _display_sbom_summary(sbom_data, image)

        # Determine output path
        if auto_save:
            # Parse image name and tag
            if ':' in image:
                image_name, tag = image.rsplit(':', 1)
            else:
                image_name, tag = image, "latest"

            file_ext = get_format_extension(format)
            output_path = get_docker_sbom_path(image_name, tag, file_ext)
        elif output:
            output_path = output
        else:
            output_path = None

        if output_path:
            save_sbom(sbom_data, output_path)
            console.print(f"\n[green]SBOM saved to {output_path}[/green]")

    except RuntimeError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("read")
def read(
    sbom_path: Path = typer.Argument(..., exists=True, help="Path to SBOM file"),
    format: str = typer.Option("table", "--format", "-f", help="Display format (table, json, summary)"),
    filter: Optional[str] = typer.Option(None, "--filter", help="Filter packages by name"),
):
    """
    Read and display an existing SBOM file.

    Supports CycloneDX, SPDX, and Syft JSON formats.
    """
    try:
        sbom_data = load_sbom(sbom_path)

        if format == "json":
            console.print_json(data=sbom_data)
        elif format == "summary":
            _display_sbom_summary(sbom_data, sbom_path.name)
        else:  # table
            packages = extract_packages(sbom_data)

            if filter:
                packages = [p for p in packages if filter.lower() in p.get("name", "").lower()]

            _display_packages_table(packages, title=f"Packages in {sbom_path.name}")

            if filter:
                console.print(f"\n[dim]Filtered by: {filter}[/dim]")

    except Exception as e:
        console.print(f"[red]Error reading SBOM: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("compare")
def compare(
    sbom1: Path = typer.Argument(..., exists=True, help="First SBOM file"),
    sbom2: Path = typer.Argument(..., exists=True, help="Second SBOM file"),
    show_versions: bool = typer.Option(False, "--versions", "-v", help="Show version changes"),
):
    """
    Compare two SBOM files and show differences.

    Useful for tracking dependency changes between releases.
    """
    try:
        sbom1_data = load_sbom(sbom1)
        sbom2_data = load_sbom(sbom2)

        diff = compare_sboms(sbom1_data, sbom2_data)

        console.print(f"\n[bold cyan]SBOM Comparison[/bold cyan]\n")
        console.print(f"SBOM 1: {sbom1.name}")
        console.print(f"SBOM 2: {sbom2.name}\n")

        # Summary table
        summary = Table(title="Summary")
        summary.add_column("Category", style="cyan")
        summary.add_column("Count", style="green")

        summary.add_row("Common packages", str(len(diff["common"])))
        summary.add_row("Added packages", str(len(diff["added"])))
        summary.add_row("Removed packages", str(len(diff["removed"])))

        console.print(summary)

        # Show added packages
        if diff["added"]:
            console.print("\n[bold green]Added Packages:[/bold green]")
            for pkg in sorted(diff["added"]):
                console.print(f"  [green]+[/green] {pkg}")

        # Show removed packages
        if diff["removed"]:
            console.print("\n[bold red]Removed Packages:[/bold red]")
            for pkg in sorted(diff["removed"]):
                console.print(f"  [red]-[/red] {pkg}")

        # Show version changes
        if show_versions:
            version_changes = get_version_changes(sbom1_data, sbom2_data)
            if version_changes:
                console.print("\n[bold yellow]Version Changes:[/bold yellow]")
                for pkg, (old_ver, new_ver) in sorted(version_changes.items()):
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
        sbom_data = load_sbom(sbom_path)

        console.print(f"\n[bold cyan]SBOM Statistics: {sbom_path.name}[/bold cyan]\n")

        # Package type statistics
        stats = get_package_statistics(sbom_data)

        table = Table(title="Packages by Type")
        table.add_column("Type", style="cyan")
        table.add_column("Count", style="green")

        for pkg_type, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
            table.add_row(pkg_type, str(count))

        console.print(table)

        # License statistics
        licenses = extract_licenses(sbom_data)
        if licenses:
            console.print(f"\n[bold]License Summary:[/bold]")
            console.print(f"Total unique licenses: {len(licenses)}\n")

            lic_table = Table(title="Top Licenses")
            lic_table.add_column("License", style="cyan")
            lic_table.add_column("Package Count", style="green")

            # Show top 10 licenses
            sorted_licenses = sorted(licenses.items(), key=lambda x: len(x[1]), reverse=True)
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
    format: str = typer.Option("csv", "--format", "-f", help="Export format (csv, requirements)"),
):
    """
    Export SBOM to different formats.

    Supported formats:
    - csv: Comma-separated values
    - requirements: Python requirements.txt format
    """
    try:
        sbom_data = load_sbom(sbom_path)

        if format == "csv":
            convert_to_csv(sbom_data, output)
            console.print(f"[green]CSV exported to {output}[/green]")
        elif format == "requirements":
            convert_to_requirements(sbom_data, output)
            console.print(f"[green]Requirements file exported to {output}[/green]")
        else:
            console.print(f"[red]Unsupported format: {format}[/red]")
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
        sbom_data = load_sbom(sbom_path)
        results = search_packages(sbom_data, query)

        if not results:
            console.print(f"[yellow]No packages found matching '{query}'[/yellow]")
            return

        _display_packages_table(results, title=f"Search Results for '{query}'")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("list")
def list_sboms(
    category: str = typer.Option("all", "--category", "-c", help="Category to list (docker, local, comparisons, archives, all)"),
    limit: Optional[int] = typer.Option(None, "--limit", "-n", help="Limit number of results"),
):
    """
    List all stored SBOMs in sbom_storage directory.

    Shows SBOMs organized by category with timestamps and sizes.
    """
    try:
        sboms = list_stored_sboms(category)

        if not sboms:
            console.print(f"[yellow]No SBOMs found in category '{category}'[/yellow]")
            return

        # Apply limit
        if limit:
            sboms = sboms[:limit]

        # Display table
        table = Table(title=f"Stored SBOMs ({category})")
        table.add_column("Filename", style="cyan", max_width=60)
        table.add_column("Category", style="magenta")
        table.add_column("Size", style="green")
        table.add_column("Modified", style="blue")

        for sbom_path in sboms:
            filename = sbom_path.name
            cat = sbom_path.parent.name
            size = sbom_path.stat().st_size
            size_str = f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / (1024 * 1024):.1f} MB"
            modified = datetime.fromtimestamp(sbom_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")

            table.add_row(filename, cat, size_str, modified)

        console.print(table)
        console.print(f"\n[dim]Total: {len(sboms)} SBOM(s)[/dim]")

        if limit and len(list_stored_sboms(category)) > limit:
            total = len(list_stored_sboms(category))
            console.print(f"[dim]Showing {limit} of {total} total SBOMs[/dim]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("components")
def components(
    sbom_path: Path = typer.Argument(..., exists=True, help="Path to SBOM file"),
    type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by type (library, file, os, application)"),
    language: Optional[str] = typer.Option(None, "--language", "-l", help="Filter by language (python, javascript, go)"),
    details: bool = typer.Option(False, "--details", "-d", help="Show detailed component information"),
    group_by: Optional[str] = typer.Option(None, "--group-by", "-g", help="Group by (type, language)"),
    limit: Optional[int] = typer.Option(None, "--limit", "-n", help="Limit number of components shown"),
):
    """
    Display all components from SBOM with filtering and grouping options.

    Shows libraries, files, OS packages, and other component types.
    """
    try:
        sbom_data = load_sbom(sbom_path)

        # Apply filters
        if type:
            components_list = filter_packages_by_type(sbom_data, type)
            if language:
                components_list = [
                    c for c in components_list
                    if (extract_component_metadata(c).get("language") or "").lower() == language.lower()
                ]
        elif language:
            components_list = filter_components_by_language(sbom_data, language)
        else:
            components_list = extract_packages(sbom_data)

        if not components_list:
            console.print(f"[yellow]No components found matching the criteria[/yellow]")
            return

        # Apply limit
        if limit:
            components_list = components_list[:limit]

        # Display based on grouping
        if group_by == "type":
            _display_components_grouped_by_type(sbom_data, components_list, details)
        elif group_by == "language":
            _display_components_grouped_by_language(components_list, details)
        elif details:
            _display_detailed_components(components_list)
        else:
            _display_components_summary(components_list, sbom_path.name)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


def _display_sbom_summary(sbom_data: dict, source: str) -> None:
    """Display summary of SBOM."""
    console.print(f"\n[bold cyan]SBOM Summary[/bold cyan]\n")

    packages = extract_packages(sbom_data)
    stats = get_package_statistics(sbom_data)

    # Basic info
    info_table = Table(show_header=False, box=None)
    info_table.add_column("Property", style="yellow")
    info_table.add_column("Value", style="white")

    info_table.add_row("Source", str(source))
    info_table.add_row("Total Packages", str(len(packages)))
    info_table.add_row("Package Types", str(len(stats)))

    console.print(info_table)

    # Package types
    if stats:
        console.print("\n[bold]Packages by Type:[/bold]")
        type_table = Table()
        type_table.add_column("Type", style="cyan")
        type_table.add_column("Count", style="green")

        for pkg_type, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
            type_table.add_row(pkg_type, str(count))

        console.print(type_table)


def _display_packages_table(packages: list, title: str = "Packages") -> None:
    """Display packages in a table."""
    if not packages:
        console.print("[yellow]No packages to display[/yellow]")
        return

    table = Table(title=title)
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="green")
    table.add_column("Type", style="magenta")

    for pkg in packages[:100]:  # Limit to first 100
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        pkg_type = pkg.get("type", "")
        table.add_row(name, version, pkg_type)

    console.print(table)

    if len(packages) > 100:
        console.print(f"\n[dim]... and {len(packages) - 100} more packages[/dim]")


def _display_components_summary(components: list, source: str) -> None:
    """Display summary of components."""
    console.print(f"\n[bold cyan]Components in {source}[/bold cyan]\n")

    # Count by type
    type_counts = {}
    for comp in components:
        comp_type = comp.get("type", "unknown")
        type_counts[comp_type] = type_counts.get(comp_type, 0) + 1

    # Summary table
    summary_table = Table(title="Components by Type")
    summary_table.add_column("Type", style="cyan")
    summary_table.add_column("Count", style="green")

    for comp_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        summary_table.add_row(comp_type, str(count))

    console.print(summary_table)

    # Show samples
    console.print("\n[bold]Sample Components:[/bold]")
    comp_table = Table()
    comp_table.add_column("Name", style="cyan", max_width=50)
    comp_table.add_column("Version", style="green")
    comp_table.add_column("Type", style="magenta")
    comp_table.add_column("Language", style="yellow")

    for comp in components[:20]:
        name = comp.get("name", "")
        version = comp.get("version", "") or "N/A"
        comp_type = comp.get("type", "")
        metadata = extract_component_metadata(comp)
        language = metadata.get("language") or "N/A"

        comp_table.add_row(name, version, comp_type, language)

    console.print(comp_table)

    if len(components) > 20:
        console.print(f"\n[dim]... and {len(components) - 20} more components[/dim]")


def _display_detailed_components(components: list) -> None:
    """Display detailed component information."""
    console.print(f"\n[bold cyan]Detailed Component Information[/bold cyan]\n")

    for idx, comp in enumerate(components[:50], 1):
        details = get_component_details(comp)

        console.print(f"[bold]{idx}. {details['name']}[/bold]")

        info_table = Table(show_header=False, box=None, padding=(0, 2))
        info_table.add_column("Property", style="yellow")
        info_table.add_column("Value", style="white")

        if details.get("version"):
            info_table.add_row("Version", details["version"])
        info_table.add_row("Type", details["type"])
        if details.get("language"):
            info_table.add_row("Language", details["language"])
        if details.get("author"):
            info_table.add_row("Author", details["author"])
        if details.get("purl"):
            info_table.add_row("PURL", details["purl"])
        if details.get("location"):
            info_table.add_row("Location", details["location"])
        if details.get("licenses"):
            licenses_str = ", ".join([str(l) for l in details["licenses"]])
            info_table.add_row("Licenses", licenses_str)

        console.print(info_table)
        console.print()

    if len(components) > 50:
        console.print(f"[dim]... and {len(components) - 50} more components[/dim]")


def _display_components_grouped_by_type(sbom_data: dict, components: list, show_details: bool) -> None:
    """Display components grouped by type."""
    console.print(f"\n[bold cyan]Components Grouped by Type[/bold cyan]\n")

    grouped = {}
    for comp in components:
        comp_type = comp.get("type", "unknown")
        if comp_type not in grouped:
            grouped[comp_type] = []
        grouped[comp_type].append(comp)

    for comp_type, comps in sorted(grouped.items(), key=lambda x: len(x[1]), reverse=True):
        console.print(f"\n[bold green]{comp_type.upper()} ({len(comps)} items)[/bold green]")

        if comp_type == "file":
            # Special handling for files - categorize them
            file_categories = get_files_by_category({"components": comps})
            for category, files in file_categories.items():
                console.print(f"  [yellow]{category.capitalize()}:[/yellow] {len(files)} files")
                if show_details:
                    for f in files[:5]:
                        console.print(f"    - {f.get('name', '')}")
                    if len(files) > 5:
                        console.print(f"    [dim]... and {len(files) - 5} more[/dim]")
        else:
            # Show table for libraries and other types
            table = Table()
            table.add_column("Name", style="cyan", max_width=40)
            table.add_column("Version", style="green")

            if comp_type == "library":
                table.add_column("Language", style="yellow")

            for comp in comps[:20]:
                name = comp.get("name", "")
                version = comp.get("version", "") or "N/A"

                if comp_type == "library":
                    metadata = extract_component_metadata(comp)
                    language = metadata.get("language") or "N/A"
                    table.add_row(name, version, language)
                else:
                    table.add_row(name, version)

            console.print(table)

            if len(comps) > 20:
                console.print(f"[dim]... and {len(comps) - 20} more {comp_type} components[/dim]")


def _display_components_grouped_by_language(components: list, show_details: bool) -> None:
    """Display components grouped by language."""
    console.print(f"\n[bold cyan]Components Grouped by Language[/bold cyan]\n")

    grouped = {}
    for comp in components:
        metadata = extract_component_metadata(comp)
        language = metadata.get("language") or "unknown"
        if language not in grouped:
            grouped[language] = []
        grouped[language].append(comp)

    for language, comps in sorted(grouped.items(), key=lambda x: len(x[1]), reverse=True):
        lang_display = language.upper() if language else "UNKNOWN"
        console.print(f"\n[bold green]{lang_display} ({len(comps)} components)[/bold green]")

        table = Table()
        table.add_column("Name", style="cyan", max_width=40)
        table.add_column("Version", style="green")
        table.add_column("Type", style="magenta")

        for comp in comps[:20]:
            name = comp.get("name", "")
            version = comp.get("version", "") or "N/A"
            comp_type = comp.get("type", "")
            table.add_row(name, version, comp_type)

        console.print(table)

        if len(comps) > 20:
            console.print(f"[dim]... and {len(comps) - 20} more {lang_display.lower()} components[/dim]")
