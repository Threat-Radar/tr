"""Docker CLI commands for container analysis."""

import typer
from typing import Optional
from dataclasses import asdict
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..utils import (
    docker_analyzer,
    docker_client,
    parse_image_reference,
    format_bytes,
    save_json,
    handle_cli_error,
    create_package_table,
)

# from ..core.python_sbom import PythonPackageExtractor  # Module doesn't exist yet

app = typer.Typer(help="Docker container analysis commands")
console = Console()


@app.command()
def import_image(
    image: str = typer.Argument(
        ..., help="Image name to import (e.g., 'alpine', 'ubuntu:22.04')"
    ),
    tag: str = typer.Option(
        "latest", "--tag", "-t", help="Image tag (ignored if tag is in image name)"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to JSON file"
    ),
):
    """
    Import and analyze a Docker image.

    Pulls the specified image and extracts package information.
    """
    # Parse image name and tag
    image_name, image_tag = parse_image_reference(image, tag)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Importing {image_name}:{image_tag}...", total=None)

        with handle_cli_error("importing image", console, progress):
            with docker_analyzer() as analyzer:
                analysis = analyzer.import_container(image_name, image_tag)

                progress.update(task, completed=True, description="Import complete!")

                # Display results
                _display_analysis(analysis)

                # Save to file if requested
                if output:
                    save_json(asdict(analysis), output, console)


@app.command()
def scan(
    image: str = typer.Argument(..., help="Image name to scan"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to JSON file"
    ),
):
    """
    Scan a local Docker image and extract packages.

    Analyzes an already-pulled image without pulling it again.
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Scanning {image}...", total=None)

        with handle_cli_error("scanning image", console, progress):
            with docker_analyzer() as analyzer:
                analysis = analyzer.analyze_container(image)

                progress.update(task, completed=True, description="Scan complete!")

                # Display results
                _display_analysis(analysis)

                # Save to file if requested
                if output:
                    save_json(asdict(analysis), output, console)


@app.command()
def list_images():
    """
    List all available Docker images.

    Shows locally available images that can be analyzed.
    """
    with handle_cli_error("listing images", console):
        with docker_analyzer() as analyzer:
            images = analyzer.list_analyzed_images()

            if not images:
                console.print("[yellow]No Docker images found[/yellow]")
                return

            # Create table
            table = Table(title="Available Docker Images")
            table.add_column("Image ID", style="cyan", no_wrap=True)
            table.add_column("Tags", style="green")
            table.add_column("Size", style="magenta")
            table.add_column("Created", style="blue")

            for image in images:
                image_id = image["id"][:12]  # Show short ID
                tags = ", ".join(image["tags"]) if image["tags"] else "<none>"
                size = format_bytes(image["size"])
                created = image["created"][:19] if image["created"] else "N/A"

                table.add_row(image_id, tags, size, created)

            console.print(table)


@app.command()
def packages(
    image: str = typer.Argument(..., help="Image name"),
    limit: Optional[int] = typer.Option(
        None, "--limit", "-n", help="Limit number of packages shown"
    ),
    filter_name: Optional[str] = typer.Option(
        None, "--filter", "-f", help="Filter packages by name"
    ),
):
    """
    List packages installed in a Docker image.

    Shows detailed package information including versions.
    """
    with handle_cli_error("listing packages", console):
        with docker_analyzer() as analyzer:
            analysis = analyzer.analyze_container(image)

            if not analysis.packages:
                console.print(f"[yellow]No packages found in {image}[/yellow]")
                return

            # Filter packages if requested
            filtered_packages = analysis.packages
            if filter_name:
                filtered_packages = [
                    p
                    for p in filtered_packages
                    if filter_name.lower() in p.name.lower()
                ]

            # Create and display table
            table = create_package_table(
                filtered_packages,
                title=f"Packages in {image}",
                show_architecture=True,
                limit=limit,
            )

            console.print(table)
            console.print(f"\n[blue]Total: {len(filtered_packages)} packages[/blue]")

            if filter_name:
                console.print(f"[dim]Filtered by: {filter_name}[/dim]")


def _display_analysis(analysis):
    """Display analysis results in a formatted way."""
    console.print("\n[bold cyan]Container Analysis Results[/bold cyan]\n")

    # Basic info table
    info_table = Table(show_header=False, box=None)
    info_table.add_column("Property", style="yellow")
    info_table.add_column("Value", style="white")

    info_table.add_row("Image", analysis.image_name)
    info_table.add_row("Image ID", analysis.image_id[:12])

    if analysis.distro:
        distro_str = analysis.distro
        if analysis.distro_version:
            distro_str += f" {analysis.distro_version}"
        info_table.add_row("Distribution", distro_str)

    if analysis.architecture:
        info_table.add_row("Architecture", analysis.architecture)

    if analysis.size:
        info_table.add_row("Size", format_bytes(analysis.size))

    info_table.add_row("Packages", str(len(analysis.packages)))

    console.print(info_table)

    # Show sample packages
    if analysis.packages:
        console.print("\n[bold]Sample Packages:[/bold]")
        pkg_table = create_package_table(analysis.packages, title="", limit=10)
        console.print(pkg_table)

        if len(analysis.packages) > 10:
            console.print(
                f"[dim]... and {len(analysis.packages) - 10} more packages[/dim]"
            )


def _format_size(size_bytes: int) -> str:
    """Format size in bytes to human-readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


@app.command()
def python_sbom(
    image: str = typer.Argument(..., help="Image name"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save SBOM to file"
    ),
    format: str = typer.Option(
        "cyclonedx", "--format", "-f", help="SBOM format (cyclonedx, csv, txt)"
    ),
):
    """
    Generate Python package SBOM from Docker image.

    Extracts pip packages and generates CycloneDX SBOM.
    """
    # Parse image name and tag
    image_name, image_tag = parse_image_reference(image, "latest")
    full_image = f"{image_name}:{image_tag}"

    with handle_cli_error("generating Python SBOM", console):
        with docker_client() as client:
            extractor = PythonPackageExtractor(client)

            console.print(
                f"\n[cyan]Extracting Python packages from {full_image}...[/cyan]"
            )

            packages = extractor.extract_pip_packages(full_image)

            if not packages:
                console.print(f"[yellow]No Python packages found in {image}[/yellow]")
                return

            # Display packages
            table = create_package_table(
                packages, title=f"Python Packages in {full_image}"
            )
            console.print(table)
            console.print(f"\n[blue]Total: {len(packages)} Python packages[/blue]")

            # Generate and save SBOM
            if output:
                if format == "cyclonedx":
                    sbom = extractor.generate_cyclonedx_sbom(full_image, packages)
                    save_json(
                        sbom, output, console, f"CycloneDX SBOM saved to {output}"
                    )
                elif format == "csv":
                    csv_content = "name,version\n"
                    csv_content += "\n".join(
                        f"{pkg.name},{pkg.version}" for pkg in packages
                    )
                    from ..utils.file_utils import save_text

                    save_text(csv_content, output, console, f"CSV saved to {output}")
                elif format == "txt":
                    txt_content = "\n".join(
                        f"{pkg.name}=={pkg.version}" for pkg in packages
                    )
                    from ..utils.file_utils import save_text

                    save_text(
                        txt_content,
                        output,
                        console,
                        f"Requirements format saved to {output}",
                    )
