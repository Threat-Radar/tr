"""Docker CLI commands for container analysis."""
import typer
import json
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..core.container_analyzer import ContainerAnalyzer
from ..core.python_sbom import PythonPackageExtractor
from ..core.docker_integration import DockerClient

app = typer.Typer(help="Docker container analysis commands")
console = Console()


@app.command()
def import_image(
    image: str = typer.Argument(..., help="Image name to import (e.g., 'alpine', 'ubuntu:22.04')"),
    tag: str = typer.Option("latest", "--tag", "-t", help="Image tag (ignored if tag is in image name)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON file"),
):
    """
    Import and analyze a Docker image.

    Pulls the specified image and extracts package information.
    """
    # Parse image name and tag
    if ':' in image:
        # Tag already specified in image name
        image_name, image_tag = image.rsplit(':', 1)
    else:
        # Use separate tag parameter
        image_name = image
        image_tag = tag

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Importing {image_name}:{image_tag}...", total=None)

        try:
            analyzer = ContainerAnalyzer()
            analysis = analyzer.import_container(image_name, image_tag)

            progress.update(task, completed=True, description="Import complete!")

            # Display results
            _display_analysis(analysis)

            # Save to file if requested
            if output:
                with open(output, 'w') as f:
                    json.dump(analysis.to_dict(), f, indent=2)
                console.print(f"\n[green]Results saved to {output}[/green]")

            analyzer.close()

        except Exception as e:
            progress.stop()
            console.print(f"[red]Error importing image: {e}[/red]")
            raise typer.Exit(code=1)


@app.command()
def scan(
    image: str = typer.Argument(..., help="Image name to scan"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON file"),
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

        try:
            analyzer = ContainerAnalyzer()
            analysis = analyzer.analyze_container(image)

            progress.update(task, completed=True, description="Scan complete!")

            # Display results
            _display_analysis(analysis)

            # Save to file if requested
            if output:
                with open(output, 'w') as f:
                    json.dump(analysis.to_dict(), f, indent=2)
                console.print(f"\n[green]Results saved to {output}[/green]")

            analyzer.close()

        except Exception as e:
            progress.stop()
            console.print(f"[red]Error scanning image: {e}[/red]")
            raise typer.Exit(code=1)


@app.command()
def list_images():
    """
    List all available Docker images.

    Shows locally available images that can be analyzed.
    """
    try:
        analyzer = ContainerAnalyzer()
        images = analyzer.list_analyzed_images()

        if not images:
            console.print("[yellow]No Docker images found[/yellow]")
            analyzer.close()
            return

        # Create table
        table = Table(title="Available Docker Images")
        table.add_column("Image ID", style="cyan", no_wrap=True)
        table.add_column("Tags", style="green")
        table.add_column("Size", style="magenta")
        table.add_column("Created", style="blue")

        for image in images:
            image_id = image['id'][:12]  # Show short ID
            tags = ', '.join(image['tags']) if image['tags'] else '<none>'
            size = _format_size(image['size'])
            created = image['created'][:19] if image['created'] else 'N/A'

            table.add_row(image_id, tags, size, created)

        console.print(table)
        analyzer.close()

    except Exception as e:
        console.print(f"[red]Error listing images: {e}[/red]")
        raise typer.Exit(code=1)


@app.command()
def packages(
    image: str = typer.Argument(..., help="Image name"),
    limit: Optional[int] = typer.Option(None, "--limit", "-n", help="Limit number of packages shown"),
    filter_name: Optional[str] = typer.Option(None, "--filter", "-f", help="Filter packages by name"),
):
    """
    List packages installed in a Docker image.

    Shows detailed package information including versions.
    """
    try:
        analyzer = ContainerAnalyzer()
        analysis = analyzer.analyze_container(image)

        if not analysis.packages:
            console.print(f"[yellow]No packages found in {image}[/yellow]")
            analyzer.close()
            return

        # Filter packages if requested
        packages = analysis.packages
        if filter_name:
            packages = [p for p in packages if filter_name.lower() in p.name.lower()]

        # Limit packages if requested
        if limit:
            packages = packages[:limit]

        # Create table
        table = Table(title=f"Packages in {image}")
        table.add_column("Package", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Architecture", style="magenta")

        for pkg in packages:
            table.add_row(
                pkg.name,
                pkg.version,
                pkg.architecture or "N/A"
            )

        console.print(table)
        console.print(f"\n[blue]Total: {len(packages)} packages[/blue]")

        if filter_name:
            console.print(f"[dim]Filtered by: {filter_name}[/dim]")

        analyzer.close()

    except Exception as e:
        console.print(f"[red]Error listing packages: {e}[/red]")
        raise typer.Exit(code=1)


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
        info_table.add_row("Size", _format_size(analysis.size))

    info_table.add_row("Packages", str(len(analysis.packages)))

    console.print(info_table)

    # Show sample packages
    if analysis.packages:
        console.print("\n[bold]Sample Packages:[/bold]")
        pkg_table = Table(show_header=True)
        pkg_table.add_column("Package", style="cyan")
        pkg_table.add_column("Version", style="green")

        # Show first 10 packages
        for pkg in analysis.packages[:10]:
            pkg_table.add_row(pkg.name, pkg.version)

        console.print(pkg_table)

        if len(analysis.packages) > 10:
            console.print(f"[dim]... and {len(analysis.packages) - 10} more packages[/dim]")


@app.command()
def python_sbom(
    image: str = typer.Argument(..., help="Image name"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save SBOM to file"),
    format: str = typer.Option("cyclonedx", "--format", "-f", help="SBOM format (cyclonedx, csv, txt)"),
):
    """
    Generate Python package SBOM from Docker image.

    Extracts pip packages and generates CycloneDX SBOM.
    """
    # Parse image name and tag
    if ':' in image:
        image_name, image_tag = image.rsplit(':', 1)
    else:
        image_name = image
        image_tag = "latest"

    try:
        docker_client = DockerClient()
        extractor = PythonPackageExtractor(docker_client)

        console.print(f"\n[cyan]Extracting Python packages from {image_name}:{image_tag}...[/cyan]")

        packages = extractor.extract_pip_packages(f"{image_name}:{image_tag}")

        if not packages:
            console.print(f"[yellow]No Python packages found in {image}[/yellow]")
            docker_client.close()
            return

        # Display packages
        table = Table(title=f"Python Packages in {image_name}:{image_tag}")
        table.add_column("Package", style="cyan")
        table.add_column("Version", style="green")

        for pkg in packages:
            table.add_row(pkg.name, pkg.version)

        console.print(table)
        console.print(f"\n[blue]Total: {len(packages)} Python packages[/blue]")

        # Generate and save SBOM
        if output:
            if format == "cyclonedx":
                import json
                sbom = extractor.generate_cyclonedx_sbom(f"{image_name}:{image_tag}", packages)
                with open(output, 'w') as f:
                    json.dump(sbom, f, indent=2)
                console.print(f"\n[green]CycloneDX SBOM saved to {output}[/green]")
            elif format == "csv":
                with open(output, 'w') as f:
                    f.write("name,version\n")
                    for pkg in packages:
                        f.write(f"{pkg.name},{pkg.version}\n")
                console.print(f"\n[green]CSV saved to {output}[/green]")
            elif format == "txt":
                with open(output, 'w') as f:
                    for pkg in packages:
                        f.write(f"{pkg.name}=={pkg.version}\n")
                console.print(f"\n[green]Requirements format saved to {output}[/green]")

        docker_client.close()

    except Exception as e:
        console.print(f"[red]Error generating Python SBOM: {e}[/red]")
        raise typer.Exit(code=1)


def _format_size(size_bytes: int) -> str:
    """Format size in bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"
