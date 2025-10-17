"""CVE vulnerability scanning operations using Grype."""
import typer
from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..core.grype_integration import GrypeClient, GrypeSeverity, GrypeOutputFormat
from ..utils import save_json, handle_cli_error, ScanCleanupContext, get_cve_storage

app = typer.Typer(help="CVE vulnerability scanning operations")
console = Console()


@app.command("scan-image")
def scan_docker_image(
    image: str = typer.Argument(..., help="Docker image to scan (e.g., alpine:3.18, python:3.11)"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by minimum severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON file"),
    only_fixed: bool = typer.Option(False, "--only-fixed", help="Only show vulnerabilities with fixes available"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit with error if vulnerabilities of this severity or higher are found"),
    scope: str = typer.Option("squashed", "--scope", help="Scope for Docker images (squashed, all-layers)"),
    cleanup: bool = typer.Option(False, "--cleanup", help="Remove Docker image after scan (only if pulled during this scan)"),
    auto_save: bool = typer.Option(False, "--auto-save", "--as", help="Automatically save results to storage/cve_storage/ directory"),
):
    """
    Scan Docker image for CVE vulnerabilities using Grype.

    Grype analyzes Docker images and identifies known vulnerabilities in packages.
    It uses an automatically updated vulnerability database that includes CVE data
    from NVD, Linux distribution security databases, and more.

    The --cleanup flag automatically removes the Docker image after scanning, but only
    if the image was pulled during this scan. Pre-existing images are never deleted.

    The --auto-save flag automatically saves results to ./storage/cve_storage/ directory with
    timestamped filenames. This is useful for keeping a history of scan results.

    Examples:
        threat-radar cve scan-image alpine:3.18
        threat-radar cve scan-image python:3.11 --severity HIGH
        threat-radar cve scan-image ubuntu:22.04 --only-fixed -o results.json
        threat-radar cve scan-image nginx:latest --cleanup  # Remove after scan
        threat-radar cve scan-image myapp:latest --auto-save  # Auto-save to storage/cve_storage/
        threat-radar cve scan-image myapp:latest --as --cleanup  # Both features
    """
    with handle_cli_error("scanning image", console):
        # Use cleanup context to manage Docker image lifecycle
        with ScanCleanupContext(image, cleanup=cleanup):
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task(f"Scanning {image} with Grype...", total=None)

                # Initialize Grype client
                grype = GrypeClient()

                # Parse fail-on severity if provided
                fail_on_severity = None
                if fail_on:
                    try:
                        fail_on_severity = GrypeSeverity(fail_on.lower())
                    except ValueError:
                        console.print(f"[red]Invalid severity: {fail_on}. Use: NEGLIGIBLE, LOW, MEDIUM, HIGH, CRITICAL[/red]")
                        return

                # Run scan
                result = grype.scan_docker_image(
                    image,
                    output_format=GrypeOutputFormat.JSON,
                    scope=scope,
                    fail_on_severity=fail_on_severity
                )

                progress.update(task, completed=True, description="Scan complete!")

            if cleanup:
                console.print(f"[dim]Cleanup: Image will be removed if it was pulled during scan[/dim]")

        # Filter by severity if requested
        if severity:
            try:
                min_severity = GrypeSeverity(severity.lower())
                result = result.filter_by_severity(min_severity)
            except ValueError:
                console.print(f"[red]Invalid severity: {severity}. Use: NEGLIGIBLE, LOW, MEDIUM, HIGH, CRITICAL[/red]")
                return

        # Filter by only-fixed if requested
        if only_fixed:
            result.vulnerabilities = [v for v in result.vulnerabilities if v.fixed_in_version]
            result.total_count = len(result.vulnerabilities)
            result.__post_init__()  # Recalculate counts

        # Prepare output data (used for both --output and --auto-save)
        output_data = {
            "target": result.target,
            "total_vulnerabilities": result.total_count,
            "severity_counts": result.severity_counts,
            "vulnerabilities": [
                {
                    "id": v.id,
                    "severity": v.severity,
                    "package": f"{v.package_name}@{v.package_version}",
                    "package_type": v.package_type,
                    "fixed_in": v.fixed_in_version,
                    "description": v.description,
                    "cvss_score": v.cvss_score,
                    "urls": v.urls
                }
                for v in result.vulnerabilities
            ],
            "scan_metadata": result.scan_metadata
        }

        # Display results
        if not result.vulnerabilities:
            console.print(f"\n[green]✓ No vulnerabilities found in {image}![/green]")
        else:
            console.print(f"\n[red]⚠ Found {result.total_count} vulnerabilities in {image}:[/red]\n")

            # Display severity breakdown
            _display_severity_summary(result.severity_counts)

            # Display detailed vulnerability table
            _display_vulnerability_table(result.vulnerabilities, limit=20)

        # Save to file if --output specified
        if output:
            save_json(output_data, output, console)

        # Auto-save to cve_storage if --auto-save specified
        if auto_save:
            storage = get_cve_storage()
            saved_path = storage.save_report(output_data, image, scan_type="image")
            console.print(f"\n[green]💾 Auto-saved to: {saved_path}[/green]")


@app.command("scan-sbom")
def scan_sbom_file(
    sbom_path: Path = typer.Argument(..., exists=True, help="Path to SBOM file (CycloneDX, SPDX, or Syft JSON)"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by minimum severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON file"),
    only_fixed: bool = typer.Option(False, "--only-fixed", help="Only show vulnerabilities with fixes available"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit with error if vulnerabilities of this severity or higher are found"),
    cleanup: bool = typer.Option(False, "--cleanup", help="Remove source Docker image after scan (if SBOM was from Docker image)"),
    image: Optional[str] = typer.Option(None, "--image", help="Specify source Docker image name for cleanup (e.g., alpine:3.18)"),
    auto_save: bool = typer.Option(False, "--auto-save", "--as", help="Automatically save results to storage/cve_storage/ directory"),
):
    """
    Scan a pre-generated SBOM file for CVE vulnerabilities using Grype.

    Supports CycloneDX JSON, SPDX JSON, and Syft JSON formats.
    Perfect for CI/CD pipelines where SBOMs are already generated.

    The --cleanup flag removes the source Docker image after scanning, but only works
    if you specify the --image flag or if the SBOM metadata contains image information.
    Pre-existing images are never deleted.

    The --auto-save flag automatically saves results to ./storage/cve_storage/ directory with
    timestamped filenames.

    Examples:
        threat-radar cve scan-sbom my-app-sbom.json
        threat-radar cve scan-sbom docker-sbom.json --severity HIGH
        threat-radar cve scan-sbom sbom.json --only-fixed -o results.json
        threat-radar cve scan-sbom sbom.json --cleanup --image alpine:3.18
        threat-radar cve scan-sbom sbom.json --auto-save  # Auto-save to storage/cve_storage/
    """
    with handle_cli_error("scanning SBOM", console):
        # Determine if we should cleanup and what image to cleanup
        cleanup_image = None
        if cleanup and image:
            cleanup_image = image
        elif cleanup:
            console.print("[yellow]Warning: --cleanup specified but no --image provided. Skipping cleanup.[/yellow]")

        # Use cleanup context if we have an image to cleanup
        cleanup_ctx = ScanCleanupContext(cleanup_image, cleanup=cleanup) if cleanup_image else None

        try:
            if cleanup_ctx:
                cleanup_ctx.__enter__()

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task(f"Scanning SBOM {sbom_path.name} with Grype...", total=None)

                # Initialize Grype client
                grype = GrypeClient()

                # Parse fail-on severity if provided
                fail_on_severity = None
                if fail_on:
                    try:
                        fail_on_severity = GrypeSeverity(fail_on.lower())
                    except ValueError:
                        console.print(f"[red]Invalid severity: {fail_on}. Use: NEGLIGIBLE, LOW, MEDIUM, HIGH, CRITICAL[/red]")
                        return

                # Run scan
                result = grype.scan_sbom(
                    sbom_path,
                    output_format=GrypeOutputFormat.JSON,
                    fail_on_severity=fail_on_severity
                )

                progress.update(task, completed=True, description="Scan complete!")

            if cleanup_image:
                console.print(f"[dim]Cleanup: Image {cleanup_image} will be removed if it was pulled during scan[/dim]")

        finally:
            if cleanup_ctx:
                cleanup_ctx.__exit__(None, None, None)

        # Filter by severity if requested
        if severity:
            try:
                min_severity = GrypeSeverity(severity.lower())
                result = result.filter_by_severity(min_severity)
            except ValueError:
                console.print(f"[red]Invalid severity: {severity}. Use: NEGLIGIBLE, LOW, MEDIUM, HIGH, CRITICAL[/red]")
                return

        # Filter by only-fixed if requested
        if only_fixed:
            result.vulnerabilities = [v for v in result.vulnerabilities if v.fixed_in_version]
            result.total_count = len(result.vulnerabilities)
            result.__post_init__()  # Recalculate counts

        # Prepare output data (used for both --output and --auto-save)
        output_data = {
            "sbom_file": str(sbom_path),
            "total_vulnerabilities": result.total_count,
            "severity_counts": result.severity_counts,
            "vulnerabilities": [
                {
                    "id": v.id,
                    "severity": v.severity,
                    "package": f"{v.package_name}@{v.package_version}",
                    "package_type": v.package_type,
                    "fixed_in": v.fixed_in_version,
                    "description": v.description,
                    "cvss_score": v.cvss_score,
                    "urls": v.urls
                }
                for v in result.vulnerabilities
            ],
            "scan_metadata": result.scan_metadata
        }

        # Display results
        if not result.vulnerabilities:
            console.print(f"\n[green]✓ No vulnerabilities found in {sbom_path.name}![/green]")
        else:
            console.print(f"\n[red]⚠ Found {result.total_count} vulnerabilities in SBOM:[/red]\n")

            # Display severity breakdown
            _display_severity_summary(result.severity_counts)

            # Display detailed vulnerability table
            _display_vulnerability_table(result.vulnerabilities, limit=20)

        # Save to file if --output specified
        if output:
            save_json(output_data, output, console)

        # Auto-save to cve_storage if --auto-save specified
        if auto_save:
            storage = get_cve_storage()
            target_name = sbom_path.stem  # Use filename without extension
            saved_path = storage.save_report(output_data, target_name, scan_type="sbom")
            console.print(f"\n[green]💾 Auto-saved to: {saved_path}[/green]")


@app.command("scan-directory")
def scan_directory(
    directory: Path = typer.Argument(..., exists=True, help="Path to directory to scan"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by minimum severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON file"),
    only_fixed: bool = typer.Option(False, "--only-fixed", help="Only show vulnerabilities with fixes available"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit with error if vulnerabilities of this severity or higher are found"),
    auto_save: bool = typer.Option(False, "--auto-save", "--as", help="Automatically save results to storage/cve_storage/ directory"),
):
    """
    Scan a local directory for CVE vulnerabilities using Grype.

    Grype will analyze files in the directory and identify vulnerabilities in
    detected packages (e.g., package-lock.json, requirements.txt, go.mod, etc.).

    The --auto-save flag automatically saves results to ./storage/cve_storage/ directory with
    timestamped filenames.

    Examples:
        threat-radar cve scan-directory ./my-app
        threat-radar cve scan-directory /path/to/project --severity MEDIUM
        threat-radar cve scan-directory . --only-fixed -o results.json
        threat-radar cve scan-directory ./src --auto-save  # Auto-save to storage/cve_storage/
    """
    with handle_cli_error("scanning directory", console):
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Scanning directory with Grype...", total=None)

            # Initialize Grype client
            grype = GrypeClient()

            # Parse fail-on severity if provided
            fail_on_severity = None
            if fail_on:
                try:
                    fail_on_severity = GrypeSeverity(fail_on.lower())
                except ValueError:
                    console.print(f"[red]Invalid severity: {fail_on}. Use: NEGLIGIBLE, LOW, MEDIUM, HIGH, CRITICAL[/red]")
                    return

            # Run scan
            result = grype.scan_directory(
                directory,
                output_format=GrypeOutputFormat.JSON,
                fail_on_severity=fail_on_severity
            )

            progress.update(task, completed=True, description="Scan complete!")

        # Filter by severity if requested
        if severity:
            try:
                min_severity = GrypeSeverity(severity.lower())
                result = result.filter_by_severity(min_severity)
            except ValueError:
                console.print(f"[red]Invalid severity: {severity}. Use: NEGLIGIBLE, LOW, MEDIUM, HIGH, CRITICAL[/red]")
                return

        # Filter by only-fixed if requested
        if only_fixed:
            result.vulnerabilities = [v for v in result.vulnerabilities if v.fixed_in_version]
            result.total_count = len(result.vulnerabilities)
            result.__post_init__()  # Recalculate counts

        # Prepare output data (used for both --output and --auto-save)
        output_data = {
            "directory": str(directory),
            "total_vulnerabilities": result.total_count,
            "severity_counts": result.severity_counts,
            "vulnerabilities": [
                {
                    "id": v.id,
                    "severity": v.severity,
                    "package": f"{v.package_name}@{v.package_version}",
                    "package_type": v.package_type,
                    "fixed_in": v.fixed_in_version,
                    "description": v.description,
                    "cvss_score": v.cvss_score,
                    "urls": v.urls
                }
                for v in result.vulnerabilities
            ],
            "scan_metadata": result.scan_metadata
        }

        # Display results
        if not result.vulnerabilities:
            console.print(f"\n[green]✓ No vulnerabilities found in {directory}![/green]")
        else:
            console.print(f"\n[red]⚠ Found {result.total_count} vulnerabilities:[/red]\n")

            # Display severity breakdown
            _display_severity_summary(result.severity_counts)

            # Display detailed vulnerability table
            _display_vulnerability_table(result.vulnerabilities, limit=20)

        # Save to file if --output specified
        if output:
            save_json(output_data, output, console)

        # Auto-save to cve_storage if --auto-save specified
        if auto_save:
            storage = get_cve_storage()
            target_name = directory.name if directory.name != "." else "current_dir"
            saved_path = storage.save_report(output_data, target_name, scan_type="directory")
            console.print(f"\n[green]💾 Auto-saved to: {saved_path}[/green]")


@app.command("db-update")
def update_database():
    """
    Update Grype vulnerability database.

    Downloads the latest vulnerability data from Grype's sources.
    This is typically done automatically, but can be forced manually.

    Example:
        threat-radar cve db-update
    """
    with handle_cli_error("updating database", console):
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Updating Grype vulnerability database...", total=None)

            grype = GrypeClient()
            grype.update_database()

            progress.update(task, completed=True, description="Database updated!")

        console.print("[green]✓ Grype vulnerability database updated successfully[/green]")


@app.command("db-status")
def database_status():
    """
    Show Grype vulnerability database status.

    Displays information about the current Grype database.

    Example:
        threat-radar cve db-status
    """
    with handle_cli_error("fetching database status", console):
        grype = GrypeClient()
        status = grype.get_db_status()

        console.print("\n[bold cyan]Grype Vulnerability Database Status[/bold cyan]\n")

        # Display status information
        info_table = Table(show_header=False, box=None)
        info_table.add_column("Property", style="yellow")
        info_table.add_column("Value", style="white")

        for key, value in status.items():
            # Format key to be more readable
            readable_key = key.replace('_', ' ').title()
            info_table.add_row(readable_key, str(value))

        console.print(info_table)


def _display_severity_summary(severity_counts: dict) -> None:
    """Display severity breakdown summary."""
    console.print("[bold]Severity Breakdown:[/bold]")

    summary_table = Table(show_header=False, box=None)
    summary_table.add_column("Severity", style="cyan")
    summary_table.add_column("Count", style="white", justify="right")

    # Display in order: Critical -> High -> Medium -> Low -> Negligible
    severity_order = ["critical", "high", "medium", "low", "negligible"]

    for severity in severity_order:
        count = severity_counts.get(severity, 0)
        if count > 0:
            color = _get_severity_color(severity)
            summary_table.add_row(
                f"[{color}]{severity.upper()}[/{color}]",
                f"{count}"
            )

    console.print(summary_table)
    console.print()


def _display_vulnerability_table(vulnerabilities: list, limit: int = 20) -> None:
    """Display detailed vulnerability table."""
    console.print(f"[bold]Vulnerabilities (showing top {min(len(vulnerabilities), limit)}):[/bold]\n")

    table = Table()
    table.add_column("CVE ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="red")
    table.add_column("Package", style="yellow")
    table.add_column("Installed", style="white")
    table.add_column("Fixed In", style="green")
    table.add_column("CVSS", style="magenta", justify="right")

    # Sort by severity (critical first) then by CVSS score
    severity_priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4}

    sorted_vulns = sorted(
        vulnerabilities,
        key=lambda v: (
            severity_priority.get(v.severity.lower(), 5),
            -(v.cvss_score or 0)
        )
    )

    for vuln in sorted_vulns[:limit]:
        severity_color = _get_severity_color(vuln.severity)
        fixed_version = vuln.fixed_in_version or "No fix"

        table.add_row(
            vuln.id,
            f"[{severity_color}]{vuln.severity.upper()}[/{severity_color}]",
            vuln.package_name,
            vuln.package_version,
            fixed_version,
            f"{vuln.cvss_score:.1f}" if vuln.cvss_score else "N/A"
        )

    console.print(table)

    if len(vulnerabilities) > limit:
        console.print(f"\n[dim]... and {len(vulnerabilities) - limit} more vulnerabilities[/dim]")


def _get_severity_color(severity: str) -> str:
    """Get color for severity level."""
    severity = severity.lower()
    colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "negligible": "green",
    }
    return colors.get(severity, "white")
