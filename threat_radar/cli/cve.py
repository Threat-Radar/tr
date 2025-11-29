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
    image: str = typer.Argument(
        ..., help="Docker image to scan (e.g., alpine:3.18, python:3.11)"
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by minimum severity (LOW, MEDIUM, HIGH, CRITICAL)",
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to JSON file"
    ),
    only_fixed: bool = typer.Option(
        False, "--only-fixed", help="Only show vulnerabilities with fixes available"
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit with error if vulnerabilities of this severity or higher are found",
    ),
    scope: str = typer.Option(
        "squashed", "--scope", help="Scope for Docker images (squashed, all-layers)"
    ),
    cleanup: bool = typer.Option(
        False,
        "--cleanup",
        help="Remove Docker image after scan (only if pulled during this scan)",
    ),
    auto_save: bool = typer.Option(
        False,
        "--auto-save",
        "--as",
        help="Automatically save results to storage/cve_storage/ directory",
    ),
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
                        console.print(
                            f"[red]Invalid severity: {fail_on}. Use: NEGLIGIBLE, LOW, MEDIUM, HIGH, CRITICAL[/red]"
                        )
                        return

                # Run scan
                result = grype.scan_docker_image(
                    image,
                    output_format=GrypeOutputFormat.JSON,
                    scope=scope,
                    fail_on_severity=fail_on_severity,
                )

                progress.update(task, completed=True, description="Scan complete!")

            if cleanup:
                console.print(
                    f"[dim]Cleanup: Image will be removed if it was pulled during scan[/dim]"
                )

        # Filter by severity if requested
        if severity:
            try:
                min_severity = GrypeSeverity(severity.lower())
                result = result.filter_by_severity(min_severity)
            except ValueError:
                console.print(
                    f"[red]Invalid severity: {severity}. Use: NEGLIGIBLE, LOW, MEDIUM, HIGH, CRITICAL[/red]"
                )
                return

        # Filter by only-fixed if requested
        if only_fixed:
            result.vulnerabilities = [
                v for v in result.vulnerabilities if v.fixed_in_version
            ]
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
                    "urls": v.urls,
                }
                for v in result.vulnerabilities
            ],
            "scan_metadata": result.scan_metadata,
        }

        # Display results
        if not result.vulnerabilities:
            console.print(f"\n[green]✓ No vulnerabilities found in {image}![/green]")
        else:
            console.print(
                f"\n[red]⚠ Found {result.total_count} vulnerabilities in {image}:[/red]\n"
            )

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
    sbom_path: Path = typer.Argument(
        ..., exists=True, help="Path to SBOM file (CycloneDX, SPDX, or Syft JSON)"
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by minimum severity (LOW, MEDIUM, HIGH, CRITICAL)",
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to JSON file"
    ),
    only_fixed: bool = typer.Option(
        False, "--only-fixed", help="Only show vulnerabilities with fixes available"
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit with error if vulnerabilities of this severity or higher are found",
    ),
    cleanup: bool = typer.Option(
        False,
        "--cleanup",
        help="Remove source Docker image after scan (if SBOM was from Docker image)",
    ),
    image: Optional[str] = typer.Option(
        None,
        "--image",
        help="Specify source Docker image name for cleanup (e.g., alpine:3.18)",
    ),
    auto_save: bool = typer.Option(
        False,
        "--auto-save",
        "--as",
        help="Automatically save results to storage/cve_storage/ directory",
    ),
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
            console.print(
                "[yellow]Warning: --cleanup specified but no --image provided. Skipping cleanup.[/yellow]"
            )

        # Use cleanup context if we have an image to cleanup
        cleanup_ctx = (
            ScanCleanupContext(cleanup_image, cleanup=cleanup)
            if cleanup_image
            else None
        )

        try:
            if cleanup_ctx:
                cleanup_ctx.__enter__()

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task(
                    f"Scanning SBOM {sbom_path.name} with Grype...", total=None
                )

                # Initialize Grype client
                grype = GrypeClient()

                # Parse fail-on severity if provided
                fail_on_severity = None
                if fail_on:
                    try:
                        fail_on_severity = GrypeSeverity(fail_on.lower())
                    except ValueError:
                        console.print(
                            f"[red]Invalid severity: {fail_on}. Use: NEGLIGIBLE, LOW, MEDIUM, HIGH, CRITICAL[/red]"
                        )
                        return

                # Run scan
                result = grype.scan_sbom(
                    sbom_path,
                    output_format=GrypeOutputFormat.JSON,
                    fail_on_severity=fail_on_severity,
                )

                progress.update(task, completed=True, description="Scan complete!")

            if cleanup_image:
                console.print(
                    f"[dim]Cleanup: Image {cleanup_image} will be removed if it was pulled during scan[/dim]"
                )

        finally:
            if cleanup_ctx:
                cleanup_ctx.__exit__(None, None, None)

        # Filter by severity if requested
        if severity:
            try:
                min_severity = GrypeSeverity(severity.lower())
                result = result.filter_by_severity(min_severity)
            except ValueError:
                console.print(
                    f"[red]Invalid severity: {severity}. Use: NEGLIGIBLE, LOW, MEDIUM, HIGH, CRITICAL[/red]"
                )
                return

        # Filter by only-fixed if requested
        if only_fixed:
            result.vulnerabilities = [
                v for v in result.vulnerabilities if v.fixed_in_version
            ]
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
                    "urls": v.urls,
                }
                for v in result.vulnerabilities
            ],
            "scan_metadata": result.scan_metadata,
        }

        # Display results
        if not result.vulnerabilities:
            console.print(
                f"\n[green]✓ No vulnerabilities found in {sbom_path.name}![/green]"
            )
        else:
            console.print(
                f"\n[red]⚠ Found {result.total_count} vulnerabilities in SBOM:[/red]\n"
            )

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
    directory: Path = typer.Argument(
        ..., exists=True, help="Path to directory to scan"
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by minimum severity (LOW, MEDIUM, HIGH, CRITICAL)",
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to JSON file"
    ),
    only_fixed: bool = typer.Option(
        False, "--only-fixed", help="Only show vulnerabilities with fixes available"
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit with error if vulnerabilities of this severity or higher are found",
    ),
    auto_save: bool = typer.Option(
        False,
        "--auto-save",
        "--as",
        help="Automatically save results to storage/cve_storage/ directory",
    ),
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
                    console.print(
                        f"[red]Invalid severity: {fail_on}. Use: NEGLIGIBLE, LOW, MEDIUM, HIGH, CRITICAL[/red]"
                    )
                    return

            # Run scan
            result = grype.scan_directory(
                directory,
                output_format=GrypeOutputFormat.JSON,
                fail_on_severity=fail_on_severity,
            )

            progress.update(task, completed=True, description="Scan complete!")

        # Filter by severity if requested
        if severity:
            try:
                min_severity = GrypeSeverity(severity.lower())
                result = result.filter_by_severity(min_severity)
            except ValueError:
                console.print(
                    f"[red]Invalid severity: {severity}. Use: NEGLIGIBLE, LOW, MEDIUM, HIGH, CRITICAL[/red]"
                )
                return

        # Filter by only-fixed if requested
        if only_fixed:
            result.vulnerabilities = [
                v for v in result.vulnerabilities if v.fixed_in_version
            ]
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
                    "urls": v.urls,
                }
                for v in result.vulnerabilities
            ],
            "scan_metadata": result.scan_metadata,
        }

        # Display results
        if not result.vulnerabilities:
            console.print(
                f"\n[green]✓ No vulnerabilities found in {directory}![/green]"
            )
        else:
            console.print(
                f"\n[red]⚠ Found {result.total_count} vulnerabilities:[/red]\n"
            )

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
            saved_path = storage.save_report(
                output_data, target_name, scan_type="directory"
            )
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
            task = progress.add_task(
                "Updating Grype vulnerability database...", total=None
            )

            grype = GrypeClient()
            grype.update_database()

            progress.update(task, completed=True, description="Database updated!")

        console.print(
            "[green]✓ Grype vulnerability database updated successfully[/green]"
        )


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
            readable_key = key.replace("_", " ").title()
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
            summary_table.add_row(f"[{color}]{severity.upper()}[/{color}]", f"{count}")

    console.print(summary_table)
    console.print()


def _display_vulnerability_table(vulnerabilities: list, limit: int = 20) -> None:
    """Display detailed vulnerability table."""
    console.print(
        f"[bold]Vulnerabilities (showing top {min(len(vulnerabilities), limit)}):[/bold]\n"
    )

    table = Table()
    table.add_column("CVE ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="red")
    table.add_column("Package", style="yellow")
    table.add_column("Installed", style="white")
    table.add_column("Fixed In", style="green")
    table.add_column("CVSS", style="magenta", justify="right")

    # Sort by severity (critical first) then by CVSS score
    severity_priority = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "negligible": 4,
    }

    sorted_vulns = sorted(
        vulnerabilities,
        key=lambda v: (
            severity_priority.get(v.severity.lower(), 5),
            -(v.cvss_score or 0),
        ),
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
            f"{vuln.cvss_score:.1f}" if vuln.cvss_score else "N/A",
        )

    console.print(table)

    if len(vulnerabilities) > limit:
        console.print(
            f"\n[dim]... and {len(vulnerabilities) - limit} more vulnerabilities[/dim]"
        )


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


@app.command("list-scans")
def list_scans(
    type: str = typer.Option(
        "all", "--type", "-t", help="Filter by scan type (image, sbom, directory, all)"
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter scans with minimum severity (critical, high, medium, low)",
    ),
    limit: Optional[int] = typer.Option(
        None, "--limit", "-n", help="Limit number of results shown"
    ),
    sort_by: str = typer.Option(
        "date", "--sort-by", help="Sort by: date, vulnerabilities, critical, name"
    ),
    details: bool = typer.Option(
        False, "--details", "-d", help="Show detailed view with severity breakdown"
    ),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json"
    ),
):
    """
    List all stored CVE scan results.

    Shows scans from the storage/cve_storage/ directory with metadata including
    scan target, type, total vulnerabilities, severity breakdown, and scan date.

    Examples:
        threat-radar cve list-scans
        threat-radar cve list-scans --type image
        threat-radar cve list-scans --severity critical
        threat-radar cve list-scans --details
        threat-radar cve list-scans --limit 10 --sort-by vulnerabilities
        threat-radar cve list-scans --format json
    """
    from ..core.cve_storage_manager import CVEStorageManager
    from ..utils.cve_utils import display_scans_table

    with handle_cli_error("listing CVE scans", console):
        manager = CVEStorageManager()

        # Get scans
        scans = manager.list_scans(
            type_filter=type, severity_filter=severity, limit=limit, sort_by=sort_by
        )

        if format == "json":
            import json

            scans_data = [
                {
                    "filename": s.filename,
                    "target": s.target,
                    "scan_type": s.scan_type,
                    "total_vulnerabilities": s.total_vulnerabilities,
                    "severity_counts": s.severity_counts,
                    "scan_date": s.scan_date.isoformat(),
                    "file_size": s.file_size,
                }
                for s in scans
            ]
            console.print_json(data=scans_data)
        else:
            display_scans_table(scans, console, details=details)


@app.command("show")
def show_scan(
    scan_file: Path = typer.Argument(
        ..., help="CVE scan file to display (can use wildcards)"
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by severity (critical, high, medium, low, all)",
    ),
    package: Optional[str] = typer.Option(
        None, "--package", "-p", help="Filter by package name (partial match)"
    ),
    cve_id: Optional[str] = typer.Option(
        None, "--cve-id", "-c", help="Filter by specific CVE ID"
    ),
    fixed_only: bool = typer.Option(
        False, "--fixed-only", help="Show only vulnerabilities with fixes"
    ),
    no_fix: bool = typer.Option(
        False, "--no-fix", help="Show only vulnerabilities without fixes"
    ),
    limit: Optional[int] = typer.Option(
        20, "--limit", "-n", help="Limit vulnerabilities shown"
    ),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output: table, json, summary, detailed"
    ),
    group_by: Optional[str] = typer.Option(
        None, "--group-by", "-g", help="Group by: package, severity, type"
    ),
    export: Optional[Path] = typer.Option(
        None, "--export", "-o", help="Export filtered results to file"
    ),
):
    """
    Display detailed information about a specific CVE scan.

    Shows vulnerabilities with filtering, grouping, and export capabilities.

    Examples:
        threat-radar cve show storage/cve_storage/alpine*.json
        threat-radar cve show node_16_*.json --severity critical
        threat-radar cve show scan.json --package openssl
        threat-radar cve show scan.json --cve-id CVE-2023-4863
        threat-radar cve show scan.json --no-fix --severity high
        threat-radar cve show scan.json --group-by package
        threat-radar cve show scan.json --severity high --export critical.json
    """
    from ..core.cve_storage_manager import CVEStorageManager
    from ..utils.cve_utils import (
        display_scan_summary,
        display_vulnerabilities_table,
        display_vulnerabilities_grouped_by_package,
    )
    import glob

    with handle_cli_error("displaying CVE scan", console):
        # Handle wildcards
        scan_path_str = str(scan_file)
        matching_files = glob.glob(scan_path_str)

        if not matching_files:
            console.print(
                f"[red]Error: No files found matching '{scan_path_str}'[/red]"
            )
            raise typer.Exit(code=1)

        if len(matching_files) > 1:
            console.print(
                f"[yellow]Warning: Multiple files match. Using first: {matching_files[0]}[/yellow]"
            )

        scan_path = Path(matching_files[0])

        if not scan_path.exists():
            console.print(f"[red]Error: File not found: {scan_path}[/red]")
            raise typer.Exit(code=1)

        manager = CVEStorageManager()
        scan_data = manager.load_scan(scan_path)
        vulnerabilities = scan_data.get("vulnerabilities", [])

        # Apply filters
        filtered_vulns = vulnerabilities

        # Severity filter
        if severity:
            severity_priority = {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "negligible": 4,
            }
            min_level = severity_priority.get(severity.lower(), 5)
            filtered_vulns = [
                v
                for v in filtered_vulns
                if severity_priority.get(v.get("severity", "").lower(), 5) <= min_level
            ]

        # Package filter
        if package:
            filtered_vulns = [
                v
                for v in filtered_vulns
                if package.lower() in v.get("package", "").lower()
            ]

        # CVE ID filter
        if cve_id:
            filtered_vulns = [
                v for v in filtered_vulns if cve_id.upper() in v.get("id", "").upper()
            ]

        # Fix availability filters
        if fixed_only:
            filtered_vulns = [v for v in filtered_vulns if v.get("fixed_in")]
        elif no_fix:
            filtered_vulns = [v for v in filtered_vulns if not v.get("fixed_in")]

        # Update scan data with filtered vulnerabilities for export
        if export:
            export_data = scan_data.copy()
            export_data["vulnerabilities"] = filtered_vulns
            export_data["total_vulnerabilities"] = len(filtered_vulns)
            save_json(export_data, export, console)

        # Display based on format
        target = (
            scan_data.get("target")
            or scan_data.get("sbom_file")
            or scan_data.get("directory", scan_path.name)
        )

        if format == "json":
            console.print_json(data=scan_data)
        elif format == "summary":
            display_scan_summary(scan_data, target, console)
        elif format == "detailed" or group_by == "package":
            display_vulnerabilities_grouped_by_package(
                filtered_vulns, console, severity
            )
        else:  # table
            if format != "detailed":
                # Show summary first
                display_scan_summary(scan_data, target, console)
                console.print()

            # Then show table
            display_vulnerabilities_table(filtered_vulns, console, limit=limit)


@app.command("search")
def search_scans(
    query: str = typer.Argument(
        ..., help="Search query (CVE ID, package name, or description text)"
    ),
    query_type: str = typer.Option(
        "auto",
        "--query-type",
        "-t",
        help="Search type: auto, cve-id, package, description",
    ),
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s", help="Filter by minimum severity"
    ),
    scans: str = typer.Option(
        "*", "--scans", help="Limit to specific scans (glob pattern)"
    ),
    case_sensitive: bool = typer.Option(
        False, "--case-sensitive", help="Case-sensitive search"
    ),
    exact_match: bool = typer.Option(
        False, "--exact-match", help="Exact match only (no partial)"
    ),
    show_scan_info: bool = typer.Option(
        True, "--show-scan-info", help="Show which scan each result came from"
    ),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json"
    ),
):
    """
    Search across ALL stored CVE scans for specific vulnerabilities, packages, or patterns.

    Searches through all scans in storage/cve_storage/ directory.

    Examples:
        threat-radar cve search CVE-2023-4863
        threat-radar cve search openssl --query-type package
        threat-radar cve search "buffer overflow" --query-type description
        threat-radar cve search "node" --severity critical
        threat-radar cve search "CVE-2023*" --scans "*node*"
        threat-radar cve search "libwebp" --exact-match
    """
    from ..core.cve_storage_manager import CVEStorageManager
    from ..utils.cve_utils import display_search_results

    with handle_cli_error("searching CVE scans", console):
        manager = CVEStorageManager()

        # Perform search
        results = manager.search_scans(
            query=query,
            query_type=query_type,
            severity_filter=severity,
            scan_pattern=scans,
            case_sensitive=case_sensitive,
            exact_match=exact_match,
        )

        if format == "json":
            import json

            results_data = [
                {
                    "scan": {
                        "target": r.scan_metadata.target,
                        "scan_type": r.scan_metadata.scan_type,
                        "scan_date": r.scan_metadata.scan_date.isoformat(),
                    },
                    "matches": r.total_matches,
                    "vulnerabilities": r.matching_vulnerabilities,
                }
                for r in results
            ]
            console.print_json(data=results_data)
        else:
            display_search_results(results, query, console)


@app.command("stats")
def show_stats(
    scans: str = typer.Option("*", "--scans", help="Filter scans (glob pattern)"),
    type: str = typer.Option(
        "all", "--type", "-t", help="Scan type filter (image, sbom, directory, all)"
    ),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json"
    ),
):
    """
    Show aggregate statistics across all stored CVE scans.

    Displays total vulnerabilities, severity breakdown, top CVEs, and more.

    Examples:
        threat-radar cve stats
        threat-radar cve stats --type image
        threat-radar cve stats --scans "*node*"
        threat-radar cve stats --format json
    """
    from ..core.cve_storage_manager import CVEStorageManager
    from ..utils.cve_utils import display_aggregate_stats

    with handle_cli_error("calculating CVE statistics", console):
        manager = CVEStorageManager()

        # Get aggregate stats
        stats = manager.get_aggregate_stats(scan_pattern=scans, type_filter=type)

        if format == "json":
            import json

            stats_data = {
                "total_scans": stats.total_scans,
                "total_storage_size_bytes": stats.total_storage_size,
                "total_vulnerabilities": stats.total_vulnerabilities,
                "unique_cve_ids": stats.unique_cve_ids,
                "severity_breakdown": stats.severity_breakdown,
                "top_cves": [
                    {"cve_id": cve, "scan_count": sc, "package_count": pc}
                    for cve, sc, pc in stats.top_cves
                ],
                "package_type_breakdown": stats.package_type_breakdown,
                "fix_availability": stats.fix_availability,
            }
            console.print_json(data=stats_data)
        else:
            display_aggregate_stats(stats, console)
