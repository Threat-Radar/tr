"""CVE operations CLI commands."""
import typer
from typing import List, Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from dataclasses import asdict

from ..core.nvd_client import NVDClient
from ..core.cve_database import CVEDatabase
from ..core.cve_matcher import CVEMatcher
from ..core.container_analyzer import ContainerAnalyzer
from ..utils import docker_analyzer, save_json, handle_cli_error

app = typer.Typer(help="CVE vulnerability operations")
console = Console()


@app.command("get")
def get_cve(
    cve_ids: List[str] = typer.Argument(..., help="CVE IDs to retrieve (e.g., CVE-2021-44228)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON file"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass cache and fetch from NVD"),
):
    """
    Retrieve specific CVEs by ID.

    Fetches CVE details from NVD API or local cache.
    """
    with handle_cli_error("retrieving CVEs", console):
        client = NVDClient()

        results = []
        for cve_id in cve_ids:
            console.print(f"\n[cyan]Fetching {cve_id}...[/cyan]")

            cve = client.get_cve_by_id(cve_id, use_cache=not no_cache)

            if cve:
                _display_cve(cve)
                results.append(asdict(cve))
            else:
                console.print(f"[yellow]CVE {cve_id} not found[/yellow]")

        client.close()

        # Save to file if requested
        if output and results:
            save_json({"cves": results, "count": len(results)}, output, console)


@app.command("search")
def search_cves(
    keyword: Optional[str] = typer.Option(None, "--keyword", "-k", help="Search keyword"),
    cpe: Optional[str] = typer.Option(None, "--cpe", help="CPE name to search"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="CVSS severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    days: Optional[int] = typer.Option(None, "--days", "-d", help="CVEs modified in last N days"),
    limit: int = typer.Option(20, "--limit", "-n", help="Maximum results to return"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON file"),
):
    """
    Search for CVEs using various filters.

    Search the NVD database by keyword, CPE, severity, or modification date.
    """
    with handle_cli_error("searching CVEs", console):
        client = NVDClient()

        console.print("\n[cyan]Searching NVD database...[/cyan]")

        if days:
            cves = client.get_recent_cves(days=days)
        else:
            from datetime import datetime, timedelta
            cves = client.search_cves(
                keyword=keyword,
                cpe_name=cpe,
                cvss_severity=severity,
                results_per_page=limit
            )

        if not cves:
            console.print("[yellow]No CVEs found matching criteria[/yellow]")
            client.close()
            return

        # Display results in table
        table = Table(title=f"CVE Search Results ({len(cves)} found)")
        table.add_column("CVE ID", style="cyan", no_wrap=True)
        table.add_column("Severity", style="red")
        table.add_column("CVSS", style="yellow")
        table.add_column("Description", style="white")

        for cve in cves[:limit]:
            severity_color = _get_severity_color(cve.severity)
            table.add_row(
                cve.cve_id,
                f"[{severity_color}]{cve.severity or 'N/A'}[/{severity_color}]",
                f"{cve.cvss_score or 'N/A'}",
                cve.description[:80] + "..." if len(cve.description) > 80 else cve.description
            )

        console.print(table)
        client.close()

        # Save to file if requested
        if output:
            results = [asdict(cve) for cve in cves]
            save_json({"cves": results, "count": len(results)}, output, console)


@app.command("update")
def update_database(
    days: int = typer.Option(7, "--days", "-d", help="Number of days to look back"),
    force: bool = typer.Option(False, "--force", "-f", help="Force update even if recently updated"),
):
    """
    Update local CVE database from NVD.

    Downloads recent CVEs and stores them locally for faster searching.
    """
    with handle_cli_error("updating database", console):
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Updating CVE database (last {days} days)...", total=None)

            db = CVEDatabase()
            count = db.update_from_nvd(days=days, force=force)

            progress.update(task, completed=True, description="Update complete!")

            console.print(f"\n[green]✓ Updated {count} CVEs in local database[/green]")

            # Show database stats
            stats = db.get_stats()
            console.print(f"\n[bold]Database Statistics:[/bold]")
            console.print(f"  Total CVEs: {stats['total_cves']}")
            console.print(f"  Last Update: {stats.get('last_update', 'Never')}")

            if stats.get('by_severity'):
                console.print(f"\n[bold]By Severity:[/bold]")
                for severity, count in sorted(stats['by_severity'].items()):
                    color = _get_severity_color(severity)
                    console.print(f"  [{color}]{severity}[/{color}]: {count}")

            db.close()


@app.command("db-search")
def search_local(
    keyword: Optional[str] = typer.Option(None, "--keyword", "-k", help="Search keyword in description"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity"),
    min_cvss: Optional[float] = typer.Option(None, "--min-cvss", help="Minimum CVSS score"),
    limit: int = typer.Option(20, "--limit", "-n", help="Maximum results"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON file"),
):
    """
    Search local CVE database (faster than NVD API).

    Queries the local database built with 'cve update' command.
    """
    with handle_cli_error("searching local database", console):
        db = CVEDatabase()

        console.print("\n[cyan]Searching local database...[/cyan]")

        cves = db.search_cves(
            severity=severity,
            min_cvss_score=min_cvss,
            keyword=keyword,
            limit=limit
        )

        if not cves:
            console.print("[yellow]No CVEs found in local database[/yellow]")
            console.print("[dim]Tip: Run 'threat-radar cve update' to populate the database[/dim]")
            db.close()
            return

        # Display results
        table = Table(title=f"Local Database Results ({len(cves)} found)")
        table.add_column("CVE ID", style="cyan", no_wrap=True)
        table.add_column("Severity", style="red")
        table.add_column("CVSS", style="yellow")
        table.add_column("Published", style="blue")
        table.add_column("Description", style="white")

        for cve in cves:
            severity_color = _get_severity_color(cve.severity)
            published = cve.published_date[:10] if cve.published_date else "N/A"
            table.add_row(
                cve.cve_id,
                f"[{severity_color}]{cve.severity or 'N/A'}[/{severity_color}]",
                f"{cve.cvss_score or 'N/A'}",
                published,
                cve.description[:60] + "..." if len(cve.description) > 60 else cve.description
            )

        console.print(table)
        db.close()

        # Save to file if requested
        if output:
            results = [asdict(cve) for cve in cves]
            save_json({"cves": results, "count": len(results)}, output, console)


@app.command("scan-image")
def scan_docker_image(
    image: str = typer.Argument(..., help="Docker image to scan"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by minimum severity"),
    confidence: float = typer.Option(0.7, "--confidence", "-c", help="Minimum confidence threshold (0.0-1.0)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON file"),
):
    """
    Scan Docker image for CVE vulnerabilities.

    Analyzes packages in a Docker image and matches them against CVE database.
    """
    with handle_cli_error("scanning image", console):
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            # Analyze container
            task1 = progress.add_task(f"Analyzing {image}...", total=None)

            with docker_analyzer() as analyzer:
                analysis = analyzer.analyze_container(image)
                progress.update(task1, completed=True, description="Analysis complete!")

                if not analysis.packages:
                    console.print(f"[yellow]No packages found in {image}[/yellow]")
                    return

                console.print(f"\n[bold]Found {len(analysis.packages)} packages[/bold]")

            # Update CVE database
            task2 = progress.add_task("Updating CVE database...", total=None)
            db = CVEDatabase()
            db.update_from_nvd(days=30, force=False)
            progress.update(task2, completed=True, description="Database ready!")

            # Get recent CVEs
            task3 = progress.add_task("Fetching CVEs...", total=None)
            cves = db.search_cves(severity=severity, limit=5000)
            progress.update(task3, completed=True, description=f"Loaded {len(cves)} CVEs!")

            # Match packages against CVEs
            task4 = progress.add_task("Matching vulnerabilities...", total=None)
            matcher = CVEMatcher(min_confidence=confidence)
            matches = matcher.bulk_match_packages(analysis.packages, cves)
            progress.update(task4, completed=True, description="Matching complete!")

        # Display results
        if not matches:
            console.print("\n[green]✓ No vulnerabilities found![/green]")
            db.close()
            return

        console.print(f"\n[red]⚠ Found vulnerabilities in {len(matches)} packages:[/red]\n")

        for package_name, package_matches in matches.items():
            console.print(f"\n[bold yellow]{package_name}[/bold yellow]")

            for match in package_matches[:3]:  # Show top 3 matches per package
                severity_color = _get_severity_color(match.cve.severity)
                console.print(f"  [{severity_color}]● {match.cve.cve_id}[/{severity_color}] "
                             f"(Confidence: {match.confidence:.0%})")
                console.print(f"    Severity: [{severity_color}]{match.cve.severity or 'N/A'}[/{severity_color}] "
                             f"| CVSS: {match.cve.cvss_score or 'N/A'}")
                console.print(f"    {match.match_reason}")

        # Summary
        total_vulns = sum(len(m) for m in matches.values())
        console.print(f"\n[bold]Summary:[/bold]")
        console.print(f"  Vulnerable packages: {len(matches)}")
        console.print(f"  Total vulnerabilities: {total_vulns}")

        db.close()

        # Save to file if requested
        if output:
            results = {
                "image": image,
                "total_packages": len(analysis.packages),
                "vulnerable_packages": len(matches),
                "matches": {
                    pkg: [{"cve_id": m.cve.cve_id, "confidence": m.confidence,
                          "severity": m.cve.severity, "cvss_score": m.cve.cvss_score}
                         for m in match_list]
                    for pkg, match_list in matches.items()
                }
            }
            save_json(results, output, console)


@app.command("stats")
def database_stats():
    """
    Show local CVE database statistics.

    Displays information about the local CVE database.
    """
    with handle_cli_error("fetching stats", console):
        db = CVEDatabase()
        stats = db.get_stats()

        console.print("\n[bold cyan]CVE Database Statistics[/bold cyan]\n")

        # Basic stats
        info_table = Table(show_header=False, box=None)
        info_table.add_column("Property", style="yellow")
        info_table.add_column("Value", style="white")

        info_table.add_row("Total CVEs", str(stats['total_cves']))
        info_table.add_row("Last Update", str(stats.get('last_update', 'Never')))

        if stats.get('date_range'):
            info_table.add_row("Earliest CVE", stats['date_range']['earliest'] or 'N/A')
            info_table.add_row("Latest CVE", stats['date_range']['latest'] or 'N/A')

        console.print(info_table)

        # Severity breakdown
        if stats.get('by_severity'):
            console.print("\n[bold]CVEs by Severity:[/bold]")
            severity_table = Table()
            severity_table.add_column("Severity", style="cyan")
            severity_table.add_column("Count", style="green", justify="right")
            severity_table.add_column("Percentage", style="magenta", justify="right")

            total = stats['total_cves']
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = stats['by_severity'].get(severity, 0)
                percentage = (count / total * 100) if total > 0 else 0
                color = _get_severity_color(severity)

                severity_table.add_row(
                    f"[{color}]{severity}[/{color}]",
                    f"{count:,}",
                    f"{percentage:.1f}%"
                )

            console.print(severity_table)

        db.close()


@app.command("clear-cache")
def clear_cache(
    days: Optional[int] = typer.Option(None, "--older-than", help="Clear cache older than N days"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """
    Clear CVE cache.

    Removes cached CVE data to free up space or force fresh downloads.
    """
    with handle_cli_error("clearing cache", console):
        if not confirm:
            if days:
                message = f"Clear cache entries older than {days} days?"
            else:
                message = "Clear ALL cache entries?"

            if not typer.confirm(message):
                console.print("[yellow]Cancelled[/yellow]")
                return

        client = NVDClient()
        removed = client.clear_cache(older_than_days=days)
        client.close()

        console.print(f"[green]✓ Removed {removed} cached files[/green]")


def _display_cve(cve) -> None:
    """Display detailed CVE information."""
    console.print(f"\n[bold cyan]{cve.cve_id}[/bold cyan]")

    # Basic info
    info_table = Table(show_header=False, box=None)
    info_table.add_column("Property", style="yellow")
    info_table.add_column("Value", style="white")

    severity_color = _get_severity_color(cve.severity)
    info_table.add_row("Severity", f"[{severity_color}]{cve.severity or 'N/A'}[/{severity_color}]")
    info_table.add_row("CVSS Score", str(cve.cvss_score or 'N/A'))
    info_table.add_row("Published", cve.published_date[:10] if cve.published_date else 'N/A')
    info_table.add_row("Modified", cve.last_modified_date[:10] if cve.last_modified_date else 'N/A')

    if cve.cwe_ids:
        info_table.add_row("CWE IDs", ", ".join(cve.cwe_ids))

    console.print(info_table)

    # Description
    console.print(f"\n[bold]Description:[/bold]")
    console.print(cve.description)

    # Affected products
    if cve.affected_products:
        console.print(f"\n[bold]Affected Products:[/bold] ({len(cve.affected_products)} entries)")
        for product in cve.affected_products[:5]:
            console.print(f"  • {product.get('cpe23Uri', 'N/A')}")
        if len(cve.affected_products) > 5:
            console.print(f"  ... and {len(cve.affected_products) - 5} more")


def _get_severity_color(severity: Optional[str]) -> str:
    """Get color for severity level."""
    if not severity:
        return "white"

    severity = severity.upper()
    colors = {
        "CRITICAL": "red bold",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
    }
    return colors.get(severity, "white")
