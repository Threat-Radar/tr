"""Utility functions for displaying CVE scan data."""
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from collections import defaultdict

from ..core.cve_storage_manager import CVEScanMetadata, CVESearchResult, CVEAggregateStats


def display_scans_table(
    scans: List[CVEScanMetadata],
    console: Console,
    details: bool = False
) -> None:
    """Display CVE scans in a table format.

    Args:
        scans: List of scan metadata
        console: Rich console for output
        details: Show detailed severity breakdown
    """
    if not scans:
        console.print("[yellow]No CVE scans found[/yellow]")
        return

    # Create table
    table = Table(title="Stored CVE Scans")

    if details:
        # Detailed view with full severity breakdown
        table.add_column("Scan Target", style="cyan", no_wrap=False, max_width=40)
        table.add_column("Type", style="magenta")
        table.add_column("Size", style="white")
        table.add_column("Total", style="green", justify="right")
        table.add_column("Crit", style="red bold", justify="right")
        table.add_column("High", style="red", justify="right")
        table.add_column("Med", style="yellow", justify="right")
        table.add_column("Low/Neg", style="blue", justify="right")
        table.add_column("Scan Date", style="blue")

        for scan in scans:
            table.add_row(
                scan.target,
                scan.scan_type,
                scan.file_size_str,
                str(scan.total_vulnerabilities),
                str(scan.critical_count),
                str(scan.high_count),
                str(scan.medium_count),
                str(scan.low_count),
                scan.scan_date.strftime("%Y-%m-%d %H:%M")
            )

    else:
        # Compact view
        table.add_column("Scan Target", style="cyan", no_wrap=False, max_width=40)
        table.add_column("Type", style="magenta")
        table.add_column("Size", style="white")
        table.add_column("Total", style="green", justify="right")
        table.add_column("Critical/High", style="red", justify="right")
        table.add_column("Scan Date", style="blue")

        for scan in scans:
            critical_high = f"{scan.critical_count}/{scan.high_count}"
            table.add_row(
                scan.target,
                scan.scan_type,
                scan.file_size_str,
                str(scan.total_vulnerabilities),
                critical_high,
                scan.scan_date.strftime("%Y-%m-%d %H:%M")
            )

    console.print(table)

    # Summary footer
    total_vulns = sum(s.total_vulnerabilities for s in scans)
    total_critical = sum(s.critical_count for s in scans)
    total_high = sum(s.high_count for s in scans)

    summary = Text()
    summary.append(f"\nTotal: {len(scans)} scan(s)", style="bold")
    summary.append(f" | {total_vulns:,} vulnerabilities", style="green")
    summary.append(f" | {total_critical} critical", style="red bold")
    summary.append(f" | {total_high} high", style="red")

    console.print(summary)


def display_scan_summary(
    scan_data: Dict[str, Any],
    target: str,
    console: Console
) -> None:
    """Display summary of a single CVE scan.

    Args:
        scan_data: Full scan data dictionary
        target: Target name (image, file, directory)
        console: Rich console for output
    """
    total_vulns = scan_data.get("total_vulnerabilities", 0)
    severity_counts = scan_data.get("severity_counts", {})
    vulnerabilities = scan_data.get("vulnerabilities", [])

    # Header
    console.print(f"\n[bold cyan]CVE Scan Report: {target}[/bold cyan]")
    console.print("━" * 60)

    # Scan metadata
    if "scan_metadata" in scan_data and "descriptor" in scan_data["scan_metadata"]:
        timestamp = scan_data["scan_metadata"]["descriptor"].get("timestamp", "Unknown")
        console.print(f"Scanned: {timestamp}")

    console.print(f"Total Vulnerabilities: [bold]{total_vulns}[/bold]\n")

    # Severity breakdown
    console.print("[bold]Severity Breakdown:[/bold]")
    _display_severity_breakdown(severity_counts, total_vulns, console)

    # Fix availability
    if vulnerabilities:
        fixed_count = sum(1 for v in vulnerabilities if v.get("fixed_in"))
        no_fix_count = total_vulns - fixed_count

        console.print("\n[bold]Fix Availability:[/bold]")
        if total_vulns > 0:
            fixed_pct = (fixed_count / total_vulns) * 100
            no_fix_pct = (no_fix_count / total_vulns) * 100
            console.print(f"  ✅ Fixes available: {fixed_pct:.1f}% ({fixed_count})")
            console.print(f"  ❌ No fix:          {no_fix_pct:.1f}% ({no_fix_count})")

        # Top vulnerable packages
        package_vulns = defaultdict(int)
        for vuln in vulnerabilities:
            package = vuln.get("package", "").split("@")[0]
            package_vulns[package] += 1

        if package_vulns:
            console.print("\n[bold]Top 5 Vulnerable Packages:[/bold]")
            top_packages = sorted(package_vulns.items(), key=lambda x: x[1], reverse=True)[:5]
            for i, (package, count) in enumerate(top_packages, 1):
                console.print(f"  {i}. {package:<30} - {count} vulnerabilities")


def display_vulnerabilities_table(
    vulnerabilities: List[Dict[str, Any]],
    console: Console,
    title: str = "Vulnerabilities",
    limit: Optional[int] = 20
) -> None:
    """Display vulnerabilities in a table format.

    Args:
        vulnerabilities: List of vulnerability dictionaries
        console: Rich console for output
        title: Table title
        limit: Maximum number to display
    """
    if not vulnerabilities:
        console.print("[green]✓ No vulnerabilities found[/green]")
        return

    # Sort by severity and CVSS score
    severity_priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4, "unknown": 5}
    sorted_vulns = sorted(
        vulnerabilities,
        key=lambda v: (
            severity_priority.get(v.get("severity", "").lower(), 6),
            -(v.get("cvss_score") or 0)
        )
    )

    # Create table
    table = Table(title=title)
    table.add_column("CVE ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="red")
    table.add_column("Package", style="yellow", max_width=25)
    table.add_column("Installed", style="white", max_width=15)
    table.add_column("Fixed In", style="green", max_width=15)
    table.add_column("CVSS", style="magenta", justify="right")

    # Add rows
    display_count = min(len(sorted_vulns), limit) if limit else len(sorted_vulns)

    for vuln in sorted_vulns[:display_count]:
        severity_color = _get_severity_color(vuln.get("severity", "unknown"))
        severity_text = vuln.get("severity", "UNKNOWN").upper()
        fixed_version = vuln.get("fixed_in") or "No fix"

        # Extract package name and version
        package_full = vuln.get("package", "")
        if "@" in package_full:
            package_name, package_version = package_full.split("@", 1)
        else:
            package_name = package_full
            package_version = "N/A"

        cvss_score = vuln.get("cvss_score")
        cvss_str = f"{cvss_score:.1f}" if cvss_score else "N/A"

        table.add_row(
            vuln.get("id", "N/A"),
            f"[{severity_color}]{severity_text}[/{severity_color}]",
            package_name,
            package_version,
            fixed_version,
            cvss_str
        )

    console.print(table)

    # Show truncation message
    if limit and len(vulnerabilities) > limit:
        remaining = len(vulnerabilities) - limit
        console.print(f"\n[dim]... and {remaining:,} more vulnerabilities (use --limit to see more)[/dim]")


def display_vulnerabilities_grouped_by_package(
    vulnerabilities: List[Dict[str, Any]],
    console: Console,
    severity_filter: Optional[str] = None
) -> None:
    """Display vulnerabilities grouped by package.

    Args:
        vulnerabilities: List of vulnerability dictionaries
        console: Rich console for output
        severity_filter: Optional severity filter for display
    """
    # Group by package
    package_groups = defaultdict(list)

    for vuln in vulnerabilities:
        package = vuln.get("package", "unknown")
        package_groups[package].append(vuln)

    # Sort packages by vulnerability count
    sorted_packages = sorted(
        package_groups.items(),
        key=lambda x: len(x[1]),
        reverse=True
    )

    console.print(f"\n[bold cyan]Vulnerabilities Grouped by Package[/bold cyan]")
    console.print(f"Total packages affected: {len(sorted_packages)}\n")

    for package, pkg_vulns in sorted_packages:
        # Count severity levels
        severity_counts = defaultdict(int)
        for vuln in pkg_vulns:
            severity_counts[vuln.get("severity", "unknown").lower()] += 1

        # Extract package info
        if "@" in package:
            pkg_name, pkg_version = package.split("@", 1)
        else:
            pkg_name = package
            pkg_version = "N/A"

        pkg_type = pkg_vulns[0].get("package_type", "unknown")

        # Build severity summary
        severity_summary = []
        for sev in ["critical", "high", "medium", "low", "negligible"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                color = _get_severity_color(sev)
                severity_summary.append(f"[{color}]{count} {sev.upper()}[/{color}]")

        # Display package header
        console.print("━" * 60)
        console.print(f"[bold yellow]Package:[/bold yellow] {pkg_name}@{pkg_version} ({pkg_type})")
        console.print(f"[bold]Vulnerabilities:[/bold] {len(pkg_vulns)} ({', '.join(severity_summary)})\n")

        # Display vulnerabilities for this package
        for vuln in sorted(pkg_vulns, key=lambda v: _severity_sort_key(v.get("severity", ""))):
            severity = vuln.get("severity", "unknown")
            color = _get_severity_color(severity)
            icon = _get_severity_icon(severity)

            cve_id = vuln.get("id", "N/A")
            cvss = vuln.get("cvss_score")
            cvss_str = f"CVSS: {cvss:.1f}" if cvss else ""
            fixed_in = vuln.get("fixed_in", "No fix available")

            console.print(f"  {icon} [{color}]{cve_id} [{severity.upper()}][/{color}] {cvss_str}")
            console.print(f"     Fixed in: {fixed_in}")

            # Show description (truncated)
            description = vuln.get("description", "")
            if description:
                desc_short = description[:100] + "..." if len(description) > 100 else description
                console.print(f"     {desc_short}\n", style="dim")
            else:
                console.print()


def display_search_results(
    results: List[CVESearchResult],
    query: str,
    console: Console
) -> None:
    """Display CVE search results.

    Args:
        results: List of search results
        query: Original search query
        console: Rich console for output
    """
    if not results:
        console.print(f"[yellow]No results found for '{query}'[/yellow]")
        return

    console.print(f"\n[bold cyan]Search Results: {query}[/bold cyan]")
    console.print(f"Found in {len(results)} scan(s)\n")

    total_matches = sum(r.total_matches for r in results)

    for result in results:
        console.print("━" * 60)
        console.print(f"[bold]Scan:[/bold] {result.scan_metadata.target} ({result.scan_metadata.scan_date.strftime('%Y-%m-%d %H:%M')})")
        console.print(f"[bold]Matches:[/bold] {result.total_matches}\n")

        # Display matching vulnerabilities
        display_vulnerabilities_table(
            result.matching_vulnerabilities,
            console,
            title="",
            limit=None
        )

        console.print()

    console.print(f"\n[bold]Total:[/bold] {total_matches} occurrences across {len(results)} scan(s)")


def display_aggregate_stats(
    stats: CVEAggregateStats,
    console: Console
) -> None:
    """Display aggregate CVE statistics.

    Args:
        stats: Aggregate statistics
        console: Rich console for output
    """
    console.print("\n[bold cyan]CVE Storage Statistics[/bold cyan]")
    console.print("━" * 60)

    # Basic stats
    console.print(f"\nTotal Scans: [bold]{stats.total_scans}[/bold]")
    size_mb = stats.total_storage_size / (1024 * 1024)
    console.print(f"Total Storage Size: [bold]{size_mb:.1f} MB[/bold]")

    # Vulnerability summary
    console.print("\n[bold]Vulnerability Summary:[/bold]")
    console.print(f"  Total Vulnerabilities: {stats.total_vulnerabilities:,}")
    console.print(f"  Unique CVE IDs: {stats.unique_cve_ids:,}")

    # Severity breakdown
    console.print("\n[bold]  By Severity:[/bold]")
    _display_severity_breakdown(stats.severity_breakdown, stats.total_vulnerabilities, console, indent="    ")

    # Fix availability
    if stats.fix_availability["fixed"] > 0 or stats.fix_availability["no_fix"] > 0:
        total = stats.fix_availability["fixed"] + stats.fix_availability["no_fix"]
        fixed_pct = (stats.fix_availability["fixed"] / total) * 100 if total > 0 else 0

        console.print("\n[bold]  Fix Availability:[/bold]")
        console.print(f"    ✅ Fixes available: {fixed_pct:.1f}% ({stats.fix_availability['fixed']:,})")
        console.print(f"    ❌ No fix: {100-fixed_pct:.1f}% ({stats.fix_availability['no_fix']:,})")

    # Top CVEs
    if stats.top_cves:
        console.print("\n[bold]Top 10 Most Common CVEs:[/bold]")
        for i, (cve_id, scan_count, package_count) in enumerate(stats.top_cves, 1):
            scan_text = "scan" if scan_count == 1 else "scans"
            pkg_text = "package" if package_count == 1 else "packages"
            console.print(f"  {i:2d}. {cve_id:<20} → Found in {scan_count} {scan_text} ({package_count} {pkg_text})")

    # Package type breakdown
    if stats.package_type_breakdown:
        console.print("\n[bold]Most Vulnerable Package Types:[/bold]")
        for i, (pkg_type, count) in enumerate(list(stats.package_type_breakdown.items())[:5], 1):
            console.print(f"  {i}. {pkg_type:<15} → {count:,} vulnerabilities")


def _display_severity_breakdown(
    severity_counts: Dict[str, int],
    total: int,
    console: Console,
    indent: str = "  "
) -> None:
    """Display severity breakdown with percentages."""
    severity_order = [
        ("critical", "🔴", "red bold"),
        ("high", "🟠", "red"),
        ("medium", "🟡", "yellow"),
        ("low", "🔵", "blue"),
        ("negligible", "⚪", "white"),
        ("unknown", "❓", "dim")
    ]

    for severity, icon, color in severity_order:
        count = severity_counts.get(severity, 0)
        if count > 0:
            percentage = (count / total * 100) if total > 0 else 0
            console.print(
                f"{indent}{icon} [{color}]{severity.capitalize():<12}[/{color}] {count:>6,}  ({percentage:>5.1f}%)"
            )


def _get_severity_color(severity: str) -> str:
    """Get color for severity level."""
    severity = severity.lower()
    colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "negligible": "white",
        "unknown": "dim"
    }
    return colors.get(severity, "white")


def _get_severity_icon(severity: str) -> str:
    """Get icon for severity level."""
    severity = severity.lower()
    icons = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "negligible": "⚪",
        "unknown": "❓"
    }
    return icons.get(severity, "⚪")


def _severity_sort_key(severity: str) -> int:
    """Get sort key for severity level."""
    severity_priority = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "negligible": 4,
        "unknown": 5
    }
    return severity_priority.get(severity.lower(), 6)
