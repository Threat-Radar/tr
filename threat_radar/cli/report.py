"""Comprehensive report generation commands."""
import typer
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
import json

from ..utils.comprehensive_report import ComprehensiveReportGenerator
from ..utils.report_templates import ReportLevel
from ..utils.report_formatters import get_formatter
from ..utils import handle_cli_error
from ..core.grype_integration import GrypeScanResult, GrypeVulnerability

app = typer.Typer(help="Comprehensive vulnerability report generation")
console = Console()


def load_scan_results(scan_file: Path) -> GrypeScanResult:
    """Load scan results from JSON file."""
    if not scan_file.exists():
        raise FileNotFoundError(f"Scan results file not found: {scan_file}")

    with open(scan_file, 'r') as f:
        data = json.load(f)

    # Parse vulnerabilities
    vulnerabilities = []
    for v in data.get('vulnerabilities', []):
        # Handle both old and new formats
        if 'package_name' in v:
            package_name = v['package_name']
            package_version = v['package_version']
        elif 'package' in v:
            package_full = v['package']
            if '@' in package_full:
                package_name, package_version = package_full.rsplit('@', 1)
            else:
                package_name = package_full
                package_version = 'unknown'
        else:
            package_name = 'unknown'
            package_version = 'unknown'

        fixed_in_version = v.get('fixed_in_version') or v.get('fixed_in')

        vulnerabilities.append(
            GrypeVulnerability(
                id=v['id'],
                severity=v['severity'],
                package_name=package_name,
                package_version=package_version,
                package_type=v.get('package_type', 'unknown'),
                fixed_in_version=fixed_in_version,
                description=v.get('description'),
                cvss_score=v.get('cvss_score'),
                urls=v.get('urls', []),
                data_source=v.get('data_source'),
                namespace=v.get('namespace'),
                artifact_path=v.get('artifact_path'),
                artifact_location=v.get('artifact_location'),
            )
        )

    return GrypeScanResult(
        target=data.get('target', 'unknown'),
        vulnerabilities=vulnerabilities,
        total_count=len(vulnerabilities),
        severity_counts=data.get('severity_counts', {}),
        scan_metadata=data.get('scan_metadata'),
    )


@app.command("generate")
def generate_report(
    scan_file: Path = typer.Argument(..., exists=True, help="Path to CVE scan results JSON file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path (format inferred from extension)"),
    format: str = typer.Option("json", "--format", "-f", help="Output format (json, markdown, html, pdf)"),
    level: str = typer.Option("detailed", "--level", "-l", help="Report level (executive, summary, detailed, critical-only)"),
    include_executive_summary: bool = typer.Option(True, "--executive/--no-executive", help="Include AI-powered executive summary"),
    include_dashboard_data: bool = typer.Option(True, "--dashboard/--no-dashboard", help="Include dashboard visualization data"),
    attack_paths_file: Optional[Path] = typer.Option(None, "--attack-paths", help="Path to attack paths JSON file (from graph attack-paths command)"),
    ai_provider: Optional[str] = typer.Option(None, "--ai-provider", help="AI provider for executive summary (openai, ollama)"),
    ai_model: Optional[str] = typer.Option(None, "--ai-model", help="AI model name"),
):
    """
    Generate comprehensive vulnerability report with AI-powered insights.

    Supports multiple output formats and report levels for different audiences.

    Examples:
        # Generate detailed report with AI summary
        threat-radar report generate scan-results.json -o report.html -f html

        # Executive summary in Markdown
        threat-radar report generate scan-results.json -o summary.md -f markdown --level executive

        # Critical-only issues in JSON
        threat-radar report generate scan-results.json -o critical.json --level critical-only

        # Report with attack path analysis
        threat-radar report generate scan.json -o report.html --attack-paths attack-paths.json

        # Full report with custom AI model and attack paths
        threat-radar report generate scan-results.json --ai-provider ollama --ai-model llama2 --attack-paths paths.json
    """
    with handle_cli_error("generating report", console):
        # Validate report level
        try:
            # Replace hyphens with underscores for enum compatibility
            report_level = ReportLevel(level.lower().replace("-", "_"))
        except ValueError:
            console.print(f"[red]Invalid report level: {level}[/red]")
            console.print(f"Valid levels: executive, summary, detailed, critical-only")
            raise typer.Exit(code=1)

        # Load scan results
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Loading scan results...", total=None)
            scan_result = load_scan_results(scan_file)
            progress.update(task, completed=True, description=f"Loaded {scan_result.total_count} vulnerabilities")

        if scan_result.total_count == 0:
            console.print("[yellow]No vulnerabilities found in scan results.[/yellow]")
            return

        # Generate report
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Generating comprehensive report...", total=None)

            generator = ComprehensiveReportGenerator(ai_provider=ai_provider, ai_model=ai_model)

            report = generator.generate_report(
                scan_result=scan_result,
                report_level=report_level,
                include_executive_summary=include_executive_summary,
                include_dashboard_data=include_dashboard_data,
                attack_paths_file=attack_paths_file,
            )

            progress.update(task, completed=True, description="Report generated!")

        # Display summary
        console.print("\n")
        console.print(Panel(
            f"[bold]Report Generated Successfully[/bold]\n\n"
            f"Report ID: {report.report_id}\n"
            f"Target: {report.target}\n"
            f"Level: {report.report_level}\n"
            f"Total Vulnerabilities: {report.summary.total_vulnerabilities}\n"
            f"Critical/High: {report.summary.critical + report.summary.high}",
            border_style="green"
        ))

        # Show executive summary if present
        if report.executive_summary:
            console.print(f"\n[bold cyan]Executive Summary:[/bold cyan]")
            console.print(f"Risk Rating: [bold]{report.executive_summary.overall_risk_rating}[/bold]")
            console.print(f"\nKey Findings:")
            for finding in report.executive_summary.key_findings[:3]:
                console.print(f"  • {finding}")

        # Show attack surface data if present
        if report.attack_surface_data:
            console.print(f"\n[bold cyan]Attack Surface Analysis:[/bold cyan]")
            console.print(f"Total Attack Paths: {report.attack_surface_data.total_attack_paths}")
            console.print(f"Critical Paths: {report.attack_surface_data.critical_paths}")
            console.print(f"High Paths: {report.attack_surface_data.high_paths}")
            console.print(f"Risk Score: {report.attack_surface_data.total_risk_score:.2f}/100")

        # Determine output format
        output_format = format
        if output and not format:
            # Infer from file extension
            ext = output.suffix.lstrip('.')
            output_format = ext if ext in ['json', 'md', 'markdown', 'html', 'pdf'] else 'json'

        # Format output
        formatter = get_formatter(output_format)
        formatted_output = formatter.format(report)

        # Save to file if specified
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)

            # Handle binary formats (PDF)
            if output_format == 'pdf':
                with open(output, 'wb') as f:
                    f.write(formatted_output)
            else:
                with open(output, 'w') as f:
                    f.write(formatted_output)

            console.print(f"\n[green]✓ Report saved to: {output}[/green]")
        else:
            # Print to console (JSON only for readability)
            if output_format == 'pdf':
                console.print("[yellow]PDF output requires --output file path.[/yellow]")
            elif output_format == 'json':
                console.print_json(formatted_output)
            else:
                console.print(formatted_output)


@app.command("dashboard-export")
def export_dashboard_data(
    scan_file: Path = typer.Argument(..., exists=True, help="Path to CVE scan results JSON file"),
    output: Path = typer.Option(..., "--output", "-o", help="Output JSON file for dashboard data"),
):
    """
    Export dashboard-ready visualization data from scan results.

    Generates JSON data optimized for dashboard integrations (Grafana, custom dashboards, etc.).

    Example:
        threat-radar report dashboard-export scan-results.json -o dashboard.json
    """
    with handle_cli_error("exporting dashboard data", console):
        # Load scan results
        scan_result = load_scan_results(scan_file)

        # Generate report with dashboard data
        generator = ComprehensiveReportGenerator()
        report = generator.generate_report(
            scan_result=scan_result,
            report_level=ReportLevel.SUMMARY,
            include_executive_summary=False,
            include_dashboard_data=True,
        )

        if not report.dashboard_data:
            console.print("[yellow]No dashboard data generated.[/yellow]")
            return

        # Save dashboard data
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, 'w') as f:
            json.dump(report.dashboard_data.to_dict(), f, indent=2)

        console.print(f"\n[green]✓ Dashboard data exported to: {output}[/green]")

        # Show summary
        console.print(f"\n[bold]Dashboard Data Summary:[/bold]")
        console.print(f"  • Summary Cards: {len(report.dashboard_data.summary_cards)} metrics")
        console.print(f"  • Severity Distribution: {len(report.dashboard_data.severity_distribution_chart)} categories")
        console.print(f"  • Top Packages: {len(report.dashboard_data.top_vulnerable_packages_chart)} packages")
        console.print(f"  • Critical Items: {len(report.dashboard_data.critical_items)} items")


@app.command("compare")
def compare_reports(
    report1: Path = typer.Argument(..., exists=True, help="First report JSON file"),
    report2: Path = typer.Argument(..., exists=True, help="Second report JSON file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output comparison report"),
):
    """
    Compare two vulnerability reports to track changes over time.

    Shows new vulnerabilities, fixed vulnerabilities, and overall trends.

    Example:
        threat-radar report compare old-scan.json new-scan.json -o comparison.md
    """
    with handle_cli_error("comparing reports", console):
        # Load both scan results
        scan1 = load_scan_results(report1)
        scan2 = load_scan_results(report2)

        # Build sets of CVE IDs
        cves1 = set(v.id for v in scan1.vulnerabilities)
        cves2 = set(v.id for v in scan2.vulnerabilities)

        # Calculate differences
        new_cves = cves2 - cves1
        fixed_cves = cves1 - cves2
        common_cves = cves1 & cves2

        # Display comparison
        console.print("\n[bold cyan]Vulnerability Report Comparison[/bold cyan]\n")

        console.print(f"Report 1: {report1.name}")
        console.print(f"  Total Vulnerabilities: {scan1.total_count}")
        console.print(f"  Critical: {scan1.severity_counts.get('critical', 0)}")
        console.print(f"  High: {scan1.severity_counts.get('high', 0)}\n")

        console.print(f"Report 2: {report2.name}")
        console.print(f"  Total Vulnerabilities: {scan2.total_count}")
        console.print(f"  Critical: {scan2.severity_counts.get('critical', 0)}")
        console.print(f"  High: {scan2.severity_counts.get('high', 0)}\n")

        console.print(f"[bold]Changes:[/bold]")
        console.print(f"  [red]New Vulnerabilities: {len(new_cves)}[/red]")
        console.print(f"  [green]Fixed Vulnerabilities: {len(fixed_cves)}[/green]")
        console.print(f"  Common: {len(common_cves)}\n")

        # Show new vulnerabilities
        if new_cves:
            console.print(f"[bold red]New Vulnerabilities:[/bold red]")
            new_vulns = [v for v in scan2.vulnerabilities if v.id in new_cves]
            for v in sorted(new_vulns, key=lambda x: (0 if x.severity == 'critical' else 1 if x.severity == 'high' else 2))[:10]:
                console.print(f"  • {v.id} - {v.package_name} ({v.severity.upper()})")

        # Show fixed vulnerabilities
        if fixed_cves:
            console.print(f"\n[bold green]Fixed Vulnerabilities:[/bold green]")
            fixed_vulns = [v for v in scan1.vulnerabilities if v.id in fixed_cves]
            for v in sorted(fixed_vulns, key=lambda x: (0 if x.severity == 'critical' else 1 if x.severity == 'high' else 2))[:10]:
                console.print(f"  • {v.id} - {v.package_name} ({v.severity.upper()})")

        # Generate comparison report if output specified
        if output:
            comparison_data = {
                'comparison_date': typer.get_text_stream('stdin').isatty(),
                'report1': {
                    'file': str(report1),
                    'total_vulnerabilities': scan1.total_count,
                    'severity_counts': scan1.severity_counts,
                },
                'report2': {
                    'file': str(report2),
                    'total_vulnerabilities': scan2.total_count,
                    'severity_counts': scan2.severity_counts,
                },
                'changes': {
                    'new_vulnerabilities': list(new_cves),
                    'fixed_vulnerabilities': list(fixed_cves),
                    'common_vulnerabilities': len(common_cves),
                },
                'trend': 'improving' if len(fixed_cves) > len(new_cves) else 'worsening' if len(new_cves) > len(fixed_cves) else 'stable',
            }

            output.parent.mkdir(parents=True, exist_ok=True)
            with open(output, 'w') as f:
                json.dump(comparison_data, f, indent=2)

            console.print(f"\n[green]✓ Comparison report saved to: {output}[/green]")
