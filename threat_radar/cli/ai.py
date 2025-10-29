"""AI-powered vulnerability analysis and remediation commands."""
import typer
from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.markdown import Markdown
import json

from ..core.grype_integration import GrypeScanResult, GrypeVulnerability
from ..ai.vulnerability_analyzer import VulnerabilityAnalyzer
from ..ai.prioritization import PrioritizationEngine
from ..ai.remediation_generator import RemediationGenerator
from ..ai.business_context_analyzer import BusinessContextAnalyzer
from ..environment.parser import EnvironmentParser
from ..utils import save_json, handle_cli_error, get_ai_storage

app = typer.Typer(help="AI-powered vulnerability analysis and remediation")
console = Console()


def load_cve_results(file_path: str) -> GrypeScanResult:
    """Load CVE scan results from JSON file"""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(path, "r") as f:
        data = json.load(f)

    # Parse JSON back into GrypeScanResult
    vulnerabilities = []
    for v in data.get("vulnerabilities", []):
        # Handle both old and new formats
        # Old format: "package": "name@version"
        # New format: "package_name": "name", "package_version": "version"
        if "package_name" in v:
            package_name = v["package_name"]
            package_version = v["package_version"]
        elif "package" in v:
            # Parse "name@version" format
            package_full = v["package"]
            if "@" in package_full:
                package_name, package_version = package_full.rsplit("@", 1)
            else:
                package_name = package_full
                package_version = "unknown"
        else:
            package_name = "unknown"
            package_version = "unknown"

        # Handle both "fixed_in" and "fixed_in_version"
        fixed_in_version = v.get("fixed_in_version") or v.get("fixed_in")

        vulnerabilities.append(
            GrypeVulnerability(
                id=v["id"],
                severity=v["severity"],
                package_name=package_name,
                package_version=package_version,
                package_type=v.get("package_type", "unknown"),
                fixed_in_version=fixed_in_version,
                description=v.get("description"),
                cvss_score=v.get("cvss_score"),
                urls=v.get("urls", []),
                data_source=v.get("data_source"),
                namespace=v.get("namespace"),
                artifact_path=v.get("artifact_path"),
                artifact_location=v.get("artifact_location"),
            )
        )

    return GrypeScanResult(
        target=data.get("target", "unknown"),
        vulnerabilities=vulnerabilities,
        total_count=len(vulnerabilities),
        severity_counts=data.get("severity_counts", {}),
        scan_metadata=data.get("scan_metadata"),
    )


@app.command("analyze")
def analyze_vulnerabilities(
    cve_results: str = typer.Argument(..., help="Path to CVE scan results JSON file"),
    provider: Optional[str] = typer.Option(None, "--provider", "-p", help="AI provider (openai, anthropic, ollama)"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name (e.g., gpt-4o, llama2)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save analysis to JSON file"),
    auto_save: bool = typer.Option(False, "--auto-save", "--as", help="Auto-save to storage/ai_analysis/"),
    batch_mode: str = typer.Option(
        "auto",
        "--batch-mode",
        help="Batch processing mode: auto (default), enabled, disabled"
    ),
    batch_size: int = typer.Option(
        25,
        "--batch-size",
        help="Vulnerabilities per batch (default: 25)"
    ),
    show_progress: bool = typer.Option(
        True,
        "--progress/--no-progress",
        help="Show progress bar for batch processing"
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        help="Filter to minimum severity: critical, high, medium, low"
    ),
):
    """
    Analyze vulnerabilities using AI to assess exploitability and business impact.

    Reads CVE scan results and uses AI to provide:
    - Exploitability assessment (how easily can it be exploited)
    - Attack vector analysis (what are the possible attack methods)
    - Business impact evaluation (potential damage to operations)
    - Contextual recommendations

    BATCH PROCESSING:
    - Automatically handles large scans (>30 CVEs) via batch processing
    - Use --batch-mode to control: auto (default), enabled, disabled
    - Adjust --batch-size for optimal performance (default: 25)

    Examples:
        # Auto batch for large scans (recommended)
        threat-radar ai analyze cve-results.json

        # Analyze only critical and high severity vulnerabilities
        threat-radar ai analyze scan.json --severity high

        # Force batch mode with custom size
        threat-radar ai analyze scan.json --batch-mode enabled --batch-size 30

        # Combine severity filter with batching
        threat-radar ai analyze large-scan.json --severity critical --batch-size 20

        # Disable batching (may fail for large scans)
        threat-radar ai analyze scan.json --batch-mode disabled

        # With specific AI provider
        threat-radar ai analyze results.json --provider openai --model gpt-4o
    """
    with handle_cli_error("analyzing vulnerabilities", console):
        # Load CVE scan results
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Loading CVE results...", total=None)
            scan_result = load_cve_results(cve_results)
            progress.update(task, completed=True, description=f"Loaded {scan_result.total_count} vulnerabilities")

        if scan_result.total_count == 0:
            console.print("[yellow]No vulnerabilities found in scan results.[/yellow]")
            return

        # Validate batch_mode
        if batch_mode not in ["auto", "enabled", "disabled"]:
            console.print(f"[red]Invalid --batch-mode: {batch_mode}. Use: auto, enabled, or disabled[/red]")
            return

        # Create analyzer with batch configuration
        analyzer = VulnerabilityAnalyzer(
            provider=provider,
            model=model,
            batch_size=batch_size,
            auto_batch_threshold=30,
        )

        # Apply severity filter if specified
        original_count = scan_result.total_count
        if severity:
            try:
                scan_result = analyzer.filter_by_severity(scan_result, severity)
                if scan_result.total_count == 0:
                    console.print(f"[yellow]No vulnerabilities found at {severity.upper()} severity or above.[/yellow]")
                    console.print(f"[dim]Original scan had {original_count} vulnerabilities[/dim]")
                    return
                console.print(f"[cyan]Filtered to {scan_result.total_count} vulnerabilities (>= {severity.upper()}) from {original_count} total[/cyan]")
            except ValueError as e:
                console.print(f"[red]Error: {str(e)}[/red]")
                return

        # Analyze with AI - with batch progress tracking
        if show_progress and (batch_mode == "enabled" or (batch_mode == "auto" and scan_result.total_count > 30)):
            # Use batch progress display
            from rich.progress import BarColumn, TimeRemainingColumn

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                total_batches = (scan_result.total_count + batch_size - 1) // batch_size
                task = progress.add_task(
                    f"Analyzing {scan_result.total_count} vulnerabilities...",
                    total=total_batches
                )

                def progress_callback(batch_num, total_batches, analyzed_count):
                    progress.update(
                        task,
                        completed=batch_num,
                        description=f"Batch {batch_num}/{total_batches} - {analyzed_count} analyzed"
                    )

                analysis = analyzer.analyze_scan_result(
                    scan_result,
                    batch_mode=batch_mode,
                    progress_callback=progress_callback,
                )

                progress.update(task, completed=total_batches, description="Analysis complete!")
        else:
            # Simple progress for single-pass analysis
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Analyzing with AI...", total=None)

                analysis = analyzer.analyze_scan_result(
                    scan_result,
                    batch_mode=batch_mode,
                )

                progress.update(task, completed=True, description="Analysis complete!")

        # Display results
        console.print("\n")

        # Build panel content with batch info if applicable
        panel_content = f"[bold]AI Vulnerability Analysis[/bold]\n\nTarget: {scan_result.target}\nTotal Vulnerabilities: {scan_result.total_count}"

        if analysis.metadata.get("batch_processing"):
            batches = analysis.metadata.get("batches_processed", 0)
            insights = analysis.metadata.get("insights_generated", 0)
            panel_content += f"\nBatch Processing: {batches} batches (size: {batch_size})\nInsights Generated: {insights}"

        console.print(Panel(panel_content, border_style="blue"))

        console.print(f"\n[bold cyan]Summary:[/bold cyan]")
        console.print(analysis.summary)

        # Show high-priority vulnerabilities
        high_priority = analyzer.get_high_priority_vulnerabilities(analysis)
        if high_priority:
            console.print(f"\n[bold red]High Priority Vulnerabilities ({len(high_priority)}):[/bold red]")

            table = Table(show_header=True)
            table.add_column("CVE ID", style="cyan")
            table.add_column("Package", style="yellow")
            table.add_column("Exploitability", style="red")
            table.add_column("Business Impact", style="magenta")

            for vuln in high_priority[:10]:  # Show top 10
                table.add_row(
                    vuln.cve_id,
                    vuln.package_name,
                    vuln.exploitability,
                    vuln.business_impact,
                )

            console.print(table)

            if len(high_priority) > 10:
                console.print(f"[dim]... and {len(high_priority) - 10} more high priority vulnerabilities[/dim]")

        # Save results
        output_data = analysis.to_dict()

        if output:
            save_json(output_data, output)
            console.print(f"\n[green]Analysis saved to {output}[/green]")

        if auto_save:
            storage = get_ai_storage()
            saved_path = storage.save_analysis(scan_result.target, output_data, "analysis")
            console.print(f"[green]Analysis auto-saved to {saved_path}[/green]")


@app.command("prioritize")
def prioritize_vulnerabilities(
    cve_results: str = typer.Argument(..., help="Path to CVE scan results JSON file"),
    provider: Optional[str] = typer.Option(None, "--provider", "-p", help="AI provider (openai, ollama)"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name (e.g., gpt-4o, llama2)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save prioritized list to JSON file"),
    auto_save: bool = typer.Option(False, "--auto-save", "--as", help="Auto-save to storage/ai_analysis/"),
    top_n: int = typer.Option(10, "--top", "-n", help="Show top N priorities"),
):
    """
    Generate AI-powered prioritized vulnerability remediation list.

    Uses AI to rank vulnerabilities based on:
    - CVSS severity scores
    - Exploitability analysis
    - Business impact assessment
    - Availability of patches

    Examples:
        threat-radar ai prioritize cve-results.json
        threat-radar ai prioritize results.json --top 20
        threat-radar ai prioritize scan.json -o priorities.json
    """
    with handle_cli_error("prioritizing vulnerabilities", console):
        # Load and analyze
        scan_result = load_cve_results(cve_results)

        if scan_result.total_count == 0:
            console.print("[yellow]No vulnerabilities found in scan results.[/yellow]")
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            # Analyze first
            task1 = progress.add_task("Analyzing vulnerabilities...", total=None)
            analyzer = VulnerabilityAnalyzer(provider=provider, model=model)
            analysis = analyzer.analyze_scan_result(scan_result)
            progress.update(task1, completed=True)

            # Prioritize
            task2 = progress.add_task("Generating priority list...", total=None)
            engine = PrioritizationEngine(provider=provider, model=model)
            prioritized = engine.prioritize_vulnerabilities(analysis)
            progress.update(task2, completed=True)

        # Display results
        console.print("\n")
        console.print(Panel(
            f"[bold]Prioritized Vulnerability List[/bold]\n\nTarget: {scan_result.target}",
            border_style="blue"
        ))

        console.print(f"\n[bold]Overall Strategy:[/bold]")
        console.print(prioritized.overall_strategy)

        if prioritized.quick_wins:
            console.print(f"\n[bold green]Quick Wins:[/bold green]")
            for idx, win in enumerate(prioritized.quick_wins, 1):
                console.print(f"{idx}. {win}")

        # Show top priorities
        console.print(f"\n[bold red]Top {top_n} Priorities:[/bold red]")
        top_priorities = engine.get_top_priorities(prioritized, limit=top_n)

        table = Table(show_header=True)
        table.add_column("#", style="dim")
        table.add_column("CVE ID", style="cyan")
        table.add_column("Package", style="yellow")
        table.add_column("Urgency", style="red")
        table.add_column("Reason", style="white")

        for idx, vuln in enumerate(top_priorities, 1):
            urgency_color = "red" if vuln.urgency_score >= 80 else "yellow" if vuln.urgency_score >= 60 else "white"
            table.add_row(
                str(idx),
                vuln.cve_id,
                vuln.package_name,
                f"[{urgency_color}]{vuln.urgency_score}[/{urgency_color}]",
                vuln.reason[:60] + "..." if len(vuln.reason) > 60 else vuln.reason,
            )

        console.print(table)

        # Summary stats
        console.print(f"\n[bold]Priority Distribution:[/bold]")
        console.print(f"  Critical: {prioritized.metadata['total_critical']}")
        console.print(f"  High: {prioritized.metadata['total_high']}")
        console.print(f"  Medium: {prioritized.metadata['total_medium']}")
        console.print(f"  Low: {prioritized.metadata['total_low']}")

        # Save results
        output_data = prioritized.to_dict()

        if output:
            save_json(output_data, output)
            console.print(f"\n[green]Priorities saved to {output}[/green]")

        if auto_save:
            storage = get_ai_storage()
            saved_path = storage.save_analysis(scan_result.target, output_data, "prioritization")
            console.print(f"[green]Priorities auto-saved to {saved_path}[/green]")


@app.command("remediate")
def generate_remediation(
    cve_results: str = typer.Argument(..., help="Path to CVE scan results JSON file"),
    provider: Optional[str] = typer.Option(None, "--provider", "-p", help="AI provider (openai, ollama)"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name (e.g., gpt-4o, llama2)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save remediation plan to JSON file"),
    auto_save: bool = typer.Option(False, "--auto-save", "--as", help="Auto-save to storage/ai_analysis/"),
    show_commands: bool = typer.Option(True, "--show-commands/--no-commands", help="Display upgrade commands"),
):
    """
    Generate AI-powered remediation plan with actionable steps.

    Provides detailed remediation guidance including:
    - Immediate mitigation actions
    - Specific version upgrades and patches
    - Workarounds when patches unavailable
    - Testing steps to verify fixes
    - Reference links to advisories

    Examples:
        threat-radar ai remediate cve-results.json
        threat-radar ai remediate results.json -o remediation.json
        threat-radar ai remediate scan.json --provider ollama
    """
    with handle_cli_error("generating remediation plan", console):
        scan_result = load_cve_results(cve_results)

        if scan_result.total_count == 0:
            console.print("[yellow]No vulnerabilities found in scan results.[/yellow]")
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Generating remediation plan...", total=None)

            generator = RemediationGenerator(provider=provider, model=model)
            remediation = generator.generate_remediation_plan(scan_result)

            progress.update(task, completed=True)

        # Display results
        console.print("\n")
        console.print(Panel(
            f"[bold]Remediation Plan[/bold]\n\nTarget: {scan_result.target}\nVulnerabilities: {remediation.metadata['total_vulnerabilities']}\nPackages Affected: {remediation.metadata['packages_affected']}",
            border_style="blue"
        ))

        # Show package groups
        console.print(f"\n[bold]Packages Requiring Updates:[/bold]")
        for pkg, group in remediation.grouped_by_package.items():
            status = "✓ Upgrade fixes all" if group.upgrade_fixes_all else "⚠ Partial fix"
            console.print(f"  • {pkg}: {group.vulnerabilities_count} vulnerabilities → {group.recommended_version or 'No fix'} [{status}]")

        # Show upgrade commands if requested
        if show_commands:
            commands = generator.get_package_upgrade_commands(remediation)
            if commands:
                console.print(f"\n[bold cyan]Upgrade Commands:[/bold cyan]")
                for pkg_manager, cmds in commands.items():
                    console.print(f"\n[yellow]{pkg_manager.upper()}:[/yellow]")
                    for cmd in cmds[:5]:  # Limit to 5 per package manager
                        console.print(f"  {cmd}")
                    if len(cmds) > 5:
                        console.print(f"  [dim]... and {len(cmds) - 5} more commands[/dim]")

        # Show quick fixes
        quick_fixes = generator.get_quick_fixes(remediation)
        if quick_fixes:
            console.print(f"\n[bold green]Quick Fixes ({len(quick_fixes)} low-effort remediations):[/bold green]")
            for fix in quick_fixes[:5]:
                console.print(f"  • {fix.cve_id} ({fix.package_name}): {fix.upgrade_command or 'See workarounds'}")
            if len(quick_fixes) > 5:
                console.print(f"  [dim]... and {len(quick_fixes) - 5} more quick fixes[/dim]")

        # Save results
        output_data = remediation.to_dict()

        if output:
            save_json(output_data, output)
            console.print(f"\n[green]Remediation plan saved to {output}[/green]")

        if auto_save:
            storage = get_ai_storage()
            saved_path = storage.save_analysis(scan_result.target, output_data, "remediation")
            console.print(f"[green]Remediation plan auto-saved to {saved_path}[/green]")


@app.command("analyze-with-context")
def analyze_with_business_context(
    cve_results: str = typer.Argument(..., help="Path to CVE scan results JSON file"),
    environment: str = typer.Argument(..., help="Path to environment configuration JSON file"),
    provider: Optional[str] = typer.Option(None, "--provider", "-p", help="AI provider (openai, anthropic, ollama)"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name (e.g., gpt-4o, llama2)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save analysis to JSON file"),
    auto_save: bool = typer.Option(False, "--auto-save", "--as", help="Auto-save to storage/ai_analysis/"),
    asset_id: Optional[str] = typer.Option(None, "--asset-id", help="Explicit asset ID from environment"),
    batch_mode: str = typer.Option(
        "auto",
        "--batch-mode",
        help="Batch processing mode: auto (default), enabled, disabled"
    ),
    show_top: int = typer.Option(10, "--show-top", help="Show top N business risks"),
):
    """
    Analyze vulnerabilities with business context from environment configuration.

    This command enhances vulnerability analysis with business context including:
    - Asset criticality levels and scores
    - Data classification (PII, PCI, PHI)
    - Network exposure (internet-facing vs internal)
    - Compliance requirements (PCI-DSS, HIPAA, GDPR)
    - Business impact assessment

    The business risk score (0-100) is computed from:
    - Technical severity (CVSS score)
    - Asset criticality (from environment config)
    - Network exposure (internet-facing assets)
    - Data sensitivity (PII, PCI, PHI handling)

    Examples:
        # Analyze with business context
        threat-radar ai analyze-with-context cve-scan.json production-env.json

        # Specify which asset the scan corresponds to
        threat-radar ai analyze-with-context scan.json env.json --asset-id api-gateway-001

        # Save results and show top 20 business risks
        threat-radar ai analyze-with-context scan.json env.json -o analysis.json --show-top 20

        # Use with specific AI provider
        threat-radar ai analyze-with-context scan.json env.json --provider ollama --model llama2
    """
    with handle_cli_error("analyzing vulnerabilities with business context", console):
        # Load CVE scan results
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Loading CVE results...", total=None)
            scan_result = load_cve_results(cve_results)
            progress.update(task, completed=True, description=f"Loaded {scan_result.total_count} vulnerabilities")

        if scan_result.total_count == 0:
            console.print("[yellow]No vulnerabilities found in scan results.[/yellow]")
            return

        # Load environment configuration
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Loading environment configuration...", total=None)
            env = EnvironmentParser.load_from_file(environment)
            progress.update(task, completed=True, description=f"Loaded environment: {env.environment.name}")

        console.print(f"\n[cyan]Environment:[/cyan] {env.environment.name} ({env.environment.type.value})")
        console.print(f"[cyan]Assets:[/cyan] {len(env.assets)}")

        if env.environment.compliance_requirements:
            frameworks = ", ".join([f.value.upper() for f in env.environment.compliance_requirements])
            console.print(f"[cyan]Compliance:[/cyan] {frameworks}")

        # Create analyzer with business context
        analyzer = BusinessContextAnalyzer(
            provider=provider,
            model=model,
            batch_size=25,
            auto_batch_threshold=30,
        )

        # Build asset mapping if provided
        asset_mapping = None
        if asset_id:
            asset_mapping = {scan_result.target: asset_id}

        # Analyze with business context
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Analyzing with AI and business context...", total=None)

            analysis = analyzer.analyze_with_business_context(
                scan_result=scan_result,
                environment=env,
                asset_mapping=asset_mapping,
                batch_mode=batch_mode,
            )

            progress.update(task, completed=True, description="Analysis complete!")

        # Display results
        console.print("\n")

        # Asset information
        if analysis.metadata.get("asset_id"):
            asset_criticality = analysis.metadata.get("asset_criticality", "unknown")
            criticality_score = analysis.metadata.get("criticality_score", 0)
            internet_facing = "Yes" if analysis.metadata.get("internet_facing") else "No"

            console.print(Panel(
                f"[bold]Business Context Analysis[/bold]\n\n"
                f"Asset: {analysis.metadata.get('asset_name', 'Unknown')}\n"
                f"Criticality: {asset_criticality.upper()} (Score: {criticality_score}/100)\n"
                f"Internet-Facing: {internet_facing}\n"
                f"Overall Risk Rating: [bold red]{analysis.overall_risk_rating}[/bold red]",
                border_style="blue"
            ))
        else:
            console.print(Panel(
                f"[bold]Vulnerability Analysis[/bold]\n\n"
                f"[yellow]Warning: Could not map scan target to environment asset[/yellow]\n"
                f"Using technical analysis only",
                border_style="yellow"
            ))

        # Environment summary
        if analysis.environment_summary:
            console.print(f"\n[bold cyan]Environment Summary:[/bold cyan]")
            console.print(analysis.environment_summary)

        # Compliance summary
        if analysis.compliance_summary:
            console.print(f"\n[bold magenta]Compliance Impact:[/bold magenta]")
            console.print(analysis.compliance_summary)

        # Prioritized actions
        if analysis.prioritized_actions:
            console.print(f"\n[bold green]Prioritized Actions:[/bold green]")
            for idx, action in enumerate(analysis.prioritized_actions, 1):
                console.print(f"{idx}. {action}")

        # Show top business risks
        if analysis.business_assessments:
            console.print(f"\n[bold red]Top {show_top} Business Risks:[/bold red]")

            top_risks = analyzer.get_top_business_risks(analysis, limit=show_top)

            table = Table(show_header=True)
            table.add_column("CVE ID", style="cyan")
            table.add_column("Package", style="yellow")
            table.add_column("Tech.", style="white")
            table.add_column("Business Risk", style="red")
            table.add_column("Risk Factors", style="dim")

            for risk in top_risks:
                # Colorize business risk score
                if risk.business_risk_score >= 80:
                    risk_color = "bold red"
                elif risk.business_risk_score >= 60:
                    risk_color = "red"
                elif risk.business_risk_score >= 40:
                    risk_color = "yellow"
                else:
                    risk_color = "white"

                # Truncate risk factors for display
                factors_str = ", ".join(risk.risk_factors[:2])
                if len(risk.risk_factors) > 2:
                    factors_str += "..."

                table.add_row(
                    risk.cve_id,
                    risk.package_name,
                    risk.technical_severity,
                    f"[{risk_color}]{risk.business_risk_score}[/{risk_color}] ({risk.business_risk_level})",
                    factors_str,
                )

            console.print(table)

            # Summary statistics
            critical_count = sum(1 for r in analysis.business_assessments if r.business_risk_level == "CRITICAL")
            high_count = sum(1 for r in analysis.business_assessments if r.business_risk_level == "HIGH")
            immediate_count = sum(1 for r in analysis.business_assessments if r.remediation_urgency == "IMMEDIATE")

            console.print(f"\n[bold]Business Risk Distribution:[/bold]")
            console.print(f"  Critical Business Risk: {critical_count}")
            console.print(f"  High Business Risk: {high_count}")
            console.print(f"  Immediate Remediation Required: {immediate_count}")

        # Save results
        output_data = analysis.to_dict()

        if output:
            save_json(output_data, output)
            console.print(f"\n[green]Analysis saved to {output}[/green]")

        if auto_save:
            storage = get_ai_storage()
            saved_path = storage.save_analysis(scan_result.target, output_data, "business_context_analysis")
            console.print(f"[green]Analysis auto-saved to {saved_path}[/green]")
