"""Main CLI application with global options support."""
import typer
from typing import Optional
from pathlib import Path

from . import cve as cve_cmd, sbom, config, docker, ai, report, graph, env, visualize, health
from ..utils.cli_context import CLIContext, set_cli_context

app = typer.Typer(
    help="Threat Radar - Enterprise-grade threat assessment and vulnerability analysis",
    no_args_is_help=True,
)

# sub-commands (map 1:1 to your UX)
app.add_typer(cve_cmd.app, name="cve", help="CVE vulnerability scanning operations")
app.add_typer(sbom.app, name="sbom", help="SBOM generation and operations")
app.add_typer(config.app, name="config", help="Configuration management")
app.add_typer(docker.app, name="docker", help="Docker container analysis")
app.add_typer(ai.app, name="ai", help="AI-powered vulnerability analysis")
app.add_typer(report.app, name="report", help="Comprehensive vulnerability reporting")
app.add_typer(graph.app, name="graph", help="Graph database operations for vulnerability modeling")
app.add_typer(env.app, name="env", help="Environment configuration and business context management")
app.add_typer(visualize.app, name="visualize", help="Interactive graph visualization")
app.add_typer(health.app, name="health", help="Health check and system status")


@app.callback()
def main_callback(
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to configuration file (JSON format)",
        exists=True,
    ),
    verbosity: int = typer.Option(
        1,
        "--verbose",
        "-v",
        count=True,
        help="Increase verbosity (can be repeated: -v, -vv, -vvv)",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress all output except errors",
    ),
    output_format: str = typer.Option(
        "table",
        "--output-format",
        "-f",
        help="Default output format (table, json, yaml, csv)",
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable colored output",
    ),
    no_progress: bool = typer.Option(
        False,
        "--no-progress",
        help="Disable progress indicators",
    ),
):
    """
    Global options for Threat Radar CLI.

    These options apply to all commands and can also be configured
    via configuration file (~/.threat-radar/config.json).

    Verbosity levels:
      0 (--quiet):     Errors only
      1 (default):     Warnings and errors
      2 (-v):          Info, warnings, and errors
      3 (-vv):         Debug - everything

    Examples:
      threat-radar -v cve scan-image alpine:3.18
      threat-radar --config myconfig.json ai analyze scan.json
      threat-radar -vv --output-format json sbom docker python:3.11
    """
    # Apply quiet flag (overrides verbosity)
    if quiet:
        verbosity = 0

    # Create and set global CLI context
    context = CLIContext.create(
        config_file=config_file,
        verbosity=verbosity,
        output_format=output_format,
        no_color=no_color,
        no_progress=no_progress,
    )
    set_cli_context(context)


def main() -> None:
    """Main entry point for CLI."""
    app()
