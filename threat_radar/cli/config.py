"""Configuration management commands."""
from pathlib import Path
import json
import typer
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from ..utils.config_manager import get_config_manager, ThreatRadarConfig

app = typer.Typer(help="Configuration management")
console = Console()


@app.command("show")
def show_config(
    key: str = typer.Argument(None, help="Specific configuration key to show (e.g., 'scan.severity')"),
):
    """
    Show current configuration.

    Examples:
      threat-radar config show
      threat-radar config show scan.severity
      threat-radar config show ai.provider
    """
    config_manager = get_config_manager()

    if key:
        # Show specific key
        value = config_manager.get(key)
        if value is not None:
            console.print(f"[cyan]{key}[/cyan] = [green]{value}[/green]")
        else:
            console.print(f"[red]Key not found: {key}[/red]")
    else:
        # Show entire configuration
        config_dict = config_manager.config.to_dict()
        json_str = json.dumps(config_dict, indent=2)

        syntax = Syntax(json_str, "json", theme="monokai", line_numbers=False)
        console.print("\n[bold]Current Configuration:[/bold]\n")
        console.print(syntax)

        # Show config file location if one was loaded
        if config_manager.config_path:
            console.print(f"\n[dim]Loaded from: {config_manager.config_path}[/dim]")
        else:
            console.print("\n[dim]Using defaults (no config file found)[/dim]")


@app.command("set")
def set_config(
    key: str = typer.Argument(..., help="Configuration key (e.g., 'scan.severity')"),
    value: str = typer.Argument(..., help="Value to set"),
    save: bool = typer.Option(True, "--save/--no-save", help="Save to config file"),
):
    """
    Set configuration value.

    Examples:
      threat-radar config set scan.severity HIGH
      threat-radar config set ai.provider ollama
      threat-radar config set output.verbosity 2
    """
    config_manager = get_config_manager()

    try:
        # Convert value to appropriate type
        if value.lower() in ('true', 'false'):
            typed_value = value.lower() == 'true'
        elif value.isdigit():
            typed_value = int(value)
        else:
            typed_value = value

        # Set value
        config_manager.set(key, typed_value)
        console.print(f"[green]✓[/green] Set [cyan]{key}[/cyan] = [green]{typed_value}[/green]")

        # Save if requested
        if save:
            path = config_manager.save_config()
            console.print(f"[green]✓[/green] Saved to: {path}")

    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command("init")
def init_config(
    path: Path = typer.Option(
        Path.home() / ".threat-radar" / "config.json",
        "--path",
        "-p",
        help="Path to create config file",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing config file",
    ),
):
    """
    Initialize a new configuration file with defaults.

    Creates ~/.threat-radar/config.json with default settings.

    Examples:
      threat-radar config init
      threat-radar config init --path ./my-config.json
      threat-radar config init --force  # Overwrite existing
    """
    # Check if file exists
    if path.exists() and not force:
        console.print(f"[yellow]Warning:[/yellow] Config file already exists: {path}")
        console.print("Use --force to overwrite")
        raise typer.Exit(1)

    # Create new config with defaults
    config_manager = get_config_manager()
    saved_path = config_manager.save_config(path)

    console.print(f"[green]✓[/green] Created configuration file: {saved_path}")
    console.print("\nYou can edit this file directly or use:")
    console.print("  threat-radar config set <key> <value>")


@app.command("path")
def show_paths():
    """
    Show configuration file locations.

    Displays where Threat Radar looks for configuration files.
    """
    from ..utils.config_manager import ConfigManager

    console.print("\n[bold]Configuration File Locations (in order of precedence):[/bold]\n")

    table = Table(show_header=True)
    table.add_column("Priority", style="cyan")
    table.add_column("Path", style="green")
    table.add_column("Exists", style="yellow")

    for i, path in enumerate(ConfigManager.DEFAULT_CONFIG_LOCATIONS, 1):
        exists = "✓" if path.exists() else "✗"
        table.add_row(str(i), str(path), exists)

    console.print(table)

    # Show which one is currently loaded
    config_manager = get_config_manager()
    if config_manager.config_path:
        console.print(f"\n[bold green]Currently loaded:[/bold green] {config_manager.config_path}")
    else:
        console.print("\n[dim]No configuration file loaded (using defaults)[/dim]")


@app.command("validate")
def validate_config(
    config_file: Path = typer.Argument(
        None,
        help="Path to config file to validate",
        exists=True,
    ),
):
    """
    Validate configuration file.

    Checks if a configuration file is valid and shows any errors.

    Examples:
      threat-radar config validate
      threat-radar config validate ./my-config.json
    """
    if config_file is None:
        # Validate current config
        config_manager = get_config_manager()
        if config_manager.config_path:
            config_file = config_manager.config_path
        else:
            console.print("[yellow]No config file loaded. Specify a file to validate.[/yellow]")
            raise typer.Exit(1)

    try:
        with open(config_file, 'r') as f:
            data = json.load(f)

        # Try to create config from data
        ThreatRadarConfig.from_dict(data)

        console.print(f"[green]✓[/green] Configuration file is valid: {config_file}")

    except json.JSONDecodeError as e:
        console.print(f"[red]✗ Invalid JSON:[/red] {e}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]✗ Validation error:[/red] {e}")
        raise typer.Exit(1)
