"""CLI utility functions for command-line interface."""
from contextlib import contextmanager
from typing import Optional, List, Any, Iterator
from rich.console import Console
from rich.progress import Progress
from rich.table import Table
import typer


@contextmanager
def handle_cli_error(action: str, console: Console, progress: Optional[Progress] = None) -> Iterator[None]:
    """
    Context manager for standardized CLI error handling.

    Args:
        action: Description of the action being performed (e.g., "importing image")
        console: Rich Console instance for output
        progress: Optional Progress instance to stop on error

    Yields:
        None

    Raises:
        typer.Exit: On any exception with exit code 1

    Example:
        >>> from rich.console import Console
        >>> console = Console()
        >>> with handle_cli_error("importing image", console):
        ...     # Your command logic here
        ...     pass
    """
    try:
        yield
    except Exception as e:
        if progress:
            progress.stop()
        console.print(f"[red]Error {action}: {e}[/red]")
        raise typer.Exit(code=1)


def create_package_table(
    packages: List[Any],
    title: str = "Packages",
    show_architecture: bool = False,
    limit: Optional[int] = None
) -> Table:
    """
    Create a standardized Rich table for displaying package information.

    Args:
        packages: List of Package or PythonPackage objects
        title: Table title (default: "Packages")
        show_architecture: Include architecture column (default: False)
        limit: Maximum number of packages to display (default: None, shows all)

    Returns:
        Rich Table object ready to display

    Example:
        >>> from threat_radar.core.package_extractors import Package
        >>> packages = [Package("curl", "7.68.0", "amd64")]
        >>> table = create_package_table(packages, show_architecture=True)
    """
    table = Table(title=title)
    table.add_column("Package", style="cyan")
    table.add_column("Version", style="green")

    if show_architecture:
        table.add_column("Architecture", style="magenta")

    # Apply limit if specified
    display_packages = packages[:limit] if limit else packages

    for pkg in display_packages:
        row = [pkg.name, pkg.version]
        if show_architecture:
            arch = getattr(pkg, 'architecture', None) or "N/A"
            row.append(arch)
        table.add_row(*row)

    return table
