"""File I/O utility functions for CLI commands."""

import json
from pathlib import Path
from typing import Any, Dict, Optional
from rich.console import Console


def save_json(
    data: Dict[str, Any],
    filepath: str,
    console: Optional[Console] = None,
    success_message: Optional[str] = None,
) -> None:
    """
    Save data as JSON file with error handling and user feedback.

    Args:
        data: Dictionary to serialize as JSON
        filepath: Path to output file
        console: Rich Console instance for user feedback (optional)
        success_message: Custom success message (optional)

    Raises:
        IOError: If file write fails
        TypeError: If data is not JSON serializable

    Example:
        >>> from rich.console import Console
        >>> console = Console()
        >>> save_json({"key": "value"}, "output.json", console)
    """
    try:
        # Ensure parent directory exists
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        if console:
            msg = success_message or f"Results saved to {filepath}"
            console.print(f"\n[green]{msg}[/green]")

    except (IOError, OSError) as e:
        if console:
            console.print(f"[red]Failed to save file: {e}[/red]")
        raise
    except TypeError as e:
        if console:
            console.print(f"[red]Data is not JSON serializable: {e}[/red]")
        raise


def save_text(
    content: str,
    filepath: str,
    console: Optional[Console] = None,
    success_message: Optional[str] = None,
) -> None:
    """
    Save text content to file with error handling and user feedback.

    Args:
        content: Text content to write
        filepath: Path to output file
        console: Rich Console instance for user feedback (optional)
        success_message: Custom success message (optional)

    Raises:
        IOError: If file write fails

    Example:
        >>> from rich.console import Console
        >>> console = Console()
        >>> save_text("Hello, World!", "output.txt", console)
    """
    try:
        # Ensure parent directory exists
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, "w") as f:
            f.write(content)

        if console:
            msg = success_message or f"Results saved to {filepath}"
            console.print(f"\n[green]{msg}[/green]")

    except (IOError, OSError) as e:
        if console:
            console.print(f"[red]Failed to save file: {e}[/red]")
        raise
