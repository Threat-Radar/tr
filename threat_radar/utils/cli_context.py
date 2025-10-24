"""CLI context management for global options."""
import logging
from typing import Optional
from pathlib import Path
from dataclasses import dataclass
from rich.console import Console

from .config_manager import get_config_manager, ConfigManager


@dataclass
class CLIContext:
    """Global CLI context holding configuration and state."""
    config_manager: ConfigManager
    verbosity: int
    output_format: str
    no_color: bool
    no_progress: bool
    console: Console

    @classmethod
    def create(
        cls,
        config_file: Optional[Path] = None,
        verbosity: int = 1,
        output_format: str = "table",
        no_color: bool = False,
        no_progress: bool = False,
    ) -> 'CLIContext':
        """
        Create CLI context with specified options.

        Args:
            config_file: Path to configuration file
            verbosity: Verbosity level (0=quiet, 1=normal, 2=verbose, 3=debug)
            output_format: Default output format
            no_color: Disable colored output
            no_progress: Disable progress indicators

        Returns:
            CLIContext instance
        """
        # Load configuration
        config_manager = get_config_manager(config_file)

        # Apply verbosity from config if not explicitly set
        if verbosity == 1 and config_manager.get('output.verbosity'):
            verbosity = config_manager.get('output.verbosity')

        # Apply output format from config if not explicitly set
        if output_format == "table" and config_manager.get('output.format'):
            output_format = config_manager.get('output.format')

        # Apply color setting from config
        if not no_color and config_manager.get('output.color') is False:
            no_color = True

        # Apply progress setting from config
        if not no_progress and config_manager.get('output.progress') is False:
            no_progress = True

        # Setup logging based on verbosity
        _setup_logging(verbosity)

        # Create console
        console = Console(no_color=no_color, force_terminal=not no_color)

        return cls(
            config_manager=config_manager,
            verbosity=verbosity,
            output_format=output_format,
            no_color=no_color,
            no_progress=no_progress,
            console=console,
        )


def _setup_logging(verbosity: int):
    """
    Setup logging based on verbosity level.

    Args:
        verbosity: Verbosity level (0=quiet, 1=normal, 2=verbose, 3=debug)
    """
    # Map verbosity to log level
    level_map = {
        0: logging.ERROR,      # Quiet - only errors
        1: logging.WARNING,    # Normal - warnings and errors
        2: logging.INFO,       # Verbose - info, warnings, and errors
        3: logging.DEBUG,      # Debug - everything
    }

    log_level = level_map.get(verbosity, logging.WARNING)

    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s' if verbosity >= 2 else '%(levelname)s: %(message)s',
        force=True,
    )

    # Reduce noise from external libraries in non-debug mode
    if verbosity < 3:
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('docker').setLevel(logging.WARNING)
        logging.getLogger('openai').setLevel(logging.WARNING)


# Global CLI context
_cli_context: Optional[CLIContext] = None


def get_cli_context() -> Optional[CLIContext]:
    """Get current CLI context."""
    return _cli_context


def set_cli_context(context: CLIContext):
    """Set global CLI context."""
    global _cli_context
    _cli_context = context


def reset_cli_context():
    """Reset CLI context (useful for testing)."""
    global _cli_context
    _cli_context = None
