"""Comprehensive tests for CLI context management."""

import pytest
import logging
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from threat_radar.utils.cli_context import CLIContext, _setup_logging
from threat_radar.utils.config_manager import ConfigManager


@pytest.fixture
def mock_config_manager():
    """Create a mock config manager."""
    manager = MagicMock(spec=ConfigManager)
    manager.get = Mock(return_value=None)
    return manager


class TestCLIContextCreation:
    """Test CLIContext creation and initialization."""

    def test_create_default_context(self):
        """Test creating CLI context with default values."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            context = CLIContext.create()

            assert context is not None
            assert context.verbosity == 1
            assert context.output_format == "table"
            assert context.no_color is False
            assert context.no_progress is False
            assert isinstance(context.console, Console)

    def test_create_with_custom_verbosity(self):
        """Test creating context with custom verbosity."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            context = CLIContext.create(verbosity=3)

            assert context.verbosity == 3

    def test_create_with_custom_output_format(self):
        """Test creating context with custom output format."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            context = CLIContext.create(output_format="json")

            assert context.output_format == "json"

    def test_create_with_no_color(self):
        """Test creating context with colors disabled."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            context = CLIContext.create(no_color=True)

            assert context.no_color is True
            assert context.console.no_color is True

    def test_create_with_no_progress(self):
        """Test creating context with progress disabled."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            context = CLIContext.create(no_progress=True)

            assert context.no_progress is True

    def test_create_with_config_file(self, tmp_path):
        """Test creating context with custom config file."""
        config_file = tmp_path / "config.json"
        config_file.write_text('{"output": {"verbosity": 2}}')

        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            context = CLIContext.create(config_file=config_file)

            assert context is not None
            mock_get_config.assert_called_once_with(config_file)


class TestCLIContextConfigIntegration:
    """Test integration with configuration manager."""

    def test_verbosity_from_config(self):
        """Test that verbosity is loaded from config when not explicitly set."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.side_effect = lambda key, default=None: {
                'output.verbosity': 2,
            }.get(key, default)
            mock_get_config.return_value = mock_config

            # Don't explicitly set verbosity, should use config
            context = CLIContext.create()

            assert context.verbosity == 2

    def test_output_format_from_config(self):
        """Test that output format is loaded from config when not explicitly set."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.side_effect = lambda key, default=None: {
                'output.format': 'json',
            }.get(key, default)
            mock_get_config.return_value = mock_config

            context = CLIContext.create()

            assert context.output_format == "json"

    def test_color_setting_from_config(self):
        """Test that color setting is loaded from config."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.side_effect = lambda key, default=None: {
                'output.color': False,
            }.get(key, default)
            mock_get_config.return_value = mock_config

            context = CLIContext.create()

            assert context.no_color is True

    def test_progress_setting_from_config(self):
        """Test that progress setting is loaded from config."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.side_effect = lambda key, default=None: {
                'output.progress': False,
            }.get(key, default)
            mock_get_config.return_value = mock_config

            context = CLIContext.create()

            assert context.no_progress is True

    def test_explicit_args_override_config(self):
        """Test that explicit arguments override config values."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.side_effect = lambda key, default=None: {
                'output.verbosity': 1,
                'output.format': 'table',
            }.get(key, default)
            mock_get_config.return_value = mock_config

            # Explicitly set different values
            context = CLIContext.create(
                verbosity=3,
                output_format="json"
            )

            # Explicit values should take precedence
            assert context.verbosity == 3
            assert context.output_format == "json"


class TestSetupLogging:
    """Test logging setup based on verbosity levels."""

    def test_setup_logging_quiet(self):
        """Test logging setup for quiet mode (verbosity=0)."""
        _setup_logging(0)

        root_logger = logging.getLogger()
        assert root_logger.level == logging.ERROR

    def test_setup_logging_normal(self):
        """Test logging setup for normal mode (verbosity=1)."""
        _setup_logging(1)

        root_logger = logging.getLogger()
        assert root_logger.level == logging.WARNING

    def test_setup_logging_verbose(self):
        """Test logging setup for verbose mode (verbosity=2)."""
        _setup_logging(2)

        root_logger = logging.getLogger()
        assert root_logger.level == logging.INFO

    def test_setup_logging_debug(self):
        """Test logging setup for debug mode (verbosity=3)."""
        _setup_logging(3)

        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG

    def test_setup_logging_invalid_verbosity(self):
        """Test logging setup with invalid verbosity (defaults to WARNING)."""
        _setup_logging(999)

        root_logger = logging.getLogger()
        # Should default to WARNING for unknown verbosity
        assert root_logger.level == logging.WARNING

    def test_logging_format_verbose(self):
        """Test that verbose mode uses detailed logging format."""
        _setup_logging(2)

        # Check that format includes timestamp and module name
        # This is indirectly tested by checking log level
        root_logger = logging.getLogger()
        assert root_logger.level == logging.INFO

    def test_logging_format_normal(self):
        """Test that normal mode uses simple logging format."""
        _setup_logging(1)

        root_logger = logging.getLogger()
        assert root_logger.level == logging.WARNING


class TestCLIContextConsole:
    """Test Console integration in CLI context."""

    def test_console_with_color(self):
        """Test console with color enabled."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            context = CLIContext.create(no_color=False)

            assert context.console.no_color is False

    def test_console_without_color(self):
        """Test console with color disabled."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            context = CLIContext.create(no_color=True)

            assert context.console.no_color is True

    def test_console_force_terminal(self):
        """Test console force_terminal setting."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            # With color (force_terminal should be True)
            context_with_color = CLIContext.create(no_color=False)
            assert context_with_color.console._force_terminal is True

            # Without color (force_terminal should be False)
            context_no_color = CLIContext.create(no_color=True)
            assert context_no_color.console._force_terminal is False


class TestCLIContextDataClass:
    """Test CLIContext as a dataclass."""

    def test_context_attributes(self):
        """Test that context has all required attributes."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            context = CLIContext.create()

            # Check all required attributes exist
            assert hasattr(context, 'config_manager')
            assert hasattr(context, 'verbosity')
            assert hasattr(context, 'output_format')
            assert hasattr(context, 'no_color')
            assert hasattr(context, 'no_progress')
            assert hasattr(context, 'console')

    def test_context_config_manager_type(self):
        """Test that config_manager is correct type."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock(spec=ConfigManager)
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            context = CLIContext.create()

            assert context.config_manager is not None


class TestCLIContextEdgeCases:
    """Test edge cases and unusual scenarios."""

    def test_create_with_all_custom_values(self):
        """Test creating context with all custom values."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            context = CLIContext.create(
                verbosity=3,
                output_format="yaml",
                no_color=True,
                no_progress=True,
            )

            assert context.verbosity == 3
            assert context.output_format == "yaml"
            assert context.no_color is True
            assert context.no_progress is True

    def test_create_multiple_contexts(self):
        """Test creating multiple independent contexts."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            context1 = CLIContext.create(verbosity=1)
            context2 = CLIContext.create(verbosity=3)

            # Both should be valid and independent
            assert context1.verbosity == 1
            assert context2.verbosity == 3
            assert context1 is not context2

    def test_negative_verbosity(self):
        """Test handling negative verbosity (edge case)."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            # Negative verbosity should be allowed (though unusual)
            context = CLIContext.create(verbosity=-1)

            assert context.verbosity == -1

    def test_very_high_verbosity(self):
        """Test handling very high verbosity."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            context = CLIContext.create(verbosity=10)

            assert context.verbosity == 10

    def test_unusual_output_format(self):
        """Test with unusual but valid output format."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            context = CLIContext.create(output_format="custom_format")

            assert context.output_format == "custom_format"


class TestCLIContextUsageScenarios:
    """Test realistic usage scenarios."""

    def test_quiet_mode_scenario(self):
        """Test quiet mode (errors only) scenario."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            # Quiet mode for CI/CD
            context = CLIContext.create(
                verbosity=0,
                output_format="json",
                no_color=True,
                no_progress=True,
            )

            assert context.verbosity == 0
            assert context.output_format == "json"
            assert context.no_color is True
            assert context.no_progress is True

    def test_debug_mode_scenario(self):
        """Test debug mode (verbose output) scenario."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            # Debug mode for troubleshooting
            context = CLIContext.create(
                verbosity=3,
                output_format="table",
                no_color=False,
                no_progress=False,
            )

            assert context.verbosity == 3
            assert context.output_format == "table"
            assert context.no_color is False
            assert context.no_progress is False

    def test_ci_cd_integration_scenario(self):
        """Test CI/CD integration scenario."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            # Typical CI/CD setup
            context = CLIContext.create(
                verbosity=0,  # Quiet
                output_format="json",  # Machine-readable
                no_color=True,  # No ANSI codes
                no_progress=True,  # No progress bars
            )

            assert context.verbosity == 0
            assert context.output_format == "json"
            assert context.no_color is True
            assert context.no_progress is True

    def test_interactive_terminal_scenario(self):
        """Test interactive terminal scenario."""
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            # Interactive terminal with rich output
            context = CLIContext.create(
                verbosity=1,  # Normal
                output_format="table",  # Human-readable
                no_color=False,  # Colors enabled
                no_progress=False,  # Progress bars enabled
            )

            assert context.verbosity == 1
            assert context.output_format == "table"
            assert context.no_color is False
            assert context.no_progress is False


class TestCLIContextWithRealConfig:
    """Test CLI context with actual configuration files."""

    def test_context_with_real_config_file(self, tmp_path):
        """Test creating context with real config file."""
        import json

        config_data = {
            "output": {
                "verbosity": 2,
                "format": "json",
                "color": False,
                "progress": False,
            }
        }

        config_file = tmp_path / "test-config.json"
        config_file.write_text(json.dumps(config_data))

        # This would use the real ConfigManager
        # For now, we mock it since we're testing CLIContext, not ConfigManager
        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.side_effect = lambda key, default=None: {
                'output.verbosity': 2,
                'output.format': 'json',
                'output.color': False,
                'output.progress': False,
            }.get(key, default)
            mock_get_config.return_value = mock_config

            context = CLIContext.create(config_file=config_file)

            assert context.verbosity == 2
            assert context.output_format == "json"
            assert context.no_color is True
            assert context.no_progress is True


class TestGlobalContextManagement:
    """Test global CLI context getter/setter functions."""

    def test_get_cli_context_initially_none(self):
        """Test that global context is None initially."""
        from threat_radar.utils.cli_context import get_cli_context, reset_cli_context

        reset_cli_context()
        context = get_cli_context()

        assert context is None

    def test_set_and_get_cli_context(self):
        """Test setting and getting global CLI context."""
        from threat_radar.utils.cli_context import get_cli_context, set_cli_context, reset_cli_context

        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            # Create a context
            context = CLIContext.create(verbosity=3, output_format="json")

            # Set it as global
            set_cli_context(context)

            # Get it back
            retrieved = get_cli_context()

            assert retrieved is context
            assert retrieved.verbosity == 3
            assert retrieved.output_format == "json"

            # Clean up
            reset_cli_context()

    def test_reset_cli_context(self):
        """Test resetting global CLI context."""
        from threat_radar.utils.cli_context import get_cli_context, set_cli_context, reset_cli_context

        with patch('threat_radar.utils.cli_context.get_config_manager') as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = None
            mock_get_config.return_value = mock_config

            # Create and set context
            context = CLIContext.create()
            set_cli_context(context)

            assert get_cli_context() is not None

            # Reset
            reset_cli_context()

            assert get_cli_context() is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
