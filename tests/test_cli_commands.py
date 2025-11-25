"""Comprehensive tests for CLI commands."""

import pytest
import json
from pathlib import Path
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, Mock

from threat_radar.cli.app import app
from threat_radar.cli import config as config_cmd
from threat_radar.utils.config_manager import ConfigManager, reset_config_manager


# Fixtures
runner = CliRunner()


@pytest.fixture(autouse=True)
def reset_global_state():
    """Reset global state before and after each test."""
    reset_config_manager()
    yield
    reset_config_manager()


@pytest.fixture
def temp_config_file(tmp_path):
    """Create a temporary config file."""
    config_data = {
        "scan": {"severity": "HIGH"},
        "ai": {"provider": "openai"},
        "output": {"verbosity": 2}
    }
    config_file = tmp_path / "test-config.json"
    config_file.write_text(json.dumps(config_data))
    return config_file


# Test App Global Options
class TestAppGlobalOptions:
    """Test main app global options and callback."""

    def test_app_help(self):
        """Test main app help output."""
        result = runner.invoke(app, ["--help"])

        assert result.exit_code == 0
        assert "Threat Radar" in result.stdout
        assert "cve" in result.stdout
        assert "sbom" in result.stdout
        assert "config" in result.stdout

    def test_app_with_verbose_flag(self):
        """Test app with verbose flag."""
        # Since we need a subcommand, use config show
        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock()
            mock_config_obj = MagicMock()
            mock_config_obj.to_dict.return_value = {"scan": {"severity": None}}
            mock_manager.config = mock_config_obj
            mock_manager.config_path = None
            mock_get_config.return_value = mock_manager

            result = runner.invoke(app, ["-v", "config", "show"])

            # Should not error
            assert result.exit_code == 0

    def test_app_with_quiet_flag(self):
        """Test app with quiet flag."""
        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock()
            mock_config_obj = MagicMock()
            mock_config_obj.to_dict.return_value = {"scan": {"severity": None}}
            mock_manager.config = mock_config_obj
            mock_manager.config_path = None
            mock_get_config.return_value = mock_manager

            result = runner.invoke(app, ["--quiet", "config", "show"])

            assert result.exit_code == 0

    def test_app_with_output_format(self):
        """Test app with output format option."""
        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock()
            mock_config_obj = MagicMock()
            mock_config_obj.to_dict.return_value = {"scan": {"severity": None}}
            mock_manager.config = mock_config_obj
            mock_manager.config_path = None
            mock_get_config.return_value = mock_manager

            result = runner.invoke(app, ["--output-format", "json", "config", "show"])

            assert result.exit_code == 0

    def test_app_with_no_color(self):
        """Test app with no-color flag."""
        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock()
            mock_config_obj = MagicMock()
            mock_config_obj.to_dict.return_value = {"scan": {"severity": None}}
            mock_manager.config = mock_config_obj
            mock_manager.config_path = None
            mock_get_config.return_value = mock_manager

            result = runner.invoke(app, ["--no-color", "config", "show"])

            assert result.exit_code == 0

    def test_app_with_config_file(self, temp_config_file):
        """Test app with config file option."""
        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock()
            mock_config_obj = MagicMock()
            mock_config_obj.to_dict.return_value = {"scan": {"severity": "HIGH"}}
            mock_manager.config = mock_config_obj
            mock_manager.config_path = temp_config_file
            mock_get_config.return_value = mock_manager

            result = runner.invoke(app, ["--config", str(temp_config_file), "config", "show"])

            assert result.exit_code == 0


# Test Config Commands
class TestConfigCommands:
    """Test configuration management commands."""

    def test_config_show_all(self):
        """Test showing all configuration."""
        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock(spec=ConfigManager)
            mock_config_obj = MagicMock()
            mock_config_obj.to_dict.return_value = {
                "scan": {"severity": "HIGH"},
                "ai": {"provider": "openai"}
            }
            mock_manager.config = mock_config_obj
            mock_manager.config_path = None
            mock_get_config.return_value = mock_manager

            result = runner.invoke(config_cmd.app, ["show"])

            assert result.exit_code == 0
            assert "Current Configuration" in result.stdout

    def test_config_show_specific_key(self):
        """Test showing specific configuration key."""
        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock(spec=ConfigManager)
            mock_manager.get.return_value = "HIGH"
            mock_get_config.return_value = mock_manager

            result = runner.invoke(config_cmd.app, ["show", "scan.severity"])

            assert result.exit_code == 0
            assert "scan.severity" in result.stdout
            assert "HIGH" in result.stdout

    def test_config_show_nonexistent_key(self):
        """Test showing nonexistent configuration key."""
        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock(spec=ConfigManager)
            mock_manager.get.return_value = None
            mock_get_config.return_value = mock_manager

            result = runner.invoke(config_cmd.app, ["show", "nonexistent.key"])

            assert result.exit_code == 0
            assert "Key not found" in result.stdout

    def test_config_set_string_value(self):
        """Test setting string configuration value."""
        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock(spec=ConfigManager)
            mock_manager.save_config.return_value = Path("/tmp/config.json")
            mock_get_config.return_value = mock_manager

            result = runner.invoke(config_cmd.app, ["set", "scan.severity", "CRITICAL"])

            assert result.exit_code == 0
            mock_manager.set.assert_called_once_with("scan.severity", "CRITICAL")
            mock_manager.save_config.assert_called_once()

    def test_config_set_boolean_value(self):
        """Test setting boolean configuration value."""
        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock(spec=ConfigManager)
            mock_manager.save_config.return_value = Path("/tmp/config.json")
            mock_get_config.return_value = mock_manager

            result = runner.invoke(config_cmd.app, ["set", "scan.auto_save", "true"])

            assert result.exit_code == 0
            mock_manager.set.assert_called_once_with("scan.auto_save", True)

    def test_config_set_integer_value(self):
        """Test setting integer configuration value."""
        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock(spec=ConfigManager)
            mock_manager.save_config.return_value = Path("/tmp/config.json")
            mock_get_config.return_value = mock_manager

            result = runner.invoke(config_cmd.app, ["set", "output.verbosity", "3"])

            assert result.exit_code == 0
            mock_manager.set.assert_called_once_with("output.verbosity", 3)

    def test_config_set_without_save(self):
        """Test setting config without saving to file."""
        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock(spec=ConfigManager)
            mock_get_config.return_value = mock_manager

            result = runner.invoke(config_cmd.app, ["set", "scan.severity", "HIGH", "--no-save"])

            assert result.exit_code == 0
            mock_manager.set.assert_called_once()
            mock_manager.save_config.assert_not_called()

    def test_config_set_invalid_key(self):
        """Test setting invalid configuration key."""
        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock(spec=ConfigManager)
            mock_manager.set.side_effect = ValueError("Invalid key")
            mock_get_config.return_value = mock_manager

            result = runner.invoke(config_cmd.app, ["set", "invalid.key", "value"])

            assert result.exit_code == 1
            assert "Error" in result.stdout

    def test_config_init_default_path(self, tmp_path):
        """Test initializing config file at default path."""
        config_path = tmp_path / "config.json"

        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock()
            mock_manager.save_config.return_value = config_path
            mock_get_config.return_value = mock_manager

            with patch('threat_radar.cli.config.Path.home', return_value=tmp_path):
                result = runner.invoke(config_cmd.app, ["init", "--path", str(config_path)])

                assert result.exit_code == 0
                assert "Created" in result.stdout

    def test_config_init_custom_path(self, tmp_path):
        """Test initializing config file at custom path."""
        custom_path = tmp_path / "custom-config.json"

        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock(spec=ConfigManager)
            mock_manager.save_config.return_value = custom_path
            mock_get_config.return_value = mock_manager

            result = runner.invoke(config_cmd.app, ["init", "--path", str(custom_path)])

            assert result.exit_code == 0

    def test_config_init_file_exists_no_force(self, tmp_path):
        """Test init when file exists without force flag."""
        existing_file = tmp_path / "config.json"
        existing_file.write_text("{}")

        result = runner.invoke(config_cmd.app, ["init", "--path", str(existing_file)])

        # Should either succeed with warning or fail
        assert "exists" in result.stdout.lower() or result.exit_code == 0

    def test_config_init_file_exists_with_force(self, tmp_path):
        """Test init when file exists with force flag."""
        existing_file = tmp_path / "config.json"
        existing_file.write_text("{}")

        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock(spec=ConfigManager)
            mock_manager.save_config.return_value = existing_file
            mock_get_config.return_value = mock_manager

            result = runner.invoke(config_cmd.app, ["init", "--path", str(existing_file), "--force"])

            assert result.exit_code == 0

    def test_config_path_no_file_found(self):
        """Test showing config path when no file is found."""
        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock()
            mock_manager.config_path = None
            mock_get_config.return_value = mock_manager

            result = runner.invoke(config_cmd.app, ["path"])

            assert result.exit_code == 0
            assert "No configuration file loaded" in result.stdout or "defaults" in result.stdout

    def test_config_path_file_found(self, tmp_path):
        """Test showing config path when file is found."""
        config_file = tmp_path / "config.json"
        config_file.write_text("{}")

        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock()
            mock_manager.config_path = config_file
            mock_get_config.return_value = mock_manager

            result = runner.invoke(config_cmd.app, ["path"])

            assert result.exit_code == 0
            assert "Currently loaded" in result.stdout

    def test_config_validate_valid_config(self, tmp_path):
        """Test validating valid configuration."""
        config_file = tmp_path / "valid.json"
        config_file.write_text(json.dumps({"scan": {"severity": "HIGH"}}))

        result = runner.invoke(config_cmd.app, ["validate", str(config_file)])

        assert result.exit_code == 0
        assert "valid" in result.stdout.lower() or "✓" in result.stdout

    def test_config_validate_invalid_json(self, tmp_path):
        """Test validating invalid JSON."""
        config_file = tmp_path / "invalid.json"
        config_file.write_text("{ invalid json }")

        result = runner.invoke(config_cmd.app, ["validate", str(config_file)])

        assert result.exit_code == 1
        assert "Invalid JSON" in result.stdout or "JSON" in result.stdout

    def test_config_validate_no_file_arg(self):
        """Test validate without file argument when no config loaded."""
        with patch('threat_radar.cli.config.get_config_manager') as mock_get_config:
            mock_manager = MagicMock()
            mock_manager.config_path = None
            mock_get_config.return_value = mock_manager

            result = runner.invoke(config_cmd.app, ["validate"])

            assert result.exit_code == 1
            assert "No config file" in result.stdout or "Specify a file" in result.stdout


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
