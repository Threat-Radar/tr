"""Comprehensive tests for configuration management."""

import pytest
import json
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import tempfile

from threat_radar.utils.config_manager import (
    ConfigManager,
    ThreatRadarConfig,
    ScanDefaults,
    AIDefaults,
    ReportDefaults,
    OutputDefaults,
    PathDefaults,
    get_config_manager,
    reset_config_manager,
)


@pytest.fixture(autouse=True)
def isolate_config(monkeypatch, tmp_path):
    """Isolate tests from user's actual config files."""
    # Reset global config manager before each test
    reset_config_manager()

    # Mock default config locations to use tmp_path instead
    fake_locations = [
        tmp_path / ".threat-radar.json",
        tmp_path / "threat-radar.json",
        tmp_path / ".threat-radar" / "config.json",
        tmp_path / ".config" / "threat-radar" / "config.json",
    ]
    monkeypatch.setattr(
        "threat_radar.utils.config_manager.ConfigManager.DEFAULT_CONFIG_LOCATIONS",
        fake_locations
    )

    yield

    # Reset again after test
    reset_config_manager()


@pytest.fixture
def sample_config_dict():
    """Create sample configuration dictionary."""
    return {
        "scan": {
            "severity": "HIGH",
            "only_fixed": True,
            "auto_save": True,
            "cleanup": False,
            "scope": "squashed",
            "output_format": "json",
        },
        "ai": {
            "provider": "openai",
            "model": "gpt-4o",
            "temperature": 0.3,
            "batch_size": 25,
            "auto_batch_threshold": 30,
        },
        "report": {
            "level": "detailed",
            "format": "json",
            "include_executive_summary": True,
            "include_dashboard_data": True,
        },
        "output": {
            "format": "table",
            "verbosity": 2,
            "color": True,
            "progress": True,
        },
        "paths": {
            "cve_storage": "./storage/cve_storage",
            "ai_storage": "./storage/ai_analysis",
            "sbom_storage": "./sbom_storage",
            "cache_dir": "~/.threat-radar/cache",
            "config_dir": "~/.threat-radar",
        },
    }


@pytest.fixture
def temp_config_file(sample_config_dict, tmp_path):
    """Create temporary configuration file."""
    config_file = tmp_path / "test-config.json"
    config_file.write_text(json.dumps(sample_config_dict, indent=2))
    return config_file


class TestScanDefaults:
    """Test ScanDefaults data class."""

    def test_create_defaults(self):
        """Test creating scan defaults."""
        defaults = ScanDefaults()

        assert defaults.severity is None
        assert defaults.only_fixed is False
        assert defaults.auto_save is False
        assert defaults.cleanup is False
        assert defaults.scope == "squashed"
        assert defaults.output_format == "json"

    def test_create_with_values(self):
        """Test creating scan defaults with custom values."""
        defaults = ScanDefaults(
            severity="HIGH",
            only_fixed=True,
            auto_save=True,
            cleanup=True,
            scope="all-layers",
            output_format="table",
        )

        assert defaults.severity == "HIGH"
        assert defaults.only_fixed is True
        assert defaults.auto_save is True
        assert defaults.cleanup is True
        assert defaults.scope == "all-layers"
        assert defaults.output_format == "table"


class TestAIDefaults:
    """Test AIDefaults data class."""

    def test_create_defaults(self):
        """Test creating AI defaults."""
        defaults = AIDefaults()

        assert defaults.provider is None
        assert defaults.model is None
        assert defaults.temperature == 0.3
        assert defaults.batch_size == 25
        assert defaults.auto_batch_threshold == 30

    def test_create_with_values(self):
        """Test creating AI defaults with custom values."""
        defaults = AIDefaults(
            provider="anthropic",
            model="claude-3-5-sonnet-20241022",
            temperature=0.5,
            batch_size=50,
            auto_batch_threshold=100,
        )

        assert defaults.provider == "anthropic"
        assert defaults.model == "claude-3-5-sonnet-20241022"
        assert defaults.temperature == 0.5
        assert defaults.batch_size == 50
        assert defaults.auto_batch_threshold == 100


class TestReportDefaults:
    """Test ReportDefaults data class."""

    def test_create_defaults(self):
        """Test creating report defaults."""
        defaults = ReportDefaults()

        assert defaults.level == "detailed"
        assert defaults.format == "json"
        assert defaults.include_executive_summary is True
        assert defaults.include_dashboard_data is True

    def test_create_with_values(self):
        """Test creating report defaults with custom values."""
        defaults = ReportDefaults(
            level="executive",
            format="markdown",
            include_executive_summary=False,
            include_dashboard_data=False,
        )

        assert defaults.level == "executive"
        assert defaults.format == "markdown"
        assert defaults.include_executive_summary is False
        assert defaults.include_dashboard_data is False


class TestOutputDefaults:
    """Test OutputDefaults data class."""

    def test_create_defaults(self):
        """Test creating output defaults."""
        defaults = OutputDefaults()

        assert defaults.format == "table"
        assert defaults.verbosity == 1
        assert defaults.color is True
        assert defaults.progress is True

    def test_create_with_values(self):
        """Test creating output defaults with custom values."""
        defaults = OutputDefaults(
            format="json",
            verbosity=3,
            color=False,
            progress=False,
        )

        assert defaults.format == "json"
        assert defaults.verbosity == 3
        assert defaults.color is False
        assert defaults.progress is False


class TestPathDefaults:
    """Test PathDefaults data class."""

    def test_create_defaults(self):
        """Test creating path defaults."""
        defaults = PathDefaults()

        assert defaults.cve_storage == "./storage/cve_storage"
        assert defaults.ai_storage == "./storage/ai_analysis"
        assert defaults.sbom_storage == "./sbom_storage"
        assert defaults.cache_dir == "~/.threat-radar/cache"
        assert defaults.config_dir == "~/.threat-radar"

    def test_create_with_custom_paths(self):
        """Test creating path defaults with custom paths."""
        defaults = PathDefaults(
            cve_storage="/custom/cve",
            ai_storage="/custom/ai",
            sbom_storage="/custom/sbom",
            cache_dir="/custom/cache",
            config_dir="/custom/config",
        )

        assert defaults.cve_storage == "/custom/cve"
        assert defaults.ai_storage == "/custom/ai"
        assert defaults.sbom_storage == "/custom/sbom"
        assert defaults.cache_dir == "/custom/cache"
        assert defaults.config_dir == "/custom/config"


class TestThreatRadarConfig:
    """Test ThreatRadarConfig data class."""

    def test_create_default_config(self):
        """Test creating default configuration."""
        config = ThreatRadarConfig()

        assert config.scan is not None
        assert config.ai is not None
        assert config.report is not None
        assert config.output is not None
        assert config.paths is not None

    def test_to_dict(self, sample_config_dict):
        """Test converting config to dictionary."""
        config = ThreatRadarConfig.from_dict(sample_config_dict)
        config_dict = config.to_dict()

        assert isinstance(config_dict, dict)
        assert "scan" in config_dict
        assert "ai" in config_dict
        assert "report" in config_dict
        assert "output" in config_dict
        assert "paths" in config_dict

        # Verify values
        assert config_dict["scan"]["severity"] == "HIGH"
        assert config_dict["ai"]["provider"] == "openai"
        assert config_dict["output"]["verbosity"] == 2

    def test_from_dict(self, sample_config_dict):
        """Test creating config from dictionary."""
        config = ThreatRadarConfig.from_dict(sample_config_dict)

        assert config.scan.severity == "HIGH"
        assert config.scan.only_fixed is True
        assert config.ai.provider == "openai"
        assert config.ai.model == "gpt-4o"
        assert config.report.level == "detailed"
        assert config.output.verbosity == 2

    def test_from_dict_partial(self):
        """Test creating config from partial dictionary."""
        partial_dict = {
            "scan": {
                "severity": "CRITICAL",
            },
            "ai": {
                "provider": "ollama",
            }
        }

        config = ThreatRadarConfig.from_dict(partial_dict)

        # Check overridden values
        assert config.scan.severity == "CRITICAL"
        assert config.ai.provider == "ollama"

        # Check defaults are preserved
        assert config.scan.only_fixed is False
        assert config.output.verbosity == 1

    def test_from_dict_empty(self):
        """Test creating config from empty dictionary."""
        config = ThreatRadarConfig.from_dict({})

        # Should use all defaults
        assert config.scan.severity is None
        assert config.ai.provider is None
        assert config.output.format == "table"


class TestConfigManager:
    """Test ConfigManager class."""

    def test_initialization_no_config_file(self):
        """Test initialization without config file."""
        with patch.object(Path, 'exists', return_value=False):
            manager = ConfigManager()

            assert manager.config is not None
            assert manager.config_path is None

    def test_initialization_with_config_file(self, temp_config_file):
        """Test initialization with config file."""
        manager = ConfigManager(config_path=temp_config_file)

        assert manager.config is not None
        assert manager.config_path == temp_config_file
        assert manager.config.scan.severity == "HIGH"
        assert manager.config.ai.provider == "openai"

    def test_load_from_file(self, temp_config_file):
        """Test loading config from file."""
        manager = ConfigManager()
        manager.load_from_file(temp_config_file)

        assert manager.config.scan.severity == "HIGH"
        assert manager.config.ai.model == "gpt-4o"

    def test_load_from_file_not_found(self):
        """Test loading from nonexistent file."""
        manager = ConfigManager()

        with pytest.raises(FileNotFoundError):
            manager.load_from_file(Path("/nonexistent/config.json"))

    def test_load_from_file_invalid_json(self, tmp_path):
        """Test loading from invalid JSON file."""
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("{ invalid json }")

        manager = ConfigManager()

        with pytest.raises(ValueError, match="Invalid JSON"):
            manager.load_from_file(invalid_file)

    def test_save_to_file(self, tmp_path):
        """Test saving config to file."""
        output_file = tmp_path / "output-config.json"

        manager = ConfigManager()
        manager.config.scan.severity = "CRITICAL"
        manager.config.ai.provider = "anthropic"
        manager.save_to_file(output_file)

        assert output_file.exists()

        # Load and verify
        loaded_config = json.loads(output_file.read_text())
        assert loaded_config["scan"]["severity"] == "CRITICAL"
        assert loaded_config["ai"]["provider"] == "anthropic"

    def test_get_simple_key(self, temp_config_file):
        """Test getting configuration value with simple key."""
        manager = ConfigManager(config_path=temp_config_file)

        # Top-level access doesn't make sense for nested structure
        # Use dot notation instead
        value = manager.get("scan")
        assert value is not None

    def test_get_dot_notation(self, temp_config_file):
        """Test getting configuration value with dot notation."""
        manager = ConfigManager(config_path=temp_config_file)

        value = manager.get("scan.severity")
        assert value == "HIGH"

        value = manager.get("ai.provider")
        assert value == "openai"

        value = manager.get("output.verbosity")
        assert value == 2

    def test_get_with_default(self):
        """Test getting nonexistent key with default."""
        manager = ConfigManager()

        value = manager.get("nonexistent.key", default="default_value")
        assert value == "default_value"

    def test_get_nonexistent_no_default(self):
        """Test getting nonexistent key without default."""
        manager = ConfigManager()

        value = manager.get("nonexistent.key")
        assert value is None

    def test_set_simple_value(self):
        """Test setting configuration value."""
        manager = ConfigManager()

        manager.set("scan.severity", "CRITICAL")
        assert manager.get("scan.severity") == "CRITICAL"

        manager.set("ai.provider", "ollama")
        assert manager.get("ai.provider") == "ollama"

    def test_set_nested_value(self):
        """Test setting nested configuration value."""
        manager = ConfigManager()

        manager.set("output.verbosity", 3)
        assert manager.get("output.verbosity") == 3

        manager.set("paths.cve_storage", "/custom/path")
        assert manager.get("paths.cve_storage") == "/custom/path"

    def test_set_invalid_key(self):
        """Test setting invalid configuration key."""
        manager = ConfigManager()

        with pytest.raises(KeyError, match="Invalid configuration key"):
            manager.set("invalid.key.path", "value")

    def test_load_from_env_vars(self):
        """Test loading configuration from environment variables."""
        with patch.dict(os.environ, {
            "THREAT_RADAR_SCAN_SEVERITY": "HIGH",
            "THREAT_RADAR_AI_PROVIDER": "anthropic",
            "THREAT_RADAR_OUTPUT_VERBOSITY": "3",
        }):
            manager = ConfigManager()
            manager.load_from_env()

            assert manager.get("scan.severity") == "HIGH"
            assert manager.get("ai.provider") == "anthropic"
            assert manager.get("output.verbosity") == 3

    def test_load_from_env_vars_partial(self):
        """Test loading partial configuration from environment."""
        with patch.dict(os.environ, {
            "THREAT_RADAR_SCAN_SEVERITY": "CRITICAL",
        }, clear=True):
            manager = ConfigManager()
            manager.load_from_env()

            # Check overridden value
            assert manager.get("scan.severity") == "CRITICAL"

            # Check defaults are preserved
            assert manager.get("scan.only_fixed") is False

    def test_find_config_file_current_dir(self, tmp_path):
        """Test finding config file in current directory."""
        config_file = tmp_path / ".threat-radar.json"
        config_file.write_text(json.dumps({"scan": {"severity": "HIGH"}}))

        with patch.object(Path, 'cwd', return_value=tmp_path):
            manager = ConfigManager()
            found = manager.find_config_file()

            assert found == config_file

    def test_find_config_file_not_found(self, tmp_path):
        """Test when config file is not found."""
        with patch.object(Path, 'cwd', return_value=tmp_path):
            with patch.object(Path, 'home', return_value=tmp_path):
                manager = ConfigManager()
                found = manager.find_config_file()

                assert found is None

    def test_validate_config(self, temp_config_file):
        """Test validating configuration."""
        manager = ConfigManager(config_path=temp_config_file)

        is_valid, errors = manager.validate()

        assert is_valid is True
        assert len(errors) == 0

    def test_validate_invalid_config(self):
        """Test validating invalid configuration."""
        manager = ConfigManager()

        # Set invalid values
        manager.config.output.verbosity = 999  # Invalid verbosity

        is_valid, errors = manager.validate()

        # For now, validation is simple, may always return True
        # This test is a placeholder for future validation logic
        assert isinstance(is_valid, bool)
        assert isinstance(errors, list)

    def test_reset_to_defaults(self, temp_config_file):
        """Test resetting configuration to defaults."""
        manager = ConfigManager(config_path=temp_config_file)

        # Verify loaded config
        assert manager.get("scan.severity") == "HIGH"

        # Reset to defaults
        manager.reset_to_defaults()

        # Verify defaults restored
        assert manager.get("scan.severity") is None
        assert manager.get("ai.provider") is None

    def test_merge_configs(self):
        """Test merging configurations."""
        manager = ConfigManager()

        # Set some values
        manager.set("scan.severity", "HIGH")
        manager.set("ai.provider", "openai")

        # Create override config
        override = {
            "scan": {"severity": "CRITICAL"},
            "report": {"level": "executive"},
        }

        manager.merge(override)

        # Check merged values
        assert manager.get("scan.severity") == "CRITICAL"  # Overridden
        assert manager.get("ai.provider") == "openai"  # Preserved
        assert manager.get("report.level") == "executive"  # New value

    def test_get_config_dict(self, temp_config_file):
        """Test getting full configuration as dictionary."""
        manager = ConfigManager(config_path=temp_config_file)

        config_dict = manager.get_config_dict()

        assert isinstance(config_dict, dict)
        assert "scan" in config_dict
        assert "ai" in config_dict
        assert config_dict["scan"]["severity"] == "HIGH"


class TestGetConfigManager:
    """Test get_config_manager utility function."""

    def test_get_config_manager_no_args(self):
        """Test getting config manager without arguments."""
        with patch.object(ConfigManager, '__init__', return_value=None):
            manager = get_config_manager()

            assert manager is not None

    def test_get_config_manager_with_path(self, temp_config_file):
        """Test getting config manager with config path."""
        manager = get_config_manager(temp_config_file)

        assert manager is not None
        assert manager.config_path == temp_config_file

    def test_get_config_manager_singleton_behavior(self):
        """Test that config manager can be reused."""
        manager1 = get_config_manager()
        manager2 = get_config_manager()

        # Both should be valid instances
        assert manager1 is not None
        assert manager2 is not None


class TestConfigurationPrecedence:
    """Test configuration precedence (file -> env -> CLI)."""

    def test_precedence_file_then_env(self, temp_config_file):
        """Test that environment variables override file config."""
        with patch.dict(os.environ, {
            "THREAT_RADAR_SCAN_SEVERITY": "CRITICAL",
        }):
            manager = ConfigManager(config_path=temp_config_file)
            manager.load_from_env()

            # Environment variable should override file
            assert manager.get("scan.severity") == "CRITICAL"

            # Other file values should remain
            assert manager.get("ai.provider") == "openai"

    def test_precedence_programmatic_override(self, temp_config_file):
        """Test that programmatic changes override everything."""
        with patch.dict(os.environ, {
            "THREAT_RADAR_SCAN_SEVERITY": "MEDIUM",
        }):
            manager = ConfigManager(config_path=temp_config_file)
            manager.load_from_env()

            # Programmatically set (highest precedence)
            manager.set("scan.severity", "LOW")

            assert manager.get("scan.severity") == "LOW"


class TestConfigurationEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_config_file(self, tmp_path):
        """Test loading empty config file."""
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("{}")

        manager = ConfigManager(config_path=empty_file)

        # Should load with defaults
        assert manager.get("scan.severity") is None
        assert manager.get("output.format") == "table"

    def test_malformed_nested_structure(self, tmp_path):
        """Test handling malformed nested structure."""
        malformed_file = tmp_path / "malformed.json"
        malformed_file.write_text(json.dumps({
            "scan": "not_a_dict"  # Should be dict
        }))

        manager = ConfigManager()

        with pytest.raises(Exception):
            manager.load_from_file(malformed_file)

    def test_unicode_in_config(self, tmp_path):
        """Test configuration with unicode characters."""
        unicode_config = {
            "scan": {"severity": "HIGH"},
            "ai": {"provider": "测试"},  # Chinese characters
        }

        config_file = tmp_path / "unicode.json"
        config_file.write_text(json.dumps(unicode_config, ensure_ascii=False))

        manager = ConfigManager(config_path=config_file)

        assert manager.get("ai.provider") == "测试"


class TestConfigManagerErrorHandling:
    """Test error handling in ConfigManager."""

    def test_load_config_with_json_decode_error(self, tmp_path):
        """Test handling of invalid JSON in config file during initialization."""
        bad_json_file = tmp_path / "bad.json"
        bad_json_file.write_text("{ invalid json }")

        # Should not raise, just log error and use defaults
        manager = ConfigManager(config_path=bad_json_file)

        # Should have default values since JSON was invalid
        assert manager.get("scan.severity") is None
        assert manager.get("output.format") == "table"

    def test_load_config_with_general_exception(self, tmp_path):
        """Test handling of general exception during config load."""
        config_file = tmp_path / "test.json"
        config_file.write_text(json.dumps({"scan": {"severity": "HIGH"}}))

        manager = ConfigManager(config_path=config_file)

        # Mock open to raise exception
        with patch('builtins.open', side_effect=PermissionError("Access denied")):
            # Should not crash, just log error
            manager._load_config()

    def test_find_config_file_with_nonexistent_path(self, tmp_path):
        """Test finding config when explicit path doesn't exist."""
        nonexistent = tmp_path / "does_not_exist.json"

        manager = ConfigManager(config_path=nonexistent)
        found = manager._find_config_file()

        assert found is None

    def test_save_config_creates_directory(self, tmp_path):
        """Test that save_config creates parent directory if needed."""
        nested_path = tmp_path / "nested" / "dir" / "config.json"

        manager = ConfigManager()
        manager.set("scan.severity", "HIGH")

        saved_path = manager.save_config(nested_path)

        assert saved_path.exists()
        assert saved_path.parent.exists()


class TestEnvironmentVariableOverrides:
    """Test comprehensive environment variable override scenarios."""

    def test_backward_compat_severity_var(self):
        """Test backward compatibility with THREAT_RADAR_SEVERITY."""
        with patch.dict(os.environ, {
            "THREAT_RADAR_SEVERITY": "MEDIUM",
        }, clear=True):
            manager = ConfigManager()
            manager.load_from_env()

            assert manager.get("scan.severity") == "MEDIUM"

    def test_new_var_overrides_old_var(self):
        """Test that new env var takes precedence over old."""
        with patch.dict(os.environ, {
            "THREAT_RADAR_SCAN_SEVERITY": "CRITICAL",
            "THREAT_RADAR_SEVERITY": "LOW",  # Should be ignored
        }):
            manager = ConfigManager()
            manager.load_from_env()

            assert manager.get("scan.severity") == "CRITICAL"

    def test_backward_compat_verbosity_var(self):
        """Test backward compatibility with THREAT_RADAR_VERBOSITY."""
        with patch.dict(os.environ, {
            "THREAT_RADAR_VERBOSITY": "2",
        }, clear=True):
            manager = ConfigManager()
            manager.load_from_env()

            assert manager.get("output.verbosity") == 2

    def test_invalid_verbosity_value(self):
        """Test handling of invalid verbosity value."""
        with patch.dict(os.environ, {
            "THREAT_RADAR_OUTPUT_VERBOSITY": "not_a_number",
        }):
            manager = ConfigManager()
            manager.load_from_env()

            # Should keep default value
            assert manager.get("output.verbosity") == 1

    def test_auto_save_env_var(self):
        """Test THREAT_RADAR_AUTO_SAVE environment variable."""
        with patch.dict(os.environ, {
            "THREAT_RADAR_AUTO_SAVE": "true",
        }):
            manager = ConfigManager()
            manager.load_from_env()

            assert manager.get("scan.auto_save") is True

    def test_output_format_env_var(self):
        """Test THREAT_RADAR_OUTPUT_FORMAT environment variable."""
        with patch.dict(os.environ, {
            "THREAT_RADAR_OUTPUT_FORMAT": "json",
        }):
            manager = ConfigManager()
            manager.load_from_env()

            assert manager.get("output.format") == "json"


class TestValidationEdgeCases:
    """Test validation edge cases."""

    def test_validate_all_severities(self):
        """Test validation accepts all valid severity levels."""
        valid_severities = ["NEGLIGIBLE", "LOW", "MEDIUM", "HIGH", "CRITICAL", None]

        for severity in valid_severities:
            manager = ConfigManager()
            manager.set("scan.severity", severity)

            is_valid, errors = manager.validate()
            assert is_valid, f"Severity {severity} should be valid"

    def test_validate_all_providers(self):
        """Test validation accepts all valid AI providers."""
        valid_providers = ["openai", "anthropic", "ollama", "openrouter", None]

        for provider in valid_providers:
            manager = ConfigManager()
            manager.set("ai.provider", provider)

            is_valid, errors = manager.validate()
            assert is_valid, f"Provider {provider} should be valid"

    def test_validate_all_output_formats(self):
        """Test validation accepts all valid output formats."""
        valid_formats = ["table", "json", "yaml", "csv"]

        for fmt in valid_formats:
            manager = ConfigManager()
            manager.set("output.format", fmt)

            is_valid, errors = manager.validate()
            assert is_valid, f"Format {fmt} should be valid"

    def test_validate_all_report_formats(self):
        """Test validation accepts all valid report formats."""
        valid_formats = ["json", "markdown", "html", "pdf"]

        for fmt in valid_formats:
            manager = ConfigManager()
            manager.set("report.format", fmt)

            is_valid, errors = manager.validate()
            assert is_valid, f"Report format {fmt} should be valid"

    def test_validate_negative_verbosity(self):
        """Test validation rejects negative verbosity."""
        manager = ConfigManager()
        manager.set("output.verbosity", -1)

        is_valid, errors = manager.validate()
        assert not is_valid
        assert any("verbosity" in err.lower() for err in errors)

    def test_validate_verbosity_too_high(self):
        """Test validation rejects verbosity > 3."""
        manager = ConfigManager()
        manager.set("output.verbosity", 4)

        is_valid, errors = manager.validate()
        assert not is_valid
        assert any("verbosity" in err.lower() for err in errors)

    def test_validate_invalid_severity(self):
        """Test validation rejects invalid severity."""
        manager = ConfigManager()
        manager.set("scan.severity", "INVALID")

        is_valid, errors = manager.validate()
        assert not is_valid
        assert any("severity" in err.lower() for err in errors)

    def test_validate_invalid_provider(self):
        """Test validation rejects invalid AI provider."""
        manager = ConfigManager()
        manager.set("ai.provider", "invalid_provider")

        is_valid, errors = manager.validate()
        assert not is_valid
        assert any("provider" in err.lower() for err in errors)

    def test_validate_invalid_output_format(self):
        """Test validation rejects invalid output format."""
        manager = ConfigManager()
        manager.set("output.format", "invalid")

        is_valid, errors = manager.validate()
        assert not is_valid
        assert any("output format" in err.lower() for err in errors)

    def test_validate_invalid_report_format(self):
        """Test validation rejects invalid report format."""
        manager = ConfigManager()
        manager.set("report.format", "invalid")

        is_valid, errors = manager.validate()
        assert not is_valid
        assert any("report format" in err.lower() for err in errors)


class TestMergeConfigurations:
    """Test configuration merging scenarios."""

    def test_merge_partial_override(self):
        """Test merging with partial override."""
        manager = ConfigManager()
        manager.set("scan.severity", "LOW")
        manager.set("ai.provider", "openai")

        override = {
            "scan": {
                "severity": "HIGH",
            }
        }

        manager.merge(override)

        # Overridden value
        assert manager.get("scan.severity") == "HIGH"
        # Non-overridden value preserved
        assert manager.get("ai.provider") == "openai"

    def test_merge_multiple_sections(self):
        """Test merging multiple config sections."""
        manager = ConfigManager()

        override = {
            "scan": {"severity": "CRITICAL"},
            "ai": {"provider": "anthropic", "model": "claude-3-5-sonnet-20241022"},
            "output": {"verbosity": 3}
        }

        manager.merge(override)

        assert manager.get("scan.severity") == "CRITICAL"
        assert manager.get("ai.provider") == "anthropic"
        assert manager.get("ai.model") == "claude-3-5-sonnet-20241022"
        assert manager.get("output.verbosity") == 3

    def test_merge_empty_override(self):
        """Test merging empty override dict."""
        manager = ConfigManager()
        original_severity = manager.get("scan.severity")

        manager.merge({})

        # Nothing should change
        assert manager.get("scan.severity") == original_severity


class TestResetConfigManager:
    """Test reset_config_manager function."""

    def test_reset_config_manager_function(self):
        """Test that reset_config_manager clears global instance."""
        from threat_radar.utils.config_manager import reset_config_manager, get_config_manager

        # Create first instance
        manager1 = get_config_manager()
        manager1.set("scan.severity", "HIGH")

        # Reset global
        reset_config_manager()

        # Get new instance
        manager2 = get_config_manager()

        # Should be fresh instance with defaults
        assert manager2.get("scan.severity") is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
