"""Configuration management for Threat Radar CLI."""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict, field

logger = logging.getLogger(__name__)


@dataclass
class ScanDefaults:
    """Default settings for vulnerability scanning."""

    severity: Optional[str] = None  # Minimum severity filter
    only_fixed: bool = False
    auto_save: bool = False
    cleanup: bool = False
    scope: str = "squashed"
    output_format: str = "json"


@dataclass
class AIDefaults:
    """Default settings for AI analysis."""

    provider: Optional[str] = None
    model: Optional[str] = None
    temperature: float = 0.3
    batch_size: int = 25
    auto_batch_threshold: int = 30


@dataclass
class ReportDefaults:
    """Default settings for report generation."""

    level: str = "detailed"
    format: str = "json"
    include_executive_summary: bool = True
    include_dashboard_data: bool = True


@dataclass
class OutputDefaults:
    """Default output settings."""

    format: str = "table"  # table, json, yaml, csv
    verbosity: int = 1  # 0=quiet, 1=normal, 2=verbose, 3=debug
    color: bool = True
    progress: bool = True


@dataclass
class PathDefaults:
    """Default path settings."""

    cve_storage: str = "./storage/cve_storage"
    ai_storage: str = "./storage/ai_analysis"
    sbom_storage: str = "./sbom_storage"
    cache_dir: str = "~/.threat-radar/cache"
    config_dir: str = "~/.threat-radar"


@dataclass
class ThreatRadarConfig:
    """Complete Threat Radar configuration."""

    scan: ScanDefaults = field(default_factory=ScanDefaults)
    ai: AIDefaults = field(default_factory=AIDefaults)
    report: ReportDefaults = field(default_factory=ReportDefaults)
    output: OutputDefaults = field(default_factory=OutputDefaults)
    paths: PathDefaults = field(default_factory=PathDefaults)

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatRadarConfig":
        """Create configuration from dictionary."""
        return cls(
            scan=ScanDefaults(**data.get("scan", {})),
            ai=AIDefaults(**data.get("ai", {})),
            report=ReportDefaults(**data.get("report", {})),
            output=OutputDefaults(**data.get("output", {})),
            paths=PathDefaults(**data.get("paths", {})),
        )


class ConfigManager:
    """Manages Threat Radar configuration from files and environment."""

    DEFAULT_CONFIG_LOCATIONS = [
        Path.cwd() / ".threat-radar.json",
        Path.cwd() / "threat-radar.json",
        Path.home() / ".threat-radar" / "config.json",
        Path.home() / ".config" / "threat-radar" / "config.json",
    ]

    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize configuration manager.

        Args:
            config_path: Optional explicit path to config file
        """
        self.config_path = config_path
        self.config = ThreatRadarConfig()
        self._load_config()

    def _find_config_file(self) -> Optional[Path]:
        """Find configuration file in default locations."""
        # Use explicit path if provided
        if self.config_path:
            if self.config_path.exists():
                return self.config_path
            else:
                logger.warning(f"Config file not found: {self.config_path}")
                return None

        # Search default locations
        for path in self.DEFAULT_CONFIG_LOCATIONS:
            if path.exists():
                logger.debug(f"Found config file: {path}")
                return path

        logger.debug("No config file found, using defaults")
        return None

    def _load_config(self):
        """Load configuration from file."""
        config_file = self._find_config_file()
        if not config_file:
            return

        try:
            with open(config_file, "r") as f:
                data = json.load(f)

            self.config = ThreatRadarConfig.from_dict(data)
            logger.info(f"Loaded configuration from: {config_file}")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file {config_file}: {e}")
        except Exception as e:
            logger.error(f"Error loading config file {config_file}: {e}")

    def _apply_env_overrides(self):
        """Apply environment variable overrides to configuration."""
        # Scan defaults
        if os.getenv("THREAT_RADAR_SCAN_SEVERITY"):
            self.config.scan.severity = os.getenv("THREAT_RADAR_SCAN_SEVERITY")
        elif os.getenv("THREAT_RADAR_SEVERITY"):  # Backward compatibility
            self.config.scan.severity = os.getenv("THREAT_RADAR_SEVERITY")
        if os.getenv("THREAT_RADAR_AUTO_SAVE"):
            self.config.scan.auto_save = (
                os.getenv("THREAT_RADAR_AUTO_SAVE").lower() == "true"
            )

        # AI defaults
        if os.getenv("THREAT_RADAR_AI_PROVIDER"):
            self.config.ai.provider = os.getenv("THREAT_RADAR_AI_PROVIDER")
        elif os.getenv("AI_PROVIDER"):  # Backward compatibility
            self.config.ai.provider = os.getenv("AI_PROVIDER")
        if os.getenv("THREAT_RADAR_AI_MODEL"):
            self.config.ai.model = os.getenv("THREAT_RADAR_AI_MODEL")
        elif os.getenv("AI_MODEL"):  # Backward compatibility
            self.config.ai.model = os.getenv("AI_MODEL")

        # Output defaults
        if os.getenv("THREAT_RADAR_OUTPUT_VERBOSITY"):
            try:
                self.config.output.verbosity = int(
                    os.getenv("THREAT_RADAR_OUTPUT_VERBOSITY")
                )
            except ValueError:
                pass
        elif os.getenv("THREAT_RADAR_VERBOSITY"):  # Backward compatibility
            try:
                self.config.output.verbosity = int(os.getenv("THREAT_RADAR_VERBOSITY"))
            except ValueError:
                pass

        if os.getenv("THREAT_RADAR_OUTPUT_FORMAT"):
            self.config.output.format = os.getenv("THREAT_RADAR_OUTPUT_FORMAT")

    def load_from_file(self, path: Path):
        """
        Load configuration from a specific file.

        Args:
            path: Path to configuration file

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If JSON is invalid
        """
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        try:
            with open(path, "r") as f:
                data = json.load(f)

            self.config = ThreatRadarConfig.from_dict(data)
            logger.info(f"Loaded configuration from: {path}")

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in config file {path}: {e}")
        except Exception as e:
            raise ValueError(f"Error loading config file {path}: {e}")

    def load_from_env(self):
        """Load configuration from environment variables."""
        self._apply_env_overrides()

    def find_config_file(self) -> Optional[Path]:
        """
        Find configuration file in default locations.

        Returns:
            Path to config file if found, None otherwise
        """
        return self._find_config_file()

    def save_config(self, path: Optional[Path] = None):
        """
        Save current configuration to file.

        Args:
            path: Path to save config file (default: ~/.threat-radar/config.json)
        """
        if path is None:
            path = Path.home() / ".threat-radar" / "config.json"

        # Create directory if needed
        path.parent.mkdir(parents=True, exist_ok=True)

        # Save configuration
        with open(path, "w") as f:
            json.dump(self.config.to_dict(), f, indent=2)

        logger.info(f"Saved configuration to: {path}")
        return path

    def save_to_file(self, path: Path):
        """
        Save current configuration to a specific file.

        Args:
            path: Path to save config file
        """
        return self.save_config(path)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-notation key.

        Args:
            key: Configuration key (e.g., 'scan.severity', 'ai.provider')
            default: Default value if key not found

        Returns:
            Configuration value
        """
        parts = key.split(".")
        value = self.config

        for part in parts:
            if hasattr(value, part):
                value = getattr(value, part)
            else:
                return default

        return value

    def set(self, key: str, value: Any):
        """
        Set configuration value by dot-notation key.

        Args:
            key: Configuration key (e.g., 'scan.severity')
            value: Value to set

        Raises:
            KeyError: If configuration key is invalid
        """
        parts = key.split(".")
        obj = self.config

        # Navigate to parent object
        for part in parts[:-1]:
            if hasattr(obj, part):
                obj = getattr(obj, part)
            else:
                raise KeyError(f"Invalid configuration key: {key}")

        # Set final attribute
        final_key = parts[-1]
        if hasattr(obj, final_key):
            setattr(obj, final_key, value)
        else:
            raise KeyError(f"Invalid configuration key: {key}")

    def validate(self) -> tuple[bool, list[str]]:
        """
        Validate current configuration.

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Validate verbosity level
        if self.config.output.verbosity < 0 or self.config.output.verbosity > 3:
            errors.append(
                f"Invalid verbosity level: {self.config.output.verbosity}. Must be 0-3."
            )

        # Validate severity if set
        valid_severities = ["NEGLIGIBLE", "LOW", "MEDIUM", "HIGH", "CRITICAL", None]
        if (
            self.config.scan.severity
            and self.config.scan.severity not in valid_severities
        ):
            errors.append(
                f"Invalid severity: {self.config.scan.severity}. Must be one of {valid_severities}"
            )

        # Validate AI provider if set
        valid_providers = ["openai", "anthropic", "ollama", "openrouter", None]
        if self.config.ai.provider and self.config.ai.provider not in valid_providers:
            errors.append(
                f"Invalid AI provider: {self.config.ai.provider}. Must be one of {valid_providers}"
            )

        # Validate output format
        valid_formats = ["table", "json", "yaml", "csv"]
        if self.config.output.format not in valid_formats:
            errors.append(
                f"Invalid output format: {self.config.output.format}. Must be one of {valid_formats}"
            )

        # Validate report format
        valid_report_formats = ["json", "markdown", "html", "pdf"]
        if self.config.report.format not in valid_report_formats:
            errors.append(
                f"Invalid report format: {self.config.report.format}. Must be one of {valid_report_formats}"
            )

        return len(errors) == 0, errors

    def reset_to_defaults(self):
        """Reset configuration to default values."""
        self.config = ThreatRadarConfig()
        logger.info("Configuration reset to defaults")

    def merge(self, override_dict: Dict[str, Any]):
        """
        Merge override configuration with current config.

        Args:
            override_dict: Dictionary with configuration overrides
        """
        # Create temporary config from override
        override_config = ThreatRadarConfig.from_dict(override_dict)

        # Merge each section
        for section in ["scan", "ai", "report", "output", "paths"]:
            override_section = getattr(override_config, section)
            current_section = getattr(self.config, section)

            # Update only non-None values from override
            for attr in vars(override_section):
                override_value = getattr(override_section, attr)
                # Only override if explicitly set in override dict
                if section in override_dict and attr in override_dict[section]:
                    setattr(current_section, attr, override_value)

        logger.info("Configuration merged with overrides")

    def get_config_dict(self) -> Dict[str, Any]:
        """
        Get full configuration as dictionary.

        Returns:
            Configuration dictionary
        """
        return self.config.to_dict()


# Global configuration instance
_config_manager: Optional[ConfigManager] = None


def get_config_manager(config_path: Optional[Path] = None) -> ConfigManager:
    """
    Get or create global configuration manager.

    Args:
        config_path: Optional path to config file

    Returns:
        ConfigManager instance
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_path)
    return _config_manager


def reset_config_manager():
    """Reset global configuration manager (useful for testing)."""
    global _config_manager
    _config_manager = None
