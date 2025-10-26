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
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatRadarConfig':
        """Create configuration from dictionary."""
        return cls(
            scan=ScanDefaults(**data.get('scan', {})),
            ai=AIDefaults(**data.get('ai', {})),
            report=ReportDefaults(**data.get('report', {})),
            output=OutputDefaults(**data.get('output', {})),
            paths=PathDefaults(**data.get('paths', {}))
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
            with open(config_file, 'r') as f:
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
        if os.getenv('THREAT_RADAR_SEVERITY'):
            self.config.scan.severity = os.getenv('THREAT_RADAR_SEVERITY')
        if os.getenv('THREAT_RADAR_AUTO_SAVE'):
            self.config.scan.auto_save = os.getenv('THREAT_RADAR_AUTO_SAVE').lower() == 'true'

        # AI defaults
        if os.getenv('AI_PROVIDER'):
            self.config.ai.provider = os.getenv('AI_PROVIDER')
        if os.getenv('AI_MODEL'):
            self.config.ai.model = os.getenv('AI_MODEL')

        # Output defaults
        if os.getenv('THREAT_RADAR_VERBOSITY'):
            try:
                self.config.output.verbosity = int(os.getenv('THREAT_RADAR_VERBOSITY'))
            except ValueError:
                pass

        if os.getenv('THREAT_RADAR_OUTPUT_FORMAT'):
            self.config.output.format = os.getenv('THREAT_RADAR_OUTPUT_FORMAT')

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
        with open(path, 'w') as f:
            json.dump(self.config.to_dict(), f, indent=2)

        logger.info(f"Saved configuration to: {path}")
        return path

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-notation key.

        Args:
            key: Configuration key (e.g., 'scan.severity', 'ai.provider')
            default: Default value if key not found

        Returns:
            Configuration value
        """
        parts = key.split('.')
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
        """
        parts = key.split('.')
        obj = self.config

        # Navigate to parent object
        for part in parts[:-1]:
            if hasattr(obj, part):
                obj = getattr(obj, part)
            else:
                raise ValueError(f"Invalid configuration key: {key}")

        # Set final attribute
        final_key = parts[-1]
        if hasattr(obj, final_key):
            setattr(obj, final_key, value)
        else:
            raise ValueError(f"Invalid configuration key: {key}")


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
