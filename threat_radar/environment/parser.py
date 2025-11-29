"""Parse and validate environment configuration files.

Supports JSON and YAML formats with Pydantic validation.
"""

import json
import logging
from pathlib import Path
from typing import Union, Dict, Any

from pydantic import ValidationError

from .models import Environment

logger = logging.getLogger(__name__)


class EnvironmentParser:
    """Parse and validate environment configuration files."""

    @staticmethod
    def load_from_file(file_path: Union[str, Path]) -> Environment:
        """
        Load and validate environment from JSON or YAML file.

        Args:
            file_path: Path to environment configuration file

        Returns:
            Validated Environment object

        Raises:
            FileNotFoundError: If file doesn't exist
            ValidationError: If configuration is invalid
            ValueError: If file format is unsupported
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Environment file not found: {file_path}")

        # Determine file type
        suffix = file_path.suffix.lower()

        if suffix == ".json":
            return EnvironmentParser.load_from_json(file_path)
        elif suffix in [".yml", ".yaml"]:
            return EnvironmentParser.load_from_yaml(file_path)
        else:
            raise ValueError(
                f"Unsupported file format: {suffix}. "
                f"Supported formats: .json, .yml, .yaml"
            )

    @staticmethod
    def load_from_json(file_path: Union[str, Path]) -> Environment:
        """
        Load environment from JSON file.

        Args:
            file_path: Path to JSON file

        Returns:
            Validated Environment object

        Raises:
            ValidationError: If JSON is invalid or doesn't match schema
        """
        file_path = Path(file_path)
        logger.info(f"Loading environment from JSON: {file_path}")

        with open(file_path, "r") as f:
            data = json.load(f)

        try:
            environment = Environment(**data)
            logger.info(
                f"✓ Loaded environment '{environment.environment.name}' "
                f"with {len(environment.assets)} assets"
            )
            return environment
        except ValidationError as e:
            logger.error(f"Validation error in {file_path}")
            raise

    @staticmethod
    def load_from_yaml(file_path: Union[str, Path]) -> Environment:
        """
        Load environment from YAML file.

        Args:
            file_path: Path to YAML file

        Returns:
            Validated Environment object

        Raises:
            ImportError: If PyYAML is not installed
            ValidationError: If YAML is invalid or doesn't match schema
        """
        try:
            import yaml
        except ImportError:
            raise ImportError(
                "PyYAML is required for YAML support. "
                "Install with: pip install pyyaml"
            )

        file_path = Path(file_path)
        logger.info(f"Loading environment from YAML: {file_path}")

        with open(file_path, "r") as f:
            data = yaml.safe_load(f)

        try:
            environment = Environment(**data)
            logger.info(
                f"✓ Loaded environment '{environment.environment.name}' "
                f"with {len(environment.assets)} assets"
            )
            return environment
        except ValidationError as e:
            logger.error(f"Validation error in {file_path}")
            raise

    @staticmethod
    def load_from_dict(data: Dict[str, Any]) -> Environment:
        """
        Load environment from dictionary.

        Args:
            data: Environment configuration dictionary

        Returns:
            Validated Environment object

        Raises:
            ValidationError: If data doesn't match schema
        """
        return Environment(**data)

    @staticmethod
    def validate_file(file_path: Union[str, Path]) -> bool:
        """
        Validate environment file without loading.

        Args:
            file_path: Path to environment file

        Returns:
            True if valid, False otherwise
        """
        try:
            EnvironmentParser.load_from_file(file_path)
            return True
        except (ValidationError, FileNotFoundError, ValueError) as e:
            logger.error(f"Validation failed: {e}")
            return False

    @staticmethod
    def save_to_file(
        environment: Environment, file_path: Union[str, Path], indent: int = 2
    ) -> None:
        """
        Save environment to JSON file.

        Args:
            environment: Environment object to save
            file_path: Destination file path
            indent: JSON indentation (default: 2)
        """
        file_path = Path(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, "w") as f:
            json.dump(
                environment.model_dump(mode="json", exclude_none=True), f, indent=indent
            )

        logger.info(f"✓ Saved environment to: {file_path}")

    @staticmethod
    def get_validation_errors(file_path: Union[str, Path]) -> list:
        """
        Get detailed validation errors for an environment file.

        Args:
            file_path: Path to environment file

        Returns:
            List of validation error dictionaries
        """
        try:
            EnvironmentParser.load_from_file(file_path)
            return []
        except ValidationError as e:
            return e.errors()
        except Exception as e:
            return [{"error": str(e)}]

    @staticmethod
    def generate_template() -> Dict[str, Any]:
        """
        Generate a minimal environment template.

        Returns:
            Dictionary with minimal valid environment structure
        """
        return {
            "environment": {
                "name": "my-environment",
                "type": "production",
                "cloud_provider": "aws",
                "region": "us-east-1",
                "compliance_requirements": [],
                "owner": "team@company.com",
                "tags": {},
            },
            "assets": [
                {
                    "id": "asset-example",
                    "name": "Example Asset",
                    "type": "container",
                    "host": "10.0.1.50",
                    "software": {"image": "nginx:alpine", "os": "Alpine Linux 3.18"},
                    "network": {
                        "internal_ip": "10.0.1.50",
                        "exposed_ports": [
                            {"port": 80, "protocol": "http", "public": False}
                        ],
                    },
                    "business_context": {
                        "criticality": "medium",
                        "criticality_score": 50,
                        "function": "web-server",
                        "data_classification": "internal",
                        "customer_facing": False,
                        "owner_team": "platform-team",
                    },
                }
            ],
            "dependencies": [],
            "network_topology": {"zones": [], "segmentation_rules": []},
            "business_context": {
                "organization": "My Organization",
                "business_unit": "engineering",
                "risk_tolerance": "medium",
            },
        }
