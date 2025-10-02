"""Python package extraction and CycloneDX SBOM generation."""
import json
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass
from docker.errors import APIError

logger = logging.getLogger(__name__)


@dataclass
class PythonPackage:
    """Represents a Python package."""
    name: str
    version: str
    location: Optional[str] = None


class PythonPackageExtractor:
    """Extract Python packages from Docker containers."""

    def __init__(self, docker_client):
        """Initialize with Docker client."""
        self.docker_client = docker_client

    def extract_pip_packages(self, image_name: str) -> List[PythonPackage]:
        """
        Extract pip packages from a container image.

        Args:
            image_name: Docker image to analyze

        Returns:
            List of PythonPackage objects
        """
        try:
            # Try pip list --format=json (newer pip versions)
            output = self.docker_client.run_container(
                image_name,
                "pip list --format=json",
                remove=True
            )
            return self._parse_pip_json(output)
        except APIError as e:
            logger.warning(f"Could not run pip list: {e}")
            # Fallback: try older format
            try:
                output = self.docker_client.run_container(
                    image_name,
                    "pip list",
                    remove=True
                )
                return self._parse_pip_text(output)
            except APIError:
                logger.error("No pip found in container")
                return []

    def _parse_pip_json(self, output: bytes) -> List[PythonPackage]:
        """Parse pip list JSON output."""
        try:
            packages_data = json.loads(output.decode('utf-8'))
            packages = []

            for pkg_data in packages_data:
                package = PythonPackage(
                    name=pkg_data['name'],
                    version=pkg_data['version'],
                    location=pkg_data.get('location')
                )
                packages.append(package)

            logger.info(f"Extracted {len(packages)} pip packages")
            return packages
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse pip JSON: {e}")
            return []

    def _parse_pip_text(self, output: bytes) -> List[PythonPackage]:
        """Parse pip list text output (fallback)."""
        packages = []
        lines = output.decode('utf-8', errors='ignore').strip().split('\n')

        # Skip header lines
        for line in lines[2:]:
            parts = line.split()
            if len(parts) >= 2:
                package = PythonPackage(
                    name=parts[0],
                    version=parts[1]
                )
                packages.append(package)

        logger.info(f"Extracted {len(packages)} pip packages (text format)")
        return packages

    def generate_cyclonedx_sbom(
        self,
        image_name: str,
        packages: List[PythonPackage]
    ) -> Dict:
        """
        Generate CycloneDX SBOM from Python packages.

        Args:
            image_name: Docker image name
            packages: List of Python packages

        Returns:
            CycloneDX SBOM dictionary (JSON format)
        """
        components = []

        for pkg in packages:
            component = {
                "type": "library",
                "bom-ref": f"pkg:pypi/{pkg.name}@{pkg.version}",
                "name": pkg.name,
                "version": pkg.version,
                "purl": f"pkg:pypi/{pkg.name}@{pkg.version}",
            }

            if pkg.location:
                component["properties"] = [
                    {
                        "name": "location",
                        "value": pkg.location
                    }
                ]

            components.append(component)

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "component": {
                    "type": "container",
                    "name": image_name,
                    "bom-ref": f"container:{image_name}",
                }
            },
            "components": components
        }

        return sbom

    def generate_cyclonedx_from_image(self, image_name: str) -> Dict:
        """
        Extract packages and generate CycloneDX SBOM in one step.

        Args:
            image_name: Docker image to analyze

        Returns:
            CycloneDX SBOM dictionary
        """
        packages = self.extract_pip_packages(image_name)
        return self.generate_cyclonedx_sbom(image_name, packages)
