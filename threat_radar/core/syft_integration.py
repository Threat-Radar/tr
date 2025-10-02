"""Syft integration for comprehensive SBOM generation."""
import json
import subprocess
import logging
from typing import Dict, List, Optional, Union
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class SBOMFormat(Enum):
    """Supported SBOM output formats."""
    CYCLONEDX_JSON = "cyclonedx-json"
    CYCLONEDX_XML = "cyclonedx-xml"
    SPDX_JSON = "spdx-json"
    SPDX_TAG_VALUE = "spdx-tag-value"
    SYFT_JSON = "syft-json"
    TABLE = "table"
    TEXT = "text"


class ScanSource(Enum):
    """Source types that Syft can scan."""
    DIRECTORY = "dir"
    FILE = "file"
    DOCKER_IMAGE = "docker"
    OCI_IMAGE = "oci"
    ARCHIVE = "archive"


@dataclass
class SyftPackage:
    """Represents a package found by Syft."""
    name: str
    version: str
    type: str
    language: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None
    licenses: Optional[List[str]] = None
    locations: Optional[List[str]] = None
    metadata: Optional[Dict] = None


class SyftClient:
    """Wrapper for Syft CLI tool."""

    def __init__(self, syft_path: Optional[str] = None):
        """
        Initialize Syft client.

        Args:
            syft_path: Custom path to syft binary. If None, uses PATH.
        """
        self.syft_path = syft_path or "syft"
        self._check_installation()

    def _check_installation(self) -> None:
        """Verify Syft is installed and accessible."""
        try:
            result = subprocess.run(
                [self.syft_path, "version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                raise RuntimeError(f"Syft check failed: {result.stderr}")

            logger.info(f"Syft is available: {result.stdout.split()[0]}")
        except FileNotFoundError:
            raise RuntimeError(
                f"Syft not found at {self.syft_path}. "
                "Install it from: https://github.com/anchore/syft#installation"
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Syft version check timed out")

    def scan(
        self,
        target: Union[str, Path],
        output_format: SBOMFormat = SBOMFormat.SYFT_JSON,
        scope: str = "all-layers",
        quiet: bool = False,
        additional_args: Optional[List[str]] = None
    ) -> Union[Dict, str]:
        """
        Scan a target and generate SBOM.

        Args:
            target: Path to directory, file, or Docker image (e.g., 'alpine:latest')
            output_format: Output format for SBOM
            scope: Scope for Docker images (all-layers, squashed)
            quiet: Suppress progress output
            additional_args: Additional CLI arguments

        Returns:
            Parsed JSON dict for JSON formats, raw string for text formats

        Raises:
            RuntimeError: If scan fails
        """
        target_str = str(target)

        # Build command
        cmd = [
            self.syft_path,
            "scan",
            target_str,
            "-o", output_format.value,
            "--scope", scope
        ]

        if quiet:
            cmd.append("--quiet")

        if additional_args:
            cmd.extend(additional_args)

        logger.info(f"Running Syft scan: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )

            if result.returncode != 0:
                raise RuntimeError(f"Syft scan failed: {result.stderr}")

            # Parse JSON formats
            if "json" in output_format.value:
                return json.loads(result.stdout)

            # Return raw text for other formats
            return result.stdout

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Syft scan timed out after 300s for target: {target_str}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse Syft output: {e}")

    def scan_directory(
        self,
        directory: Union[str, Path],
        output_format: SBOMFormat = SBOMFormat.CYCLONEDX_JSON
    ) -> Union[Dict, str]:
        """
        Scan a local directory.

        Args:
            directory: Path to directory
            output_format: Output format

        Returns:
            SBOM data
        """
        path = Path(directory)
        if not path.exists():
            raise ValueError(f"Directory does not exist: {directory}")
        if not path.is_dir():
            raise ValueError(f"Path is not a directory: {directory}")

        return self.scan(path, output_format=output_format)

    def scan_docker_image(
        self,
        image: str,
        output_format: SBOMFormat = SBOMFormat.CYCLONEDX_JSON,
        scope: str = "squashed"
    ) -> Union[Dict, str]:
        """
        Scan a Docker image.

        Args:
            image: Docker image name (e.g., 'alpine:3.18', 'ubuntu:latest')
            output_format: Output format
            scope: Image scope (squashed, all-layers)

        Returns:
            SBOM data
        """
        return self.scan(
            f"docker:{image}",
            output_format=output_format,
            scope=scope
        )

    def scan_file(
        self,
        file_path: Union[str, Path],
        output_format: SBOMFormat = SBOMFormat.SYFT_JSON
    ) -> Union[Dict, str]:
        """
        Scan a single file.

        Args:
            file_path: Path to file
            output_format: Output format

        Returns:
            SBOM data
        """
        path = Path(file_path)
        if not path.exists():
            raise ValueError(f"File does not exist: {file_path}")
        if not path.is_file():
            raise ValueError(f"Path is not a file: {file_path}")

        return self.scan(path, output_format=output_format)

    def parse_syft_json(self, syft_output: Dict) -> List[SyftPackage]:
        """
        Parse Syft JSON output into SyftPackage objects.

        Args:
            syft_output: Syft JSON output dictionary

        Returns:
            List of SyftPackage objects
        """
        packages = []

        for artifact in syft_output.get("artifacts", []):
            package = SyftPackage(
                name=artifact.get("name", ""),
                version=artifact.get("version", ""),
                type=artifact.get("type", ""),
                language=artifact.get("language"),
                purl=artifact.get("purl"),
                cpe=artifact.get("cpes", [None])[0] if artifact.get("cpes") else None,
                licenses=artifact.get("licenses", []),
                locations=[loc.get("path") for loc in artifact.get("locations", [])],
                metadata=artifact.get("metadata")
            )
            packages.append(package)

        logger.info(f"Parsed {len(packages)} packages from Syft output")
        return packages

    def convert_format(
        self,
        sbom_data: str,
        from_format: SBOMFormat,
        to_format: SBOMFormat,
        output_file: Optional[Union[str, Path]] = None
    ) -> str:
        """
        Convert SBOM between formats using Syft.

        Args:
            sbom_data: Input SBOM data
            from_format: Source format
            to_format: Target format
            output_file: Optional output file

        Returns:
            Converted SBOM data
        """
        cmd = [
            self.syft_path,
            "convert",
            "-",  # Read from stdin
            "-o", to_format.value
        ]

        if output_file:
            cmd.extend(["-f", str(output_file)])

        try:
            result = subprocess.run(
                cmd,
                input=sbom_data,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                raise RuntimeError(f"Format conversion failed: {result.stderr}")

            return result.stdout

        except subprocess.TimeoutExpired:
            raise RuntimeError("Format conversion timed out")

    @staticmethod
    def get_supported_ecosystems() -> List[str]:
        """
        Get list of package ecosystems supported by Syft.

        Returns:
            List of ecosystem names
        """
        return [
            "python",
            "javascript",
            "java",
            "go",
            "ruby",
            "rust",
            "php",
            "dotnet",
            "swift",
            "dart",
            "elixir",
            "cpp",
            "c",
        ]

    def get_package_count(self, sbom_data: Dict) -> int:
        """
        Get package count from SBOM.

        Args:
            sbom_data: SBOM dictionary

        Returns:
            Number of packages
        """
        # Handle different SBOM formats
        if "artifacts" in sbom_data:  # Syft JSON
            return len(sbom_data.get("artifacts", []))
        elif "components" in sbom_data:  # CycloneDX
            return len(sbom_data.get("components", []))
        elif "packages" in sbom_data:  # SPDX
            return len(sbom_data.get("packages", []))

        return 0
