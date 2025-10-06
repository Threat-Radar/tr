"""Core SBOM operations - business logic for SBOM generation, analysis, and management."""
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass
from datetime import datetime

from .syft_integration import SyftClient, SBOMFormat
from ..utils.sbom_utils import (
    save_sbom,
    load_sbom,
    extract_packages,
    compare_sboms,
    get_package_statistics,
    extract_licenses,
    convert_to_csv,
    convert_to_requirements,
    search_packages,
    get_version_changes,
    filter_components_by_language,
    filter_packages_by_type,
    extract_component_metadata,
)
from ..utils.sbom_storage import (
    get_docker_sbom_path,
    get_local_sbom_path,
    get_format_extension,
    list_stored_sboms,
)


@dataclass
class SBOMGenerationResult:
    """Result from SBOM generation operation."""
    sbom_data: Any  # Dict or str depending on format
    source: str
    output_path: Optional[Path] = None


@dataclass
class SBOMComparisonResult:
    """Result from SBOM comparison operation."""
    sbom1_name: str
    sbom2_name: str
    common: Set[str]
    added: Set[str]
    removed: Set[str]
    version_changes: Optional[Dict[str, Tuple[str, str]]] = None


@dataclass
class SBOMStatistics:
    """SBOM statistics data."""
    package_stats: Dict[str, int]
    licenses: Dict[str, List[str]]
    total_packages: int
    total_licenses: int


class SBOMGenerator:
    """Handles SBOM generation from various sources."""

    def __init__(self, syft_client: Optional[SyftClient] = None):
        """
        Initialize generator.

        Args:
            syft_client: Optional SyftClient instance (creates new if None)
        """
        self.client = syft_client or SyftClient()

    def generate_from_path(
        self,
        path: Path,
        format: str = "cyclonedx-json",
        output: Optional[Path] = None,
        auto_save: bool = False,
    ) -> SBOMGenerationResult:
        """
        Generate SBOM from local path.

        Args:
            path: Directory or file to scan
            format: SBOM format string
            output: Optional output path
            auto_save: Auto-save to storage directory

        Returns:
            SBOMGenerationResult with data and output path

        Raises:
            ValueError: If path doesn't exist or format is invalid
            RuntimeError: If scan fails
        """
        if not path.exists():
            raise ValueError(f"Path does not exist: {path}")

        sbom_format = self._parse_format(format)
        sbom_data = self.client.scan(path, output_format=sbom_format, quiet=True)

        # Determine output path
        output_path = self._determine_output_path(
            output=output,
            auto_save=auto_save,
            source_path=path,
            format_str=format,
            is_docker=False,
        )

        # Save if output path determined
        if output_path and isinstance(sbom_data, dict):
            save_sbom(sbom_data, output_path)
        elif output_path:
            output_path.write_text(str(sbom_data))

        return SBOMGenerationResult(
            sbom_data=sbom_data,
            source=str(path),
            output_path=output_path,
        )

    def generate_from_docker(
        self,
        image: str,
        format: str = "cyclonedx-json",
        scope: str = "squashed",
        output: Optional[Path] = None,
        auto_save: bool = False,
    ) -> SBOMGenerationResult:
        """
        Generate SBOM from Docker image.

        Args:
            image: Docker image name (e.g., 'alpine:3.18')
            format: SBOM format string
            scope: Image scope (squashed, all-layers)
            output: Optional output path
            auto_save: Auto-save to storage directory

        Returns:
            SBOMGenerationResult with data and output path

        Raises:
            RuntimeError: If scan fails
        """
        sbom_format = self._parse_format(format)
        sbom_data = self.client.scan_docker_image(
            image,
            output_format=sbom_format,
            scope=scope,
        )

        # Determine output path for Docker image
        output_path = None
        if auto_save:
            if ':' in image:
                image_name, tag = image.rsplit(':', 1)
            else:
                image_name, tag = image, "latest"

            file_ext = get_format_extension(format)
            output_path = get_docker_sbom_path(image_name, tag, file_ext)
        elif output:
            output_path = output

        # Save if output path determined
        if output_path:
            save_sbom(sbom_data, output_path)

        return SBOMGenerationResult(
            sbom_data=sbom_data,
            source=image,
            output_path=output_path,
        )

    def _parse_format(self, format_str: str) -> SBOMFormat:
        """Parse format string to SBOMFormat enum."""
        format_map = {
            "cyclonedx-json": SBOMFormat.CYCLONEDX_JSON,
            "cyclonedx-xml": SBOMFormat.CYCLONEDX_XML,
            "spdx-json": SBOMFormat.SPDX_JSON,
            "spdx-tag-value": SBOMFormat.SPDX_TAG_VALUE,
            "syft-json": SBOMFormat.SYFT_JSON,
            "table": SBOMFormat.TABLE,
        }

        sbom_format = format_map.get(format_str)
        if not sbom_format:
            raise ValueError(
                f"Unsupported format '{format_str}'. "
                f"Supported: {', '.join(format_map.keys())}"
            )
        return sbom_format

    def _determine_output_path(
        self,
        output: Optional[Path],
        auto_save: bool,
        source_path: Path,
        format_str: str,
        is_docker: bool,
    ) -> Optional[Path]:
        """Determine the output path for generated SBOM."""
        if auto_save:
            project_name = source_path.name if source_path.is_dir() else source_path.stem
            file_ext = get_format_extension(format_str)
            return get_local_sbom_path(project_name, file_ext)
        elif output:
            return output
        return None


class SBOMReader:
    """Handles reading and formatting SBOM files."""

    def read_sbom(self, sbom_path: Path) -> Dict:
        """
        Load SBOM from file.

        Args:
            sbom_path: Path to SBOM file

        Returns:
            SBOM dictionary

        Raises:
            FileNotFoundError: If file doesn't exist
            json.JSONDecodeError: If file is not valid JSON
        """
        return load_sbom(sbom_path)

    def get_packages(
        self,
        sbom_data: Dict,
        name_filter: Optional[str] = None,
    ) -> List[Dict]:
        """
        Extract packages from SBOM with optional filtering.

        Args:
            sbom_data: SBOM dictionary
            name_filter: Optional filter string for package names

        Returns:
            List of package dictionaries
        """
        packages = extract_packages(sbom_data)

        if name_filter:
            packages = [
                p for p in packages
                if name_filter.lower() in p.get("name", "").lower()
            ]

        return packages


class SBOMComparator:
    """Handles SBOM comparison operations."""

    def compare(
        self,
        sbom1_path: Path,
        sbom2_path: Path,
        include_versions: bool = False,
    ) -> SBOMComparisonResult:
        """
        Compare two SBOM files.

        Args:
            sbom1_path: Path to first SBOM
            sbom2_path: Path to second SBOM
            include_versions: Include version change analysis

        Returns:
            SBOMComparisonResult with differences

        Raises:
            FileNotFoundError: If either file doesn't exist
        """
        sbom1_data = load_sbom(sbom1_path)
        sbom2_data = load_sbom(sbom2_path)

        diff = compare_sboms(sbom1_data, sbom2_data)

        version_changes = None
        if include_versions:
            version_changes = get_version_changes(sbom1_data, sbom2_data)

        return SBOMComparisonResult(
            sbom1_name=sbom1_path.name,
            sbom2_name=sbom2_path.name,
            common=diff["common"],
            added=diff["added"],
            removed=diff["removed"],
            version_changes=version_changes,
        )


class SBOMAnalyzer:
    """Handles SBOM analysis and statistics."""

    def get_statistics(self, sbom_path: Path) -> SBOMStatistics:
        """
        Get statistics from SBOM.

        Args:
            sbom_path: Path to SBOM file

        Returns:
            SBOMStatistics with package and license info
        """
        sbom_data = load_sbom(sbom_path)

        package_stats = get_package_statistics(sbom_data)
        licenses = extract_licenses(sbom_data)

        total_packages = sum(package_stats.values())
        total_licenses = len(licenses)

        return SBOMStatistics(
            package_stats=package_stats,
            licenses=licenses,
            total_packages=total_packages,
            total_licenses=total_licenses,
        )

    def search(self, sbom_path: Path, query: str) -> List[Dict]:
        """
        Search for packages in SBOM.

        Args:
            sbom_path: Path to SBOM file
            query: Search term

        Returns:
            List of matching packages
        """
        sbom_data = load_sbom(sbom_path)
        return search_packages(sbom_data, query)

    def get_components(
        self,
        sbom_path: Path,
        type_filter: Optional[str] = None,
        language_filter: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Dict]:
        """
        Get components from SBOM with filtering.

        Args:
            sbom_path: Path to SBOM file
            type_filter: Filter by component type
            language_filter: Filter by language
            limit: Limit number of results

        Returns:
            List of component dictionaries
        """
        sbom_data = load_sbom(sbom_path)

        # Apply filters
        if type_filter:
            components = filter_packages_by_type(sbom_data, type_filter)
            if language_filter:
                components = [
                    c for c in components
                    if (extract_component_metadata(c).get("language") or "").lower() == language_filter.lower()
                ]
        elif language_filter:
            components = filter_components_by_language(sbom_data, language_filter)
        else:
            components = extract_packages(sbom_data)

        # Apply limit
        if limit:
            components = components[:limit]

        return components


class SBOMExporter:
    """Handles SBOM export to different formats."""

    def export(
        self,
        sbom_path: Path,
        output_path: Path,
        format: str,
    ) -> None:
        """
        Export SBOM to different format.

        Args:
            sbom_path: Path to SBOM file
            output_path: Output file path
            format: Export format (csv, requirements)

        Raises:
            ValueError: If format is unsupported
        """
        sbom_data = load_sbom(sbom_path)

        if format == "csv":
            convert_to_csv(sbom_data, output_path)
        elif format == "requirements":
            convert_to_requirements(sbom_data, output_path)
        else:
            raise ValueError(f"Unsupported export format: {format}")


class SBOMStorageManager:
    """Handles SBOM storage and listing operations."""

    def list_sboms(
        self,
        category: str = "all",
        limit: Optional[int] = None,
    ) -> List[Path]:
        """
        List stored SBOMs by category.

        Args:
            category: Category to list (docker, local, comparisons, archives, all)
            limit: Optional limit on number of results

        Returns:
            List of SBOM file paths
        """
        sboms = list_stored_sboms(category)

        if limit:
            sboms = sboms[:limit]

        return sboms

    def get_sbom_metadata(self, sbom_path: Path) -> Dict[str, Any]:
        """
        Get metadata for an SBOM file.

        Args:
            sbom_path: Path to SBOM file

        Returns:
            Dictionary with metadata (filename, size, modified time, category)
        """
        stat = sbom_path.stat()
        size = stat.st_size

        return {
            "filename": sbom_path.name,
            "category": sbom_path.parent.name,
            "size": size,
            "size_str": f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / (1024 * 1024):.1f} MB",
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
            "modified_timestamp": stat.st_mtime,
        }
