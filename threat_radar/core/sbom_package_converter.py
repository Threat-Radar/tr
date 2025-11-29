"""SBOM Package Converter - Convert SBOM formats to Package objects."""

from typing import Dict, List, Optional, Any
from .package_extractors import Package
import logging

logger = logging.getLogger(__name__)


def detect_sbom_format(sbom_data: Dict[str, Any]) -> str:
    """
    Detect the format of an SBOM file.

    Args:
        sbom_data: SBOM data as a dictionary

    Returns:
        Format type: "syft", "cyclonedx", or "spdx"

    Raises:
        ValueError: If format cannot be detected
    """
    # Check for Syft format
    if "artifacts" in sbom_data and "descriptor" in sbom_data:
        if sbom_data.get("descriptor", {}).get("name") == "syft":
            return "syft"

    # Check for CycloneDX format
    if "bomFormat" in sbom_data and sbom_data.get("bomFormat") == "CycloneDX":
        return "cyclonedx"

    # Check for SPDX format
    if "spdxVersion" in sbom_data:
        return "spdx"

    raise ValueError(
        "Unable to detect SBOM format. Supported formats: Syft, CycloneDX, SPDX"
    )


def convert_sbom_to_packages(
    sbom_data: Dict[str, Any],
    format: Optional[str] = None,
    include_types: Optional[List[str]] = None,
) -> List[Package]:
    """
    Convert SBOM data to a list of Package objects.

    Args:
        sbom_data: SBOM data as a dictionary
        format: SBOM format ("syft", "cyclonedx", "spdx"). If None, auto-detect
        include_types: Optional list of package types to include (e.g., ["deb", "rpm"])

    Returns:
        List of Package objects

    Raises:
        ValueError: If format is unsupported or invalid
    """
    # Auto-detect format if not specified
    if format is None:
        format = detect_sbom_format(sbom_data)

    # Convert based on format
    if format == "syft":
        return _convert_syft_packages(sbom_data, include_types)
    elif format == "cyclonedx":
        return _convert_cyclonedx_packages(sbom_data, include_types)
    elif format == "spdx":
        return _convert_spdx_packages(sbom_data, include_types)
    else:
        raise ValueError(f"Unsupported SBOM format: {format}")


def _convert_syft_packages(
    sbom_data: Dict[str, Any], include_types: Optional[List[str]] = None
) -> List[Package]:
    """Convert Syft format artifacts to Package objects."""
    packages = []

    for artifact in sbom_data.get("artifacts", []):
        # Skip if missing required fields
        if not artifact.get("name") or not artifact.get("version"):
            continue

        # Filter by type if specified
        pkg_type = artifact.get("type", "")
        if include_types and pkg_type not in include_types:
            continue

        # Extract architecture from metadata
        metadata = artifact.get("metadata", {})
        architecture = metadata.get("architecture")

        # Create Package object
        package = Package(
            name=artifact["name"],
            version=artifact["version"],
            architecture=architecture,
            description=None,  # Syft doesn't typically include descriptions
            type=pkg_type,
        )
        packages.append(package)

    return packages


def _convert_cyclonedx_packages(
    sbom_data: Dict[str, Any], include_types: Optional[List[str]] = None
) -> List[Package]:
    """Convert CycloneDX format components to Package objects."""
    packages = []

    for component in sbom_data.get("components", []):
        # Skip if missing required fields
        if not component.get("name") or not component.get("version"):
            continue

        # Extract architecture and type from purl if available
        architecture = None
        pkg_type = None
        purl = component.get("purl", "")
        if purl:
            # Extract type from purl (e.g., pkg:deb/... -> deb)
            try:
                pkg_type = purl.split(":")[1].split("/")[0]
            except (IndexError, AttributeError):
                pass

            # Extract arch from purl query string
            if "arch=" in purl:
                try:
                    arch_part = purl.split("arch=")[1].split("&")[0]
                    architecture = arch_part
                except (IndexError, AttributeError):
                    pass

        # Create Package object
        package = Package(
            name=component["name"],
            version=component["version"],
            architecture=architecture,
            description=component.get("description"),
            type=pkg_type,
        )
        packages.append(package)

    return packages


def _convert_spdx_packages(
    sbom_data: Dict[str, Any], include_types: Optional[List[str]] = None
) -> List[Package]:
    """Convert SPDX format packages to Package objects."""
    packages = []

    for pkg in sbom_data.get("packages", []):
        # Skip if missing required fields
        name = pkg.get("name")
        version = pkg.get("versionInfo")

        if not name or not version:
            continue

        # Extract architecture and type from purl in externalRefs if available
        architecture = None
        pkg_type = None
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")

                # Extract type from purl
                try:
                    pkg_type = purl.split(":")[1].split("/")[0]
                except (IndexError, AttributeError):
                    pass

                # Extract architecture from purl
                if "arch=" in purl:
                    try:
                        arch_part = purl.split("arch=")[1].split("&")[0]
                        architecture = arch_part
                    except (IndexError, AttributeError):
                        pass

        # Create Package object
        package = Package(
            name=name,
            version=version,
            architecture=architecture,
            description=pkg.get("summary"),
            type=pkg_type,
        )
        packages.append(package)

    return packages


def get_package_statistics(packages: List[Package]) -> Dict[str, int]:
    """
    Get statistics about package types.

    Args:
        packages: List of Package objects

    Returns:
        Dictionary mapping package type to count
    """
    stats: Dict[str, int] = {}

    for package in packages:
        pkg_type = package.type or "unknown"
        stats[pkg_type] = stats.get(pkg_type, 0) + 1

    return stats
