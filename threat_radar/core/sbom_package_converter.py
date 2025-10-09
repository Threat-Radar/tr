"""Convert SBOM packages from various formats to Package objects for CVE matching."""
import logging
from typing import Dict, List, Optional
from .package_extractors import Package

logger = logging.getLogger(__name__)


def detect_sbom_format(sbom_data: Dict) -> str:
    """
    Auto-detect SBOM format from data structure.

    Args:
        sbom_data: Parsed SBOM dictionary

    Returns:
        Format string: "cyclonedx", "spdx", or "syft"

    Raises:
        ValueError: If format cannot be determined
    """
    # Check CycloneDX format
    if "bomFormat" in sbom_data:
        if sbom_data["bomFormat"] == "CycloneDX":
            logger.info("Detected CycloneDX SBOM format")
            return "cyclonedx"

    # Check SPDX format
    if "spdxVersion" in sbom_data:
        logger.info(f"Detected SPDX SBOM format: {sbom_data['spdxVersion']}")
        return "spdx"

    # Check Syft JSON format
    if "artifacts" in sbom_data and "source" in sbom_data:
        logger.info("Detected Syft JSON SBOM format")
        return "syft"

    raise ValueError(
        "Unable to detect SBOM format. Supported formats: CycloneDX, SPDX, Syft JSON"
    )


def convert_sbom_to_packages(
    sbom_data: Dict,
    format: Optional[str] = None,
    include_types: Optional[List[str]] = None
) -> List[Package]:
    """
    Convert SBOM packages to CVE-matchable Package objects.

    Args:
        sbom_data: Parsed SBOM dictionary
        format: SBOM format (auto-detected if None)
        include_types: Optional list of package types to include (e.g., ["deb", "rpm", "apk"])

    Returns:
        List of Package objects for CVE matching

    Raises:
        ValueError: If SBOM format is unsupported or invalid
    """
    if format is None:
        format = detect_sbom_format(sbom_data)

    format_lower = format.lower()

    if format_lower == "cyclonedx":
        packages = _convert_cyclonedx_packages(sbom_data)
    elif format_lower == "spdx":
        packages = _convert_spdx_packages(sbom_data)
    elif format_lower == "syft":
        packages = _convert_syft_packages(sbom_data)
    else:
        raise ValueError(f"Unsupported SBOM format: {format}")

    # Filter by package type if specified
    if include_types:
        include_types_lower = [t.lower() for t in include_types]
        filtered_packages = []
        for pkg in packages:
            # Check if package has type information (stored in description temporarily)
            pkg_type = getattr(pkg, '_type', None)
            if pkg_type and pkg_type.lower() in include_types_lower:
                filtered_packages.append(pkg)
            elif not pkg_type:
                # Include packages without type info
                filtered_packages.append(pkg)

        logger.info(
            f"Filtered {len(packages)} packages to {len(filtered_packages)} "
            f"packages matching types: {include_types}"
        )
        packages = filtered_packages

    logger.info(f"Converted {len(packages)} SBOM packages to Package objects")
    return packages


def _convert_cyclonedx_packages(sbom_data: Dict) -> List[Package]:
    """
    Convert CycloneDX components to Package objects.

    CycloneDX format has components array with:
    - name: Component name
    - version: Component version
    - purl: Package URL (optional)
    - type: Component type (library, application, etc.)
    """
    packages = []
    components = sbom_data.get("components", [])

    for component in components:
        name = component.get("name")
        version = component.get("version")

        if not name or not version:
            logger.debug(f"Skipping component without name or version: {component}")
            continue

        # Extract architecture from purl if available
        purl = component.get("purl", "")
        architecture = _extract_arch_from_purl(purl)

        # Get component type
        comp_type = component.get("type", "unknown")

        # Create package
        pkg = Package(
            name=name,
            version=version,
            architecture=architecture,
            description=None
        )

        # Store type for filtering (not part of Package dataclass)
        pkg._type = comp_type
        packages.append(pkg)

    logger.info(f"Converted {len(packages)} CycloneDX components to packages")
    return packages


def _convert_spdx_packages(sbom_data: Dict) -> List[Package]:
    """
    Convert SPDX packages to Package objects.

    SPDX format has packages array with:
    - name: Package name
    - versionInfo: Version string
    - externalRefs: External references (may contain CPE/PURL)
    """
    packages = []
    spdx_packages = sbom_data.get("packages", [])

    for spdx_pkg in spdx_packages:
        name = spdx_pkg.get("name")
        version = spdx_pkg.get("versionInfo")

        if not name:
            logger.debug(f"Skipping SPDX package without name: {spdx_pkg}")
            continue

        # SPDX may not always have version
        if not version:
            version = "unknown"

        # Try to extract package type from external refs
        pkg_type = _extract_type_from_spdx(spdx_pkg)

        pkg = Package(
            name=name,
            version=version,
            architecture=None,  # SPDX doesn't typically have architecture
            description=spdx_pkg.get("summary")
        )

        pkg._type = pkg_type
        packages.append(pkg)

    logger.info(f"Converted {len(packages)} SPDX packages to packages")
    return packages


def _convert_syft_packages(sbom_data: Dict) -> List[Package]:
    """
    Convert Syft artifacts to Package objects.

    Syft JSON format has artifacts array with:
    - name: Package name
    - version: Package version
    - type: Package type (deb, rpm, python, npm, etc.)
    - metadata: Additional package metadata
    """
    packages = []
    artifacts = sbom_data.get("artifacts", [])

    for artifact in artifacts:
        name = artifact.get("name")
        version = artifact.get("version")

        if not name or not version:
            logger.debug(f"Skipping artifact without name or version: {artifact}")
            continue

        # Get package type (very useful in Syft)
        pkg_type = artifact.get("type", "unknown")

        # Try to extract architecture from metadata
        architecture = None
        metadata = artifact.get("metadata", {})
        if isinstance(metadata, dict):
            architecture = metadata.get("architecture") or metadata.get("arch")

        pkg = Package(
            name=name,
            version=version,
            architecture=architecture,
            description=None
        )

        pkg._type = pkg_type
        packages.append(pkg)

    logger.info(f"Converted {len(packages)} Syft artifacts to packages")
    return packages


def _extract_arch_from_purl(purl: str) -> Optional[str]:
    """
    Extract architecture from Package URL (purl).

    Example: pkg:deb/debian/curl@7.64.0-4+deb10u1?arch=amd64
    """
    if not purl or "arch=" not in purl:
        return None

    try:
        arch_part = purl.split("arch=")[1]
        arch = arch_part.split("&")[0]  # Handle multiple query params
        return arch
    except (IndexError, AttributeError):
        return None


def _extract_type_from_spdx(spdx_pkg: Dict) -> str:
    """
    Try to determine package type from SPDX external references.

    SPDX external refs may contain PURL which has type information.
    """
    external_refs = spdx_pkg.get("externalRefs", [])

    for ref in external_refs:
        if ref.get("referenceType") == "purl":
            purl = ref.get("referenceLocator", "")
            # PURL format: pkg:type/namespace/name@version
            if purl.startswith("pkg:"):
                try:
                    pkg_type = purl.split(":")[1].split("/")[0]
                    return pkg_type
                except (IndexError, AttributeError):
                    pass

    return "unknown"


def get_package_statistics(packages: List[Package]) -> Dict[str, int]:
    """
    Get statistics about package types.

    Args:
        packages: List of Package objects

    Returns:
        Dictionary mapping package type to count
    """
    stats = {}

    for pkg in packages:
        pkg_type = getattr(pkg, '_type', 'unknown')
        stats[pkg_type] = stats.get(pkg_type, 0) + 1

    return stats
