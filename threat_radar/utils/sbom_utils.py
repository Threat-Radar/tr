"""Utility functions for SBOM processing and analysis."""
import json
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path
from dataclasses import asdict


def save_sbom(sbom_data: Dict, output_path: Path, pretty: bool = True) -> None:
    """
    Save SBOM to file.

    Args:
        sbom_data: SBOM dictionary
        output_path: Output file path
        pretty: Pretty-print JSON (default: True)
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        if pretty:
            json.dump(sbom_data, f, indent=2)
        else:
            json.dump(sbom_data, f)


def load_sbom(sbom_path: Path) -> Dict:
    """
    Load SBOM from file.

    Args:
        sbom_path: Path to SBOM file

    Returns:
        SBOM dictionary
    """
    with open(sbom_path, 'r') as f:
        return json.load(f)


def extract_packages(sbom_data: Dict) -> List[Dict]:
    """
    Extract package list from SBOM (format-agnostic).

    Args:
        sbom_data: SBOM dictionary

    Returns:
        List of package dictionaries
    """
    # Syft JSON format
    if "artifacts" in sbom_data:
        return sbom_data.get("artifacts", [])

    # CycloneDX format
    elif "components" in sbom_data:
        return sbom_data.get("components", [])

    # SPDX format
    elif "packages" in sbom_data:
        return sbom_data.get("packages", [])

    return []


def get_package_names(sbom_data: Dict) -> Set[str]:
    """
    Extract all package names from SBOM.

    Args:
        sbom_data: SBOM dictionary

    Returns:
        Set of package names
    """
    packages = extract_packages(sbom_data)
    return {pkg.get("name", "") for pkg in packages if pkg.get("name")}


def compare_sboms(sbom1: Dict, sbom2: Dict) -> Dict[str, Set[str]]:
    """
    Compare two SBOMs and find differences.

    Args:
        sbom1: First SBOM
        sbom2: Second SBOM

    Returns:
        Dictionary with 'added', 'removed', 'common' package sets
    """
    packages1 = get_package_names(sbom1)
    packages2 = get_package_names(sbom2)

    return {
        "added": packages2 - packages1,
        "removed": packages1 - packages2,
        "common": packages1 & packages2
    }


def get_package_by_name(sbom_data: Dict, package_name: str) -> Optional[Dict]:
    """
    Find a package by name in SBOM.

    Args:
        sbom_data: SBOM dictionary
        package_name: Package name to search

    Returns:
        Package dictionary or None if not found
    """
    packages = extract_packages(sbom_data)

    for pkg in packages:
        if pkg.get("name", "").lower() == package_name.lower():
            return pkg

    return None


def filter_packages_by_type(sbom_data: Dict, package_type: str) -> List[Dict]:
    """
    Filter packages by type (e.g., 'python', 'npm', 'go-module').

    Args:
        sbom_data: SBOM dictionary
        package_type: Package type to filter

    Returns:
        List of matching packages
    """
    packages = extract_packages(sbom_data)

    return [
        pkg for pkg in packages
        if pkg.get("type", "").lower() == package_type.lower()
    ]


def get_package_statistics(sbom_data: Dict) -> Dict[str, int]:
    """
    Get statistics about packages in SBOM.

    Args:
        sbom_data: SBOM dictionary

    Returns:
        Dictionary with package type counts
    """
    packages = extract_packages(sbom_data)
    stats = {}

    for pkg in packages:
        pkg_type = pkg.get("type", "unknown")
        stats[pkg_type] = stats.get(pkg_type, 0) + 1

    return stats


def extract_licenses(sbom_data: Dict) -> Dict[str, List[str]]:
    """
    Extract all licenses from SBOM.

    Args:
        sbom_data: SBOM dictionary

    Returns:
        Dictionary mapping license names to package names
    """
    packages = extract_packages(sbom_data)
    licenses = {}

    for pkg in packages:
        pkg_licenses = pkg.get("licenses", [])
        pkg_name = pkg.get("name", "unknown")

        if isinstance(pkg_licenses, list):
            for lic in pkg_licenses:
                lic_name = lic if isinstance(lic, str) else str(lic)
                if lic_name not in licenses:
                    licenses[lic_name] = []
                licenses[lic_name].append(pkg_name)

    return licenses


def get_sbom_metadata(sbom_data: Dict) -> Dict:
    """
    Extract metadata from SBOM.

    Args:
        sbom_data: SBOM dictionary

    Returns:
        Metadata dictionary
    """
    metadata = {}

    # Syft JSON format
    if "source" in sbom_data:
        metadata["source"] = sbom_data["source"]
        metadata["descriptor"] = sbom_data.get("descriptor", {})

    # CycloneDX format
    elif "metadata" in sbom_data:
        metadata = sbom_data["metadata"]
        metadata["bomFormat"] = sbom_data.get("bomFormat")
        metadata["specVersion"] = sbom_data.get("specVersion")

    # SPDX format
    elif "spdxVersion" in sbom_data:
        metadata["spdxVersion"] = sbom_data["spdxVersion"]
        metadata["creationInfo"] = sbom_data.get("creationInfo", {})
        metadata["name"] = sbom_data.get("name")

    return metadata


def convert_to_csv(sbom_data: Dict, output_path: Path) -> None:
    """
    Convert SBOM to CSV format.

    Args:
        sbom_data: SBOM dictionary
        output_path: Output CSV file path
    """
    packages = extract_packages(sbom_data)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        # Header
        f.write("name,version,type,purl,licenses\n")

        # Rows
        for pkg in packages:
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            pkg_type = pkg.get("type", "")
            purl = pkg.get("purl", "")
            licenses = ";".join(pkg.get("licenses", []))

            f.write(f'"{name}","{version}","{pkg_type}","{purl}","{licenses}"\n')


def convert_to_requirements(sbom_data: Dict, output_path: Path) -> None:
    """
    Convert SBOM to requirements.txt format (Python packages only).

    Args:
        sbom_data: SBOM dictionary
        output_path: Output requirements.txt file path
    """
    packages = filter_packages_by_type(sbom_data, "python")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        for pkg in packages:
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if name and version:
                f.write(f"{name}=={version}\n")


def get_version_changes(
    old_sbom: Dict,
    new_sbom: Dict
) -> Dict[str, Tuple[str, str]]:
    """
    Compare package versions between two SBOMs.

    Args:
        old_sbom: Original SBOM
        new_sbom: New SBOM

    Returns:
        Dictionary mapping package names to (old_version, new_version) tuples
    """
    old_packages = {
        pkg.get("name"): pkg.get("version")
        for pkg in extract_packages(old_sbom)
        if pkg.get("name")
    }

    new_packages = {
        pkg.get("name"): pkg.get("version")
        for pkg in extract_packages(new_sbom)
        if pkg.get("name")
    }

    changes = {}

    # Find version changes
    for name in old_packages:
        if name in new_packages:
            old_ver = old_packages[name]
            new_ver = new_packages[name]
            if old_ver != new_ver:
                changes[name] = (old_ver, new_ver)

    return changes


def search_packages(sbom_data: Dict, search_term: str) -> List[Dict]:
    """
    Search for packages by name (case-insensitive).

    Args:
        sbom_data: SBOM dictionary
        search_term: Search term

    Returns:
        List of matching packages
    """
    packages = extract_packages(sbom_data)
    search_lower = search_term.lower()

    return [
        pkg for pkg in packages
        if search_lower in pkg.get("name", "").lower()
    ]


def group_components_by_type(sbom_data: Dict) -> Dict[str, List[Dict]]:
    """
    Group all components by their type (library, file, os, application, etc.).

    Args:
        sbom_data: SBOM dictionary

    Returns:
        Dictionary mapping component type to list of components
    """
    components = extract_packages(sbom_data)
    grouped = {}

    for component in components:
        comp_type = component.get("type", "unknown")
        if comp_type not in grouped:
            grouped[comp_type] = []
        grouped[comp_type].append(component)

    return grouped


def extract_component_metadata(component: Dict) -> Dict[str, Optional[str]]:
    """
    Extract metadata from component properties.

    Args:
        component: Component dictionary

    Returns:
        Dictionary with language, package_type, location, etc.
    """
    metadata = {
        "language": None,
        "package_type": None,
        "location": None,
        "foundBy": None,
        "metadataType": None
    }

    properties = component.get("properties", [])
    if not isinstance(properties, list):
        return metadata

    for prop in properties:
        if not isinstance(prop, dict):
            continue

        name = prop.get("name", "")
        value = prop.get("value", "")

        if name == "syft:package:language":
            metadata["language"] = value
        elif name == "syft:package:type":
            metadata["package_type"] = value
        elif name == "syft:package:foundBy":
            metadata["foundBy"] = value
        elif name == "syft:package:metadataType":
            metadata["metadataType"] = value
        elif name.startswith("syft:location") and name.endswith(":path"):
            metadata["location"] = value

    return metadata


def get_files_by_category(sbom_data: Dict) -> Dict[str, List[Dict]]:
    """
    Categorize file components by type (metadata, source, config, docs, etc.).

    Args:
        sbom_data: SBOM dictionary

    Returns:
        Dictionary mapping file category to list of file components
    """
    file_components = filter_packages_by_type(sbom_data, "file")
    categories = {
        "metadata": [],
        "record": [],
        "source": [],
        "config": [],
        "documentation": [],
        "other": []
    }

    for file_comp in file_components:
        name = file_comp.get("name", "").lower()

        if "metadata" in name or name.endswith(".dist-info/metadata"):
            categories["metadata"].append(file_comp)
        elif "record" in name or name.endswith(".dist-info/record"):
            categories["record"].append(file_comp)
        elif name.endswith((".py", ".js", ".go", ".rs", ".java")):
            categories["source"].append(file_comp)
        elif name.endswith((".json", ".yaml", ".yml", ".toml", ".ini", ".cfg")):
            categories["config"].append(file_comp)
        elif name.endswith((".md", ".txt", ".rst", "readme", "license")):
            categories["documentation"].append(file_comp)
        else:
            categories["other"].append(file_comp)

    # Remove empty categories
    return {k: v for k, v in categories.items() if v}


def get_component_details(component: Dict) -> Dict:
    """
    Get comprehensive details for a component.

    Args:
        component: Component dictionary

    Returns:
        Dictionary with all component details including metadata
    """
    details = {
        "name": component.get("name", ""),
        "version": component.get("version", ""),
        "type": component.get("type", ""),
        "purl": component.get("purl"),
        "cpe": component.get("cpe"),
        "author": component.get("author"),
        "licenses": component.get("licenses", []),
        "bom_ref": component.get("bom-ref"),
    }

    # Extract metadata from properties
    metadata = extract_component_metadata(component)
    details.update(metadata)

    return details


def filter_components_by_language(sbom_data: Dict, language: str) -> List[Dict]:
    """
    Filter components by programming language.

    Args:
        sbom_data: SBOM dictionary
        language: Language to filter (e.g., 'python', 'javascript', 'go')

    Returns:
        List of matching components
    """
    components = extract_packages(sbom_data)
    filtered = []

    for component in components:
        metadata = extract_component_metadata(component)
        comp_language = metadata.get("language") or ""
        if comp_language.lower() == language.lower():
            filtered.append(component)

    return filtered


def get_language_statistics(sbom_data: Dict) -> Dict[str, int]:
    """
    Get statistics about components by language.

    Args:
        sbom_data: SBOM dictionary

    Returns:
        Dictionary mapping language names to component counts
    """
    components = extract_packages(sbom_data)
    stats = {}

    for component in components:
        metadata = extract_component_metadata(component)
        language = metadata.get("language") or "unknown"
        stats[language] = stats.get(language, 0) + 1

    return stats
