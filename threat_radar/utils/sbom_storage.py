"""SBOM storage and naming utilities."""
import os
from pathlib import Path
from datetime import datetime
from typing import Optional
import re


def get_sbom_storage_root() -> Path:
    """
    Get the root SBOM storage directory.

    Returns:
        Path to sbom_storage directory
    """
    # Try to find project root by looking for pyproject.toml
    current = Path.cwd()
    while current != current.parent:
        if (current / "pyproject.toml").exists():
            return current / "sbom_storage"
        current = current.parent

    # Fallback to current directory
    return Path.cwd() / "sbom_storage"


def ensure_storage_directories() -> None:
    """Create SBOM storage directories if they don't exist."""
    root = get_sbom_storage_root()
    directories = [
        root / "docker",
        root / "local",
        root / "comparisons",
        root / "archives"
    ]

    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)


def sanitize_name(name: str) -> str:
    """
    Sanitize a name for use in filenames.

    Args:
        name: Name to sanitize

    Returns:
        Sanitized name safe for filenames
    """
    # Replace special characters with underscores
    sanitized = re.sub(r'[^\w\-.]', '_', name)
    # Remove consecutive underscores
    sanitized = re.sub(r'_+', '_', sanitized)
    # Remove leading/trailing underscores
    sanitized = sanitized.strip('_')
    return sanitized


def get_timestamp() -> str:
    """
    Get current timestamp in standardized format.

    Returns:
        Timestamp string (YYYYMMDD_HHMMSS)
    """
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def generate_docker_sbom_name(
    image_name: str,
    tag: str = "latest",
    format: str = "json",
    timestamp: Optional[str] = None
) -> str:
    """
    Generate SBOM filename for Docker container scan.

    Args:
        image_name: Docker image name (e.g., 'alpine', 'ubuntu')
        tag: Image tag (e.g., '3.18', 'latest')
        format: File format (json, xml, spdx.json, syft.json)
        timestamp: Optional timestamp, uses current time if None

    Returns:
        Filename following convention: docker_<image>_<tag>_<timestamp>.<format>

    Examples:
        >>> generate_docker_sbom_name("alpine", "3.18")
        'docker_alpine_3.18_20251002_143022.json'
        >>> generate_docker_sbom_name("jupyter/datascience-notebook", "latest")
        'docker_jupyter_datascience-notebook_latest_20251002_143022.json'
    """
    ts = timestamp or get_timestamp()
    clean_image = sanitize_name(image_name)
    clean_tag = sanitize_name(tag)

    return f"docker_{clean_image}_{clean_tag}_{ts}.{format}"


def generate_local_sbom_name(
    project_name: str,
    format: str = "json",
    timestamp: Optional[str] = None
) -> str:
    """
    Generate SBOM filename for local project scan.

    Args:
        project_name: Project name or directory name
        format: File format (json, xml, spdx.json, syft.json)
        timestamp: Optional timestamp, uses current time if None

    Returns:
        Filename following convention: local_<project>_<timestamp>.<format>

    Examples:
        >>> generate_local_sbom_name("threat-radar")
        'local_threat-radar_20251002_143022.json'
    """
    ts = timestamp or get_timestamp()
    clean_project = sanitize_name(project_name)

    return f"local_{clean_project}_{ts}.{format}"


def generate_comparison_name(
    name1: str,
    name2: str,
    format: str = "json",
    timestamp: Optional[str] = None
) -> str:
    """
    Generate filename for SBOM comparison result.

    Args:
        name1: First SBOM name/version
        name2: Second SBOM name/version
        format: File format (json, txt)
        timestamp: Optional timestamp, uses current time if None

    Returns:
        Filename following convention: compare_<name1>_vs_<name2>_<timestamp>.<format>

    Examples:
        >>> generate_comparison_name("alpine-3.17", "alpine-3.18")
        'compare_alpine-3.17_vs_alpine-3.18_20251002_143022.json'
    """
    ts = timestamp or get_timestamp()
    clean_name1 = sanitize_name(name1)
    clean_name2 = sanitize_name(name2)

    return f"compare_{clean_name1}_vs_{clean_name2}_{ts}.{format}"


def get_docker_sbom_path(
    image_name: str,
    tag: str = "latest",
    format: str = "json",
    timestamp: Optional[str] = None
) -> Path:
    """
    Get full path for Docker SBOM.

    Args:
        image_name: Docker image name
        tag: Image tag
        format: File format
        timestamp: Optional timestamp

    Returns:
        Full path to SBOM file in docker/ directory
    """
    ensure_storage_directories()
    filename = generate_docker_sbom_name(image_name, tag, format, timestamp)
    return get_sbom_storage_root() / "docker" / filename


def get_local_sbom_path(
    project_name: str,
    format: str = "json",
    timestamp: Optional[str] = None
) -> Path:
    """
    Get full path for local project SBOM.

    Args:
        project_name: Project name
        format: File format
        timestamp: Optional timestamp

    Returns:
        Full path to SBOM file in local/ directory
    """
    ensure_storage_directories()
    filename = generate_local_sbom_name(project_name, format, timestamp)
    return get_sbom_storage_root() / "local" / filename


def get_comparison_path(
    name1: str,
    name2: str,
    format: str = "json",
    timestamp: Optional[str] = None
) -> Path:
    """
    Get full path for comparison result.

    Args:
        name1: First SBOM name
        name2: Second SBOM name
        format: File format
        timestamp: Optional timestamp

    Returns:
        Full path to comparison file in comparisons/ directory
    """
    ensure_storage_directories()
    filename = generate_comparison_name(name1, name2, format, timestamp)
    return get_sbom_storage_root() / "comparisons" / filename


def list_stored_sboms(category: str = "all") -> list[Path]:
    """
    List all stored SBOMs in a category.

    Args:
        category: Category to list (docker, local, comparisons, archives, all)

    Returns:
        List of Path objects to SBOM files
    """
    root = get_sbom_storage_root()

    if category == "all":
        directories = ["docker", "local", "comparisons", "archives"]
    else:
        directories = [category]

    sboms = []
    for directory in directories:
        dir_path = root / directory
        if dir_path.exists():
            sboms.extend(dir_path.glob("*.json"))
            sboms.extend(dir_path.glob("*.xml"))

    return sorted(sboms, key=lambda p: p.stat().st_mtime, reverse=True)


def archive_old_sboms(days: int = 30) -> int:
    """
    Move SBOMs older than specified days to archives.

    Args:
        days: Number of days threshold

    Returns:
        Number of files archived
    """
    from datetime import timedelta

    root = get_sbom_storage_root()
    archive_dir = root / "archives"
    archive_dir.mkdir(parents=True, exist_ok=True)

    threshold = datetime.now() - timedelta(days=days)
    archived_count = 0

    for category in ["docker", "local"]:
        category_dir = root / category
        if not category_dir.exists():
            continue

        for sbom_file in category_dir.glob("*.json"):
            if datetime.fromtimestamp(sbom_file.stat().st_mtime) < threshold:
                archive_name = f"archive_{sbom_file.name}"
                archive_path = archive_dir / archive_name
                sbom_file.rename(archive_path)
                archived_count += 1

    return archived_count


def get_format_extension(sbom_format: str) -> str:
    """
    Get file extension for SBOM format.

    Args:
        sbom_format: Format name (cyclonedx-json, spdx-json, etc.)

    Returns:
        File extension (e.g., 'json', 'xml', 'spdx.json')
    """
    format_map = {
        "cyclonedx-json": "json",
        "cyclonedx-xml": "xml",
        "spdx-json": "spdx.json",
        "spdx-tag-value": "spdx",
        "syft-json": "syft.json",
        "table": "txt",
        "text": "txt"
    }

    return format_map.get(sbom_format, "json")
