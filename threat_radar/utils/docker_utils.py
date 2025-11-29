"""Docker-related utility functions and context managers."""

from contextlib import contextmanager
from typing import Tuple, Iterator
import logging

logger = logging.getLogger(__name__)


@contextmanager
def docker_analyzer() -> Iterator["ContainerAnalyzer"]:
    """
    Context manager for ContainerAnalyzer with automatic resource cleanup.

    Usage:
        with docker_analyzer() as analyzer:
            analysis = analyzer.import_container("alpine", "3.18")

    Yields:
        ContainerAnalyzer instance
    """
    from threat_radar.core.container_analyzer import ContainerAnalyzer

    analyzer = ContainerAnalyzer()
    try:
        yield analyzer
    finally:
        analyzer.close()


@contextmanager
def docker_client() -> Iterator["DockerClient"]:
    """
    Context manager for DockerClient with automatic resource cleanup.

    Usage:
        with docker_client() as client:
            image = client.pull_image("alpine", "3.18")

    Yields:
        DockerClient instance
    """
    from threat_radar.core.docker_integration import DockerClient

    client = DockerClient()
    try:
        yield client
    finally:
        client.close()


def parse_image_reference(image: str, default_tag: str = "latest") -> Tuple[str, str]:
    """
    Parse Docker image reference into name and tag components.

    Args:
        image: Image reference (e.g., "alpine:3.18" or "ubuntu")
        default_tag: Default tag to use if none specified (default: "latest")

    Returns:
        Tuple of (image_name, tag)

    Examples:
        >>> parse_image_reference("alpine:3.18")
        ('alpine', '3.18')
        >>> parse_image_reference("ubuntu")
        ('ubuntu', 'latest')
        >>> parse_image_reference("registry.io/myimage:v1.0")
        ('registry.io/myimage', 'v1.0')
    """
    if ":" in image:
        # Split on the last colon to handle registry URLs like "registry.io/image:tag"
        parts = image.rsplit(":", 1)
        return parts[0], parts[1]
    return image, default_tag


def format_bytes(size_bytes: int) -> str:
    """
    Format size in bytes to human-readable string.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted string (e.g., "1.5 GB")

    Examples:
        >>> format_bytes(1024)
        '1.0 KB'
        >>> format_bytes(1536)
        '1.5 KB'
        >>> format_bytes(1073741824)
        '1.0 GB'
    """
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"
