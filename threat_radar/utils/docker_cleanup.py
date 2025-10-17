"""Docker image cleanup utilities for CVE scanning."""
import logging
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


class DockerImageCleanup:
    """Handles cleanup of Docker images after scanning."""

    @staticmethod
    def image_exists(image_name: str) -> bool:
        """
        Check if a Docker image exists locally.

        Args:
            image_name: Full image name (e.g., 'alpine:3.18')

        Returns:
            True if image exists locally, False otherwise
        """
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", image_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("Failed to check if Docker image exists")
            return False

    @staticmethod
    def remove_image(image_name: str, force: bool = False) -> bool:
        """
        Remove a Docker image.

        Args:
            image_name: Full image name (e.g., 'alpine:3.18')
            force: Force removal even if image is in use

        Returns:
            True if successfully removed, False otherwise
        """
        try:
            cmd = ["docker", "rmi", image_name]
            if force:
                cmd.append("--force")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                logger.info(f"Successfully removed Docker image: {image_name}")
                return True
            else:
                logger.warning(f"Failed to remove Docker image {image_name}: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error(f"Timeout while removing Docker image: {image_name}")
            return False
        except FileNotFoundError:
            logger.error("Docker command not found")
            return False

    @staticmethod
    def extract_image_from_sbom_scan(target: str) -> Optional[str]:
        """
        Extract Docker image name from SBOM scan target if it was scanned from an image.

        When Syft generates an SBOM from a Docker image, we can track the source image
        for cleanup purposes.

        Args:
            target: The target that was scanned (could be file path or docker:image)

        Returns:
            Docker image name if target was an image, None otherwise
        """
        # Check if target indicates a Docker image source
        # Format could be: "docker:alpine:3.18" or just "alpine:3.18"
        if target.startswith("docker:"):
            # Remove "docker:" prefix
            return target[7:]

        # For SBOM files, we can't reliably determine the source image
        # without parsing the SBOM metadata
        return None


class ScanCleanupContext:
    """
    Context manager for tracking and cleaning up Docker images after scans.

    Usage:
        with ScanCleanupContext("alpine:3.18", cleanup=True) as ctx:
            # Perform scan
            result = scan_image("alpine:3.18")
        # Image is automatically cleaned up if it was pulled during scan
    """

    def __init__(self, image_name: str, cleanup: bool = False):
        """
        Initialize cleanup context.

        Args:
            image_name: Docker image name
            cleanup: Whether to cleanup after scan
        """
        self.image_name = image_name
        self.cleanup = cleanup
        self.existed_before = False
        self.cleanup_util = DockerImageCleanup()

    def __enter__(self):
        """Check if image exists before scan."""
        self.existed_before = self.cleanup_util.image_exists(self.image_name)
        logger.debug(
            f"Image {self.image_name} existed before scan: {self.existed_before}"
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cleanup image if needed."""
        if not self.cleanup:
            return False

        # Don't clean up if there was an error
        if exc_type is not None:
            logger.debug("Skipping cleanup due to scan error")
            return False

        # Only cleanup if image was pulled during this scan
        if not self.existed_before:
            logger.info(
                f"Cleaning up Docker image {self.image_name} "
                "(image was pulled during this scan)"
            )
            self.cleanup_util.remove_image(self.image_name, force=False)
        else:
            logger.debug(
                f"Skipping cleanup for {self.image_name} "
                "(image existed before scan)"
            )

        return False
