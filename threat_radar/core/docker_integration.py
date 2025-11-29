"""Docker SDK integration for container analysis."""

import docker
from docker.errors import DockerException, ImageNotFound, APIError
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class DockerClient:
    """Wrapper for Docker SDK client with error handling."""

    def __init__(self):
        """Initialize Docker client connection."""
        self._client: Optional[docker.DockerClient] = None
        self._connect()

    def _connect(self) -> None:
        """Establish connection to Docker daemon."""
        try:
            self._client = docker.from_env()
            # Test connection
            self._client.ping()
            logger.info("Successfully connected to Docker daemon")
        except DockerException as e:
            logger.error(f"Failed to connect to Docker daemon: {e}")
            raise ConnectionError(
                "Could not connect to Docker daemon. "
                "Ensure Docker is running and accessible."
            ) from e

    @property
    def client(self) -> docker.DockerClient:
        """Get the Docker client instance."""
        if self._client is None:
            raise ConnectionError("Docker client not initialized")
        return self._client

    def pull_image(
        self, image_name: str, tag: str = "latest"
    ) -> docker.models.images.Image:
        """
        Pull a Docker image from registry.

        Args:
            image_name: Name of the image to pull
            tag: Image tag (default: latest)

        Returns:
            Docker Image object

        Raises:
            ImageNotFound: If image doesn't exist
            APIError: If pull fails
        """
        full_name = f"{image_name}:{tag}"
        try:
            logger.info(f"Pulling image: {full_name}")
            image = self.client.images.pull(image_name, tag=tag)
            logger.info(f"Successfully pulled image: {full_name}")
            return image
        except ImageNotFound as e:
            logger.error(f"Image not found: {full_name}")
            raise
        except APIError as e:
            logger.error(f"Failed to pull image {full_name}: {e}")
            raise

    def get_image(self, image_name: str) -> docker.models.images.Image:
        """
        Get a Docker image from local registry.

        Args:
            image_name: Name or ID of the image

        Returns:
            Docker Image object

        Raises:
            ImageNotFound: If image doesn't exist locally
        """
        try:
            return self.client.images.get(image_name)
        except ImageNotFound:
            logger.warning(f"Image {image_name} not found locally")
            raise

    def list_images(self) -> list:
        """
        List all Docker images.

        Returns:
            List of Docker Image objects
        """
        return self.client.images.list()

    def run_container(
        self, image_name: str, command: str, remove: bool = True, **kwargs
    ) -> bytes:
        """
        Run a command in a container and return output.

        Args:
            image_name: Name of the image to run
            command: Command to execute
            remove: Remove container after execution (default: True)
            **kwargs: Additional arguments for container.run()

        Returns:
            Command output as bytes

        Raises:
            APIError: If container execution fails
        """
        try:
            logger.info(f"Running command in {image_name}: {command}")
            output = self.client.containers.run(
                image_name, command, remove=remove, **kwargs
            )
            return output
        except APIError as e:
            logger.error(f"Failed to run container: {e}")
            raise

    def inspect_image(self, image_name: str) -> dict:
        """
        Get detailed information about an image.

        Args:
            image_name: Name or ID of the image

        Returns:
            Image inspection data as dict
        """
        image = self.get_image(image_name)
        return image.attrs

    def close(self) -> None:
        """Close Docker client connection."""
        if self._client:
            self._client.close()
            logger.info("Docker client connection closed")
