"""Container analysis functions for extracting metadata and packages."""
import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from docker.errors import APIError, ImageNotFound

from .docker_integration import DockerClient
from .package_extractors import Package, PackageExtractorFactory

logger = logging.getLogger(__name__)


@dataclass
class ContainerAnalysis:
    """Results of container analysis."""
    image_name: str
    image_id: str
    distro: Optional[str] = None
    distro_version: Optional[str] = None
    base_image: Optional[str] = None
    packages: List[Package] = None
    size: Optional[int] = None
    created: Optional[str] = None
    architecture: Optional[str] = None
    os: Optional[str] = None

    def __post_init__(self):
        if self.packages is None:
            self.packages = []

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        # Convert Package objects to dicts
        data['packages'] = [asdict(p) for p in self.packages]
        return data


class ContainerAnalyzer:
    """Analyzes Docker containers and extracts package information."""

    def __init__(self):
        """Initialize container analyzer."""
        self.docker_client = DockerClient()

    def import_container(self, image_name: str, tag: str = "latest") -> ContainerAnalysis:
        """
        Import and analyze a container image.

        Args:
            image_name: Name of the image to import
            tag: Image tag (default: latest)

        Returns:
            ContainerAnalysis object with extracted information
        """
        full_name = f"{image_name}:{tag}"
        logger.info(f"Importing container: {full_name}")

        # Pull the image
        image = self.docker_client.pull_image(image_name, tag)

        # Analyze the image
        return self.analyze_container(full_name)

    def analyze_container(self, image_name: str) -> ContainerAnalysis:
        """
        Analyze a container image and extract package information.

        Args:
            image_name: Name or ID of the image

        Returns:
            ContainerAnalysis object
        """
        logger.info(f"Analyzing container: {image_name}")

        # Get image metadata
        image_info = self.docker_client.inspect_image(image_name)

        # Extract basic info
        analysis = ContainerAnalysis(
            image_name=image_name,
            image_id=image_info['Id'],
            size=image_info.get('Size'),
            created=image_info.get('Created'),
            architecture=image_info.get('Architecture'),
            os=image_info.get('Os')
        )

        # Detect distribution
        distro, version = self._detect_distro(image_name)
        analysis.distro = distro
        analysis.distro_version = version

        # Extract base image info
        analysis.base_image = self._get_base_image(image_info)

        # Extract packages if we can detect the distro
        if distro:
            packages = self._extract_packages(image_name, distro)
            analysis.packages = packages

        logger.info(
            f"Analysis complete: {distro} {version}, "
            f"{len(analysis.packages)} packages extracted"
        )

        return analysis

    def _detect_distro(self, image_name: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Detect the Linux distribution and version.

        Args:
            image_name: Name of the image

        Returns:
            Tuple of (distro_name, version)
        """
        # Try reading /etc/os-release
        try:
            output = self.docker_client.run_container(
                image_name,
                "cat /etc/os-release",
                remove=True
            )
            return self._parse_os_release(output)
        except APIError as e:
            logger.warning(f"Could not read /etc/os-release: {e}")

        # Fallback: try /etc/issue
        try:
            output = self.docker_client.run_container(
                image_name,
                "cat /etc/issue",
                remove=True
            )
            return self._parse_issue(output)
        except APIError as e:
            logger.warning(f"Could not read /etc/issue: {e}")

        # Fallback: guess from image name
        return self._guess_distro_from_name(image_name)

    def _parse_os_release(self, output: bytes) -> Tuple[Optional[str], Optional[str]]:
        """Parse /etc/os-release file."""
        content = output.decode('utf-8', errors='ignore')
        distro = None
        version = None

        for line in content.split('\n'):
            if line.startswith('ID='):
                distro = line.split('=', 1)[1].strip().strip('"')
            elif line.startswith('VERSION_ID='):
                version = line.split('=', 1)[1].strip().strip('"')

        return distro, version

    def _parse_issue(self, output: bytes) -> Tuple[Optional[str], Optional[str]]:
        """Parse /etc/issue file."""
        content = output.decode('utf-8', errors='ignore').lower()

        if 'debian' in content:
            return 'debian', None
        elif 'ubuntu' in content:
            return 'ubuntu', None
        elif 'alpine' in content:
            return 'alpine', None
        elif 'centos' in content:
            return 'centos', None
        elif 'fedora' in content:
            return 'fedora', None
        elif 'red hat' in content or 'rhel' in content:
            return 'rhel', None

        return None, None

    def _guess_distro_from_name(self, image_name: str) -> Tuple[Optional[str], Optional[str]]:
        """Guess distribution from image name."""
        image_lower = image_name.lower()

        distros = {
            'alpine': 'alpine',
            'ubuntu': 'ubuntu',
            'debian': 'debian',
            'centos': 'centos',
            'fedora': 'fedora',
            'rhel': 'rhel',
            'rocky': 'rocky',
            'almalinux': 'almalinux'
        }

        for keyword, distro in distros.items():
            if keyword in image_lower:
                # Try to extract version from tag
                version_match = re.search(r':(\d+(?:\.\d+)*)', image_name)
                version = version_match.group(1) if version_match else None
                return distro, version

        return None, None

    def _get_base_image(self, image_info: Dict) -> Optional[str]:
        """Extract base image information from image config."""
        config = image_info.get('Config', {})
        labels = config.get('Labels')

        # Check common labels for base image
        if labels:
            for label_key in ['org.opencontainers.image.base.name', 'base.image']:
                if label_key in labels:
                    return labels[label_key]

        # Try to get from history
        history = image_info.get('RootFS', {})
        return None

    def _extract_packages(self, image_name: str, distro: str) -> List[Package]:
        """
        Extract installed packages from container.

        Args:
            image_name: Name of the image
            distro: Distribution name

        Returns:
            List of Package objects
        """
        extractor = PackageExtractorFactory.get_extractor(distro)
        if not extractor:
            logger.warning(f"No extractor available for {distro}")
            return []

        command = PackageExtractorFactory.get_command(distro)
        if not command:
            logger.warning(f"No command available for {distro}")
            return []

        try:
            output = self.docker_client.run_container(
                image_name,
                command,
                remove=True
            )
            packages = extractor.parse_packages(output)
            return packages
        except APIError as e:
            logger.error(f"Failed to extract packages: {e}")
            return []

    def list_analyzed_images(self) -> List[Dict]:
        """
        List all Docker images available locally.

        Returns:
            List of image metadata dictionaries
        """
        images = self.docker_client.list_images()
        result = []

        for image in images:
            result.append({
                'id': image.id,
                'tags': image.tags,
                'created': image.attrs.get('Created'),
                'size': image.attrs.get('Size'),
            })

        return result

    def close(self) -> None:
        """Close Docker client connection."""
        self.docker_client.close()
