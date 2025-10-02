"""Package extractors for different Linux distributions and package managers."""
import re
import logging
from typing import List, Dict, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class Package:
    """Represents an installed package."""
    name: str
    version: str
    architecture: Optional[str] = None
    description: Optional[str] = None


class PackageExtractor:
    """Base class for package extractors."""

    def parse_packages(self, output: bytes) -> List[Package]:
        """
        Parse package manager output into Package objects.

        Args:
            output: Raw output from package manager command

        Returns:
            List of Package objects
        """
        raise NotImplementedError


class APTExtractor(PackageExtractor):
    """Extract packages from Debian/Ubuntu systems using dpkg."""

    @staticmethod
    def get_command() -> str:
        """Return command to list packages."""
        return "dpkg-query -W -f='${Package}|${Version}|${Architecture}|${Description}\\n'"

    def parse_packages(self, output: bytes) -> List[Package]:
        """
        Parse dpkg output.

        Format: package|version|arch|description
        """
        packages = []
        lines = output.decode('utf-8', errors='ignore').strip().split('\n')

        for line in lines:
            if not line.strip():
                continue

            parts = line.split('|', maxsplit=3)
            if len(parts) >= 2:
                package = Package(
                    name=parts[0].strip(),
                    version=parts[1].strip(),
                    architecture=parts[2].strip() if len(parts) > 2 else None,
                    description=parts[3].strip() if len(parts) > 3 else None
                )
                packages.append(package)

        logger.info(f"Extracted {len(packages)} packages using APT")
        return packages


class APKExtractor(PackageExtractor):
    """Extract packages from Alpine Linux using apk."""

    @staticmethod
    def get_command() -> str:
        """Return command to list packages."""
        return "apk info -v"

    def parse_packages(self, output: bytes) -> List[Package]:
        """
        Parse apk output.

        Format: package-name-version
        Example: musl-1.2.3-r0
        """
        packages = []
        lines = output.decode('utf-8', errors='ignore').strip().split('\n')

        # Pattern to match package-name-version-release
        pattern = re.compile(r'^(.+?)-(\d+[\.\d]*-r\d+)$')

        for line in lines:
            line = line.strip()
            if not line:
                continue

            match = pattern.match(line)
            if match:
                package = Package(
                    name=match.group(1),
                    version=match.group(2)
                )
                packages.append(package)
            else:
                # Fallback: treat entire line as package name
                logger.warning(f"Could not parse apk package: {line}")
                package = Package(name=line, version="unknown")
                packages.append(package)

        logger.info(f"Extracted {len(packages)} packages using APK")
        return packages


class YUMExtractor(PackageExtractor):
    """Extract packages from RHEL/CentOS/Fedora systems using rpm."""

    @staticmethod
    def get_command() -> str:
        """Return command to list packages."""
        return "rpm -qa --queryformat '%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}\\n'"

    def parse_packages(self, output: bytes) -> List[Package]:
        """
        Parse rpm output.

        Format: name|version-release|arch
        """
        packages = []
        lines = output.decode('utf-8', errors='ignore').strip().split('\n')

        for line in lines:
            if not line.strip():
                continue

            parts = line.split('|')
            if len(parts) >= 2:
                package = Package(
                    name=parts[0].strip(),
                    version=parts[1].strip(),
                    architecture=parts[2].strip() if len(parts) > 2 else None
                )
                packages.append(package)

        logger.info(f"Extracted {len(packages)} packages using YUM/RPM")
        return packages


class PackageExtractorFactory:
    """Factory to get appropriate package extractor based on distro."""

    _extractors = {
        'debian': APTExtractor,
        'ubuntu': APTExtractor,
        'alpine': APKExtractor,
        'rhel': YUMExtractor,
        'centos': YUMExtractor,
        'fedora': YUMExtractor,
        'rocky': YUMExtractor,
        'almalinux': YUMExtractor,
    }

    @classmethod
    def get_extractor(cls, distro: str) -> Optional[PackageExtractor]:
        """
        Get package extractor for given distribution.

        Args:
            distro: Distribution name (lowercase)

        Returns:
            PackageExtractor instance or None if unsupported
        """
        distro_lower = distro.lower()
        extractor_class = cls._extractors.get(distro_lower)

        if extractor_class:
            return extractor_class()

        logger.warning(f"No package extractor found for distro: {distro}")
        return None

    @classmethod
    def get_command(cls, distro: str) -> Optional[str]:
        """
        Get package list command for given distribution.

        Args:
            distro: Distribution name

        Returns:
            Command string or None if unsupported
        """
        extractor = cls.get_extractor(distro)
        if extractor:
            return extractor.get_command()
        return None
