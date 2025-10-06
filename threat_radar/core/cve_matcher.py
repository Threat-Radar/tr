"""CVE matching engine with version comparison and fuzzy matching."""
import re
import logging
from typing import List, Optional, Tuple, Dict
from dataclasses import dataclass
from difflib import SequenceMatcher

from .nvd_client import CVEItem
from .package_extractors import Package

logger = logging.getLogger(__name__)


@dataclass
class CVEMatch:
    """Represents a CVE match for a package."""

    package: Package
    cve: CVEItem
    confidence: float  # 0.0 to 1.0
    match_reason: str
    cpe_uri: Optional[str] = None
    version_match: bool = False


class VersionComparator:
    """Handles version comparison and semantic versioning."""

    @staticmethod
    def parse_version(version: str) -> Tuple[List[int], str]:
        """
        Parse version string into comparable components.

        Args:
            version: Version string (e.g., "2.14.1", "1.0.0-beta", "3.2")

        Returns:
            Tuple of (numeric_parts, suffix)
        """
        # Remove leading 'v' if present
        version = version.lstrip('v')

        # Split on common separators and handle suffixes
        match = re.match(r'([\d.]+)(.*)', version)
        if not match:
            return ([0], version)

        numeric_part = match.group(1)
        suffix = match.group(2).strip('.-_')

        # Parse numeric parts
        try:
            parts = [int(x) for x in numeric_part.split('.')]
        except ValueError:
            parts = [0]

        return (parts, suffix)

    @staticmethod
    def compare_versions(v1: str, v2: str) -> int:
        """
        Compare two version strings.

        Args:
            v1: First version
            v2: Second version

        Returns:
            -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
        """
        parts1, suffix1 = VersionComparator.parse_version(v1)
        parts2, suffix2 = VersionComparator.parse_version(v2)

        # Normalize lengths
        max_len = max(len(parts1), len(parts2))
        parts1.extend([0] * (max_len - len(parts1)))
        parts2.extend([0] * (max_len - len(parts2)))

        # Compare numeric parts
        for p1, p2 in zip(parts1, parts2):
            if p1 < p2:
                return -1
            elif p1 > p2:
                return 1

        # If numeric parts are equal, compare suffixes
        # Versions without suffix are considered newer than with suffix
        if not suffix1 and suffix2:
            return 1
        elif suffix1 and not suffix2:
            return -1
        elif suffix1 < suffix2:
            return -1
        elif suffix1 > suffix2:
            return 1

        return 0

    @staticmethod
    def is_version_in_range(
        version: str,
        start_including: Optional[str] = None,
        start_excluding: Optional[str] = None,
        end_including: Optional[str] = None,
        end_excluding: Optional[str] = None
    ) -> bool:
        """
        Check if version falls within specified range.

        Args:
            version: Version to check
            start_including: Range start (inclusive)
            start_excluding: Range start (exclusive)
            end_including: Range end (inclusive)
            end_excluding: Range end (exclusive)

        Returns:
            True if version is in range
        """
        # Check lower bound
        if start_including:
            if VersionComparator.compare_versions(version, start_including) < 0:
                return False

        if start_excluding:
            if VersionComparator.compare_versions(version, start_excluding) <= 0:
                return False

        # Check upper bound
        if end_including:
            if VersionComparator.compare_versions(version, end_including) > 0:
                return False

        if end_excluding:
            if VersionComparator.compare_versions(version, end_excluding) >= 0:
                return False

        return True


class PackageNameMatcher:
    """Handles fuzzy matching of package names."""

    # Common package name variations
    NAME_MAPPINGS = {
        "log4j": ["log4j-core", "log4j2", "apache-log4j"],
        "openssl": ["libssl", "ssl", "openssl-libs"],
        "python": ["python3", "python2", "cpython"],
        "nginx": ["nginx-core", "nginx-full"],
        "apache": ["apache2", "httpd"],
        "postgresql": ["postgres", "pgsql"],
        "mysql": ["mariadb", "mysql-server"],
        "glibc": ["libc", "libc6", "libc-bin", "glibc-common"],
        "zlib": ["zlib1g", "libz", "zlib-devel"],
        "pcre": ["libpcre", "pcre3", "libpcre3"],
        "ncurses": ["libncurses", "ncurses-libs"],
    }

    # Package pairs that should NEVER match (prevent false positives)
    # Format: set of frozensets to allow bidirectional checking
    NEVER_MATCH = {
        frozenset(["bash", "dash"]),      # Different shells
        frozenset(["bash", "ash"]),       # Different shells
        frozenset(["gzip", "bzip2"]),     # Different compression tools
        frozenset(["gzip", "grep"]),      # Compression vs search
        frozenset(["tar", "star"]),       # Different archive tools
        frozenset(["glibc", "klibc"]),    # Different C libraries
        frozenset(["glibc", "klibc-utils"]), # glibc vs klibc utilities
        frozenset(["glibc", "libklibc"]), # glibc vs klibc library
    }

    @staticmethod
    def normalize_name(name: str) -> str:
        """
        Normalize package name for comparison.

        Args:
            name: Package name

        Returns:
            Normalized name
        """
        # Convert to lowercase
        name = name.lower()

        # Remove common prefixes/suffixes
        prefixes = ["lib", "python-", "python3-", "node-", "go-"]
        for prefix in prefixes:
            if name.startswith(prefix):
                name = name[len(prefix):]

        suffixes = ["-dev", "-devel", "-bin", "-common", "-core"]
        for suffix in suffixes:
            if name.endswith(suffix):
                name = name[:-len(suffix)]

        # Remove version numbers
        name = re.sub(r'\d+$', '', name)

        # Remove special characters
        name = re.sub(r'[_-]+', '', name)

        return name.strip()

    @staticmethod
    def similarity_score(name1: str, name2: str) -> float:
        """
        Calculate similarity score between two package names.

        Args:
            name1: First package name
            name2: Second package name

        Returns:
            Similarity score (0.0 to 1.0)
        """
        # Check if this pair should never match (prevent false positives)
        pair = frozenset([name1.lower(), name2.lower()])
        if pair in PackageNameMatcher.NEVER_MATCH:
            return 0.0

        # Exact match
        if name1.lower() == name2.lower():
            return 1.0

        # Normalize and compare
        norm1 = PackageNameMatcher.normalize_name(name1)
        norm2 = PackageNameMatcher.normalize_name(name2)

        if norm1 == norm2:
            return 0.95

        # Check known mappings
        for canonical, variants in PackageNameMatcher.NAME_MAPPINGS.items():
            if (name1.lower() == canonical or name1.lower() in variants) and \
               (name2.lower() == canonical or name2.lower() in variants):
                return 0.9

        # Use sequence matcher for fuzzy comparison
        ratio = SequenceMatcher(None, norm1, norm2).ratio()

        # For short names (<=4 chars), require very high similarity to avoid false positives
        # e.g., "dash" vs "bash" should not match
        min_length = min(len(norm1), len(norm2))
        if min_length <= 4:
            # Require much higher similarity for short names
            if ratio < 0.9:  # Must be almost identical
                return ratio * 0.5  # Penalize dissimilar short names

        # Boost score if one name contains the other (but not for very short names)
        if min_length > 4 and (norm1 in norm2 or norm2 in norm1):
            ratio = max(ratio, 0.8)

        return ratio

    @staticmethod
    def is_likely_match(name1: str, name2: str, threshold: float = 0.7) -> bool:
        """
        Check if two package names are likely to be the same package.

        Args:
            name1: First package name
            name2: Second package name
            threshold: Minimum similarity threshold

        Returns:
            True if likely match
        """
        return PackageNameMatcher.similarity_score(name1, name2) >= threshold


class CVEMatcher:
    """Matches packages against CVE database."""

    def __init__(self, min_confidence: float = 0.6):
        """
        Initialize CVE matcher.

        Args:
            min_confidence: Minimum confidence threshold for reporting matches
        """
        self.min_confidence = min_confidence

    def match_package(self, package: Package, cves: List[CVEItem]) -> List[CVEMatch]:
        """
        Find CVE matches for a package.

        Args:
            package: Package to check
            cves: List of CVEs to match against

        Returns:
            List of CVEMatch objects sorted by confidence
        """
        matches = []

        for cve in cves:
            match = self._check_cve_match(package, cve)
            if match and match.confidence >= self.min_confidence:
                matches.append(match)

        # Sort by confidence (highest first)
        matches.sort(key=lambda m: m.confidence, reverse=True)

        return matches

    def _check_cve_match(self, package: Package, cve: CVEItem) -> Optional[CVEMatch]:
        """
        Check if a package matches a CVE.

        Args:
            package: Package to check
            cve: CVE to match against

        Returns:
            CVEMatch if match found, None otherwise
        """
        best_confidence = 0.0
        best_reason = ""
        best_cpe = None
        version_matched = False

        # Check each affected product in the CVE
        for product in cve.affected_products:
            cpe_uri = product.get("cpe23Uri", "")

            # Parse CPE URI: cpe:2.3:a:vendor:product:version:...
            cpe_parts = cpe_uri.split(":")
            if len(cpe_parts) < 5:
                continue

            cpe_vendor = cpe_parts[3]
            cpe_product = cpe_parts[4]
            cpe_version = cpe_parts[5] if len(cpe_parts) > 5 else "*"

            # Calculate package name similarity
            name_similarity = PackageNameMatcher.similarity_score(
                package.name,
                cpe_product
            )

            if name_similarity < 0.5:
                continue

            # Check version match
            version_match = False
            if package.version:
                # First, check if version is in affected range (works with wildcard CPE versions)
                if any([
                    product.get("versionStartIncluding"),
                    product.get("versionStartExcluding"),
                    product.get("versionEndIncluding"),
                    product.get("versionEndExcluding")
                ]):
                    version_match = VersionComparator.is_version_in_range(
                        package.version,
                        start_including=product.get("versionStartIncluding"),
                        start_excluding=product.get("versionStartExcluding"),
                        end_including=product.get("versionEndIncluding"),
                        end_excluding=product.get("versionEndExcluding")
                    )
                # If no range specified and CPE has specific version, check exact match
                elif cpe_version != "*":
                    version_match = (
                        VersionComparator.compare_versions(package.version, cpe_version) == 0
                    )

            # Calculate confidence score
            confidence = self._calculate_confidence(
                name_similarity,
                version_match,
                package.version is not None,
                cve.cvss_score
            )

            if confidence > best_confidence:
                best_confidence = confidence
                best_cpe = cpe_uri
                version_matched = version_match
                best_reason = self._create_match_reason(
                    name_similarity,
                    version_match,
                    cpe_vendor,
                    cpe_product
                )

        if best_confidence >= self.min_confidence:
            return CVEMatch(
                package=package,
                cve=cve,
                confidence=best_confidence,
                match_reason=best_reason,
                cpe_uri=best_cpe,
                version_match=version_matched
            )

        return None

    def _calculate_confidence(
        self,
        name_similarity: float,
        version_match: bool,
        has_version: bool,
        cvss_score: Optional[float]
    ) -> float:
        """
        Calculate overall confidence score for a match.

        Args:
            name_similarity: Package name similarity (0.0-1.0)
            version_match: Whether version matched
            has_version: Whether package has version info
            cvss_score: CVSS score of CVE

        Returns:
            Confidence score (0.0-1.0)
        """
        # Start with name similarity
        confidence = name_similarity * 0.6

        # Version matching is crucial
        if has_version:
            if version_match:
                confidence += 0.35  # Strong boost for version match
            else:
                confidence *= 0.5  # Penalize version mismatch
        else:
            confidence += 0.1  # Small boost if no version to compare

        # Slight boost for high-severity CVEs (they're more likely to be reported)
        if cvss_score and cvss_score >= 7.0:
            confidence += 0.05

        return min(confidence, 1.0)

    def _create_match_reason(
        self,
        name_similarity: float,
        version_match: bool,
        vendor: str,
        product: str
    ) -> str:
        """Create human-readable match reason."""
        reason_parts = []

        if name_similarity >= 0.95:
            reason_parts.append("exact name match")
        elif name_similarity >= 0.8:
            reason_parts.append("strong name match")
        else:
            reason_parts.append("fuzzy name match")

        reason_parts.append(f"with {vendor}/{product}")

        if version_match:
            reason_parts.append("(version affected)")
        else:
            reason_parts.append("(version not confirmed)")

        return " ".join(reason_parts)

    def bulk_match_packages(
        self,
        packages: List[Package],
        cves: List[CVEItem]
    ) -> Dict[str, List[CVEMatch]]:
        """
        Match multiple packages against CVEs.

        Args:
            packages: List of packages to check
            cves: List of CVEs to match against

        Returns:
            Dictionary mapping package names to their CVE matches
        """
        results = {}

        for package in packages:
            matches = self.match_package(package, cves)
            if matches:
                results[package.name] = matches

        logger.info(
            f"Matched {len(results)} packages with vulnerabilities "
            f"out of {len(packages)} total packages"
        )

        return results
