"""Core business logic and integrations"""

from .github_integration import GitHubIntegration
from .nvd_client import NVDClient, CVEItem
from .cve_database import CVEDatabase
from .cve_matcher import CVEMatcher, CVEMatch, VersionComparator, PackageNameMatcher

__all__ = [
    "GitHubIntegration",
    "NVDClient",
    "CVEItem",
    "CVEDatabase",
    "CVEMatcher",
    "CVEMatch",
    "VersionComparator",
    "PackageNameMatcher",
]