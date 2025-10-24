"""
Threat Radar - A comprehensive threat assessment and analysis platform

This package provides enterprise-grade security analysis with:
- Docker container vulnerability scanning
- SBOM generation and analysis
- AI-powered vulnerability assessment
- Comprehensive reporting

Quick start:
    >>> from threat_radar.core import GrypeClient, SyftClient
    >>> from threat_radar.ai import VulnerabilityAnalyzer
    >>>
    >>> # Scan for vulnerabilities
    >>> grype = GrypeClient()
    >>> result = grype.scan_image("alpine:3.18")
    >>>
    >>> # Analyze with AI
    >>> analyzer = VulnerabilityAnalyzer()
    >>> analysis = analyzer.analyze_scan_result(result)

For CLI usage:
    $ threat-radar cve scan-image alpine:3.18 --auto-save
    $ threat-radar ai analyze scan-results.json
    $ threat-radar report generate scan-results.json -o report.html
"""

# Core scanning and analysis
from .core.grype_integration import (
    GrypeClient,
    GrypeScanResult,
    GrypeVulnerability,
    GrypeSeverity,
    GrypeOutputFormat,
)
from .core.syft_integration import SyftClient, SBOMFormat
from .core.container_analyzer import ContainerAnalyzer, ContainerAnalysis
from .core.docker_integration import DockerClient
from .core.github_integration import GitHubIntegration
from .core.package_extractors import Package

# AI-powered analysis
from .ai.vulnerability_analyzer import (
    VulnerabilityAnalyzer,
    VulnerabilityAnalysis,
    VulnerabilityInsight,
)
from .ai.prioritization import PrioritizationEngine, PrioritizedVulnerabilityList
from .ai.remediation_generator import RemediationGenerator, RemediationReport
from .ai.llm_client import LLMClient, OpenAIClient, get_llm_client

# Reporting
from .utils.report_templates import (
    ComprehensiveReport,
    VulnerabilitySummary,
    ExecutiveSummary,
)
from .utils.comprehensive_report import ComprehensiveReportGenerator

__version__ = "0.1.0"
__author__ = "Threat Radar Team"
__license__ = "MIT"

__all__ = [
    # Core scanning
    "GrypeClient",
    "GrypeScanResult",
    "GrypeVulnerability",
    "GrypeSeverity",
    "GrypeOutputFormat",
    "SyftClient",
    "SBOMFormat",
    "ContainerAnalyzer",
    "ContainerAnalysis",
    "DockerClient",
    "GitHubIntegration",
    "Package",
    # AI analysis
    "VulnerabilityAnalyzer",
    "VulnerabilityAnalysis",
    "VulnerabilityInsight",
    "PrioritizationEngine",
    "PrioritizedVulnerabilityList",
    "RemediationGenerator",
    "RemediationReport",
    "LLMClient",
    "OpenAIClient",
    "get_llm_client",
    # Reporting
    "ComprehensiveReport",
    "VulnerabilitySummary",
    "ExecutiveSummary",
    "ComprehensiveReportGenerator",
    # Package metadata
    "__version__",
    "__author__",
    "__license__",
]