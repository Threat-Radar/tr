"""Utilities and helper functions"""
from .docker_utils import (
    docker_analyzer,
    docker_client,
    parse_image_reference,
    format_bytes,
)
from .file_utils import save_json, save_text
from .cli_utils import handle_cli_error, create_package_table
from .docker_cleanup import DockerImageCleanup, ScanCleanupContext
from .cve_storage import CVEStorageManager, get_cve_storage
from .ai_storage import AIAnalysisManager, get_ai_storage

from .comprehensive_report import ComprehensiveReportGenerator
from .report_templates import (
    ComprehensiveReport,
    VulnerabilitySummary,
    VulnerabilityFinding,
    PackageVulnerabilities,
    ExecutiveSummary,
    DashboardData,
    ReportLevel,
    ReportFormat,
)
from .report_formatters import get_formatter, JSONFormatter, MarkdownFormatter, HTMLFormatter

__all__ = [
    "docker_analyzer",
    "docker_client",
    "parse_image_reference",
    "format_bytes",
    "save_json",
    "save_text",
    "handle_cli_error",
    "create_package_table",
    "DockerImageCleanup",
    "ScanCleanupContext",
    "CVEStorageManager",
    "get_cve_storage",
    "AIAnalysisManager",
    "get_ai_storage",
    "ComprehensiveReportGenerator",
    "ComprehensiveReport",
    "VulnerabilitySummary",
    "VulnerabilityFinding",
    "PackageVulnerabilities",
    "ExecutiveSummary",
    "DashboardData",
    "ReportLevel",
    "ReportFormat",
    "get_formatter",
    "JSONFormatter",
    "MarkdownFormatter",
    "HTMLFormatter",
]
