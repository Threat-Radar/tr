"""Comprehensive report templates and data structures for vulnerability reporting."""
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum


class ReportLevel(Enum):
    """Report detail levels."""
    EXECUTIVE = "executive"  # High-level summary for executives
    SUMMARY = "summary"      # Summary with key findings
    DETAILED = "detailed"    # Full detailed report
    CRITICAL_ONLY = "critical_only"  # Only critical/high severity findings


class ReportFormat(Enum):
    """Supported report output formats."""
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"


@dataclass
class VulnerabilitySummary:
    """Summary statistics for vulnerabilities."""
    total_vulnerabilities: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    negligible: int = 0
    unknown: int = 0

    # Additional metrics
    vulnerabilities_with_fix: int = 0
    vulnerabilities_without_fix: int = 0
    average_cvss_score: float = 0.0
    highest_cvss_score: float = 0.0

    # Package metrics
    total_packages: int = 0
    vulnerable_packages: int = 0
    vulnerable_packages_percentage: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class VulnerabilityFinding:
    """Individual vulnerability finding."""
    cve_id: str
    severity: str
    cvss_score: Optional[float]
    package_name: str
    package_version: str
    package_type: str
    fixed_in_version: Optional[str]
    description: str
    urls: List[str] = field(default_factory=list)

    # Additional metadata
    exploitability: Optional[str] = None
    business_impact: Optional[str] = None
    remediation_priority: Optional[int] = None
    attack_vector: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @property
    def has_fix(self) -> bool:
        """Check if a fix is available."""
        return self.fixed_in_version is not None


@dataclass
class PackageVulnerabilities:
    """Vulnerabilities grouped by package."""
    package_name: str
    package_version: str
    package_type: str
    vulnerability_count: int
    highest_severity: str
    highest_cvss_score: float
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    recommended_version: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data['vulnerabilities'] = [v.to_dict() for v in self.vulnerabilities]
        return data


@dataclass
class ExecutiveSummary:
    """AI-generated executive summary."""
    overall_risk_rating: str  # CRITICAL, HIGH, MEDIUM, LOW
    key_findings: List[str]
    immediate_actions: List[str]
    risk_summary: str
    compliance_impact: str
    business_context: str

    # Quick stats for executives
    critical_items_requiring_attention: int = 0
    estimated_remediation_effort: str = "Unknown"  # LOW, MEDIUM, HIGH
    days_to_patch_critical: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class TrendData:
    """Trend data for dashboard visualization."""
    severity_trend: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    package_vulnerability_trend: List[Dict[str, Any]] = field(default_factory=list)
    cvss_distribution: List[Dict[str, Any]] = field(default_factory=list)
    fix_availability_ratio: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class DashboardData:
    """Dashboard-ready data structures for visualization."""
    # High-level metrics
    summary_cards: Dict[str, Any] = field(default_factory=dict)

    # Charts data
    severity_distribution_chart: List[Dict[str, Any]] = field(default_factory=list)
    top_vulnerable_packages_chart: List[Dict[str, Any]] = field(default_factory=list)
    cvss_score_histogram: List[Dict[str, Any]] = field(default_factory=list)
    fix_availability_pie: Dict[str, int] = field(default_factory=dict)
    package_type_breakdown: List[Dict[str, Any]] = field(default_factory=list)

    # Timeline/trend data
    trend_data: Optional[TrendData] = None

    # Critical items list
    critical_items: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        if self.trend_data:
            data['trend_data'] = self.trend_data.to_dict()
        return data


@dataclass
class ComprehensiveReport:
    """Comprehensive vulnerability report with all data."""

    # Metadata
    report_id: str
    generated_at: str
    report_level: str
    target: str
    target_type: str  # "docker_image", "sbom", "directory"

    # Executive summary (AI-generated)
    executive_summary: Optional[ExecutiveSummary] = None

    # Vulnerability data
    summary: VulnerabilitySummary = field(default_factory=VulnerabilitySummary)
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    packages: List[PackageVulnerabilities] = field(default_factory=list)

    # Dashboard data
    dashboard_data: Optional[DashboardData] = None

    # Additional metadata
    scan_metadata: Dict[str, Any] = field(default_factory=dict)
    remediation_recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = {
            'report_id': self.report_id,
            'generated_at': self.generated_at,
            'report_level': self.report_level,
            'target': self.target,
            'target_type': self.target_type,
            'summary': self.summary.to_dict(),
            'findings': [f.to_dict() for f in self.findings],
            'packages': [p.to_dict() for p in self.packages],
            'scan_metadata': self.scan_metadata,
            'remediation_recommendations': self.remediation_recommendations,
        }

        if self.executive_summary:
            data['executive_summary'] = self.executive_summary.to_dict()

        if self.dashboard_data:
            data['dashboard_data'] = self.dashboard_data.to_dict()

        return data

    def filter_critical_only(self) -> 'ComprehensiveReport':
        """Return a copy with only critical/high severity findings."""
        critical_findings = [
            f for f in self.findings
            if f.severity.lower() in ['critical', 'high']
        ]

        # Recalculate summary for critical only
        critical_summary = VulnerabilitySummary(
            total_vulnerabilities=len(critical_findings),
            critical=sum(1 for f in critical_findings if f.severity.lower() == 'critical'),
            high=sum(1 for f in critical_findings if f.severity.lower() == 'high'),
            vulnerabilities_with_fix=sum(1 for f in critical_findings if f.has_fix),
            vulnerabilities_without_fix=sum(1 for f in critical_findings if not f.has_fix),
        )

        # Calculate CVSS scores
        cvss_scores = [f.cvss_score for f in critical_findings if f.cvss_score]
        if cvss_scores:
            critical_summary.average_cvss_score = sum(cvss_scores) / len(cvss_scores)
            critical_summary.highest_cvss_score = max(cvss_scores)

        # Filter packages to only those with critical/high vulnerabilities
        critical_packages = []
        for pkg in self.packages:
            critical_vulns = [
                v for v in pkg.vulnerabilities
                if v.severity.lower() in ['critical', 'high']
            ]
            if critical_vulns:
                critical_pkg = PackageVulnerabilities(
                    package_name=pkg.package_name,
                    package_version=pkg.package_version,
                    package_type=pkg.package_type,
                    vulnerability_count=len(critical_vulns),
                    highest_severity=pkg.highest_severity,
                    highest_cvss_score=pkg.highest_cvss_score,
                    vulnerabilities=critical_vulns,
                    recommended_version=pkg.recommended_version,
                )
                critical_packages.append(critical_pkg)

        return ComprehensiveReport(
            report_id=f"{self.report_id}_critical",
            generated_at=self.generated_at,
            report_level=ReportLevel.CRITICAL_ONLY.value,
            target=self.target,
            target_type=self.target_type,
            executive_summary=self.executive_summary,
            summary=critical_summary,
            findings=critical_findings,
            packages=critical_packages,
            dashboard_data=self.dashboard_data,
            scan_metadata=self.scan_metadata,
            remediation_recommendations=self.remediation_recommendations,
        )

    def get_summary_view(self) -> Dict[str, Any]:
        """Get a summary view suitable for quick overview."""
        return {
            'report_id': self.report_id,
            'generated_at': self.generated_at,
            'target': self.target,
            'summary': self.summary.to_dict(),
            'top_5_critical_findings': [
                f.to_dict() for f in sorted(
                    self.findings,
                    key=lambda x: (
                        {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x.severity.lower(), 4),
                        -(x.cvss_score or 0)
                    )
                )[:5]
            ],
            'most_vulnerable_packages': [
                {
                    'package': p.package_name,
                    'version': p.package_version,
                    'vulnerability_count': p.vulnerability_count,
                    'highest_severity': p.highest_severity,
                }
                for p in sorted(self.packages, key=lambda x: x.vulnerability_count, reverse=True)[:5]
            ],
        }
