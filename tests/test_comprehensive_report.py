"""Tests for comprehensive reporting functionality."""

import pytest
import json
from pathlib import Path

from threat_radar.utils.report_templates import (
    ComprehensiveReport,
    VulnerabilitySummary,
    VulnerabilityFinding,
    PackageVulnerabilities,
    ExecutiveSummary,
    DashboardData,
    ReportLevel,
)
from threat_radar.utils.comprehensive_report import ComprehensiveReportGenerator
from threat_radar.utils.report_formatters import (
    get_formatter,
    JSONFormatter,
    MarkdownFormatter,
    HTMLFormatter,
)
from threat_radar.core.grype_integration import GrypeScanResult, GrypeVulnerability


@pytest.fixture
def sample_vulnerabilities():
    """Create sample vulnerabilities for testing."""
    return [
        GrypeVulnerability(
            id="CVE-2024-0001",
            severity="critical",
            package_name="openssl",
            package_version="1.1.1",
            package_type="apk",
            fixed_in_version="1.1.1k",
            description="Critical vulnerability in OpenSSL",
            cvss_score=9.8,
            urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"],
        ),
        GrypeVulnerability(
            id="CVE-2024-0002",
            severity="high",
            package_name="nginx",
            package_version="1.20.0",
            package_type="apk",
            fixed_in_version="1.20.2",
            description="High severity vulnerability in Nginx",
            cvss_score=7.5,
            urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-0002"],
        ),
        GrypeVulnerability(
            id="CVE-2024-0003",
            severity="medium",
            package_name="curl",
            package_version="7.68.0",
            package_type="deb",
            fixed_in_version=None,
            description="Medium severity vulnerability in cURL",
            cvss_score=5.3,
            urls=[],
        ),
    ]


@pytest.fixture
def sample_scan_result(sample_vulnerabilities):
    """Create sample scan result for testing."""
    return GrypeScanResult(
        target="alpine:3.18",
        vulnerabilities=sample_vulnerabilities,
        total_count=len(sample_vulnerabilities),
        severity_counts={"critical": 1, "high": 1, "medium": 1},
        scan_metadata={"scanner": "grype", "db_version": "5"},
    )


class TestReportTemplates:
    """Test report template data structures."""

    def test_vulnerability_summary_creation(self):
        """Test VulnerabilitySummary creation."""
        summary = VulnerabilitySummary(
            total_vulnerabilities=10,
            critical=2,
            high=3,
            medium=5,
            vulnerable_packages=5,
        )

        assert summary.total_vulnerabilities == 10
        assert summary.critical == 2
        assert summary.high == 3
        assert summary.vulnerable_packages == 5

    def test_vulnerability_finding_has_fix(self):
        """Test VulnerabilityFinding.has_fix property."""
        finding_with_fix = VulnerabilityFinding(
            cve_id="CVE-2024-0001",
            severity="critical",
            cvss_score=9.8,
            package_name="test",
            package_version="1.0",
            package_type="apk",
            fixed_in_version="1.1",
            description="Test",
        )

        finding_without_fix = VulnerabilityFinding(
            cve_id="CVE-2024-0002",
            severity="high",
            cvss_score=7.5,
            package_name="test",
            package_version="1.0",
            package_type="apk",
            fixed_in_version=None,
            description="Test",
        )

        assert finding_with_fix.has_fix is True
        assert finding_without_fix.has_fix is False

    def test_comprehensive_report_to_dict(self):
        """Test ComprehensiveReport.to_dict() conversion."""
        report = ComprehensiveReport(
            report_id="test-123",
            generated_at="2024-01-01T00:00:00",
            report_level=ReportLevel.DETAILED.value,
            target="alpine:3.18",
            target_type="docker_image",
        )

        data = report.to_dict()

        assert data["report_id"] == "test-123"
        assert data["target"] == "alpine:3.18"
        assert data["report_level"] == "detailed"
        assert "summary" in data
        assert "findings" in data

    def test_filter_critical_only(self):
        """Test ComprehensiveReport.filter_critical_only()."""
        findings = [
            VulnerabilityFinding(
                cve_id="CVE-1",
                severity="critical",
                cvss_score=9.0,
                package_name="pkg1",
                package_version="1.0",
                package_type="apk",
                fixed_in_version=None,
                description="Critical",
            ),
            VulnerabilityFinding(
                cve_id="CVE-2",
                severity="high",
                cvss_score=7.0,
                package_name="pkg2",
                package_version="1.0",
                package_type="apk",
                fixed_in_version=None,
                description="High",
            ),
            VulnerabilityFinding(
                cve_id="CVE-3",
                severity="medium",
                cvss_score=5.0,
                package_name="pkg3",
                package_version="1.0",
                package_type="apk",
                fixed_in_version=None,
                description="Medium",
            ),
        ]

        report = ComprehensiveReport(
            report_id="test",
            generated_at="2024-01-01",
            report_level="detailed",
            target="test",
            target_type="docker_image",
            findings=findings,
        )

        critical_report = report.filter_critical_only()

        assert len(critical_report.findings) == 2  # Only critical and high
        assert critical_report.findings[0].severity in ["critical", "high"]
        assert critical_report.findings[1].severity in ["critical", "high"]


class TestComprehensiveReportGenerator:
    """Test comprehensive report generator."""

    def test_generate_report(self, sample_scan_result):
        """Test basic report generation."""
        generator = ComprehensiveReportGenerator()

        report = generator.generate_report(
            scan_result=sample_scan_result,
            report_level=ReportLevel.DETAILED,
            include_executive_summary=False,  # Skip AI for tests
            include_dashboard_data=True,
        )

        assert report.target == "alpine:3.18"
        assert report.summary.total_vulnerabilities == 3
        assert report.summary.critical == 1
        assert report.summary.high == 1
        assert report.summary.medium == 1
        assert len(report.findings) == 3
        assert len(report.packages) > 0

    def test_generate_critical_only_report(self, sample_scan_result):
        """Test critical-only report generation."""
        generator = ComprehensiveReportGenerator()

        report = generator.generate_report(
            scan_result=sample_scan_result,
            report_level=ReportLevel.CRITICAL_ONLY,
            include_executive_summary=False,
            include_dashboard_data=False,
        )

        # Should only have critical and high
        assert report.summary.total_vulnerabilities == 2
        assert all(f.severity in ["critical", "high"] for f in report.findings)

    def test_dashboard_data_generation(self, sample_scan_result):
        """Test dashboard data generation."""
        generator = ComprehensiveReportGenerator()

        report = generator.generate_report(
            scan_result=sample_scan_result,
            include_dashboard_data=True,
            include_executive_summary=False,
        )

        assert report.dashboard_data is not None
        assert "total_vulnerabilities" in report.dashboard_data.summary_cards

    def test_vulnerability_deduplication(self):
        """Test that duplicate vulnerabilities are removed during report generation."""
        # Create scan result with DUPLICATE vulnerabilities
        duplicate_vulns = [
            GrypeVulnerability(
                id="CVE-2024-0001",
                severity="critical",
                package_name="openssl",
                package_version="1.1.1",
                package_type="apk",
                fixed_in_version="1.1.1k",
                description="Critical vulnerability in OpenSSL",
                cvss_score=9.8,
                urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"],
            ),
            # DUPLICATE of CVE-2024-0001
            GrypeVulnerability(
                id="CVE-2024-0001",
                severity="critical",
                package_name="openssl",
                package_version="1.1.1",
                package_type="apk",
                fixed_in_version="1.1.1k",
                description="Critical vulnerability in OpenSSL",
                cvss_score=9.8,
                urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"],
            ),
            GrypeVulnerability(
                id="CVE-2024-0002",
                severity="high",
                package_name="nginx",
                package_version="1.20.0",
                package_type="apk",
                fixed_in_version="1.20.2",
                description="High severity vulnerability in Nginx",
                cvss_score=7.5,
                urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-0002"],
            ),
            # DUPLICATE of CVE-2024-0002
            GrypeVulnerability(
                id="CVE-2024-0002",
                severity="high",
                package_name="nginx",
                package_version="1.20.0",
                package_type="apk",
                fixed_in_version="1.20.2",
                description="High severity vulnerability in Nginx",
                cvss_score=7.5,
                urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-0002"],
            ),
        ]

        scan_result = GrypeScanResult(
            target="alpine:3.18",
            vulnerabilities=duplicate_vulns,
            total_count=4,  # 4 vulnerabilities (2 duplicates)
            severity_counts={"critical": 2, "high": 2},
            scan_metadata={"scanner": "grype", "db_version": "5"},
        )

        generator = ComprehensiveReportGenerator()

        report = generator.generate_report(
            scan_result=scan_result,
            include_executive_summary=False,
            include_dashboard_data=True,
        )

        # Should have only 2 unique vulnerabilities (duplicates removed)
        assert len(report.findings) == 2

        # Verify unique CVE IDs
        cve_ids = [f.cve_id for f in report.findings]
        assert len(set(cve_ids)) == 2
        assert "CVE-2024-0001" in cve_ids
        assert "CVE-2024-0002" in cve_ids

        # Verify summary reflects deduplicated counts
        assert report.summary.total_vulnerabilities == 2
        assert report.summary.critical == 1
        assert report.summary.high == 1

        # Verify dashboard data exists and is accurate
        assert report.dashboard_data is not None
        assert report.dashboard_data.summary_cards["total_vulnerabilities"] == 2
        assert len(report.dashboard_data.severity_distribution_chart) > 0
        assert len(report.dashboard_data.top_vulnerable_packages_chart) > 0

    def test_remediation_recommendations(self, sample_scan_result):
        """Test remediation recommendations generation."""
        generator = ComprehensiveReportGenerator()

        report = generator.generate_report(
            scan_result=sample_scan_result,
            include_executive_summary=False,
            include_dashboard_data=False,
        )

        assert len(report.remediation_recommendations) > 0
        # Should contain general recommendations
        assert any(
            "upgrade" in rec.lower() for rec in report.remediation_recommendations
        )


class TestReportFormatters:
    """Test report formatters."""

    def test_get_formatter(self):
        """Test formatter factory."""
        json_formatter = get_formatter("json")
        md_formatter = get_formatter("markdown")
        html_formatter = get_formatter("html")

        assert isinstance(json_formatter, JSONFormatter)
        assert isinstance(md_formatter, MarkdownFormatter)
        assert isinstance(html_formatter, HTMLFormatter)

        with pytest.raises(ValueError):
            get_formatter("invalid")

    def test_json_formatter(self, sample_scan_result):
        """Test JSON formatter output."""
        generator = ComprehensiveReportGenerator()
        report = generator.generate_report(
            scan_result=sample_scan_result,
            include_executive_summary=False,
            include_dashboard_data=False,
        )

        formatter = JSONFormatter()
        output = formatter.format(report)

        # Should be valid JSON
        data = json.loads(output)
        assert data["target"] == "alpine:3.18"
        assert data["summary"]["total_vulnerabilities"] == 3

    def test_markdown_formatter(self, sample_scan_result):
        """Test Markdown formatter output."""
        generator = ComprehensiveReportGenerator()
        report = generator.generate_report(
            scan_result=sample_scan_result,
            include_executive_summary=False,
            include_dashboard_data=False,
        )

        formatter = MarkdownFormatter()
        output = formatter.format(report)

        # Should contain Markdown headers
        assert "# Vulnerability Scan Report" in output
        assert "## Summary Statistics" in output
        assert "alpine:3.18" in output
        assert "CVE-2024-0001" in output

    def test_html_formatter(self, sample_scan_result):
        """Test HTML formatter output."""
        generator = ComprehensiveReportGenerator()
        report = generator.generate_report(
            scan_result=sample_scan_result,
            include_executive_summary=False,
            include_dashboard_data=False,
        )

        formatter = HTMLFormatter()
        output = formatter.format(report)

        # Should contain HTML tags
        assert "<!DOCTYPE html>" in output
        assert "<html" in output
        assert "alpine:3.18" in output
        assert "CVE-2024-0001" in output
        assert "<style>" in output  # Should have CSS


class TestExecutiveSummary:
    """Test executive summary functionality."""

    def test_executive_summary_creation(self):
        """Test ExecutiveSummary creation."""
        exec_sum = ExecutiveSummary(
            overall_risk_rating="HIGH",
            key_findings=["Finding 1", "Finding 2"],
            immediate_actions=["Action 1", "Action 2"],
            risk_summary="High risk environment",
            compliance_impact="May affect compliance",
            business_context="Critical systems affected",
            critical_items_requiring_attention=5,
            estimated_remediation_effort="MEDIUM",
            days_to_patch_critical=7,
        )

        assert exec_sum.overall_risk_rating == "HIGH"
        assert len(exec_sum.key_findings) == 2
        assert exec_sum.days_to_patch_critical == 7

    def test_executive_summary_deduplication(self, sample_scan_result):
        """Test that executive summary removes duplicate findings and actions."""
        from unittest.mock import Mock, patch

        # Create a mock risk assessment response with duplicates
        mock_risk_assessment = {
            "risk_level": "HIGH",
            "key_risks": [
                {
                    "risk": "Critical vulnerability in OpenSSL",
                    "likelihood": "HIGH",
                    "impact": "HIGH",
                },
                {
                    "risk": "Critical vulnerability in OpenSSL",
                    "likelihood": "HIGH",
                    "impact": "HIGH",
                },  # Duplicate
                {
                    "risk": "Remote code execution possible",
                    "likelihood": "MEDIUM",
                    "impact": "HIGH",
                },
                {
                    "risk": "Remote code execution possible",
                    "likelihood": "MEDIUM",
                    "impact": "HIGH",
                },  # Duplicate
                {"risk": "Data exposure risk", "likelihood": "LOW", "impact": "MEDIUM"},
            ],
            "recommended_actions": [
                {"action": "Update OpenSSL to latest version", "priority": "CRITICAL"},
                {
                    "action": "Update OpenSSL to latest version",
                    "priority": "CRITICAL",
                },  # Duplicate
                {"action": "Apply security patches immediately", "priority": "HIGH"},
                {
                    "action": "Apply security patches immediately",
                    "priority": "HIGH",
                },  # Duplicate
                {"action": "Review access controls", "priority": "MEDIUM"},
            ],
            "risk_summary": "Multiple critical vulnerabilities detected",
            "compliance_concerns": ["PCI-DSS", "SOC2"],
        }

        generator = ComprehensiveReportGenerator(
            ai_provider="openai", ai_model="gpt-4o"
        )

        # Mock the LLM client to return our test data
        with patch(
            "threat_radar.utils.comprehensive_report.get_llm_client"
        ) as mock_get_client:
            mock_client = Mock()
            mock_client.generate_json.return_value = mock_risk_assessment
            mock_get_client.return_value = mock_client

            # Generate report
            report = generator.generate_report(
                scan_result=sample_scan_result,
                include_executive_summary=True,
            )

            # Verify deduplication worked
            assert report.executive_summary is not None

            # Should have 3 unique key findings (duplicates removed)
            assert len(report.executive_summary.key_findings) == 3

            # Check that each finding is unique
            unique_findings = set(report.executive_summary.key_findings)
            assert len(unique_findings) == 3

            # Should have 2 unique immediate actions (duplicates removed, only CRITICAL/HIGH)
            assert len(report.executive_summary.immediate_actions) == 2

            # Check that each action is unique
            unique_actions = set(report.executive_summary.immediate_actions)
            assert len(unique_actions) == 2

            # Verify the content is correct
            assert any(
                "OpenSSL" in finding
                for finding in report.executive_summary.key_findings
            )
            assert any(
                "code execution" in finding
                for finding in report.executive_summary.key_findings
            )
            assert any(
                "Update OpenSSL" in action
                for action in report.executive_summary.immediate_actions
            )
            assert any(
                "security patches" in action
                for action in report.executive_summary.immediate_actions
            )


class TestDashboardData:
    """Test dashboard data structures."""

    def test_dashboard_data_to_dict(self):
        """Test DashboardData.to_dict() conversion."""
        dashboard = DashboardData(
            summary_cards={
                "total_vulnerabilities": 10,
                "critical_vulnerabilities": 2,
            },
            severity_distribution_chart=[
                {"severity": "Critical", "count": 2, "color": "#dc2626"},
            ],
        )

        data = dashboard.to_dict()

        assert data["summary_cards"]["total_vulnerabilities"] == 10
        assert len(data["severity_distribution_chart"]) == 1
