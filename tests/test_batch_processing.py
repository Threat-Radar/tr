"""Tests for batch processing functionality."""
import pytest
from unittest.mock import Mock, MagicMock, call

from threat_radar.ai.vulnerability_analyzer import VulnerabilityAnalyzer, VulnerabilityAnalysis
from threat_radar.ai.llm_client import LLMClient
from threat_radar.ai.prompt_templates import (
    format_vulnerability_data,
    create_batch_analysis_prompt,
    create_summary_consolidation_prompt,
)
from threat_radar.core.grype_integration import GrypeScanResult, GrypeVulnerability


def create_test_vulnerability(cve_id: str, severity: str = "high") -> GrypeVulnerability:
    """Helper to create test vulnerability."""
    return GrypeVulnerability(
        id=cve_id,
        severity=severity,
        package_name="test-package",
        package_version="1.0.0",
        package_type="deb",
        fixed_in_version="1.0.1",
        description=f"Test vulnerability {cve_id}",
        cvss_score=7.5,
        urls=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
        data_source="NVD",
    )


def create_scan_with_vulns(count: int) -> GrypeScanResult:
    """Helper to create scan result with N vulnerabilities."""
    vulns = [create_test_vulnerability(f"CVE-2024-{1000+i}") for i in range(count)]

    severity_counts = {}
    for v in vulns:
        severity = v.severity.lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    return GrypeScanResult(
        target="test:latest",
        vulnerabilities=vulns,
        total_count=count,
        severity_counts=severity_counts,
        scan_metadata={"grype_version": "0.74.0"},
    )


class TestBatchProcessing:
    """Test batch processing functionality."""

    def test_small_scan_no_batching(self):
        """Verify small scans use standard single-pass analysis."""
        # Create mock client
        mock_client = Mock(spec=LLMClient)
        mock_client.generate_json.return_value = {
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2024-1000",
                    "package_name": "test-package",
                    "exploitability": "HIGH",
                    "exploitability_details": "Test",
                    "attack_vectors": ["RCE"],
                    "business_impact": "HIGH",
                    "business_impact_details": "Test",
                    "recommendations": ["Upgrade"],
                }
            ],
            "summary": "Test summary",
        }

        # Create analyzer
        analyzer = VulnerabilityAnalyzer(llm_client=mock_client, batch_size=25, auto_batch_threshold=30)

        # Create small scan (20 vulns < 30 threshold)
        scan_result = create_scan_with_vulns(20)

        # Analyze with auto mode
        analysis = analyzer.analyze_scan_result(scan_result, batch_mode="auto")

        # Should use single-pass (not batched)
        assert analysis.metadata.get("batch_processing") is None
        assert len(analysis.vulnerabilities) > 0
        mock_client.generate_json.assert_called_once()  # Single API call

    def test_large_scan_auto_batching(self):
        """Verify large scans automatically use batch processing."""
        # Create mock client
        mock_client = Mock(spec=LLMClient)
        mock_client.generate_json.return_value = {
            "vulnerabilities": [
                {
                    "cve_id": f"CVE-2024-{i}",
                    "package_name": "test-package",
                    "exploitability": "HIGH",
                    "exploitability_details": "Test",
                    "attack_vectors": ["RCE"],
                    "business_impact": "HIGH",
                    "business_impact_details": "Test",
                    "recommendations": ["Upgrade"],
                }
                for i in range(25)  # Return 25 per batch
            ],
            "summary": "Batch summary",
        }
        mock_client.generate.return_value = "Consolidated summary"

        # Create analyzer
        analyzer = VulnerabilityAnalyzer(llm_client=mock_client, batch_size=25, auto_batch_threshold=30)

        # Create large scan (100 vulns > 30 threshold)
        scan_result = create_scan_with_vulns(100)

        # Analyze with auto mode
        analysis = analyzer.analyze_scan_result(scan_result, batch_mode="auto")

        # Should use batch processing
        assert analysis.metadata.get("batch_processing") is True
        assert analysis.metadata.get("batches_processed") == 4  # 100 / 25 = 4 batches
        assert analysis.metadata.get("batch_size") == 25

        # Should make 4 generate_json calls (batches) + 1 generate call (consolidation)
        assert mock_client.generate_json.call_count == 4
        assert mock_client.generate.call_count == 1

    def test_force_batch_mode(self):
        """Test forcing batch mode even for small scans."""
        mock_client = Mock(spec=LLMClient)
        mock_client.generate_json.return_value = {
            "vulnerabilities": [],
            "summary": "Batch summary",
        }
        mock_client.generate.return_value = "Consolidated summary"

        analyzer = VulnerabilityAnalyzer(llm_client=mock_client, batch_size=10)

        # Small scan but force batching
        scan_result = create_scan_with_vulns(15)

        analysis = analyzer.analyze_scan_result(scan_result, batch_mode="enabled")

        # Should use batching even though scan is small
        assert analysis.metadata.get("batch_processing") is True
        assert analysis.metadata.get("batches_processed") == 2  # 15 / 10 = 2 batches

    def test_disable_batch_mode(self):
        """Test disabling batch mode for large scans."""
        mock_client = Mock(spec=LLMClient)
        mock_client.generate_json.return_value = {
            "vulnerabilities": [],
            "summary": "Standard summary",
        }

        analyzer = VulnerabilityAnalyzer(llm_client=mock_client)

        # Large scan but disable batching
        scan_result = create_scan_with_vulns(100)

        analysis = analyzer.analyze_scan_result(scan_result, batch_mode="disabled")

        # Should NOT use batching
        assert analysis.metadata.get("batch_processing") is None
        mock_client.generate_json.assert_called_once()  # Single call

    def test_custom_batch_size(self):
        """Test custom batch sizes."""
        mock_client = Mock(spec=LLMClient)
        mock_client.generate_json.return_value = {
            "vulnerabilities": [],
            "summary": "Batch summary",
        }
        mock_client.generate.return_value = "Consolidated summary"

        # Custom batch size of 20
        analyzer = VulnerabilityAnalyzer(llm_client=mock_client, batch_size=20)

        scan_result = create_scan_with_vulns(60)

        analysis = analyzer.analyze_scan_result(scan_result, batch_mode="enabled")

        # Should create 3 batches (60 / 20)
        assert analysis.metadata.get("batches_processed") == 3
        assert mock_client.generate_json.call_count == 3

    def test_progress_callback(self):
        """Test progress callback is called correctly."""
        mock_client = Mock(spec=LLMClient)
        mock_client.generate_json.return_value = {
            "vulnerabilities": [],
            "summary": "Batch summary",
        }
        mock_client.generate.return_value = "Consolidated summary"

        analyzer = VulnerabilityAnalyzer(llm_client=mock_client, batch_size=25)

        scan_result = create_scan_with_vulns(50)

        # Mock progress callback
        progress_callback = Mock()

        analysis = analyzer.analyze_scan_result(
            scan_result, batch_mode="enabled", progress_callback=progress_callback
        )

        # Should call progress callback 2 times (one per batch)
        assert progress_callback.call_count == 2
        progress_callback.assert_any_call(1, 2, 0)  # batch 1
        progress_callback.assert_any_call(2, 2, 0)  # batch 2

    def test_batch_failure_recovery(self):
        """Test that batch failures don't stop entire analysis."""
        mock_client = Mock(spec=LLMClient)

        # First batch succeeds, second fails, third succeeds
        mock_client.generate_json.side_effect = [
            {"vulnerabilities": [], "summary": "Batch 1"},
            RuntimeError("API error"),
            {"vulnerabilities": [], "summary": "Batch 3"},
        ]
        mock_client.generate.return_value = "Consolidated summary"

        analyzer = VulnerabilityAnalyzer(llm_client=mock_client, batch_size=10)

        scan_result = create_scan_with_vulns(30)

        # Should not raise error despite batch 2 failure
        analysis = analyzer.analyze_scan_result(scan_result, batch_mode="enabled")

        # Should have processed 3 batches (with 1 failure)
        assert analysis.metadata.get("batches_processed") == 3
        assert mock_client.generate_json.call_count == 3


class TestPromptTemplates:
    """Test batch-specific prompt templates."""

    def test_format_vulnerability_data_no_limit(self):
        """Test formatting with no limit."""
        vulns = [
            {
                "id": f"CVE-2024-{i}",
                "package_name": "test-pkg",
                "package_version": "1.0.0",
                "severity": "high",
                "cvss_score": 7.5,
                "fixed_in_version": "1.0.1",
                "description": "Test",
            }
            for i in range(50)
        ]

        # No limit - should include all
        formatted = format_vulnerability_data(vulns, limit=None)

        # Should contain all 50 CVEs
        for i in range(50):
            assert f"CVE-2024-{i}" in formatted

        # Should NOT have truncation message
        assert "... and" not in formatted

    def test_format_vulnerability_data_with_limit(self):
        """Test formatting with limit."""
        vulns = [{"id": f"CVE-2024-{i}", "package_name": "test", "severity": "high"} for i in range(50)]

        # Limit to 10
        formatted = format_vulnerability_data(vulns, limit=10)

        # Should contain first 10
        for i in range(10):
            assert f"CVE-2024-{i}" in formatted

        # Should NOT contain beyond 10
        assert "CVE-2024-11" not in formatted

        # Should have truncation message
        assert "... and 40 more vulnerabilities" in formatted

    def test_create_batch_analysis_prompt(self):
        """Test batch analysis prompt generation."""
        vulns = [{"id": "CVE-2024-1000", "package_name": "test", "severity": "high"}]

        prompt = create_batch_analysis_prompt(vulns, batch_number=2, total_batches=5)

        # Should contain batch context
        assert "batch 2 of 5" in prompt.lower()
        assert "CVE-2024-1000" in prompt

    def test_create_summary_consolidation_prompt(self):
        """Test summary consolidation prompt."""
        prompt = create_summary_consolidation_prompt(
            target="alpine:3.18",
            total_vulnerabilities=100,
            severity_counts={"critical": 5, "high": 20, "medium": 75},
            batch_summaries=["Batch 1 summary", "Batch 2 summary"],
            high_priority_count=15,
        )

        assert "alpine:3.18" in prompt
        assert "100" in prompt
        assert "15" in prompt  # high priority count
        assert "Batch 1 summary" in prompt
        assert "Batch 2 summary" in prompt


class TestSeverityFiltering:
    """Test severity filtering functionality."""

    def test_filter_by_high_severity(self):
        """Test filtering to high severity and above."""
        mock_client = Mock(spec=LLMClient)
        analyzer = VulnerabilityAnalyzer(llm_client=mock_client)

        # Create scan with mixed severities
        vulns = [
            create_test_vulnerability("CVE-2024-1", "critical"),
            create_test_vulnerability("CVE-2024-2", "critical"),
            create_test_vulnerability("CVE-2024-3", "high"),
            create_test_vulnerability("CVE-2024-4", "high"),
            create_test_vulnerability("CVE-2024-5", "high"),
            create_test_vulnerability("CVE-2024-6", "medium"),
            create_test_vulnerability("CVE-2024-7", "medium"),
            create_test_vulnerability("CVE-2024-8", "low"),
        ]

        scan = GrypeScanResult(
            target="test:latest",
            vulnerabilities=vulns,
            total_count=8,
            severity_counts={"critical": 2, "high": 3, "medium": 2, "low": 1},
            scan_metadata={},
        )

        # Filter to high and above
        filtered = analyzer.filter_by_severity(scan, "high")

        # Should have critical (2) + high (3) = 5
        assert filtered.total_count == 5
        assert filtered.severity_counts["critical"] == 2
        assert filtered.severity_counts["high"] == 3
        assert "medium" not in filtered.severity_counts
        assert "low" not in filtered.severity_counts

    def test_filter_by_critical_only(self):
        """Test filtering to critical only."""
        mock_client = Mock(spec=LLMClient)
        analyzer = VulnerabilityAnalyzer(llm_client=mock_client)

        vulns = [
            create_test_vulnerability("CVE-2024-1", "critical"),
            create_test_vulnerability("CVE-2024-2", "critical"),
            create_test_vulnerability("CVE-2024-3", "high"),
            create_test_vulnerability("CVE-2024-4", "medium"),
        ]

        scan = create_scan_with_vulns(0)  # Empty scan
        scan.vulnerabilities = vulns
        scan.total_count = 4

        filtered = analyzer.filter_by_severity(scan, "critical")

        assert filtered.total_count == 2
        assert filtered.severity_counts["critical"] == 2

    def test_filter_by_medium_severity(self):
        """Test filtering to medium and above."""
        mock_client = Mock(spec=LLMClient)
        analyzer = VulnerabilityAnalyzer(llm_client=mock_client)

        vulns = [
            create_test_vulnerability("CVE-2024-1", "critical"),
            create_test_vulnerability("CVE-2024-2", "high"),
            create_test_vulnerability("CVE-2024-3", "medium"),
            create_test_vulnerability("CVE-2024-4", "medium"),
            create_test_vulnerability("CVE-2024-5", "low"),
            create_test_vulnerability("CVE-2024-6", "low"),
        ]

        scan = create_scan_with_vulns(0)
        scan.vulnerabilities = vulns
        scan.total_count = 6

        filtered = analyzer.filter_by_severity(scan, "medium")

        # Should have critical (1) + high (1) + medium (2) = 4
        assert filtered.total_count == 4

    def test_filter_invalid_severity(self):
        """Test that invalid severity raises error."""
        mock_client = Mock(spec=LLMClient)
        analyzer = VulnerabilityAnalyzer(llm_client=mock_client)

        scan = create_scan_with_vulns(10)

        with pytest.raises(ValueError, match="Invalid severity"):
            analyzer.filter_by_severity(scan, "invalid")

    def test_filter_preserves_metadata(self):
        """Test that filtering preserves original scan metadata."""
        mock_client = Mock(spec=LLMClient)
        analyzer = VulnerabilityAnalyzer(llm_client=mock_client)

        scan = create_scan_with_vulns(10)
        original_count = scan.total_count

        filtered = analyzer.filter_by_severity(scan, "high")

        # Should preserve metadata and add filter info
        assert filtered.scan_metadata["severity_filter"] == "high"
        assert filtered.scan_metadata["original_count"] == original_count
        assert filtered.target == scan.target

    def test_filter_all_filtered_out(self):
        """Test when all vulnerabilities are filtered out."""
        mock_client = Mock(spec=LLMClient)
        analyzer = VulnerabilityAnalyzer(llm_client=mock_client)

        # Only low severity vulns
        vulns = [
            create_test_vulnerability("CVE-2024-1", "low"),
            create_test_vulnerability("CVE-2024-2", "low"),
        ]

        scan = create_scan_with_vulns(0)
        scan.vulnerabilities = vulns
        scan.total_count = 2

        # Filter to critical - should get 0
        filtered = analyzer.filter_by_severity(scan, "critical")

        assert filtered.total_count == 0
        assert len(filtered.vulnerabilities) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
