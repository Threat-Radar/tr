"""Comprehensive tests for Grype integration and vulnerability scanning."""

import pytest
import json
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from io import StringIO

from threat_radar.core.grype_integration import (
    GrypeClient,
    GrypeVulnerability,
    GrypeScanResult,
    GrypeSeverity,
    GrypeOutputFormat,
)


@pytest.fixture
def grype_client():
    """Create a Grype client instance."""
    return GrypeClient()


@pytest.fixture
def sample_grype_json_output():
    """Sample Grype JSON output."""
    return {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2023-0001",
                    "severity": "Critical",
                    "description": "Critical vulnerability in OpenSSL",
                    "cvss": [
                        {
                            "version": "3.1",
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "metrics": {
                                "baseScore": 9.8
                            }
                        }
                    ],
                    "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2023-0001"],
                    "dataSource": "nvd",
                    "namespace": "nvd:cpe",
                },
                "artifact": {
                    "name": "openssl",
                    "version": "1.1.1",
                    "type": "apk",
                    "locations": [
                        {
                            "path": "/lib/apk/db/installed"
                        }
                    ]
                },
                "relatedVulnerabilities": [
                    {
                        "id": "CVE-2023-0001",
                        "severity": "Critical",
                        "dataSource": "alpine:distro:alpine:3.18",
                        "namespace": "alpine:distro:alpine:3.18",
                    }
                ],
                "matchDetails": [
                    {
                        "type": "exact-direct-match",
                        "matcher": "apk-matcher",
                        "searchedBy": {
                            "distro": {
                                "type": "alpine",
                                "version": "3.18.0"
                            },
                            "package": {
                                "name": "openssl",
                                "version": "1.1.1"
                            }
                        },
                        "found": {
                            "versionConstraint": "< 1.1.1k (apk)"
                        }
                    }
                ]
            },
            {
                "vulnerability": {
                    "id": "CVE-2023-0002",
                    "severity": "High",
                    "description": "High severity vulnerability in curl",
                    "cvss": [
                        {
                            "version": "3.1",
                            "metrics": {
                                "baseScore": 7.5
                            }
                        }
                    ],
                },
                "artifact": {
                    "name": "curl",
                    "version": "7.79.0",
                    "type": "apk",
                },
                "relatedVulnerabilities": [],
                "matchDetails": [
                    {
                        "type": "exact-direct-match",
                        "found": {
                            "versionConstraint": "< 7.79.1 (apk)"
                        }
                    }
                ]
            }
        ],
        "source": {
            "type": "image",
            "target": {
                "userInput": "alpine:3.18",
                "imageID": "sha256:abc123",
                "manifestDigest": "sha256:def456",
                "tags": ["alpine:3.18"]
            }
        },
        "distro": {
            "name": "alpine",
            "version": "3.18.0",
            "idLike": ["alpine"]
        },
        "descriptor": {
            "name": "grype",
            "version": "0.70.0",
            "db": {
                "built": "2023-12-01T00:00:00Z",
                "schemaVersion": 5,
                "location": "/home/user/.cache/grype/db/5",
                "checksum": "sha256:abc123",
                "error": None
            }
        }
    }


@pytest.fixture
def sample_vulnerabilities():
    """Create sample vulnerabilities."""
    return [
        GrypeVulnerability(
            id="CVE-2023-0001",
            severity="critical",
            package_name="openssl",
            package_version="1.1.1",
            package_type="apk",
            fixed_in_version="1.1.1k",
            description="Critical vulnerability in OpenSSL",
            cvss_score=9.8,
            urls=["https://nvd.nist.gov/vuln/detail/CVE-2023-0001"],
        ),
        GrypeVulnerability(
            id="CVE-2023-0002",
            severity="high",
            package_name="curl",
            package_version="7.79.0",
            package_type="apk",
            fixed_in_version="7.79.1",
            cvss_score=7.5,
        ),
        GrypeVulnerability(
            id="CVE-2023-0003",
            severity="medium",
            package_name="busybox",
            package_version="1.35.0",
            package_type="apk",
            cvss_score=5.3,
        ),
    ]


class TestGrypeVulnerability:
    """Test GrypeVulnerability data model."""

    def test_create_vulnerability(self):
        """Test creating a vulnerability."""
        vuln = GrypeVulnerability(
            id="CVE-2023-1234",
            severity="high",
            package_name="test-package",
            package_version="1.0.0",
            package_type="npm",
            fixed_in_version="1.0.1",
            description="Test vulnerability",
            cvss_score=7.5,
        )

        assert vuln.id == "CVE-2023-1234"
        assert vuln.severity == "high"
        assert vuln.package_name == "test-package"
        assert vuln.fixed_in_version == "1.0.1"
        assert vuln.cvss_score == 7.5

    def test_vulnerability_without_fix(self):
        """Test vulnerability without a fix available."""
        vuln = GrypeVulnerability(
            id="CVE-2023-9999",
            severity="critical",
            package_name="legacy-lib",
            package_version="0.9.0",
            package_type="pypi",
            fixed_in_version=None,
        )

        assert vuln.fixed_in_version is None


class TestGrypeScanResult:
    """Test GrypeScanResult data model."""

    def test_create_scan_result(self, sample_vulnerabilities):
        """Test creating a scan result."""
        result = GrypeScanResult(
            target="alpine:3.18",
            vulnerabilities=sample_vulnerabilities,
        )

        assert result.target == "alpine:3.18"
        assert len(result.vulnerabilities) == 3
        assert result.total_count == 3

    def test_severity_counts_auto_calculation(self, sample_vulnerabilities):
        """Test that severity counts are calculated automatically."""
        result = GrypeScanResult(
            target="test:latest",
            vulnerabilities=sample_vulnerabilities,
        )

        assert result.severity_counts["critical"] == 1
        assert result.severity_counts["high"] == 1
        assert result.severity_counts["medium"] == 1

    def test_filter_by_severity_critical(self, sample_vulnerabilities):
        """Test filtering by critical severity."""
        result = GrypeScanResult(
            target="test:latest",
            vulnerabilities=sample_vulnerabilities,
        )

        filtered = result.filter_by_severity(GrypeSeverity.CRITICAL)

        assert len(filtered.vulnerabilities) == 1
        assert filtered.vulnerabilities[0].severity == "critical"

    def test_filter_by_severity_high(self, sample_vulnerabilities):
        """Test filtering by high severity (includes critical)."""
        result = GrypeScanResult(
            target="test:latest",
            vulnerabilities=sample_vulnerabilities,
        )

        filtered = result.filter_by_severity(GrypeSeverity.HIGH)

        # Should include critical + high
        assert len(filtered.vulnerabilities) == 2
        severities = [v.severity for v in filtered.vulnerabilities]
        assert "critical" in severities
        assert "high" in severities

    def test_filter_by_severity_medium(self, sample_vulnerabilities):
        """Test filtering by medium severity (includes high and critical)."""
        result = GrypeScanResult(
            target="test:latest",
            vulnerabilities=sample_vulnerabilities,
        )

        filtered = result.filter_by_severity(GrypeSeverity.MEDIUM)

        # Should include all vulnerabilities
        assert len(filtered.vulnerabilities) == 3

    def test_empty_scan_result(self):
        """Test scan result with no vulnerabilities."""
        result = GrypeScanResult(target="clean:image")

        assert result.total_count == 0
        assert len(result.vulnerabilities) == 0
        assert result.severity_counts == {}


class TestGrypeClient:
    """Test GrypeClient functionality."""

    @patch('subprocess.run')
    def test_client_initialization(self, mock_run):
        """Test client can be initialized."""
        mock_run.return_value = MagicMock(returncode=0, stdout="grype 0.70.0")

        client = GrypeClient()
        assert client is not None
        assert client.grype_path == "grype"

    @patch('subprocess.run')
    def test_custom_grype_path(self, mock_run):
        """Test client with custom Grype path."""
        mock_run.return_value = MagicMock(returncode=0, stdout="grype 0.70.0")

        client = GrypeClient(grype_path="/custom/path/to/grype")
        assert client.grype_path == "/custom/path/to/grype"

    @patch('subprocess.run')
    def test_check_grype_installed_failure(self, mock_run):
        """Test checking if Grype is not installed."""
        mock_run.side_effect = FileNotFoundError()

        with pytest.raises(RuntimeError, match="Grype not found"):
            GrypeClient()

    @patch('subprocess.run')
    def test_scan_image_success(self, mock_run, sample_grype_json_output):
        """Test scanning Docker image successfully."""
        # Mock version check
        mock_run.return_value = MagicMock(returncode=0, stdout="grype 0.70.0")
        client = GrypeClient()

        # Mock scan
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(sample_grype_json_output),
        )

        result = client.scan_docker_image("alpine:3.18")

        assert result is not None
        assert result.target == "alpine:3.18"
        assert len(result.vulnerabilities) == 2
        assert result.vulnerabilities[0].id == "CVE-2023-0001"
        assert result.vulnerabilities[0].severity == "critical"

    @patch('subprocess.run')
    def test_scan_image_with_severity_filter(self, mock_run, sample_grype_json_output):
        """Test scanning with severity filter."""
        # Mock version check
        mock_run.return_value = MagicMock(returncode=0, stdout="grype 0.70.0")
        client = GrypeClient()

        # Mock scan
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(sample_grype_json_output),
        )

        result = client.scan_docker_image("alpine:3.18", fail_on_severity=GrypeSeverity.HIGH)

        # Verify correct command was called
        call_args = mock_run.call_args[0][0]
        assert "--fail-on" in call_args
        assert "high" in call_args

    @patch('subprocess.run')
    def test_scan_image_error(self, mock_run):
        """Test scan image with error."""
        # Mock version check
        mock_run.return_value = MagicMock(returncode=0, stdout="grype 0.70.0")
        client = GrypeClient()

        # Mock failed scan
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr="Error: failed to fetch image",
        )

        with pytest.raises(RuntimeError, match="Grype scan failed"):
            client.scan_docker_image("nonexistent:image")

    @patch('subprocess.run')
    def test_scan_sbom_success(self, mock_run, sample_grype_json_output, tmp_path):
        """Test scanning SBOM file successfully."""
        # Mock version check
        mock_run.return_value = MagicMock(returncode=0, stdout="grype 0.70.0")
        client = GrypeClient()

        # Create temporary SBOM file
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps({"packages": []}))

        # Mock scan
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(sample_grype_json_output),
        )

        result = client.scan_sbom(str(sbom_file))

        assert result is not None
        assert len(result.vulnerabilities) == 2

    @patch('subprocess.run')
    def test_scan_sbom_file_not_found(self, mock_run):
        """Test scanning nonexistent SBOM file."""
        # Mock version check
        mock_run.return_value = MagicMock(returncode=0, stdout="grype 0.70.0")
        client = GrypeClient()

        with pytest.raises(ValueError, match="SBOM file not found"):
            client.scan_sbom("/nonexistent/sbom.json")

    @patch('subprocess.run')
    def test_scan_directory_success(self, mock_run, sample_grype_json_output, tmp_path):
        """Test scanning directory successfully."""
        # Mock version check
        mock_run.return_value = MagicMock(returncode=0, stdout="grype 0.70.0")
        client = GrypeClient()

        # Mock scan
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(sample_grype_json_output),
        )

        result = client.scan_directory(str(tmp_path))

        assert result is not None
        call_args = mock_run.call_args[0][0]
        assert f"dir:{tmp_path}" in call_args

    @patch('subprocess.run')
    def test_update_database_success(self, mock_run):
        """Test updating Grype vulnerability database."""
        # Mock version check
        mock_run.return_value = MagicMock(returncode=0, stdout="grype 0.70.0")
        client = GrypeClient()

        # Mock update
        mock_run.return_value = MagicMock(returncode=0)

        client.update_database()

        call_args = mock_run.call_args[0][0]
        assert "grype" in call_args
        assert "db" in call_args
        assert "update" in call_args

    @patch('subprocess.run')
    def test_update_database_failure(self, mock_run):
        """Test database update failure."""
        # Mock version check
        mock_run.return_value = MagicMock(returncode=0, stdout="grype 0.70.0")
        client = GrypeClient()

        # Mock failed update
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr="Update failed",
        )

        with pytest.raises(RuntimeError, match="Database update failed"):
            client.update_database()

    @patch('subprocess.run')
    def test_get_database_status(self, mock_run):
        """Test getting database status."""
        # Mock version check
        mock_run.return_value = MagicMock(returncode=0, stdout="grype 0.70.0")
        client = GrypeClient()

        # Mock status
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Location: /home/user/.cache/grype/db/5\nBuilt: 2023-12-01T00:00:00Z\nSchema Version: 5\n"
        )

        status = client.get_db_status()

        assert status is not None
        assert "location" in status
        assert "built" in status

    @patch('subprocess.run')
    def test_parse_grype_output_invalid_json(self, mock_run):
        """Test parsing invalid JSON output."""
        # Mock version check
        mock_run.return_value = MagicMock(returncode=0, stdout="grype 0.70.0")
        client = GrypeClient()

        # Mock invalid JSON response
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="invalid json",
        )

        with pytest.raises(RuntimeError, match="Failed to parse Grype JSON output"):
            client.scan_docker_image("test:image")


class TestGrypeSeverity:
    """Test GrypeSeverity enum."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert GrypeSeverity.NEGLIGIBLE.value == "negligible"
        assert GrypeSeverity.LOW.value == "low"
        assert GrypeSeverity.MEDIUM.value == "medium"
        assert GrypeSeverity.HIGH.value == "high"
        assert GrypeSeverity.CRITICAL.value == "critical"

    def test_severity_from_string(self):
        """Test creating severity from string."""
        assert GrypeSeverity("critical") == GrypeSeverity.CRITICAL
        assert GrypeSeverity("high") == GrypeSeverity.HIGH


class TestGrypeOutputFormat:
    """Test GrypeOutputFormat enum."""

    def test_format_values(self):
        """Test output format enum values."""
        assert GrypeOutputFormat.JSON.value == "json"
        assert GrypeOutputFormat.TABLE.value == "table"
        assert GrypeOutputFormat.CYCLONEDX.value == "cyclonedx"


class TestGrypeIntegration:
    """Integration tests for Grype functionality."""

    @patch('subprocess.run')
    def test_complete_scan_workflow(self, mock_run, sample_grype_json_output):
        """Test complete workflow: check installation, scan, parse results."""
        # Mock version check
        mock_run.return_value = MagicMock(returncode=0, stdout="grype 0.70.0")
        client = GrypeClient()

        # Mock scan
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(sample_grype_json_output),
        )

        # Scan image
        result = client.scan_docker_image("alpine:3.18", fail_on_severity=GrypeSeverity.HIGH)

        # Verify results
        assert result is not None
        assert result.target == "alpine:3.18"
        assert len(result.vulnerabilities) > 0

        # Filter by severity
        critical_only = result.filter_by_severity(GrypeSeverity.CRITICAL)
        assert len(critical_only.vulnerabilities) <= len(result.vulnerabilities)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
