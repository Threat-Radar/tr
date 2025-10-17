"""Grype integration for vulnerability scanning of containers and SBOMs."""
import json
import subprocess
import logging
from typing import Dict, List, Optional, Union
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class GrypeOutputFormat(Enum):
    """Supported Grype output formats."""
    JSON = "json"
    TABLE = "table"
    CYCLONEDX = "cyclonedx"
    SARIF = "sarif"
    TEMPLATE = "template"


class GrypeSeverity(Enum):
    """CVE severity levels."""
    NEGLIGIBLE = "negligible"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class GrypeVulnerability:
    """Represents a vulnerability found by Grype."""
    id: str  # CVE ID
    severity: str
    package_name: str
    package_version: str
    package_type: str
    fixed_in_version: Optional[str] = None
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    urls: List[str] = field(default_factory=list)
    data_source: Optional[str] = None
    namespace: Optional[str] = None

    # Additional metadata
    artifact_path: Optional[str] = None
    artifact_location: Optional[str] = None


@dataclass
class GrypeScanResult:
    """Results of a Grype vulnerability scan."""
    target: str
    vulnerabilities: List[GrypeVulnerability] = field(default_factory=list)
    total_count: int = 0
    severity_counts: Dict[str, int] = field(default_factory=dict)
    scan_metadata: Optional[Dict] = None

    def __post_init__(self):
        """Calculate severity counts if not provided."""
        if not self.severity_counts and self.vulnerabilities:
            counts = {}
            for vuln in self.vulnerabilities:
                severity = vuln.severity.lower()
                counts[severity] = counts.get(severity, 0) + 1
            self.severity_counts = counts

        if not self.total_count:
            self.total_count = len(self.vulnerabilities)

    def filter_by_severity(self, min_severity: GrypeSeverity) -> 'GrypeScanResult':
        """
        Filter vulnerabilities by minimum severity.

        Args:
            min_severity: Minimum severity to include

        Returns:
            New GrypeScanResult with filtered vulnerabilities
        """
        severity_order = {
            GrypeSeverity.NEGLIGIBLE: 0,
            GrypeSeverity.LOW: 1,
            GrypeSeverity.MEDIUM: 2,
            GrypeSeverity.HIGH: 3,
            GrypeSeverity.CRITICAL: 4
        }

        min_level = severity_order[min_severity]

        filtered_vulns = [
            v for v in self.vulnerabilities
            if severity_order.get(
                GrypeSeverity(v.severity.lower()), 0
            ) >= min_level
        ]

        return GrypeScanResult(
            target=self.target,
            vulnerabilities=filtered_vulns,
            scan_metadata=self.scan_metadata
        )


class GrypeClient:
    """Client for interacting with Grype vulnerability scanner."""

    def __init__(self, grype_path: Optional[str] = None):
        """
        Initialize Grype client.

        Args:
            grype_path: Custom path to grype binary. If None, uses PATH.
        """
        self.grype_path = grype_path or "grype"
        self._check_installation()

    def _check_installation(self) -> None:
        """Verify Grype is installed and accessible."""
        try:
            result = subprocess.run(
                [self.grype_path, "version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                raise RuntimeError(f"Grype check failed: {result.stderr}")

            # Extract version from output
            version_line = result.stdout.strip().split('\n')[0]
            logger.info(f"Grype is available: {version_line}")

        except FileNotFoundError:
            raise RuntimeError(
                f"Grype not found at {self.grype_path}. "
                "Install it from: https://github.com/anchore/grype#installation\n"
                "  macOS: brew install grype\n"
                "  Linux: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh"
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Grype version check timed out")

    def scan(
        self,
        target: str,
        output_format: GrypeOutputFormat = GrypeOutputFormat.JSON,
        scope: str = "squashed",
        fail_on_severity: Optional[GrypeSeverity] = None,
        only_fixed: bool = False,
        additional_args: Optional[List[str]] = None
    ) -> Union[Dict, str]:
        """
        Scan a target for vulnerabilities.

        Args:
            target: Docker image, SBOM file, or directory to scan
            output_format: Output format for results
            scope: Scope for Docker images (squashed, all-layers)
            fail_on_severity: Fail if vulnerabilities of this severity or higher are found
            only_fixed: Only report vulnerabilities with fixes available
            additional_args: Additional CLI arguments

        Returns:
            Parsed JSON dict for JSON format, raw string for other formats

        Raises:
            RuntimeError: If scan fails
        """
        cmd = [self.grype_path, target, "-o", output_format.value]

        # Add scope for Docker images
        if target.startswith("docker:") or ":" in target:
            cmd.extend(["--scope", scope])

        # Add severity threshold
        if fail_on_severity:
            cmd.extend(["--fail-on", fail_on_severity.value])

        # Only show vulnerabilities with fixes
        if only_fixed:
            cmd.append("--only-fixed")

        # Add any additional arguments
        if additional_args:
            cmd.extend(additional_args)

        logger.info(f"Running Grype scan: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )

            # Grype returns non-zero if vulnerabilities are found with --fail-on
            # We still want the output, so don't treat this as an error
            if result.returncode != 0 and not fail_on_severity:
                raise RuntimeError(f"Grype scan failed: {result.stderr}")

            # Parse JSON output
            if output_format == GrypeOutputFormat.JSON:
                if not result.stdout.strip():
                    # Empty output means no vulnerabilities found
                    return {"matches": [], "source": {"target": target}}
                return json.loads(result.stdout)

            # Return raw text for other formats
            return result.stdout

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Grype scan timed out after 300s for target: {target}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse Grype JSON output: {e}")

    def scan_docker_image(
        self,
        image: str,
        output_format: GrypeOutputFormat = GrypeOutputFormat.JSON,
        scope: str = "squashed",
        fail_on_severity: Optional[GrypeSeverity] = None
    ) -> GrypeScanResult:
        """
        Scan a Docker image for vulnerabilities.

        Args:
            image: Docker image name (e.g., 'alpine:3.18', 'python:3.11')
            output_format: Output format
            scope: Image scope (squashed, all-layers)
            fail_on_severity: Fail on this severity or higher

        Returns:
            GrypeScanResult object
        """
        logger.info(f"Scanning Docker image: {image}")

        # Grype auto-detects Docker images, no need to prefix with "docker:"
        raw_result = self.scan(
            image,
            output_format=output_format,
            scope=scope,
            fail_on_severity=fail_on_severity
        )

        if output_format == GrypeOutputFormat.JSON:
            return self._parse_json_result(raw_result, target=image)

        # For non-JSON formats, return raw output wrapped in result
        return GrypeScanResult(target=image, scan_metadata={"raw_output": raw_result})

    def scan_sbom(
        self,
        sbom_path: Union[str, Path],
        output_format: GrypeOutputFormat = GrypeOutputFormat.JSON,
        fail_on_severity: Optional[GrypeSeverity] = None
    ) -> GrypeScanResult:
        """
        Scan an SBOM file for vulnerabilities.

        Args:
            sbom_path: Path to SBOM file (CycloneDX, SPDX, Syft JSON)
            output_format: Output format
            fail_on_severity: Fail on this severity or higher

        Returns:
            GrypeScanResult object
        """
        sbom_path = Path(sbom_path)

        if not sbom_path.exists():
            raise ValueError(f"SBOM file not found: {sbom_path}")

        logger.info(f"Scanning SBOM: {sbom_path}")

        # Grype auto-detects SBOM format, use sbom: prefix
        target = f"sbom:{sbom_path}"

        raw_result = self.scan(
            target,
            output_format=output_format,
            fail_on_severity=fail_on_severity
        )

        if output_format == GrypeOutputFormat.JSON:
            return self._parse_json_result(raw_result, target=str(sbom_path))

        return GrypeScanResult(target=str(sbom_path), scan_metadata={"raw_output": raw_result})

    def scan_directory(
        self,
        directory: Union[str, Path],
        output_format: GrypeOutputFormat = GrypeOutputFormat.JSON,
        fail_on_severity: Optional[GrypeSeverity] = None
    ) -> GrypeScanResult:
        """
        Scan a local directory for vulnerabilities.

        Args:
            directory: Path to directory
            output_format: Output format
            fail_on_severity: Fail on this severity or higher

        Returns:
            GrypeScanResult object
        """
        directory = Path(directory)

        if not directory.exists():
            raise ValueError(f"Directory not found: {directory}")
        if not directory.is_dir():
            raise ValueError(f"Path is not a directory: {directory}")

        logger.info(f"Scanning directory: {directory}")

        # Grype scans directories with dir: prefix
        target = f"dir:{directory}"

        raw_result = self.scan(
            target,
            output_format=output_format,
            fail_on_severity=fail_on_severity
        )

        if output_format == GrypeOutputFormat.JSON:
            return self._parse_json_result(raw_result, target=str(directory))

        return GrypeScanResult(target=str(directory), scan_metadata={"raw_output": raw_result})

    def _parse_json_result(self, grype_output: Dict, target: str) -> GrypeScanResult:
        """
        Parse Grype JSON output into GrypeScanResult.

        Args:
            grype_output: Grype JSON output dictionary
            target: Original scan target

        Returns:
            GrypeScanResult object
        """
        vulnerabilities = []

        for match in grype_output.get("matches", []):
            vulnerability = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            related_vulns = match.get("relatedVulnerabilities", [])

            # Extract CVSS score from related vulnerabilities or main vulnerability
            cvss_score = None
            for related in related_vulns:
                if "cvss" in related:
                    cvss_list = related.get("cvss", [])
                    if cvss_list:
                        # Get highest CVSS score
                        scores = [c.get("metrics", {}).get("baseScore") for c in cvss_list if c.get("metrics", {}).get("baseScore")]
                        if scores:
                            cvss_score = max(scores)
                            break

            # If no CVSS in related, try main vulnerability
            if cvss_score is None and "cvss" in vulnerability:
                cvss_list = vulnerability.get("cvss", [])
                if cvss_list:
                    scores = [c.get("metrics", {}).get("baseScore") for c in cvss_list if c.get("metrics", {}).get("baseScore")]
                    if scores:
                        cvss_score = max(scores)

            vuln = GrypeVulnerability(
                id=vulnerability.get("id", ""),
                severity=vulnerability.get("severity", "unknown").lower(),
                package_name=artifact.get("name", ""),
                package_version=artifact.get("version", ""),
                package_type=artifact.get("type", ""),
                fixed_in_version=vulnerability.get("fix", {}).get("versions", [None])[0] if vulnerability.get("fix", {}).get("versions") else None,
                description=vulnerability.get("description"),
                cvss_score=cvss_score,
                urls=vulnerability.get("urls", []),
                data_source=vulnerability.get("dataSource"),
                namespace=vulnerability.get("namespace"),
                artifact_path=artifact.get("locations", [{}])[0].get("path") if artifact.get("locations") else None,
                artifact_location=artifact.get("locations", [{}])[0].get("layerID") if artifact.get("locations") else None
            )
            vulnerabilities.append(vuln)

        # Extract metadata
        source = grype_output.get("source", {})
        descriptor = grype_output.get("descriptor", {})

        scan_metadata = {
            "source": source,
            "descriptor": descriptor,
            "grype_version": descriptor.get("version"),
            "grype_db": descriptor.get("db", {}).get("built"),
        }

        result = GrypeScanResult(
            target=target,
            vulnerabilities=vulnerabilities,
            scan_metadata=scan_metadata
        )

        logger.info(
            f"Parsed {result.total_count} vulnerabilities from Grype output "
            f"(Severity counts: {result.severity_counts})"
        )

        return result

    def update_database(self) -> None:
        """
        Update Grype vulnerability database.

        This downloads the latest vulnerability data.
        """
        logger.info("Updating Grype vulnerability database...")

        try:
            result = subprocess.run(
                [self.grype_path, "db", "update"],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode != 0:
                raise RuntimeError(f"Database update failed: {result.stderr}")

            logger.info("Grype database updated successfully")

        except subprocess.TimeoutExpired:
            raise RuntimeError("Database update timed out")

    def get_db_status(self) -> Dict:
        """
        Get Grype database status.

        Returns:
            Dictionary with database metadata
        """
        try:
            result = subprocess.run(
                [self.grype_path, "db", "status"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                raise RuntimeError(f"Failed to get DB status: {result.stderr}")

            # Parse the status output (it's typically key-value pairs)
            status = {}
            for line in result.stdout.strip().split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    status[key.strip().lower().replace(' ', '_')] = value.strip()

            return status

        except subprocess.TimeoutExpired:
            raise RuntimeError("DB status check timed out")
