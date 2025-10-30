"""AI-powered remediation plan generation"""

from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Callable
import json
import logging

from threat_radar.ai.llm_client import LLMClient, get_llm_client
from threat_radar.ai.prompt_templates import create_remediation_prompt
from threat_radar.core.grype_integration import GrypeScanResult, GrypeVulnerability

logger = logging.getLogger(__name__)


@dataclass
class RemediationPlan:
    """Remediation plan for a single vulnerability"""

    cve_id: str
    package_name: str
    current_version: str
    fixed_version: Optional[str]
    immediate_actions: List[str]
    upgrade_command: Optional[str]
    workarounds: List[str]
    testing_steps: List[str]
    references: List[str]
    estimated_effort: str  # LOW, MEDIUM, HIGH


@dataclass
class PackageRemediationGroup:
    """Grouped remediation for a package with multiple vulnerabilities"""

    vulnerabilities_count: int
    recommended_version: Optional[str]
    upgrade_fixes_all: bool


@dataclass
class RemediationReport:
    """Complete remediation report"""

    remediations: List[RemediationPlan]
    grouped_by_package: Dict[str, PackageRemediationGroup]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "remediations": [asdict(r) for r in self.remediations],
            "grouped_by_package": {
                pkg: asdict(group) for pkg, group in self.grouped_by_package.items()
            },
            "metadata": self.metadata,
        }


class RemediationGenerator:
    """Generates actionable remediation plans using AI"""

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        batch_size: int = 25,
        auto_batch_threshold: int = 30,
    ):
        """
        Initialize remediation generator.

        Args:
            llm_client: Pre-configured LLM client (optional)
            provider: AI provider if not using pre-configured client
            model: Model name if not using pre-configured client
            batch_size: Number of vulnerabilities per batch (default: 25)
            auto_batch_threshold: Trigger batching when count exceeds this (default: 30)
        """
        self.llm_client = llm_client or get_llm_client(provider=provider, model=model)
        self.batch_size = batch_size
        self.auto_batch_threshold = auto_batch_threshold

    def generate_remediation_plan(
        self,
        scan_result: GrypeScanResult,
        temperature: float = 0.3,
        batch_mode: Optional[str] = "auto",
        progress_callback: Optional[Callable[[int, int, int], None]] = None,
    ) -> RemediationReport:
        """
        Generate remediation plan for scan results with smart batching.

        Args:
            scan_result: GrypeScanResult from Grype scan
            temperature: LLM temperature for generation
            batch_mode: Batching mode - "auto", "enabled", or "disabled"
            progress_callback: Optional callback(batch_num, total_batches, processed_count)

        Returns:
            RemediationReport with actionable steps
        """
        vuln_count = len(scan_result.vulnerabilities)

        # Determine whether to use batch processing
        use_batching = False
        if batch_mode == "enabled":
            use_batching = True
        elif batch_mode == "auto" and vuln_count > self.auto_batch_threshold:
            use_batching = True
            logger.info(
                f"Large scan detected ({vuln_count} CVEs > {self.auto_batch_threshold} threshold). "
                f"Using batch processing..."
            )
        elif batch_mode == "disabled":
            use_batching = False

        # Route to appropriate generation method
        if use_batching:
            return self._generate_with_batches(
                scan_result, temperature, progress_callback
            )
        else:
            return self._generate_standard(scan_result, temperature)

    def _generate_standard(
        self, scan_result: GrypeScanResult, temperature: float = 0.3
    ) -> RemediationReport:
        """
        Standard single-pass remediation generation.

        Args:
            scan_result: GrypeScanResult from Grype scan
            temperature: LLM temperature for generation

        Returns:
            RemediationReport with actionable steps
        """
        # Convert Grype vulnerabilities to dict format
        vulnerabilities_data = [self._vuln_to_dict(v) for v in scan_result.vulnerabilities]

        # Generate remediation using AI
        prompt = create_remediation_prompt(vulnerabilities_data)

        try:
            response = self.llm_client.generate_json(prompt, temperature=temperature)

            # Parse remediations
            remediations = [
                RemediationPlan(**rem_data) for rem_data in response.get("remediations", [])
            ]

            # Parse grouped packages
            grouped_raw = response.get("grouped_by_package", {})
            grouped_by_package = {
                pkg: PackageRemediationGroup(**group_data)
                for pkg, group_data in grouped_raw.items()
            }

            # Build metadata
            metadata = {
                "target": scan_result.target,
                "total_vulnerabilities": scan_result.total_count,
                "total_remediations": len(remediations),
                "packages_affected": len(grouped_by_package),
            }

            return RemediationReport(
                remediations=remediations,
                grouped_by_package=grouped_by_package,
                metadata=metadata,
            )

        except Exception as e:
            raise RuntimeError(f"Failed to generate remediation plan: {str(e)}")

    def _generate_with_batches(
        self,
        scan_result: GrypeScanResult,
        temperature: float = 0.3,
        progress_callback: Optional[Callable[[int, int, int], None]] = None,
    ) -> RemediationReport:
        """
        Generate remediation plans in batches for large scans.

        Args:
            scan_result: GrypeScanResult from Grype scan
            temperature: LLM temperature for generation
            progress_callback: Optional callback(batch_num, total_batches, processed_count)

        Returns:
            RemediationReport with consolidated results
        """
        all_remediations = []
        all_grouped_packages = {}
        total_vulns = len(scan_result.vulnerabilities)
        total_batches = (total_vulns + self.batch_size - 1) // self.batch_size

        logger.info(f"Processing {total_vulns} vulnerabilities in {total_batches} batches of {self.batch_size}")

        # Process each batch
        for batch_idx in range(total_batches):
            start_idx = batch_idx * self.batch_size
            end_idx = min(start_idx + self.batch_size, total_vulns)
            batch = scan_result.vulnerabilities[start_idx:end_idx]
            batch_num = batch_idx + 1

            logger.debug(f"Processing batch {batch_num}/{total_batches} ({len(batch)} vulnerabilities)")

            # Convert to dict format
            batch_data = [self._vuln_to_dict(v) for v in batch]

            # Create prompt for this batch
            prompt = create_remediation_prompt(batch_data)

            try:
                response = self.llm_client.generate_json(prompt, temperature=temperature)

                # Parse batch remediations
                batch_remediations = [
                    RemediationPlan(**rem_data)
                    for rem_data in response.get("remediations", [])
                ]
                all_remediations.extend(batch_remediations)

                # Merge grouped packages
                batch_grouped = response.get("grouped_by_package", {})
                for pkg, group_data in batch_grouped.items():
                    if pkg in all_grouped_packages:
                        # Merge existing package data
                        existing = all_grouped_packages[pkg]
                        existing.vulnerabilities_count += group_data.get("vulnerabilities_count", 0)
                        # Use the higher version if available
                        if group_data.get("recommended_version"):
                            existing.recommended_version = group_data["recommended_version"]
                    else:
                        all_grouped_packages[pkg] = PackageRemediationGroup(**group_data)

                logger.debug(f"Batch {batch_num} complete: {len(batch_remediations)} remediation plans generated")

                # Call progress callback if provided
                if progress_callback:
                    progress_callback(batch_num, total_batches, len(all_remediations))

            except Exception as e:
                logger.warning(f"Batch {batch_num} failed: {str(e)}. Continuing with remaining batches...")
                continue

        # Build metadata with batch information
        metadata = {
            "target": scan_result.target,
            "total_vulnerabilities": total_vulns,
            "total_remediations": len(all_remediations),
            "packages_affected": len(all_grouped_packages),
            "batch_processing": True,
            "batches_processed": total_batches,
            "batch_size": self.batch_size,
        }

        return RemediationReport(
            remediations=all_remediations,
            grouped_by_package=all_grouped_packages,
            metadata=metadata,
        )

    def generate_for_vulnerabilities(
        self, vulnerabilities: List[GrypeVulnerability], temperature: float = 0.3
    ) -> RemediationReport:
        """
        Generate remediation plan for specific vulnerabilities.

        Args:
            vulnerabilities: List of GrypeVulnerability objects
            temperature: LLM temperature for generation

        Returns:
            RemediationReport with actionable steps
        """
        vulnerabilities_data = [self._vuln_to_dict(v) for v in vulnerabilities]

        prompt = create_remediation_prompt(vulnerabilities_data)

        try:
            response = self.llm_client.generate_json(prompt, temperature=temperature)

            remediations = [
                RemediationPlan(**rem_data) for rem_data in response.get("remediations", [])
            ]

            grouped_raw = response.get("grouped_by_package", {})
            grouped_by_package = {
                pkg: PackageRemediationGroup(**group_data)
                for pkg, group_data in grouped_raw.items()
            }

            metadata = {
                "total_vulnerabilities": len(vulnerabilities),
                "total_remediations": len(remediations),
                "packages_affected": len(grouped_by_package),
            }

            return RemediationReport(
                remediations=remediations,
                grouped_by_package=grouped_by_package,
                metadata=metadata,
            )

        except Exception as e:
            raise RuntimeError(f"Failed to generate remediation plan: {str(e)}")

    def _vuln_to_dict(self, vuln: GrypeVulnerability) -> Dict[str, Any]:
        """Convert GrypeVulnerability to dictionary"""
        return {
            "id": vuln.id,
            "severity": vuln.severity,
            "package_name": vuln.package_name,
            "package_version": vuln.package_version,
            "package_type": vuln.package_type,
            "fixed_in_version": vuln.fixed_in_version,
            "description": vuln.description,
            "cvss_score": vuln.cvss_score,
            "urls": vuln.urls,
        }

    def get_quick_fixes(self, report: RemediationReport) -> List[RemediationPlan]:
        """
        Get quick-fix remediations (low effort).

        Args:
            report: RemediationReport result

        Returns:
            List of low-effort remediation plans
        """
        return [r for r in report.remediations if r.estimated_effort == "LOW"]

    def get_package_upgrade_commands(self, report: RemediationReport) -> Dict[str, str]:
        """
        Get package upgrade commands grouped by package manager.

        Args:
            report: RemediationReport result

        Returns:
            Dictionary of package manager to upgrade commands
        """
        commands = {}

        for remediation in report.remediations:
            if remediation.upgrade_command:
                # Group by package manager (detect from command)
                if "pip install" in remediation.upgrade_command:
                    key = "pip"
                elif "npm install" in remediation.upgrade_command:
                    key = "npm"
                elif "apt" in remediation.upgrade_command:
                    key = "apt"
                elif "apk" in remediation.upgrade_command:
                    key = "apk"
                else:
                    key = "other"

                if key not in commands:
                    commands[key] = []
                commands[key].append(remediation.upgrade_command)

        return commands

    def get_packages_needing_upgrade(self, report: RemediationReport) -> List[str]:
        """
        Get list of packages that need upgrading.

        Args:
            report: RemediationReport result

        Returns:
            List of package names that should be upgraded
        """
        packages = set()

        for pkg, group in report.grouped_by_package.items():
            if group.recommended_version:
                packages.add(pkg)

        return sorted(list(packages))
