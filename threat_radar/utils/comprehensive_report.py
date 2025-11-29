"""Comprehensive vulnerability report generator with AI-powered summaries."""

import uuid
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from collections import defaultdict
from pathlib import Path

from ..core.grype_integration import GrypeScanResult, GrypeVulnerability
from ..ai.llm_client import get_llm_client
from ..ai.prompt_templates import create_risk_assessment_prompt
from .report_templates import (
    ComprehensiveReport,
    VulnerabilitySummary,
    VulnerabilityFinding,
    PackageVulnerabilities,
    ExecutiveSummary,
    DashboardData,
    TrendData,
    ReportLevel,
    AttackSurfaceData,
    AttackPathSummary,
)

logger = logging.getLogger(__name__)


class ComprehensiveReportGenerator:
    """Generate comprehensive vulnerability reports with AI-powered insights."""

    def __init__(
        self, ai_provider: Optional[str] = None, ai_model: Optional[str] = None
    ):
        """
        Initialize report generator.

        Args:
            ai_provider: AI provider for executive summaries (openai, ollama)
            ai_model: AI model name
        """
        self.ai_provider = ai_provider
        self.ai_model = ai_model

    def generate_report(
        self,
        scan_result: GrypeScanResult,
        report_level: ReportLevel = ReportLevel.DETAILED,
        include_executive_summary: bool = True,
        include_dashboard_data: bool = True,
        attack_paths_file: Optional[Path] = None,
    ) -> ComprehensiveReport:
        """
        Generate comprehensive vulnerability report.

        Args:
            scan_result: Grype scan results
            report_level: Level of detail to include
            include_executive_summary: Whether to generate AI executive summary
            include_dashboard_data: Whether to include dashboard-ready data
            attack_paths_file: Optional path to attack paths JSON file

        Returns:
            ComprehensiveReport object
        """
        logger.info(f"Generating {report_level.value} report for {scan_result.target}")

        # Create report ID
        report_id = f"vuln-report-{uuid.uuid4().hex[:8]}"

        # Build vulnerability findings
        findings = self._build_findings(scan_result)

        # Build package groupings
        packages = self._build_package_groupings(findings)

        # Build summary statistics
        summary = self._build_summary(scan_result, findings)

        # Create base report
        report = ComprehensiveReport(
            report_id=report_id,
            generated_at=datetime.now().isoformat(),
            report_level=report_level.value,
            target=scan_result.target,
            target_type=self._determine_target_type(scan_result),
            summary=summary,
            findings=findings,
            packages=packages,
            scan_metadata=scan_result.scan_metadata or {},
        )

        # Add attack path data if provided (must be loaded before executive summary)
        if attack_paths_file:
            try:
                logger.info(f"Loading attack path data from {attack_paths_file}...")
                report.attack_surface_data = self._load_attack_paths(attack_paths_file)
            except Exception as e:
                logger.warning(f"Failed to load attack paths: {e}")

        # Add executive summary if requested
        if include_executive_summary and self.ai_provider:
            try:
                logger.info("Generating AI-powered executive summary...")
                report.executive_summary = self._generate_executive_summary(report)
            except Exception as e:
                logger.warning(f"Failed to generate executive summary: {e}")

        # Add dashboard data if requested
        if include_dashboard_data:
            logger.info("Generating dashboard visualization data...")
            report.dashboard_data = self._generate_dashboard_data(report)

        # Generate remediation recommendations
        report.remediation_recommendations = self._generate_remediation_recommendations(
            packages
        )

        # Apply report level filtering if needed
        if report_level == ReportLevel.CRITICAL_ONLY:
            report = report.filter_critical_only()

        logger.info(f"Report generation complete: {report_id}")
        return report

    def _build_findings(
        self, scan_result: GrypeScanResult
    ) -> List[VulnerabilityFinding]:
        """Build vulnerability findings from scan result with deduplication."""
        findings = []
        seen_vulns = set()

        for vuln in scan_result.vulnerabilities:
            # Create unique key for deduplication based on CVE ID, package, and version
            vuln_key = (
                vuln.id,
                vuln.package_name,
                vuln.package_version,
                vuln.package_type,
            )

            # Skip if we've already seen this exact vulnerability
            if vuln_key in seen_vulns:
                logger.debug(
                    f"Skipping duplicate vulnerability: {vuln.id} in {vuln.package_name}@{vuln.package_version}"
                )
                continue

            seen_vulns.add(vuln_key)

            finding = VulnerabilityFinding(
                cve_id=vuln.id,
                severity=vuln.severity.lower(),
                cvss_score=vuln.cvss_score,
                package_name=vuln.package_name,
                package_version=vuln.package_version,
                package_type=vuln.package_type,
                fixed_in_version=vuln.fixed_in_version,
                description=vuln.description or "No description available",
                urls=vuln.urls or [],
            )
            findings.append(finding)

        if len(seen_vulns) < len(scan_result.vulnerabilities):
            duplicates_removed = len(scan_result.vulnerabilities) - len(seen_vulns)
            logger.info(f"Removed {duplicates_removed} duplicate vulnerability entries")

        return findings

    def _build_package_groupings(
        self, findings: List[VulnerabilityFinding]
    ) -> List[PackageVulnerabilities]:
        """Group vulnerabilities by package."""
        package_map = defaultdict(list)

        # Group by package
        for finding in findings:
            key = f"{finding.package_name}@{finding.package_version}"
            package_map[key].append(finding)

        # Create package objects
        packages = []
        for key, vulns in package_map.items():
            package_name, package_version = key.rsplit("@", 1)

            # Find highest severity and CVSS
            severity_order = {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "negligible": 4,
            }
            highest_severity = min(
                vulns, key=lambda v: severity_order.get(v.severity, 5)
            ).severity

            cvss_scores = [v.cvss_score for v in vulns if v.cvss_score]
            highest_cvss = max(cvss_scores) if cvss_scores else 0.0

            # Determine recommended version (if any vulnerability has a fix)
            recommended_version = None
            for vuln in vulns:
                if vuln.fixed_in_version:
                    recommended_version = vuln.fixed_in_version
                    break

            pkg = PackageVulnerabilities(
                package_name=package_name,
                package_version=package_version,
                package_type=vulns[0].package_type,
                vulnerability_count=len(vulns),
                highest_severity=highest_severity,
                highest_cvss_score=highest_cvss,
                vulnerabilities=vulns,
                recommended_version=recommended_version,
            )
            packages.append(pkg)

        # Sort by vulnerability count (descending)
        packages.sort(key=lambda p: p.vulnerability_count, reverse=True)

        return packages

    def _build_summary(
        self, scan_result: GrypeScanResult, findings: List[VulnerabilityFinding]
    ) -> VulnerabilitySummary:
        """Build summary statistics from deduplicated findings."""
        # Count severity from deduplicated findings, not from original scan result
        severity_counts = defaultdict(int)
        for finding in findings:
            severity_counts[finding.severity] += 1

        summary = VulnerabilitySummary(
            total_vulnerabilities=len(findings),  # Use deduplicated count
            critical=severity_counts.get("critical", 0),
            high=severity_counts.get("high", 0),
            medium=severity_counts.get("medium", 0),
            low=severity_counts.get("low", 0),
            negligible=severity_counts.get("negligible", 0),
            unknown=severity_counts.get("unknown", 0),
        )

        # Calculate fix availability
        summary.vulnerabilities_with_fix = sum(1 for f in findings if f.has_fix)
        summary.vulnerabilities_without_fix = (
            len(findings) - summary.vulnerabilities_with_fix
        )

        # Calculate CVSS scores
        cvss_scores = [f.cvss_score for f in findings if f.cvss_score]
        if cvss_scores:
            summary.average_cvss_score = round(sum(cvss_scores) / len(cvss_scores), 2)
            summary.highest_cvss_score = round(max(cvss_scores), 2)

        # Package metrics (we don't have total packages from Grype, estimate from unique packages)
        unique_packages = set(f"{f.package_name}@{f.package_version}" for f in findings)
        summary.vulnerable_packages = len(unique_packages)
        summary.total_packages = summary.vulnerable_packages  # Conservative estimate

        if summary.total_packages > 0:
            summary.vulnerable_packages_percentage = round(
                (summary.vulnerable_packages / summary.total_packages) * 100, 2
            )

        return summary

    def _generate_executive_summary(
        self, report: ComprehensiveReport
    ) -> ExecutiveSummary:
        """Generate AI-powered executive summary using existing prompt templates."""
        try:
            llm_client = get_llm_client(provider=self.ai_provider, model=self.ai_model)

            # Convert findings to dictionary format for prompt
            vulnerabilities = [
                {
                    "id": f.cve_id,
                    "package_name": f.package_name,
                    "package_version": f.package_version,
                    "severity": f.severity,
                    "cvss_score": f.cvss_score,
                    "fixed_in_version": f.fixed_in_version,
                    "description": f.description,
                }
                for f in report.findings
            ]

            # Use existing risk assessment prompt template
            prompt = create_risk_assessment_prompt(
                vulnerabilities=vulnerabilities,
                target=report.target,
                total_count=report.summary.total_vulnerabilities,
                severity_distribution={
                    "critical": report.summary.critical,
                    "high": report.summary.high,
                    "medium": report.summary.medium,
                    "low": report.summary.low,
                },
            )

            # Get AI response as JSON
            import json

            risk_assessment = llm_client.generate_json(prompt)

            # Extract key findings from risk assessment (deduplicated)
            key_findings = []
            seen_findings = set()
            for risk in risk_assessment.get("key_risks", []):
                finding = f"{risk.get('risk', 'Risk identified')} (Likelihood: {risk.get('likelihood', 'Unknown')}, Impact: {risk.get('impact', 'Unknown')})"
                # Deduplicate by checking if we've seen this finding before
                if finding not in seen_findings:
                    key_findings.append(finding)
                    seen_findings.add(finding)
                    if len(key_findings) >= 5:
                        break

            # Extract immediate actions from recommended actions (deduplicated)
            immediate_actions = []
            seen_actions = set()
            for action in risk_assessment.get("recommended_actions", []):
                if action.get("priority", "").upper() in ["CRITICAL", "HIGH"]:
                    action_text = action.get("action", "Action required")
                    # Deduplicate by checking if we've seen this action before
                    if action_text not in seen_actions:
                        immediate_actions.append(action_text)
                        seen_actions.add(action_text)
                        if len(immediate_actions) >= 5:
                            break

            # Determine compliance impact
            compliance_concerns = risk_assessment.get("compliance_concerns", [])
            compliance_impact = (
                f"May impact compliance with: {', '.join(compliance_concerns)}"
                if compliance_concerns
                else "Potential impact on regulatory compliance should be assessed"
            )

            # Map risk level to overall rating
            risk_level = risk_assessment.get("risk_level", "UNKNOWN").upper()

            # Estimate remediation effort based on vulnerability counts
            total_critical_high = report.summary.critical + report.summary.high
            if total_critical_high > 20:
                remediation_effort = "HIGH"
                days_to_patch = 30
            elif total_critical_high > 5:
                remediation_effort = "MEDIUM"
                days_to_patch = 14
            else:
                remediation_effort = "LOW"
                days_to_patch = 7

            # Calculate fix availability percentage
            total_vulns = report.summary.total_vulnerabilities
            fix_percentage = (
                (report.summary.vulnerabilities_with_fix / total_vulns * 100)
                if total_vulns > 0
                else 0.0
            )

            # Get internet-facing assets count from attack surface data if available
            internet_facing = 0
            if report.attack_surface_data:
                internet_facing = report.attack_surface_data.entry_points_count

            return ExecutiveSummary(
                overall_risk_rating=risk_level,
                key_findings=(
                    key_findings
                    if key_findings
                    else ["Vulnerability assessment completed"]
                ),
                immediate_actions=(
                    immediate_actions
                    if immediate_actions
                    else ["Review and prioritize critical vulnerabilities"]
                ),
                risk_summary=risk_assessment.get(
                    "risk_summary", "Risk assessment in progress"
                ),
                compliance_impact=compliance_impact,
                business_context=f"Security vulnerabilities identified across {report.summary.vulnerable_packages} packages requiring attention",
                critical_items_requiring_attention=total_critical_high,
                estimated_remediation_effort=remediation_effort,
                days_to_patch_critical=days_to_patch,
                fix_available_percentage=fix_percentage,
                internet_facing_assets=internet_facing,
            )

        except Exception as e:
            logger.error(f"Error generating executive summary: {e}")
            # Return fallback summary
            return self._generate_fallback_executive_summary(report)

    def _generate_fallback_executive_summary(
        self, report: ComprehensiveReport
    ) -> ExecutiveSummary:
        """Generate a fallback executive summary without AI."""
        # Determine risk rating based on critical/high counts
        critical_high_count = report.summary.critical + report.summary.high
        if report.summary.critical > 5:
            risk_rating = "CRITICAL"
        elif report.summary.critical > 0 or report.summary.high > 10:
            risk_rating = "HIGH"
        elif report.summary.high > 0 or report.summary.medium > 20:
            risk_rating = "MEDIUM"
        else:
            risk_rating = "LOW"

        key_findings = [
            f"Identified {report.summary.total_vulnerabilities} total vulnerabilities",
            f"Found {report.summary.critical} critical and {report.summary.high} high severity issues",
            f"{report.summary.vulnerable_packages} packages affected",
        ]

        if report.summary.vulnerabilities_without_fix > 0:
            key_findings.append(
                f"{report.summary.vulnerabilities_without_fix} vulnerabilities have no available fix"
            )

        immediate_actions = [
            "Review and prioritize critical and high severity vulnerabilities",
            "Update packages with available security fixes",
            "Implement compensating controls for vulnerabilities without fixes",
        ]

        # Calculate fix availability percentage
        total_vulns = report.summary.total_vulnerabilities
        fix_percentage = (
            (report.summary.vulnerabilities_with_fix / total_vulns * 100)
            if total_vulns > 0
            else 0.0
        )

        # Get internet-facing assets count from attack surface data if available
        internet_facing = 0
        if report.attack_surface_data:
            internet_facing = report.attack_surface_data.entry_points_count

        return ExecutiveSummary(
            overall_risk_rating=risk_rating,
            key_findings=key_findings,
            immediate_actions=immediate_actions,
            risk_summary=f"System has {critical_high_count} critical/high severity vulnerabilities requiring immediate attention.",
            compliance_impact="Security vulnerabilities may impact compliance with security frameworks (ISO 27001, SOC 2, etc.)",
            business_context="Unpatched vulnerabilities increase risk of security incidents and potential business disruption.",
            critical_items_requiring_attention=critical_high_count,
            estimated_remediation_effort="MEDIUM",
            days_to_patch_critical=14,
            fix_available_percentage=fix_percentage,
            internet_facing_assets=internet_facing,
        )

    def _generate_dashboard_data(self, report: ComprehensiveReport) -> DashboardData:
        """Generate dashboard-ready visualization data."""
        dashboard = DashboardData()

        # Summary cards
        dashboard.summary_cards = {
            "total_vulnerabilities": report.summary.total_vulnerabilities,
            "critical_vulnerabilities": report.summary.critical,
            "high_vulnerabilities": report.summary.high,
            "vulnerable_packages": report.summary.vulnerable_packages,
            "average_cvss_score": report.summary.average_cvss_score,
            "fix_available_percentage": round(
                (
                    (
                        report.summary.vulnerabilities_with_fix
                        / report.summary.total_vulnerabilities
                        * 100
                    )
                    if report.summary.total_vulnerabilities > 0
                    else 0
                ),
                2,
            ),
        }

        # Severity distribution chart (for pie/bar chart)
        dashboard.severity_distribution_chart = [
            {
                "severity": "Critical",
                "count": report.summary.critical,
                "color": "#dc2626",
            },
            {"severity": "High", "count": report.summary.high, "color": "#ea580c"},
            {"severity": "Medium", "count": report.summary.medium, "color": "#eab308"},
            {"severity": "Low", "count": report.summary.low, "color": "#3b82f6"},
            {
                "severity": "Negligible",
                "count": report.summary.negligible,
                "color": "#10b981",
            },
        ]

        # Top vulnerable packages (for horizontal bar chart)
        dashboard.top_vulnerable_packages_chart = [
            {
                "package": f"{pkg.package_name}@{pkg.package_version}",
                "vulnerability_count": pkg.vulnerability_count,
                "severity": pkg.highest_severity,
            }
            for pkg in report.packages[:10]
        ]

        # CVSS score histogram
        cvss_buckets = defaultdict(int)
        for finding in report.findings:
            if finding.cvss_score:
                bucket = int(finding.cvss_score)  # 0-9 buckets
                cvss_buckets[bucket] += 1

        dashboard.cvss_score_histogram = [
            {"score_range": f"{i}-{i+1}", "count": cvss_buckets.get(i, 0)}
            for i in range(0, 10)
        ]

        # Fix availability pie chart
        dashboard.fix_availability_pie = {
            "with_fix": report.summary.vulnerabilities_with_fix,
            "without_fix": report.summary.vulnerabilities_without_fix,
        }

        # Package type breakdown
        package_types = defaultdict(int)
        for pkg in report.packages:
            package_types[pkg.package_type] += pkg.vulnerability_count

        dashboard.package_type_breakdown = [
            {"package_type": pkg_type, "vulnerability_count": count}
            for pkg_type, count in sorted(
                package_types.items(), key=lambda x: x[1], reverse=True
            )
        ]

        # Critical items list
        critical_findings = [
            f for f in report.findings if f.severity in ["critical", "high"]
        ]
        dashboard.critical_items = [
            {
                "cve_id": f.cve_id,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "package": f"{f.package_name}@{f.package_version}",
                "has_fix": f.has_fix,
                "fixed_in": f.fixed_in_version,
            }
            for f in sorted(
                critical_findings,
                key=lambda x: (
                    0 if x.severity == "critical" else 1,
                    -(x.cvss_score or 0),
                ),
            )[:20]
        ]

        return dashboard

    def _generate_remediation_recommendations(
        self, packages: List[PackageVulnerabilities]
    ) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = []

        # Count packages with/without fixes
        packages_with_fix = sum(1 for p in packages if p.recommended_version)
        packages_without_fix = len(packages) - packages_with_fix

        if packages_with_fix > 0:
            recommendations.append(
                f"Upgrade {packages_with_fix} packages with available security patches"
            )

        if packages_without_fix > 0:
            recommendations.append(
                f"Implement compensating controls for {packages_without_fix} packages without fixes"
            )

        # Add specific recommendations for top vulnerable packages
        for pkg in packages[:3]:
            if pkg.recommended_version:
                recommendations.append(
                    f"Priority: Upgrade {pkg.package_name} from {pkg.package_version} to {pkg.recommended_version}"
                )

        recommendations.append(
            "Conduct regular vulnerability scans to track new issues"
        )
        recommendations.append("Implement automated dependency updates where possible")

        return recommendations

    def _determine_target_type(self, scan_result: GrypeScanResult) -> str:
        """Determine the type of scan target."""
        target = scan_result.target.lower()

        if any(keyword in target for keyword in ["docker", "image", ":"]):
            return "docker_image"
        elif target.endswith(".json") or target.endswith(".xml"):
            return "sbom"
        else:
            return "directory"

    def _load_attack_paths(self, attack_paths_file: Path) -> AttackSurfaceData:
        """
        Load attack path data from JSON file.

        Args:
            attack_paths_file: Path to attack paths JSON file

        Returns:
            AttackSurfaceData object with parsed attack path information
        """
        with open(attack_paths_file, "r") as f:
            data = json.load(f)

        # Parse attack paths
        attack_paths = []
        for path_data in data.get("attack_paths", []):
            # Extract steps summary
            steps_summary = []
            vulnerabilities = []
            for step in path_data.get("steps", []):
                steps_summary.append(step.get("description", ""))
                vulnerabilities.extend(step.get("vulnerabilities", []))

            attack_path = AttackPathSummary(
                path_id=path_data.get("path_id", ""),
                entry_point=path_data.get("entry_point", ""),
                target=path_data.get("target", ""),
                threat_level=path_data.get("threat_level", "medium"),
                total_cvss=path_data.get("total_cvss", 0.0),
                path_length=path_data.get("path_length", 0),
                exploitability=path_data.get("exploitability", 0.5),
                requires_privileges=path_data.get("requires_privileges", False),
                description=path_data.get("description", ""),
                vulnerabilities_exploited=list(
                    set(vulnerabilities)
                ),  # Remove duplicates
                steps_summary=steps_summary,
            )
            attack_paths.append(attack_path)

        # Create attack surface data
        attack_surface = AttackSurfaceData(
            total_attack_paths=len(attack_paths),
            critical_paths=sum(
                1 for ap in attack_paths if ap.threat_level == "critical"
            ),
            high_paths=sum(1 for ap in attack_paths if ap.threat_level == "high"),
            entry_points_count=len(data.get("entry_points", [])),
            high_value_targets_count=len(data.get("high_value_targets", [])),
            privilege_escalation_opportunities=len(
                data.get("privilege_escalations", [])
            ),
            lateral_movement_opportunities=len(data.get("lateral_movements", [])),
            total_risk_score=data.get("total_risk_score", 0.0),
            attack_paths=attack_paths,
            top_entry_points=data.get("entry_points", [])[:10],
            top_targets=data.get("high_value_targets", [])[:10],
            recommendations=data.get("recommendations", []),
        )

        return attack_surface
