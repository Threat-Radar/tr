"""Report generation utilities for vulnerability scans."""
import json
import os
from typing import Dict, List, Optional
from datetime import datetime
from dataclasses import asdict

from threat_radar.core.container_analyzer import ContainerAnalysis
from threat_radar.core.cve_matcher import CVEMatch


class VulnerabilityReportGenerator:
    """Generate vulnerability scan reports in various formats."""

    @staticmethod
    def generate_json_report(
        image: str,
        analysis: ContainerAnalysis,
        matches: Dict[str, List[CVEMatch]],
        statistics: Dict,
        additional_metadata: Optional[Dict] = None
    ) -> Dict:
        """
        Generate a JSON vulnerability report.

        Args:
            image: Docker image name
            analysis: Container analysis results
            matches: Dictionary of CVE matches
            statistics: Scan statistics
            additional_metadata: Optional additional metadata to include

        Returns:
            Dictionary containing the complete report
        """
        report = {
            "scan_timestamp": datetime.now().isoformat(),
            "image": image,
            "distribution": f"{analysis.distro} {analysis.distro_version}",
            "architecture": analysis.architecture,
            "total_packages": len(analysis.packages),
            "vulnerable_packages": statistics["vulnerable_packages"],
            "total_vulnerabilities": statistics["total_vulnerabilities"],
            "severity_breakdown": statistics["severity_breakdown"],
            "findings": []
        }

        # Add optional metadata
        if additional_metadata:
            report.update(additional_metadata)

        # Add detailed findings
        for pkg_name, pkg_matches in matches.items():
            # Find package version
            pkg_version = None
            for pkg in analysis.packages:
                if pkg.name == pkg_name:
                    pkg_version = pkg.version
                    break

            for match in pkg_matches:
                report["findings"].append({
                    "package": pkg_name,
                    "package_version": pkg_version,
                    "cve_id": match.cve.cve_id,
                    "severity": match.cve.severity,
                    "cvss_score": match.cve.cvss_score,
                    "confidence": round(match.confidence, 2),
                    "version_match": match.version_match,
                    "match_reason": match.match_reason,
                    "description": match.cve.description,
                    "published_date": match.cve.published_date,
                })

        return report

    @staticmethod
    def save_report(
        report: Dict,
        output_path: str,
        indent: int = 2
    ) -> str:
        """
        Save report to JSON file.

        Args:
            report: Report dictionary
            output_path: Path to save the report
            indent: JSON indentation level

        Returns:
            Path to the saved report file
        """
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=indent)

        return output_path

    @staticmethod
    def print_summary(
        image: str,
        analysis: ContainerAnalysis,
        statistics: Dict,
        show_severity_breakdown: bool = True
    ):
        """
        Print a summary of scan results to console.

        Args:
            image: Docker image name
            analysis: Container analysis results
            statistics: Scan statistics
            show_severity_breakdown: Whether to show severity breakdown
        """
        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)

        print(f"\nImage: {image}")
        print(f"Total Packages Scanned: {len(analysis.packages)}")
        print(f"Vulnerable Packages: {statistics['vulnerable_packages']}")
        print(f"Total Vulnerabilities: {statistics['total_vulnerabilities']}")

        if show_severity_breakdown:
            severity_breakdown = statistics["severity_breakdown"]
            print(f"\nSeverity Breakdown:")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
                count = severity_breakdown.get(sev, 0)
                if count > 0:
                    print(f"  {sev:8s}: {count:3d}")

    @staticmethod
    def print_findings(
        matches: Dict[str, List[CVEMatch]],
        analysis: ContainerAnalysis,
        max_per_package: int = 5,
        show_description: bool = True,
        description_max_length: int = 100
    ):
        """
        Print vulnerability findings to console.

        Args:
            matches: Dictionary of CVE matches
            analysis: Container analysis results
            max_per_package: Maximum findings to show per package
            show_description: Whether to show CVE descriptions
            description_max_length: Maximum description length
        """
        if not matches:
            print("\n✅ No vulnerabilities detected")
            return

        print("\nVULNERABILITY FINDINGS")
        print("=" * 70)

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, None: 4}

        for pkg_name in sorted(matches.keys()):
            pkg_matches = matches[pkg_name]

            # Sort matches by severity
            pkg_matches.sort(key=lambda m: (
                severity_order.get(m.cve.severity, 4),
                -(m.cve.cvss_score or 0)
            ))

            # Find package version
            pkg_version = None
            for pkg in analysis.packages:
                if pkg.name == pkg_name:
                    pkg_version = pkg.version
                    break

            print(f"\n📦 Package: {pkg_name} {pkg_version or ''}")
            print(f"   Vulnerabilities: {len(pkg_matches)}")

            # Show top N for each package
            for i, match in enumerate(pkg_matches[:max_per_package], 1):
                severity_icon = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "🟢"
                }.get(match.cve.severity, "⚪")

                print(f"\n   {severity_icon} [{i}] {match.cve.cve_id}")
                print(f"       Severity: {match.cve.severity or 'N/A'}")
                print(f"       CVSS Score: {match.cve.cvss_score or 'N/A'}")
                print(f"       Confidence: {match.confidence:.0%}")
                print(f"       Match: {match.match_reason}")

                # Version match details
                if match.version_match:
                    print(f"       ✓ Version is in vulnerable range")
                else:
                    print(f"       ⚠ Name match only (version not in range)")

                # Description
                if show_description:
                    desc = match.cve.description
                    if len(desc) > description_max_length:
                        desc = desc[:description_max_length] + "..."
                    print(f"       {desc}")

            if len(pkg_matches) > max_per_package:
                print(f"\n   ... and {len(pkg_matches) - max_per_package} more vulnerabilities")

    @staticmethod
    def print_validation_analysis(
        true_positives: List,
        needs_review: List,
        potential_false_positives: List,
        max_to_show: int = 10
    ):
        """
        Print validation analysis of findings.

        Args:
            true_positives: List of (package, cve_id, confidence) tuples
            needs_review: List of findings that need review
            potential_false_positives: List of potential false positives
            max_to_show: Maximum entries to show per category
        """
        print("\n" + "=" * 70)
        print("VALIDATION BREAKDOWN")
        print("=" * 70)

        print(f"\n✅ TRUE POSITIVES (High Confidence + Version Match): {len(true_positives)}")
        for pkg, cve, conf in true_positives[:max_to_show]:
            print(f"   - {pkg:20s} → {cve} ({conf:.0%})")

        if len(true_positives) > max_to_show:
            print(f"   ... and {len(true_positives) - max_to_show} more")

        print(f"\n⚠️  NEEDS REVIEW (Version Match, Lower Confidence): {len(needs_review)}")
        for pkg, cve, conf in needs_review[:max_to_show]:
            print(f"   - {pkg:20s} → {cve} ({conf:.0%})")

        if len(needs_review) > max_to_show:
            print(f"   ... and {len(needs_review) - max_to_show} more")

        print(f"\n❌ POTENTIAL FALSE POSITIVES (No Version Match): {len(potential_false_positives)}")
        for pkg, cve, conf in potential_false_positives[:max_to_show]:
            print(f"   - {pkg:20s} → {cve} ({conf:.0%})")

        if len(potential_false_positives) > max_to_show:
            print(f"   ... and {len(potential_false_positives) - max_to_show} more")

        # Calculate quality metrics
        total_findings = len(true_positives) + len(needs_review) + len(potential_false_positives)
        if total_findings > 0:
            precision_estimate = (len(true_positives) / total_findings * 100)
            false_positive_rate = (len(potential_false_positives) / total_findings * 100)

            print(f"\n" + "=" * 70)
            print("QUALITY METRICS")
            print("=" * 70)
            print(f"\nEstimated Precision: {precision_estimate:.1f}%")
            print(f"High Confidence Matches: {len(true_positives)} / {total_findings}")
            print(f"False Positive Rate (est): {false_positive_rate:.1f}%")
