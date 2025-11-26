"""Report formatters for different output formats (JSON, Markdown, HTML, PDF)."""
import json
from typing import Any, Dict
from datetime import datetime
import logging

from .report_templates import ComprehensiveReport, ReportLevel

logger = logging.getLogger(__name__)


class ReportFormatter:
    """Base class for report formatters."""

    def format(self, report: ComprehensiveReport) -> str:
        """Format report to string output."""
        raise NotImplementedError


class JSONFormatter(ReportFormatter):
    """JSON format output."""

    def format(self, report: ComprehensiveReport, indent: int = 2) -> str:
        """Format report as JSON."""
        return json.dumps(report.to_dict(), indent=indent, default=str)


class MarkdownFormatter(ReportFormatter):
    """Markdown format output for documentation."""

    def format(self, report: ComprehensiveReport) -> str:
        """Format report as Markdown."""
        md = []

        # Header
        md.append(f"# Vulnerability Scan Report")
        md.append(f"\n**Report ID:** `{report.report_id}`")
        md.append(f"**Generated:** {report.generated_at}")
        md.append(f"**Target:** `{report.target}`")
        md.append(f"**Report Level:** {report.report_level.upper()}\n")

        md.append("---\n")

        # Executive Summary (if present)
        if report.executive_summary:
            md.append("## Executive Summary\n")
            exec_sum = report.executive_summary

            md.append(f"### Overall Risk Rating: **{exec_sum.overall_risk_rating}**\n")

            md.append("### Key Findings\n")
            for finding in exec_sum.key_findings:
                md.append(f"- {finding}")
            md.append("")

            md.append("### Immediate Actions Required\n")
            for action in exec_sum.immediate_actions:
                md.append(f"1. {action}")
            md.append("")

            md.append(f"### Risk Summary\n{exec_sum.risk_summary}\n")

            md.append(f"### Compliance Impact\n{exec_sum.compliance_impact}\n")

            md.append(f"### Business Context\n{exec_sum.business_context}\n")

            md.append("### Remediation Metrics\n")
            md.append(f"- **Critical Items:** {exec_sum.critical_items_requiring_attention}")
            md.append(f"- **Estimated Effort:** {exec_sum.estimated_remediation_effort}")
            if exec_sum.days_to_patch_critical:
                md.append(f"- **Timeline:** {exec_sum.days_to_patch_critical} days to patch critical issues")
            md.append("\n---\n")

        # Summary Statistics
        md.append("## Summary Statistics\n")
        summary = report.summary

        md.append("| Metric | Value |")
        md.append("|--------|-------|")
        md.append(f"| Total Vulnerabilities | {summary.total_vulnerabilities} |")
        md.append(f"| Critical | 🔴 {summary.critical} |")
        md.append(f"| High | 🟠 {summary.high} |")
        md.append(f"| Medium | 🟡 {summary.medium} |")
        md.append(f"| Low | 🔵 {summary.low} |")
        md.append(f"| Negligible | 🟢 {summary.negligible} |")
        md.append(f"| Vulnerable Packages | {summary.vulnerable_packages} |")
        md.append(f"| Average CVSS Score | {summary.average_cvss_score:.2f} |")
        md.append(f"| Highest CVSS Score | {summary.highest_cvss_score:.2f} |")
        md.append(f"| Vulnerabilities with Fix | ✅ {summary.vulnerabilities_with_fix} |")
        md.append(f"| Vulnerabilities without Fix | ❌ {summary.vulnerabilities_without_fix} |")

        # Add new metrics from executive summary if available
        if report.executive_summary:
            exec_sum = report.executive_summary
            md.append(f"| Fix Availability | {exec_sum.fix_available_percentage:.1f}% |")
            md.append(f"| Internet-Facing Assets | 🌐 {exec_sum.internet_facing_assets} |")

        md.append("")

        # Severity Distribution Chart (text-based)
        md.append("### Severity Distribution\n")
        md.append("```")
        total = summary.total_vulnerabilities
        if total > 0:
            md.append(f"Critical   {'█' * int((summary.critical / total) * 50)} {summary.critical}")
            md.append(f"High       {'█' * int((summary.high / total) * 50)} {summary.high}")
            md.append(f"Medium     {'█' * int((summary.medium / total) * 50)} {summary.medium}")
            md.append(f"Low        {'█' * int((summary.low / total) * 50)} {summary.low}")
            md.append(f"Negligible {'█' * int((summary.negligible / total) * 50)} {summary.negligible}")
        md.append("```\n")

        md.append("---\n")

        # Top Vulnerable Packages
        if report.packages:
            md.append("## Most Vulnerable Packages\n")
            md.append("| Package | Version | Vulnerabilities | Highest Severity | Recommended Version |")
            md.append("|---------|---------|-----------------|------------------|---------------------|")

            for pkg in report.packages[:10]:
                severity_icon = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🔵',
                    'negligible': '🟢'
                }.get(pkg.highest_severity, '⚪')

                recommended = pkg.recommended_version or "No fix available"

                md.append(
                    f"| `{pkg.package_name}` | `{pkg.package_version}` | {pkg.vulnerability_count} | "
                    f"{severity_icon} {pkg.highest_severity.upper()} | `{recommended}` |"
                )
            md.append("")

        # Attack Surface Analysis (if present)
        if report.attack_surface_data:
            md.append("## Attack Surface Analysis\n")
            attack_data = report.attack_surface_data

            md.append("### Overview\n")
            md.append("| Metric | Value |")
            md.append("|--------|-------|")
            md.append(f"| Total Attack Paths | {attack_data.total_attack_paths} |")
            md.append(f"| Critical Paths | 🔴 {attack_data.critical_paths} |")
            md.append(f"| High Paths | 🟠 {attack_data.high_paths} |")
            md.append(f"| Entry Points | {attack_data.entry_points_count} |")
            md.append(f"| High-Value Targets | {attack_data.high_value_targets_count} |")
            md.append(f"| Privilege Escalation Opportunities | {attack_data.privilege_escalation_opportunities} |")
            md.append(f"| Lateral Movement Opportunities | {attack_data.lateral_movement_opportunities} |")
            md.append(f"| Total Risk Score | {attack_data.total_risk_score:.2f}/100 |")
            md.append("")

            # Critical/High Attack Paths
            critical_paths = [ap for ap in attack_data.attack_paths if ap.threat_level in ['critical', 'high']][:10]
            if critical_paths:
                md.append("### Critical & High Threat Paths\n")
                for path in critical_paths:
                    threat_icon = '🔴' if path.threat_level == 'critical' else '🟠'
                    md.append(f"#### {threat_icon} {path.path_id}\n")
                    md.append(f"**Threat Level:** {path.threat_level.upper()}")
                    md.append(f"**Entry Point:** `{path.entry_point}`")
                    md.append(f"**Target:** `{path.target}`")
                    md.append(f"**Path Length:** {path.path_length} steps")
                    md.append(f"**Total CVSS:** {path.total_cvss:.1f}")
                    md.append(f"**Exploitability:** {path.exploitability * 100:.0f}%")
                    md.append(f"**Requires Privileges:** {'Yes' if path.requires_privileges else 'No'}")
                    md.append(f"\n**Description:** {path.description}\n")

                    if path.vulnerabilities_exploited:
                        md.append(f"**CVEs Exploited:** {', '.join(path.vulnerabilities_exploited[:10])}\n")

                    if path.steps_summary:
                        md.append("**Attack Steps:**")
                        for i, step in enumerate(path.steps_summary, 1):
                            md.append(f"{i}. {step}")
                        md.append("")

            # Security Recommendations
            if attack_data.recommendations:
                md.append("### Security Recommendations\n")
                for i, rec in enumerate(attack_data.recommendations, 1):
                    md.append(f"{i}. {rec}")
                md.append("")

        # Critical/High Findings
        critical_high = [f for f in report.findings if f.severity in ['critical', 'high']]
        if critical_high:
            md.append("## Critical & High Severity Vulnerabilities\n")

            for finding in sorted(
                critical_high,
                key=lambda x: (0 if x.severity == 'critical' else 1, -(x.cvss_score or 0))
            )[:20]:
                severity_icon = '🔴' if finding.severity == 'critical' else '🟠'

                md.append(f"### {severity_icon} {finding.cve_id}\n")
                md.append(f"**Package:** `{finding.package_name}@{finding.package_version}`")
                md.append(f"**Severity:** {finding.severity.upper()}")
                md.append(f"**CVSS Score:** {finding.cvss_score or 'N/A'}")

                if finding.fixed_in_version:
                    md.append(f"**Fix Available:** ✅ Upgrade to `{finding.fixed_in_version}`")
                else:
                    md.append(f"**Fix Available:** ❌ No fix available")

                md.append(f"\n**Description:** {finding.description}\n")

                if finding.urls:
                    md.append("**References:**")
                    for url in finding.urls[:3]:
                        md.append(f"- {url}")
                    md.append("")

        # Remediation Recommendations
        if report.remediation_recommendations:
            md.append("## Remediation Recommendations\n")
            for i, rec in enumerate(report.remediation_recommendations, 1):
                md.append(f"{i}. {rec}")
            md.append("")

        # Footer
        md.append("---\n")
        md.append(f"*Report generated by Threat Radar on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

        return '\n'.join(md)


class HTMLFormatter(ReportFormatter):
    """HTML format output for web viewing."""

    def format(self, report: ComprehensiveReport) -> str:
        """Format report as HTML."""
        html = []

        # HTML header and CSS
        html.append("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        h1 {
            color: #1a202c;
            margin-bottom: 20px;
            font-size: 2.5em;
        }

        h2 {
            color: #2d3748;
            margin-top: 30px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e2e8f0;
        }

        h3 {
            color: #4a5568;
            margin-top: 20px;
            margin-bottom: 10px;
        }

        .metadata {
            background-color: #f7fafc;
            padding: 20px;
            border-radius: 6px;
            margin-bottom: 30px;
        }

        .metadata-item {
            margin-bottom: 8px;
        }

        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.875em;
            font-weight: 600;
        }

        .badge-critical {
            background-color: #fee;
            color: #c53030;
        }

        .badge-high {
            background-color: #fed7d7;
            color: #c05621;
        }

        .badge-medium {
            background-color: #fefcbf;
            color: #b7791f;
        }

        .badge-low {
            background-color: #bee3f8;
            color: #2c5282;
        }

        .badge-negligible {
            background-color: #c6f6d5;
            color: #22543d;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }

        .stat-card {
            background-color: #f7fafc;
            padding: 20px;
            border-radius: 6px;
            border-left: 4px solid #4299e1;
        }

        .stat-card h4 {
            color: #718096;
            font-size: 0.875em;
            margin-bottom: 8px;
        }

        .stat-card .value {
            font-size: 2em;
            font-weight: 700;
            color: #1a202c;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }

        th {
            background-color: #f7fafc;
            font-weight: 600;
            color: #4a5568;
        }

        tr:hover {
            background-color: #f7fafc;
        }

        .vulnerability-card {
            background-color: #f7fafc;
            padding: 20px;
            margin: 15px 0;
            border-radius: 6px;
            border-left: 4px solid #cbd5e0;
        }

        .vulnerability-card.critical {
            border-left-color: #c53030;
        }

        .vulnerability-card.high {
            border-left-color: #c05621;
        }

        .executive-summary {
            background-color: #edf2f7;
            padding: 30px;
            border-radius: 8px;
            margin: 30px 0;
        }

        .risk-rating {
            font-size: 1.5em;
            font-weight: 700;
            padding: 15px 30px;
            border-radius: 6px;
            display: inline-block;
            margin: 10px 0;
        }

        .risk-critical {
            background-color: #c53030;
            color: white;
        }

        .risk-high {
            background-color: #dd6b20;
            color: white;
        }

        .risk-medium {
            background-color: #d69e2e;
            color: white;
        }

        .risk-low {
            background-color: #38a169;
            color: white;
        }

        ul {
            margin-left: 20px;
            margin-top: 10px;
        }

        li {
            margin-bottom: 8px;
        }

        code {
            background-color: #edf2f7;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }

        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e2e8f0;
            text-align: center;
            color: #718096;
            font-size: 0.875em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Vulnerability Scan Report</h1>
""")

        # Metadata section
        html.append(f"""
        <div class="metadata">
            <div class="metadata-item"><strong>Report ID:</strong> <code>{report.report_id}</code></div>
            <div class="metadata-item"><strong>Generated:</strong> {report.generated_at}</div>
            <div class="metadata-item"><strong>Target:</strong> <code>{report.target}</code></div>
            <div class="metadata-item"><strong>Report Level:</strong> {report.report_level.upper()}</div>
        </div>
""")

        # Executive Summary
        if report.executive_summary:
            exec_sum = report.executive_summary
            risk_class = f"risk-{exec_sum.overall_risk_rating.lower()}"

            html.append(f"""
        <div class="executive-summary">
            <h2>📊 Executive Summary</h2>
            <div class="risk-rating {risk_class}">Risk Rating: {exec_sum.overall_risk_rating}</div>

            <h3>Key Findings</h3>
            <ul>
""")
            for finding in exec_sum.key_findings:
                html.append(f"                <li>{finding}</li>")

            html.append("""
            </ul>

            <h3>Immediate Actions Required</h3>
            <ol>
""")
            for action in exec_sum.immediate_actions:
                html.append(f"                <li>{action}</li>")

            html.append(f"""
            </ol>

            <h3>Risk Summary</h3>
            <p>{exec_sum.risk_summary}</p>

            <h3>Compliance Impact</h3>
            <p>{exec_sum.compliance_impact}</p>

            <h3>Business Context</h3>
            <p>{exec_sum.business_context}</p>
        </div>
""")

        # Summary Statistics
        summary = report.summary
        html.append("""
        <h2>📈 Summary Statistics</h2>
        <div class="stats-grid">
""")

        stats = [
            ("Total Vulnerabilities", summary.total_vulnerabilities, None),
            ("Critical", summary.critical, "critical"),
            ("High", summary.high, "high"),
            ("Medium", summary.medium, "medium"),
            ("Low", summary.low, "low"),
            ("Vulnerable Packages", summary.vulnerable_packages, None),
            ("Average CVSS", f"{summary.average_cvss_score:.2f}", None),
            ("Highest CVSS", f"{summary.highest_cvss_score:.2f}", None),
        ]

        # Add new metrics from executive summary if available
        if report.executive_summary:
            exec_sum = report.executive_summary
            stats.append(("Fix Availability", f"{exec_sum.fix_available_percentage:.1f}%", None))
            stats.append(("Internet-Facing Assets", exec_sum.internet_facing_assets, None))

        for title, value, badge_class in stats:
            badge_html = f' <span class="badge badge-{badge_class}">{badge_class.upper()}</span>' if badge_class else ''
            html.append(f"""
            <div class="stat-card">
                <h4>{title}{badge_html}</h4>
                <div class="value">{value}</div>
            </div>
""")

        html.append("        </div>")

        # Top Vulnerable Packages
        if report.packages:
            html.append("""
        <h2>📦 Most Vulnerable Packages</h2>
        <table>
            <thead>
                <tr>
                    <th>Package</th>
                    <th>Version</th>
                    <th>Vulnerabilities</th>
                    <th>Highest Severity</th>
                    <th>Recommended Version</th>
                </tr>
            </thead>
            <tbody>
""")

            for pkg in report.packages[:10]:
                badge_class = f"badge-{pkg.highest_severity}"
                recommended = pkg.recommended_version or "No fix available"

                html.append(f"""
                <tr>
                    <td><code>{pkg.package_name}</code></td>
                    <td><code>{pkg.package_version}</code></td>
                    <td>{pkg.vulnerability_count}</td>
                    <td><span class="badge {badge_class}">{pkg.highest_severity.upper()}</span></td>
                    <td><code>{recommended}</code></td>
                </tr>
""")

            html.append("""
            </tbody>
        </table>
""")

        # Attack Surface Analysis (if present)
        if report.attack_surface_data:
            attack_data = report.attack_surface_data
            html.append("""
        <h2>🎯 Attack Surface Analysis</h2>

        <h3>Overview</h3>
        <table>
            <thead>
                <tr>
                    <th>Metric</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>
""")
            html.append(f"""
                <tr><td>Total Attack Paths</td><td>{attack_data.total_attack_paths}</td></tr>
                <tr><td>Critical Paths</td><td><span class="badge badge-critical">{attack_data.critical_paths}</span></td></tr>
                <tr><td>High Paths</td><td><span class="badge badge-high">{attack_data.high_paths}</span></td></tr>
                <tr><td>Entry Points</td><td>{attack_data.entry_points_count}</td></tr>
                <tr><td>High-Value Targets</td><td>{attack_data.high_value_targets_count}</td></tr>
                <tr><td>Privilege Escalation Opportunities</td><td>{attack_data.privilege_escalation_opportunities}</td></tr>
                <tr><td>Lateral Movement Opportunities</td><td>{attack_data.lateral_movement_opportunities}</td></tr>
                <tr><td>Total Risk Score</td><td>{attack_data.total_risk_score:.2f}/100</td></tr>
""")
            html.append("""
            </tbody>
        </table>
""")

            # Critical/High Attack Paths
            critical_paths = [ap for ap in attack_data.attack_paths if ap.threat_level in ['critical', 'high']][:10]
            if critical_paths:
                html.append("""
        <h3>Critical & High Threat Paths</h3>
""")
                for path in critical_paths:
                    badge_class = f"badge-{path.threat_level}"
                    requires_privs = 'Yes' if path.requires_privileges else 'No'

                    html.append(f"""
        <div class="vulnerability-card {path.threat_level}">
            <h4>{path.path_id} <span class="badge {badge_class}">{path.threat_level.upper()}</span></h4>
            <p><strong>Entry Point:</strong> <code>{path.entry_point}</code></p>
            <p><strong>Target:</strong> <code>{path.target}</code></p>
            <p><strong>Path Length:</strong> {path.path_length} steps</p>
            <p><strong>Total CVSS:</strong> {path.total_cvss:.1f}</p>
            <p><strong>Exploitability:</strong> {path.exploitability * 100:.0f}%</p>
            <p><strong>Requires Privileges:</strong> {requires_privs}</p>
            <p><strong>Description:</strong> {path.description}</p>
""")
                    if path.vulnerabilities_exploited:
                        cves = ', '.join(path.vulnerabilities_exploited[:10])
                        html.append(f"            <p><strong>CVEs Exploited:</strong> <code>{cves}</code></p>")

                    if path.steps_summary:
                        html.append("            <p><strong>Attack Steps:</strong></p><ol>")
                        for step in path.steps_summary:
                            html.append(f"                <li>{step}</li>")
                        html.append("            </ol>")

                    html.append("        </div>")

            # Security Recommendations
            if attack_data.recommendations:
                html.append("""
        <h3>Security Recommendations</h3>
        <ul>
""")
                for rec in attack_data.recommendations:
                    html.append(f"            <li>{rec}</li>")

                html.append("""
        </ul>
""")

        # Critical/High Findings
        critical_high = [f for f in report.findings if f.severity in ['critical', 'high']]
        if critical_high:
            html.append("""
        <h2>🔴 Critical & High Severity Vulnerabilities</h2>
""")

            for finding in sorted(
                critical_high,
                key=lambda x: (0 if x.severity == 'critical' else 1, -(x.cvss_score or 0))
            )[:20]:
                card_class = finding.severity
                fix_status = f"✅ Upgrade to <code>{finding.fixed_in_version}</code>" if finding.fixed_in_version else "❌ No fix available"

                html.append(f"""
        <div class="vulnerability-card {card_class}">
            <h3>{finding.cve_id} <span class="badge badge-{finding.severity}">{finding.severity.upper()}</span></h3>
            <p><strong>Package:</strong> <code>{finding.package_name}@{finding.package_version}</code></p>
            <p><strong>CVSS Score:</strong> {finding.cvss_score or 'N/A'}</p>
            <p><strong>Fix Available:</strong> {fix_status}</p>
            <p><strong>Description:</strong> {finding.description}</p>
        </div>
""")

        # Footer
        html.append(f"""
        <div class="footer">
            <p>Report generated by Threat Radar on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
""")

        return '\n'.join(html)


class PDFFormatter(ReportFormatter):
    """PDF format output (converts HTML to PDF using weasyprint)."""

    def format(self, report: ComprehensiveReport) -> bytes:
        """
        Format report as PDF.

        Returns PDF as bytes (not string).
        Requires weasyprint to be installed: pip install weasyprint
        """
        try:
            from weasyprint import HTML, CSS
        except ImportError:
            logger.error("weasyprint is required for PDF export. Install with: pip install weasyprint")
            raise ImportError(
                "PDF export requires weasyprint. Install it with:\n"
                "  pip install weasyprint\n"
                "Or install threat-radar with PDF support:\n"
                "  pip install threat-radar[pdf]"
            )

        # Generate HTML using HTMLFormatter
        html_formatter = HTMLFormatter()
        html_content = html_formatter.format(report)

        # Convert HTML to PDF
        logger.info("Converting HTML to PDF...")
        pdf = HTML(string=html_content).write_pdf()

        return pdf


def get_formatter(format_type: str) -> ReportFormatter:
    """Get formatter for specified format type."""
    formatters = {
        'json': JSONFormatter,
        'markdown': MarkdownFormatter,
        'md': MarkdownFormatter,
        'html': HTMLFormatter,
        'pdf': PDFFormatter,
    }

    formatter_class = formatters.get(format_type.lower())
    if not formatter_class:
        raise ValueError(f"Unsupported format: {format_type}. Supported: {list(formatters.keys())}")

    return formatter_class()
