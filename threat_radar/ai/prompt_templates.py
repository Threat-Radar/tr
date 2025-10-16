"""Prompt templates for AI-powered vulnerability analysis"""

from typing import List, Dict, Any
import json


VULNERABILITY_ANALYSIS_PROMPT = """You are a cybersecurity expert analyzing vulnerability scan results.

Analyze the following vulnerabilities and provide insights about their exploitability, attack vectors, and business impact.

VULNERABILITY DATA:
{vulnerability_data}

For each vulnerability, analyze:
1. **Exploitability**: How easily can this vulnerability be exploited? (e.g., requires authentication, network access, user interaction)
2. **Attack Vectors**: What are the possible attack vectors? (e.g., remote code execution, SQL injection, XSS)
3. **Business Impact**: What is the potential business impact if exploited? (e.g., data breach, service disruption, financial loss)
4. **Context**: Consider the package name, version, and severity to assess real-world risk

Provide your analysis in JSON format with this structure:
{{
    "vulnerabilities": [
        {{
            "cve_id": "CVE-XXXX-XXXX",
            "package_name": "package-name",
            "exploitability": "HIGH|MEDIUM|LOW",
            "exploitability_details": "Detailed explanation",
            "attack_vectors": ["vector1", "vector2"],
            "business_impact": "HIGH|MEDIUM|LOW",
            "business_impact_details": "Detailed explanation",
            "recommendations": ["recommendation1", "recommendation2"]
        }}
    ],
    "summary": "Overall summary of the vulnerability landscape"
}}
"""


PRIORITIZATION_PROMPT = """You are a cybersecurity expert helping prioritize vulnerability remediation efforts.

Given the following vulnerability analysis, create a prioritized list based on:
1. CVSS severity score
2. Exploitability
3. Business impact
4. Availability of patches/fixes

VULNERABILITY ANALYSIS:
{analysis_data}

Create a prioritized remediation plan in JSON format:
{{
    "priority_levels": {{
        "critical": [
            {{
                "cve_id": "CVE-XXXX-XXXX",
                "package_name": "package-name",
                "reason": "Why this is critical priority",
                "urgency_score": 95
            }}
        ],
        "high": [...],
        "medium": [...],
        "low": [...]
    }},
    "overall_strategy": "High-level remediation strategy",
    "quick_wins": ["List of vulnerabilities that can be fixed quickly with high impact"]
}}

Urgency score should be 0-100 based on severity + exploitability + business impact.
"""


REMEDIATION_PROMPT = """You are a cybersecurity expert providing remediation guidance.

For the following vulnerabilities, provide detailed, actionable remediation steps.

VULNERABILITY DATA:
{vulnerability_data}

For each vulnerability, provide:
1. **Immediate Actions**: What should be done right now to mitigate risk?
2. **Patch/Upgrade Path**: Specific version upgrades or patches needed
3. **Workarounds**: If no patch available, what are the workarounds?
4. **Testing Steps**: How to verify the fix works
5. **References**: Links to security advisories, patches, documentation

Respond in JSON format:
{{
    "remediations": [
        {{
            "cve_id": "CVE-XXXX-XXXX",
            "package_name": "package-name",
            "current_version": "1.0.0",
            "fixed_version": "1.0.5",
            "immediate_actions": ["action1", "action2"],
            "upgrade_command": "pip install package==1.0.5",
            "workarounds": ["workaround1", "workaround2"],
            "testing_steps": ["step1", "step2"],
            "references": ["https://...", "https://..."],
            "estimated_effort": "LOW|MEDIUM|HIGH"
        }}
    ],
    "grouped_by_package": {{
        "package-name": {{
            "vulnerabilities_count": 3,
            "recommended_version": "1.0.5",
            "upgrade_fixes_all": true
        }}
    }}
}}
"""


RISK_ASSESSMENT_PROMPT = """You are a cybersecurity risk analyst assessing the overall risk posture.

Analyze the following vulnerability data to provide a comprehensive risk assessment.

VULNERABILITY DATA:
{vulnerability_data}

CONTEXT:
- Target: {target}
- Total Vulnerabilities: {total_count}
- Severity Distribution: {severity_distribution}

Provide a risk assessment in JSON format:
{{
    "risk_score": 85,
    "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
    "key_risks": [
        {{
            "risk": "Description of the risk",
            "likelihood": "HIGH|MEDIUM|LOW",
            "impact": "HIGH|MEDIUM|LOW",
            "affected_components": ["component1", "component2"]
        }}
    ],
    "compliance_concerns": ["PCI-DSS", "HIPAA", "GDPR"],
    "recommended_actions": [
        {{
            "action": "Specific action to take",
            "priority": "CRITICAL|HIGH|MEDIUM|LOW",
            "timeframe": "Immediately|Within 24h|Within 1 week|Within 1 month"
        }}
    ],
    "risk_summary": "Executive summary of the risk assessment"
}}

Risk score should be 0-100 based on number, severity, and exploitability of vulnerabilities.
"""


def format_vulnerability_data(vulnerabilities: List[Dict[str, Any]], limit: int = 20) -> str:
    """
    Format vulnerability data for prompt inclusion.

    Args:
        vulnerabilities: List of vulnerability dictionaries
        limit: Maximum number of vulnerabilities to include

    Returns:
        Formatted string representation
    """
    limited_vulns = vulnerabilities[:limit]

    formatted = []
    for vuln in limited_vulns:
        formatted.append(f"""
CVE ID: {vuln.get('id', 'N/A')}
Package: {vuln.get('package_name', 'N/A')} @ {vuln.get('package_version', 'N/A')}
Severity: {vuln.get('severity', 'N/A').upper()}
CVSS Score: {vuln.get('cvss_score', 'N/A')}
Fixed In: {vuln.get('fixed_in_version') or 'No fix available'}
Description: {vuln.get('description', 'No description available')[:200]}...
""".strip())

    if len(vulnerabilities) > limit:
        formatted.append(f"\n... and {len(vulnerabilities) - limit} more vulnerabilities")

    return "\n\n---\n\n".join(formatted)


def create_analysis_prompt(vulnerabilities: List[Dict[str, Any]]) -> str:
    """Create vulnerability analysis prompt"""
    vuln_data = format_vulnerability_data(vulnerabilities)
    return VULNERABILITY_ANALYSIS_PROMPT.format(vulnerability_data=vuln_data)


def create_prioritization_prompt(analysis_data: Dict[str, Any]) -> str:
    """Create prioritization prompt"""
    analysis_json = json.dumps(analysis_data, indent=2)
    return PRIORITIZATION_PROMPT.format(analysis_data=analysis_json)


def create_remediation_prompt(vulnerabilities: List[Dict[str, Any]]) -> str:
    """Create remediation prompt"""
    vuln_data = format_vulnerability_data(vulnerabilities)
    return REMEDIATION_PROMPT.format(vulnerability_data=vuln_data)


def create_risk_assessment_prompt(
    vulnerabilities: List[Dict[str, Any]],
    target: str,
    total_count: int,
    severity_distribution: Dict[str, int],
) -> str:
    """Create risk assessment prompt"""
    vuln_data = format_vulnerability_data(vulnerabilities)
    severity_dist_str = ", ".join([f"{k}: {v}" for k, v in severity_distribution.items()])

    return RISK_ASSESSMENT_PROMPT.format(
        vulnerability_data=vuln_data,
        target=target,
        total_count=total_count,
        severity_distribution=severity_dist_str,
    )
