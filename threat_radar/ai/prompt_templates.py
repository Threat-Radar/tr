"""Prompt templates for AI-powered vulnerability analysis"""

from typing import List, Dict, Any, Optional
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


def format_vulnerability_data(
    vulnerabilities: List[Dict[str, Any]],
    limit: Optional[int] = 20,
    include_truncation_notice: bool = True,
) -> str:
    """
    Format vulnerability data for prompt inclusion.

    Args:
        vulnerabilities: List of vulnerability dictionaries
        limit: Maximum number of vulnerabilities to include (None = no limit)
        include_truncation_notice: Show "... N more" message when truncated

    Returns:
        Formatted string representation
    """
    # Apply limit if specified, otherwise use all vulnerabilities
    if limit is not None:
        limited_vulns = vulnerabilities[:limit]
    else:
        limited_vulns = vulnerabilities

    formatted = []
    for vuln in limited_vulns:
        # Handle None description safely
        description = vuln.get('description') or 'No description available'
        description_preview = description[:200] + "..." if len(description) > 200 else description

        formatted.append(f"""
CVE ID: {vuln.get('id', 'N/A')}
Package: {vuln.get('package_name', 'N/A')} @ {vuln.get('package_version', 'N/A')}
Severity: {vuln.get('severity', 'N/A').upper()}
CVSS Score: {vuln.get('cvss_score', 'N/A')}
Fixed In: {vuln.get('fixed_in_version') or 'No fix available'}
Description: {description_preview}
""".strip())

    # Add truncation notice if data was limited
    if include_truncation_notice and limit is not None and len(vulnerabilities) > limit:
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


def create_batch_analysis_prompt(
    vulnerabilities: List[Dict[str, Any]],
    batch_number: int,
    total_batches: int,
) -> str:
    """
    Create prompt optimized for batch processing.

    Args:
        vulnerabilities: List of vulnerability dictionaries for this batch
        batch_number: Current batch number (1-indexed)
        total_batches: Total number of batches

    Returns:
        Formatted prompt for batch analysis
    """
    vuln_data = format_vulnerability_data(vulnerabilities, limit=None, include_truncation_notice=False)

    return f"""{VULNERABILITY_ANALYSIS_PROMPT.split('VULNERABILITY DATA:')[0]}
BATCH CONTEXT:
This is batch {batch_number} of {total_batches} in a large vulnerability scan analysis.
Focus on providing accurate, detailed analysis for the vulnerabilities in this batch.

VULNERABILITY DATA:
{vuln_data}

For each vulnerability, analyze:
1. **Exploitability**: How easily can this vulnerability be exploited? (e.g., requires authentication, network access, user interaction)
2. **Attack Vectors**: What are the possible attack vectors? (e.g., remote code execution, SQL injection, XSS)
3. **Business Impact**: What is the potential business impact if exploited? (e.g., data breach, service disruption, financial loss)
4. **Context**: Consider the package name, version, and severity to assess real-world risk

Provide your analysis in JSON format with this structure:
{{{{
    "vulnerabilities": [
        {{{{
            "cve_id": "CVE-XXXX-XXXX",
            "package_name": "package-name",
            "exploitability": "HIGH|MEDIUM|LOW",
            "exploitability_details": "Detailed explanation",
            "attack_vectors": ["vector1", "vector2"],
            "business_impact": "HIGH|MEDIUM|LOW",
            "business_impact_details": "Detailed explanation",
            "recommendations": ["recommendation1", "recommendation2"]
        }}}}
    ],
    "summary": "Summary of vulnerabilities in this batch"
}}}}
"""


def create_summary_consolidation_prompt(
    target: str,
    total_vulnerabilities: int,
    severity_counts: Dict[str, int],
    batch_summaries: List[str],
    high_priority_count: int,
) -> str:
    """
    Create prompt to consolidate multiple batch analysis results.

    Args:
        target: Scan target (image name, etc.)
        total_vulnerabilities: Total CVE count
        severity_counts: Distribution of severities
        batch_summaries: List of summary strings from each batch
        high_priority_count: Number of high-priority vulnerabilities found

    Returns:
        Formatted prompt for summary consolidation
    """
    severity_dist_str = ", ".join([f"{k.capitalize()}: {v}" for k, v in severity_counts.items()])
    batch_summaries_str = "\n\n".join([f"Batch {i+1}: {summary}" for i, summary in enumerate(batch_summaries)])

    return f"""You are a cybersecurity expert consolidating analysis from multiple batches.

SCAN OVERVIEW:
- Target: {target}
- Total Vulnerabilities: {total_vulnerabilities}
- Severity Distribution: {severity_dist_str}
- High Priority Vulnerabilities: {high_priority_count}

BATCH SUMMARIES:
{batch_summaries_str}

Create a consolidated executive summary (3-5 sentences) covering:
1. Overall risk assessment and security posture
2. Most critical threats and attack vectors identified
3. Key recommendations for immediate action
4. Business impact considerations

Provide a clear, actionable summary that gives leadership a complete picture of the vulnerability landscape.
"""
