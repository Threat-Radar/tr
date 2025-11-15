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


# ============================================================================
# Threat Modeling Prompts
# ============================================================================

ATTACK_SCENARIO_PROMPT = """You are a cybersecurity threat analyst creating a realistic attack scenario narrative.

THREAT ACTOR PROFILE:
Name: {threat_actor_name}
Description: {threat_actor_description}
Motivations: {threat_actor_motivations}
Skill Level: {threat_actor_skill_level}

ATTACK PATH TECHNICAL DETAILS:
Entry Point: {entry_point}
Target: {target}
Path Length: {path_length} steps
Total CVSS Score: {total_cvss}
Threat Level: {threat_level}

ATTACK STEPS:
{attack_steps}

MITRE ATT&CK MAPPING:
{mitre_mapping}

{business_context}

TASK:
Write a realistic, detailed attack narrative (400-600 words) that:
1. Describes the initial reconnaissance and target selection phase
2. Walks through each attack step chronologically with technical details
3. Explains how the threat actor would use their skills and tools
4. Includes estimated timelines for each phase
5. Describes the business impact and consequences
6. Uses terminology appropriate for the threat actor's skill level
7. Maintains realism based on actual threat actor tactics

Write in a storytelling format that security professionals and business stakeholders can both understand.
Focus on "what" and "how" rather than generic descriptions.
"""


MITRE_ATTACK_MAPPING_PROMPT = """You are a MITRE ATT&CK framework expert mapping attack steps to techniques.

ATTACK PATH STEPS:
{attack_steps}

TASK:
Map each attack step to appropriate MITRE ATT&CK techniques. Consider:
1. The type of action (initial access, lateral movement, privilege escalation, etc.)
2. The specific vulnerabilities being exploited
3. The infrastructure being targeted
4. The attacker's objectives

Respond in JSON format:
{{
    "steps": [
        {{
            "step_number": 1,
            "ttp_id": "T1190",
            "ttp_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "technique_description": "How this technique is used in this specific step",
            "detection_methods": ["method1", "method2"],
            "mitigation_strategies": ["strategy1", "strategy2"]
        }}
    ]
}}

Ensure TTPs accurately reflect the attack path and are from the official MITRE ATT&CK framework.
"""


THREAT_MODEL_SUMMARY_PROMPT = """You are a senior cybersecurity analyst creating an executive summary for a threat model report.

ENVIRONMENT: {environment_name}

THREAT ACTORS ANALYZED:
{threat_actors}

TOTAL SCENARIOS GENERATED: {total_scenarios}
CRITICAL SCENARIOS: {critical_count}

TOP SCENARIO SUMMARIES:
{scenario_summaries}

TASK:
Create a concise executive summary (300-400 words) for C-level executives that includes:

1. **Overall Risk Assessment**
   - Current threat landscape for the organization
   - Severity of identified risks (critical/high/medium/low)
   - Most concerning threat actor types

2. **Key Findings**
   - 3-5 most critical attack scenarios
   - Common attack patterns across scenarios
   - Primary vulnerabilities being exploited

3. **Business Impact**
   - Potential financial impact (if data available)
   - Compliance and regulatory concerns
   - Reputation and customer trust implications
   - Operational disruption risks

4. **Strategic Recommendations**
   - Top 3 immediate actions required
   - Resource allocation priorities
   - Timeline for critical remediations

Use business language appropriate for non-technical executives while maintaining accuracy.
Focus on risk, impact, and actionable decisions rather than technical details.
Avoid jargon and explain technical concepts in business terms.
"""


def create_attack_scenario_prompt(context: Dict[str, Any]) -> str:
    """
    Create prompt for AI-powered attack scenario narrative generation.

    Args:
        context: Dictionary containing:
            - threat_actor: dict with name, description, motivations, skill_level
            - attack_path: dict with entry_point, target, path_length, total_cvss, threat_level, steps
            - mitre_mapping: list of dicts with ttp_id, ttp_name, tactic
            - business_context: optional dict with business/environment details

    Returns:
        Formatted prompt for attack scenario generation
    """
    threat_actor = context.get("threat_actor", {})
    attack_path = context.get("attack_path", {})
    mitre_mapping = context.get("mitre_mapping", [])
    business_context = context.get("business_context", {})

    # Format attack steps
    steps_list = []
    for i, step in enumerate(attack_path.get("steps", []), 1):
        vulnerabilities = ", ".join(step.get("vulnerabilities", [])) or "N/A"
        cvss = step.get("cvss_score", "N/A")
        steps_list.append(
            f"Step {i}: {step.get('description', 'Unknown')}\n"
            f"  - Vulnerabilities: {vulnerabilities}\n"
            f"  - CVSS Score: {cvss}"
        )
    attack_steps_str = "\n\n".join(steps_list)

    # Format MITRE mapping
    mitre_list = []
    for mapping in mitre_mapping:
        mitre_list.append(
            f"- {mapping.get('ttp_id', 'Unknown')}: {mapping.get('ttp_name', 'Unknown')} "
            f"({mapping.get('tactic', 'Unknown')} tactic)"
        )
    mitre_str = "\n".join(mitre_list) if mitre_list else "No MITRE mapping available"

    # Format business context
    business_context_str = ""
    if business_context:
        business_context_str = "\nBUSINESS CONTEXT:\n"
        if business_context.get("pci_scope"):
            business_context_str += "- PCI-DSS scope: Payment card data at risk\n"
        if business_context.get("hipaa_scope"):
            business_context_str += "- HIPAA scope: Protected health information at risk\n"
        if business_context.get("customer_facing"):
            business_context_str += "- Customer-facing: Public reputation impact\n"
        criticality = business_context.get("criticality", "")
        if criticality:
            business_context_str += f"- Business criticality: {criticality.upper()}\n"

    return ATTACK_SCENARIO_PROMPT.format(
        threat_actor_name=threat_actor.get("name", "Unknown Actor"),
        threat_actor_description=threat_actor.get("description", "No description")[:300],
        threat_actor_motivations=", ".join(threat_actor.get("motivations", [])),
        threat_actor_skill_level=threat_actor.get("skill_level", "unknown").upper(),
        entry_point=attack_path.get("entry_point", "Unknown"),
        target=attack_path.get("target", "Unknown"),
        path_length=attack_path.get("path_length", 0),
        total_cvss=attack_path.get("total_cvss", 0),
        threat_level=attack_path.get("threat_level", "unknown").upper(),
        attack_steps=attack_steps_str,
        mitre_mapping=mitre_str,
        business_context=business_context_str
    )


def create_mitre_attack_mapping_prompt(attack_steps: List[Dict[str, Any]]) -> str:
    """
    Create prompt for MITRE ATT&CK technique mapping.

    Args:
        attack_steps: List of attack step dictionaries

    Returns:
        Formatted prompt for MITRE ATT&CK mapping
    """
    steps_list = []
    for i, step in enumerate(attack_steps, 1):
        vulnerabilities = ", ".join(step.get("vulnerabilities", [])) or "None"
        steps_list.append(
            f"Step {i}:\n"
            f"  Description: {step.get('description', 'Unknown')}\n"
            f"  Vulnerabilities: {vulnerabilities}\n"
            f"  CVSS Score: {step.get('cvss_score', 'N/A')}"
        )

    attack_steps_str = "\n\n".join(steps_list)

    return MITRE_ATTACK_MAPPING_PROMPT.format(attack_steps=attack_steps_str)


def create_threat_model_summary_prompt(summary_data: Dict[str, Any]) -> str:
    """
    Create prompt for threat model executive summary generation.

    Args:
        summary_data: Dictionary containing:
            - environment_name: str
            - threat_actors: list of str
            - total_scenarios: int
            - critical_count: int
            - scenario_summaries: list of dicts with scenario details

    Returns:
        Formatted prompt for executive summary generation
    """
    threat_actors_str = "\n".join(
        [f"- {actor}" for actor in summary_data.get("threat_actors", [])]
    )

    scenario_summaries_list = []
    for i, scenario in enumerate(summary_data.get("scenario_summaries", []), 1):
        scenario_summaries_list.append(
            f"Scenario {i}: {scenario.get('threat_actor', 'Unknown')}\n"
            f"  Narrative: {scenario.get('narrative_excerpt', 'No details')}\n"
            f"  Estimated Cost: {scenario.get('business_impact', 'Unknown')}\n"
            f"  Compliance Violations: {', '.join(scenario.get('compliance_violations', [])) or 'None'}"
        )

    scenario_summaries_str = "\n\n".join(scenario_summaries_list)

    return THREAT_MODEL_SUMMARY_PROMPT.format(
        environment_name=summary_data.get("environment_name", "Unknown Environment"),
        threat_actors=threat_actors_str,
        total_scenarios=summary_data.get("total_scenarios", 0),
        critical_count=summary_data.get("critical_count", 0),
        scenario_summaries=scenario_summaries_str
    )
