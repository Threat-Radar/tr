"""AI-powered vulnerability analysis with business context integration"""

from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
import logging

from threat_radar.ai.llm_client import LLMClient, get_llm_client
from threat_radar.ai.vulnerability_analyzer import VulnerabilityAnalyzer, VulnerabilityAnalysis
from threat_radar.core.grype_integration import GrypeScanResult, GrypeVulnerability
from threat_radar.environment.models import Environment, Asset

logger = logging.getLogger(__name__)


@dataclass
class BusinessRiskAssessment:
    """Business risk assessment for a vulnerability on a specific asset"""

    cve_id: str
    package_name: str
    asset_id: str
    asset_name: str
    technical_severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float
    business_risk_score: int  # 0-100, computed from technical + business context
    business_risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    risk_factors: List[str]  # Contributing factors (e.g., "Internet-facing", "PII data", "Critical asset")
    business_impact: str  # Detailed business impact description
    compliance_impact: List[str]  # Affected compliance frameworks
    recommended_priority: str  # CRITICAL, HIGH, MEDIUM, LOW
    remediation_urgency: str  # IMMEDIATE, URGENT, STANDARD, DEFERRED


@dataclass
class BusinessContextAnalysis:
    """Complete AI analysis with business context"""

    base_analysis: VulnerabilityAnalysis
    business_assessments: List[BusinessRiskAssessment]
    environment_summary: str
    overall_risk_rating: str  # CRITICAL, HIGH, MEDIUM, LOW
    compliance_summary: str
    prioritized_actions: List[str]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "base_analysis": self.base_analysis.to_dict(),
            "business_assessments": [asdict(b) for b in self.business_assessments],
            "environment_summary": self.environment_summary,
            "overall_risk_rating": self.overall_risk_rating,
            "compliance_summary": self.compliance_summary,
            "prioritized_actions": self.prioritized_actions,
            "metadata": self.metadata,
        }


class BusinessContextAnalyzer:
    """Analyzes vulnerabilities with business context from environment configuration"""

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        batch_size: int = 25,
        auto_batch_threshold: int = 30,
    ):
        """
        Initialize business context analyzer.

        Args:
            llm_client: Pre-configured LLM client (optional)
            provider: AI provider if not using pre-configured client
            model: Model name if not using pre-configured client
            batch_size: Number of vulnerabilities per batch
            auto_batch_threshold: Trigger batching when count exceeds this
        """
        self.llm_client = llm_client or get_llm_client(provider=provider, model=model)
        self.vulnerability_analyzer = VulnerabilityAnalyzer(
            llm_client=self.llm_client,
            batch_size=batch_size,
            auto_batch_threshold=auto_batch_threshold,
        )

    def analyze_with_business_context(
        self,
        scan_result: GrypeScanResult,
        environment: Environment,
        asset_mapping: Optional[Dict[str, str]] = None,
        temperature: float = 0.3,
        batch_mode: Optional[str] = "auto",
    ) -> BusinessContextAnalysis:
        """
        Analyze vulnerabilities with business context from environment.

        Args:
            scan_result: GrypeScanResult from Grype scan
            environment: Environment configuration with business context
            asset_mapping: Mapping from scan target to asset ID (optional, inferred if not provided)
            temperature: LLM temperature for analysis
            batch_mode: Batching mode - "auto", "enabled", or "disabled"

        Returns:
            BusinessContextAnalysis with business risk assessments
        """
        logger.info(f"Analyzing {len(scan_result.vulnerabilities)} vulnerabilities with business context")

        # Step 1: Perform base technical analysis
        base_analysis = self.vulnerability_analyzer.analyze_scan_result(
            scan_result=scan_result,
            temperature=temperature,
            batch_mode=batch_mode,
        )

        # Step 2: Map vulnerabilities to assets
        asset = self._identify_asset(scan_result.target, environment, asset_mapping)

        if not asset:
            logger.warning(f"Could not map scan target '{scan_result.target}' to environment asset")
            # Return base analysis without business context
            return self._create_fallback_analysis(base_analysis, environment)

        logger.info(f"Mapped scan target to asset: {asset.name} (ID: {asset.id})")

        # Step 3: Calculate business risk for each vulnerability
        business_assessments = []
        for vuln in scan_result.vulnerabilities:
            assessment = self._assess_business_risk(vuln, asset, environment)
            business_assessments.append(assessment)

        # Step 4: Generate business context summary
        business_context_prompt = self._create_business_context_prompt(
            environment=environment,
            asset=asset,
            scan_result=scan_result,
            business_assessments=business_assessments,
        )

        try:
            context_response = self.llm_client.generate_json(
                business_context_prompt, temperature=temperature
            )

            overall_risk_rating = context_response.get("overall_risk_rating", "MEDIUM")
            environment_summary = context_response.get("environment_summary", "")
            compliance_summary = context_response.get("compliance_summary", "")
            prioritized_actions = context_response.get("prioritized_actions", [])

        except Exception as e:
            logger.warning(f"Failed to generate business context summary: {e}")
            overall_risk_rating = self._compute_overall_risk(business_assessments)
            environment_summary = self._generate_fallback_env_summary(asset, environment)
            compliance_summary = self._generate_fallback_compliance_summary(asset)
            prioritized_actions = []

        # Step 5: Build metadata
        metadata = {
            "asset_id": asset.id,
            "asset_name": asset.name,
            "asset_criticality": asset.business_context.criticality.value,
            "criticality_score": asset.business_context.criticality_score,
            "data_classification": asset.business_context.data_classification.value if asset.business_context.data_classification else None,
            "internet_facing": self._is_internet_facing(asset),
            "compliance_scope": [f.value for f in asset.business_context.compliance_scope] if asset.business_context.compliance_scope else [],
            "environment_name": environment.environment.name,
            "environment_type": environment.environment.type.value,
            **base_analysis.metadata,
        }

        return BusinessContextAnalysis(
            base_analysis=base_analysis,
            business_assessments=business_assessments,
            environment_summary=environment_summary,
            overall_risk_rating=overall_risk_rating,
            compliance_summary=compliance_summary,
            prioritized_actions=prioritized_actions,
            metadata=metadata,
        )

    def _identify_asset(
        self,
        scan_target: str,
        environment: Environment,
        asset_mapping: Optional[Dict[str, str]] = None,
    ) -> Optional[Asset]:
        """
        Identify which asset in the environment corresponds to the scan target.

        Args:
            scan_target: Scan target (e.g., Docker image name)
            environment: Environment configuration
            asset_mapping: Optional explicit mapping

        Returns:
            Asset object or None if not found
        """
        # Check explicit mapping first
        if asset_mapping and scan_target in asset_mapping:
            asset_id = asset_mapping[scan_target]
            for asset in environment.assets:
                if asset.id == asset_id:
                    return asset

        # Try to infer from scan target
        # Match by software image name
        for asset in environment.assets:
            if asset.software and asset.software.image:
                # Extract image name (without tag)
                image_name = asset.software.image.split(":")[0]
                if image_name in scan_target or scan_target in asset.software.image:
                    return asset

            # Match by asset name
            if asset.name.lower() in scan_target.lower() or scan_target.lower() in asset.name.lower():
                return asset

        # If single asset in environment, use it
        if len(environment.assets) == 1:
            return environment.assets[0]

        return None

    def _assess_business_risk(
        self,
        vuln: GrypeVulnerability,
        asset: Asset,
        environment: Environment,
    ) -> BusinessRiskAssessment:
        """
        Calculate business risk score for a vulnerability on a specific asset.

        Args:
            vuln: Vulnerability from scan
            asset: Asset affected by vulnerability
            environment: Environment configuration

        Returns:
            BusinessRiskAssessment with computed risk scores
        """
        # Base technical severity
        severity_scores = {
            "critical": 40,
            "high": 30,
            "medium": 20,
            "low": 10,
            "negligible": 5,
        }
        base_score = severity_scores.get(vuln.severity.lower(), 10)

        # CVSS contribution (0-30 points)
        cvss_contribution = min(vuln.cvss_score * 3, 30) if vuln.cvss_score else 0

        # Business criticality (0-20 points)
        criticality_contribution = asset.business_context.criticality_score * 0.2

        # Network exposure (0-10 points)
        exposure_contribution = 10 if self._is_internet_facing(asset) else 0

        # Data sensitivity (0-10 points)
        sensitivity_contribution = 0
        if asset.business_context.data_classification:
            sensitivity_map = {
                "pci": 10,
                "phi": 10,
                "pii": 8,
                "confidential": 6,
                "internal": 3,
                "public": 0,
            }
            sensitivity_contribution = sensitivity_map.get(
                asset.business_context.data_classification.value, 0
            )

        # Calculate total business risk score (0-100)
        business_risk_score = int(
            base_score + cvss_contribution + criticality_contribution + exposure_contribution + sensitivity_contribution
        )
        business_risk_score = min(business_risk_score, 100)

        # Determine business risk level
        if business_risk_score >= 80:
            business_risk_level = "CRITICAL"
            remediation_urgency = "IMMEDIATE"
        elif business_risk_score >= 60:
            business_risk_level = "HIGH"
            remediation_urgency = "URGENT"
        elif business_risk_score >= 40:
            business_risk_level = "MEDIUM"
            remediation_urgency = "STANDARD"
        else:
            business_risk_level = "LOW"
            remediation_urgency = "DEFERRED"

        # Build risk factors list
        risk_factors = []
        if vuln.severity.lower() in ["critical", "high"]:
            risk_factors.append(f"Technical severity: {vuln.severity.upper()}")
        if vuln.cvss_score and vuln.cvss_score >= 7.0:
            risk_factors.append(f"CVSS score: {vuln.cvss_score}")
        if asset.business_context.criticality.value in ["critical", "high"]:
            risk_factors.append(f"Asset criticality: {asset.business_context.criticality.value.upper()}")
        if self._is_internet_facing(asset):
            risk_factors.append("Internet-facing asset")
        if asset.business_context.data_classification:
            risk_factors.append(f"Sensitive data: {asset.business_context.data_classification.value.upper()}")
        if asset.business_context.customer_facing:
            risk_factors.append("Customer-facing service")

        # Business impact description
        business_impact = self._generate_business_impact_description(vuln, asset)

        # Compliance impact
        compliance_impact = []
        if asset.business_context.compliance_scope:
            compliance_impact = [f.value.upper() for f in asset.business_context.compliance_scope]

        return BusinessRiskAssessment(
            cve_id=vuln.id,
            package_name=vuln.package_name,
            asset_id=asset.id,
            asset_name=asset.name,
            technical_severity=vuln.severity.upper(),
            cvss_score=vuln.cvss_score or 0.0,
            business_risk_score=business_risk_score,
            business_risk_level=business_risk_level,
            risk_factors=risk_factors,
            business_impact=business_impact,
            compliance_impact=compliance_impact,
            recommended_priority=business_risk_level,
            remediation_urgency=remediation_urgency,
        )

    def _is_internet_facing(self, asset: Asset) -> bool:
        """Check if asset is internet-facing"""
        if not asset.network:
            return False

        # Check for public IP
        if asset.network.public_ip:
            return True

        # Check for exposed public ports
        if asset.network.exposed_ports:
            for port in asset.network.exposed_ports:
                if hasattr(port, "public") and port.public:
                    return True

        return False

    def _generate_business_impact_description(
        self, vuln: GrypeVulnerability, asset: Asset
    ) -> str:
        """Generate business impact description"""
        impact_parts = []

        # Base impact from criticality
        if asset.business_context.criticality.value == "critical":
            impact_parts.append("affects business-critical infrastructure")
        elif asset.business_context.criticality.value == "high":
            impact_parts.append("affects important business operations")

        # Data impact
        if asset.business_context.data_classification:
            data_type = asset.business_context.data_classification.value.upper()
            impact_parts.append(f"potential exposure of {data_type} data")

        # Revenue impact
        if hasattr(asset.business_context, "revenue_impact") and asset.business_context.revenue_impact:
            if asset.business_context.revenue_impact.lower() == "high":
                impact_parts.append("high revenue impact")

        # Customer impact
        if asset.business_context.customer_facing:
            impact_parts.append("customer-facing service disruption")

        if not impact_parts:
            return f"Vulnerability in {asset.name} may compromise system security"

        return f"Vulnerability in {asset.name}: " + ", ".join(impact_parts)

    def _create_business_context_prompt(
        self,
        environment: Environment,
        asset: Asset,
        scan_result: GrypeScanResult,
        business_assessments: List[BusinessRiskAssessment],
    ) -> str:
        """Create prompt for business context analysis"""
        # Compute summary statistics
        critical_count = sum(1 for a in business_assessments if a.business_risk_level == "CRITICAL")
        high_count = sum(1 for a in business_assessments if a.business_risk_level == "HIGH")

        # Collect unique compliance frameworks
        compliance_frameworks = set()
        for a in business_assessments:
            compliance_frameworks.update(a.compliance_impact)

        prompt = f"""You are a cybersecurity risk analyst providing business-context-aware risk assessment.

ENVIRONMENT CONTEXT:
- Environment: {environment.environment.name} ({environment.environment.type.value})
- Cloud Provider: {environment.environment.cloud_provider.value if environment.environment.cloud_provider else "Not specified"}
- Compliance Requirements: {", ".join([f.value.upper() for f in environment.environment.compliance_requirements]) if environment.environment.compliance_requirements else "None"}

ASSET CONTEXT:
- Asset: {asset.name} (ID: {asset.id})
- Type: {asset.type.value}
- Business Criticality: {asset.business_context.criticality.value.upper()} (Score: {asset.business_context.criticality_score}/100)
- Data Classification: {asset.business_context.data_classification.value.upper() if asset.business_context.data_classification else "Not specified"}
- Internet-Facing: {"Yes" if self._is_internet_facing(asset) else "No"}
- Customer-Facing: {"Yes" if asset.business_context.customer_facing else "No"}
- Compliance Scope: {", ".join([f.value.upper() for f in asset.business_context.compliance_scope]) if asset.business_context.compliance_scope else "None"}

VULNERABILITY SUMMARY:
- Total Vulnerabilities: {len(scan_result.vulnerabilities)}
- Critical Business Risk: {critical_count}
- High Business Risk: {high_count}
- Affected Compliance Frameworks: {", ".join(compliance_frameworks) if compliance_frameworks else "None"}

Based on this business context, provide:

1. **Overall Risk Rating**: CRITICAL|HIGH|MEDIUM|LOW for the entire asset
2. **Environment Summary**: 2-3 sentences describing the security posture in business terms
3. **Compliance Summary**: Impact on compliance requirements and regulatory obligations
4. **Prioritized Actions**: Top 5 recommended actions with business justification

Respond in JSON format:
{{
    "overall_risk_rating": "CRITICAL|HIGH|MEDIUM|LOW",
    "environment_summary": "Executive summary of security posture",
    "compliance_summary": "Compliance impact and regulatory concerns",
    "prioritized_actions": [
        "Action 1 with business justification",
        "Action 2 with business justification",
        "Action 3 with business justification"
    ]
}}
"""
        return prompt

    def _compute_overall_risk(self, business_assessments: List[BusinessRiskAssessment]) -> str:
        """Compute overall risk rating from assessments"""
        if not business_assessments:
            return "LOW"

        # Count by business risk level
        critical_count = sum(1 for a in business_assessments if a.business_risk_level == "CRITICAL")
        high_count = sum(1 for a in business_assessments if a.business_risk_level == "HIGH")

        # Determine overall rating
        if critical_count > 0:
            return "CRITICAL"
        elif high_count >= 5:
            return "CRITICAL"
        elif high_count > 0:
            return "HIGH"
        else:
            avg_score = sum(a.business_risk_score for a in business_assessments) / len(business_assessments)
            if avg_score >= 60:
                return "HIGH"
            elif avg_score >= 40:
                return "MEDIUM"
            else:
                return "LOW"

    def _generate_fallback_env_summary(self, asset: Asset, environment: Environment) -> str:
        """Generate fallback environment summary"""
        return (
            f"Asset {asset.name} in {environment.environment.name} environment has "
            f"{asset.business_context.criticality.value} business criticality. "
            f"Vulnerabilities should be assessed in context of business operations."
        )

    def _generate_fallback_compliance_summary(self, asset: Asset) -> str:
        """Generate fallback compliance summary"""
        if asset.business_context.compliance_scope:
            frameworks = ", ".join([f.value.upper() for f in asset.business_context.compliance_scope])
            return f"This asset is in scope for {frameworks} compliance. Vulnerabilities may impact compliance posture."
        return "No specific compliance requirements identified for this asset."

    def _create_fallback_analysis(
        self, base_analysis: VulnerabilityAnalysis, environment: Environment
    ) -> BusinessContextAnalysis:
        """Create fallback analysis when asset mapping fails"""
        return BusinessContextAnalysis(
            base_analysis=base_analysis,
            business_assessments=[],
            environment_summary="Unable to map scan target to environment asset. Using technical analysis only.",
            overall_risk_rating="MEDIUM",
            compliance_summary="Business context not available.",
            prioritized_actions=[],
            metadata={
                "environment_name": environment.environment.name,
                "asset_mapping": "failed",
                **base_analysis.metadata,
            },
        )

    def get_critical_business_risks(
        self, analysis: BusinessContextAnalysis
    ) -> List[BusinessRiskAssessment]:
        """
        Get all CRITICAL business risk vulnerabilities.

        Args:
            analysis: BusinessContextAnalysis result

        Returns:
            List of CRITICAL business risk assessments
        """
        return [
            a for a in analysis.business_assessments
            if a.business_risk_level == "CRITICAL"
        ]

    def get_top_business_risks(
        self, analysis: BusinessContextAnalysis, limit: int = 10
    ) -> List[BusinessRiskAssessment]:
        """
        Get top N business risks sorted by business risk score.

        Args:
            analysis: BusinessContextAnalysis result
            limit: Maximum number to return

        Returns:
            Top business risks sorted by score (highest first)
        """
        sorted_risks = sorted(
            analysis.business_assessments,
            key=lambda a: a.business_risk_score,
            reverse=True,
        )
        return sorted_risks[:limit]
