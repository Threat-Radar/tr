"""AI-powered attack scenario generation with MITRE ATT&CK mapping.

This module generates realistic attack scenarios from attack paths using AI,
including narratives, MITRE ATT&CK mappings, and business impact assessments.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
import logging
import json

from threat_radar.ai.llm_client import LLMClient, get_llm_client
from threat_radar.ai.threat_actor_modeler import ThreatActorPersona
from threat_radar.graph.models import AttackPath, AttackStep, AttackStepType

logger = logging.getLogger(__name__)


@dataclass
class MitreTTP:
    """MITRE ATT&CK Tactic, Technique, and Procedure mapping."""

    ttp_id: str                    # e.g., "T1190"
    ttp_name: str                  # e.g., "Exploit Public-Facing Application"
    tactic: str                    # e.g., "Initial Access"
    technique_description: str     # How it's used in this scenario
    subtechnique: Optional[str] = None  # e.g., "T1190.001"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class AttackPhase:
    """A single phase/step in the attack timeline."""

    phase_number: int
    ttp: MitreTTP
    description: str               # AI-generated detailed description
    duration_estimate: str         # e.g., "1-2 hours", "2-3 days"
    cves_exploited: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    indicators_of_compromise: List[str] = field(default_factory=list)
    detection_methods: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data['ttp'] = self.ttp.to_dict()
        return data


@dataclass
class BusinessImpact:
    """Business impact assessment for the attack scenario."""

    estimated_cost: str            # e.g., "$2.5M - $5M"
    compliance_violations: List[str] = field(default_factory=list)
    reputation_damage: str = "unknown"  # "severe", "moderate", "low"
    customer_impact: str = "unknown"
    recovery_time: str = "unknown"  # e.g., "2-4 weeks"
    data_at_risk: str = "unknown"  # e.g., "500,000 payment records"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class AttackScenario:
    """Complete attack scenario with narrative and business context."""

    scenario_id: str
    threat_actor: str              # Persona name
    attack_path_id: str            # Reference to source AttackPath
    narrative: str                 # AI-generated attack story
    timeline: List[AttackPhase]
    business_impact: BusinessImpact
    detection_opportunities: List[str] = field(default_factory=list)
    mitigation_priorities: List[str] = field(default_factory=list)
    confidence_score: float = 0.0  # AI confidence in scenario realism (0-1)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scenario_id": self.scenario_id,
            "threat_actor": self.threat_actor,
            "attack_path_id": self.attack_path_id,
            "narrative": self.narrative,
            "timeline": [phase.to_dict() for phase in self.timeline],
            "business_impact": self.business_impact.to_dict(),
            "detection_opportunities": self.detection_opportunities,
            "mitigation_priorities": self.mitigation_priorities,
            "confidence_score": self.confidence_score
        }


class AttackScenarioGenerator:
    """
    Generates realistic attack scenarios from attack paths using AI.

    Integrates threat actor personas, MITRE ATT&CK framework, and business
    context to create comprehensive threat scenarios.
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None
    ):
        """
        Initialize scenario generator.

        Args:
            llm_client: Pre-configured LLM client (optional)
            provider: AI provider if not using pre-configured client
            model: Model name if not using pre-configured client
        """
        self.llm_client = llm_client or get_llm_client(provider=provider, model=model)
        logger.info("Initialized AttackScenarioGenerator")

    def generate_scenario(
        self,
        attack_path: AttackPath,
        threat_actor: ThreatActorPersona,
        business_context: Optional[Dict[str, Any]] = None,
        temperature: float = 0.4
    ) -> AttackScenario:
        """
        Generate comprehensive attack scenario from attack path.

        Args:
            attack_path: Attack path from graph analysis
            threat_actor: Threat actor persona
            business_context: Optional business/environment context
            temperature: LLM temperature for generation

        Returns:
            Complete AttackScenario with narrative and analysis
        """
        logger.info(
            f"Generating scenario for path {attack_path.path_id} "
            f"with actor {threat_actor.name}"
        )

        # Map attack steps to MITRE ATT&CK
        mitre_mapping = self._map_to_mitre_attack(attack_path, threat_actor)

        # Generate narrative
        narrative = self._generate_narrative(
            attack_path,
            threat_actor,
            mitre_mapping,
            business_context,
            temperature
        )

        # Create timeline
        timeline = self._create_timeline(
            attack_path,
            threat_actor,
            mitre_mapping,
            temperature
        )

        # Calculate business impact
        business_impact = self._calculate_business_impact(
            attack_path,
            threat_actor,
            business_context,
            temperature
        )

        # Generate detection opportunities
        detection_opportunities = self._generate_detection_opportunities(
            attack_path,
            mitre_mapping
        )

        # Generate mitigation priorities
        mitigation_priorities = self._generate_mitigation_priorities(
            attack_path,
            threat_actor,
            business_context
        )

        # Calculate confidence score
        confidence_score = self._calculate_confidence_score(
            attack_path,
            threat_actor
        )

        scenario = AttackScenario(
            scenario_id=f"scenario_{attack_path.path_id}",
            threat_actor=threat_actor.name,
            attack_path_id=attack_path.path_id,
            narrative=narrative,
            timeline=timeline,
            business_impact=business_impact,
            detection_opportunities=detection_opportunities,
            mitigation_priorities=mitigation_priorities,
            confidence_score=confidence_score
        )

        logger.info(
            f"Generated scenario {scenario.scenario_id} with {len(timeline)} phases "
            f"(confidence: {confidence_score:.2f})"
        )

        return scenario

    def _map_to_mitre_attack(
        self,
        attack_path: AttackPath,
        threat_actor: ThreatActorPersona
    ) -> List[MitreTTP]:
        """
        Map attack steps to MITRE ATT&CK techniques.

        Args:
            attack_path: Attack path to map
            threat_actor: Threat actor persona (provides known TTPs)

        Returns:
            List of MITRE TTPs for each step
        """
        mitre_ttps = []

        for i, step in enumerate(attack_path.steps):
            # Map step type to MITRE ATT&CK technique
            ttp_id, ttp_name, tactic = self._step_type_to_mitre(step.step_type)

            # Try to use actor's preferred TTPs if available
            if i < len(threat_actor.ttps):
                preferred_ttp = threat_actor.ttps[i]
                # Use preferred TTP if it matches the tactic
                if self._ttp_matches_tactic(preferred_ttp, tactic):
                    ttp_id = preferred_ttp
                    ttp_name = self._get_ttp_name(ttp_id)

            technique_desc = self._generate_technique_description(
                step,
                ttp_id,
                ttp_name
            )

            mitre_ttp = MitreTTP(
                ttp_id=ttp_id,
                ttp_name=ttp_name,
                tactic=tactic,
                technique_description=technique_desc
            )

            mitre_ttps.append(mitre_ttp)

        return mitre_ttps

    def _step_type_to_mitre(
        self,
        step_type: AttackStepType
    ) -> tuple[str, str, str]:
        """
        Map attack step type to MITRE ATT&CK technique.

        Returns:
            Tuple of (ttp_id, ttp_name, tactic)
        """
        mapping = {
            AttackStepType.ENTRY_POINT: (
                "T1190",
                "Exploit Public-Facing Application",
                "Initial Access"
            ),
            AttackStepType.EXPLOIT_VULNERABILITY: (
                "T1210",
                "Exploitation of Remote Services",
                "Lateral Movement"
            ),
            AttackStepType.PRIVILEGE_ESCALATION: (
                "T1068",
                "Exploitation for Privilege Escalation",
                "Privilege Escalation"
            ),
            AttackStepType.LATERAL_MOVEMENT: (
                "T1021",
                "Remote Services",
                "Lateral Movement"
            ),
            AttackStepType.TARGET_ACCESS: (
                "T1005",
                "Data from Local System",
                "Collection"
            ),
            AttackStepType.DATA_EXFILTRATION: (
                "T1041",
                "Exfiltration Over C2 Channel",
                "Exfiltration"
            )
        }

        return mapping.get(
            step_type,
            ("T1059", "Command and Scripting Interpreter", "Execution")
        )

    def _ttp_matches_tactic(self, ttp_id: str, tactic: str) -> bool:
        """Check if TTP matches the expected tactic (simplified)."""
        # Simplified mapping - in production would use MITRE ATT&CK database
        initial_access_ttps = ["T1190", "T1189", "T1566", "T1078"]
        lateral_movement_ttps = ["T1021", "T1210", "T1080"]
        privilege_escalation_ttps = ["T1068", "T1078", "T1055"]

        if tactic == "Initial Access" and ttp_id in initial_access_ttps:
            return True
        elif tactic == "Lateral Movement" and ttp_id in lateral_movement_ttps:
            return True
        elif tactic == "Privilege Escalation" and ttp_id in privilege_escalation_ttps:
            return True

        return False

    def _get_ttp_name(self, ttp_id: str) -> str:
        """Get TTP name from ID (simplified mapping)."""
        ttp_names = {
            "T1190": "Exploit Public-Facing Application",
            "T1078": "Valid Accounts",
            "T1021": "Remote Services",
            "T1071": "Application Layer Protocol",
            "T1087": "Account Discovery",
            "T1083": "File and Directory Discovery",
            "T1005": "Data from Local System",
            "T1041": "Exfiltration Over C2 Channel",
            "T1133": "External Remote Services",
            "T1059": "Command and Scripting Interpreter",
            "T1486": "Data Encrypted for Impact",
            "T1110": "Brute Force",
            "T1210": "Exploitation of Remote Services",
            "T1595": "Active Scanning",
            "T1213": "Data from Information Repositories",
            "T1068": "Exploitation for Privilege Escalation",
        }

        return ttp_names.get(ttp_id, "Unknown Technique")

    def _generate_technique_description(
        self,
        step: AttackStep,
        ttp_id: str,
        ttp_name: str
    ) -> str:
        """Generate description of how technique is used in this step."""
        cves = ", ".join(step.vulnerabilities) if step.vulnerabilities else "known vulnerabilities"

        descriptions = {
            "T1190": f"Exploit {cves} in public-facing {step.node_id} to gain initial access",
            "T1078": f"Use compromised credentials to access {step.node_id}",
            "T1021": f"Establish remote session to {step.node_id}",
            "T1210": f"Exploit {cves} in {step.node_id} for lateral movement",
            "T1068": f"Exploit {cves} to escalate privileges on {step.node_id}",
            "T1005": f"Access and collect data from {step.node_id}",
        }

        return descriptions.get(
            ttp_id,
            f"Use {ttp_name} technique on {step.node_id}"
        )

    def _generate_narrative(
        self,
        attack_path: AttackPath,
        threat_actor: ThreatActorPersona,
        mitre_mapping: List[MitreTTP],
        business_context: Optional[Dict],
        temperature: float
    ) -> str:
        """Generate AI-powered attack narrative (story format)."""
        # Import prompt function from prompt_templates (will be added in Phase 4)
        from threat_radar.ai.prompt_templates import create_attack_scenario_prompt

        # Prepare context for AI
        context = {
            "threat_actor": {
                "name": threat_actor.name,
                "description": threat_actor.description,
                "motivations": threat_actor.motivations,
                "skill_level": threat_actor.skill_level.value
            },
            "attack_path": {
                "entry_point": attack_path.entry_point,
                "target": attack_path.target,
                "path_length": attack_path.path_length,
                "total_cvss": attack_path.total_cvss,
                "threat_level": attack_path.threat_level.value,
                "steps": [
                    {
                        "description": step.description,
                        "vulnerabilities": step.vulnerabilities,
                        "cvss_score": step.cvss_score
                    }
                    for step in attack_path.steps
                ]
            },
            "mitre_mapping": [
                {
                    "ttp_id": ttp.ttp_id,
                    "ttp_name": ttp.ttp_name,
                    "tactic": ttp.tactic
                }
                for ttp in mitre_mapping
            ],
            "business_context": business_context or {}
        }

        # Generate prompt
        prompt = create_attack_scenario_prompt(context)

        try:
            # Generate narrative with AI
            narrative = self.llm_client.generate(prompt, temperature=temperature)
            return narrative.strip()
        except Exception as e:
            logger.warning(f"Failed to generate AI narrative: {e}")
            # Fallback to template-based narrative
            return self._generate_fallback_narrative(
                attack_path,
                threat_actor,
                mitre_mapping
            )

    def _generate_fallback_narrative(
        self,
        attack_path: AttackPath,
        threat_actor: ThreatActorPersona,
        mitre_mapping: List[MitreTTP]
    ) -> str:
        """Generate template-based narrative as fallback."""
        narrative_parts = [
            f"Attack Scenario: {threat_actor.name} Targeting {attack_path.target}\n",
            f"\n{threat_actor.name}, motivated by {', '.join(threat_actor.motivations)}, ",
            f"initiates a {attack_path.path_length}-stage attack against {attack_path.target}. ",
            f"The attack begins with {attack_path.steps[0].description}. "
        ]

        # Add middle steps
        if len(attack_path.steps) > 2:
            narrative_parts.append(
                f"The attacker then progresses through {len(attack_path.steps) - 2} "
                f"intermediate stages, exploiting vulnerabilities and moving laterally. "
            )

        # Add final step
        narrative_parts.append(
            f"Finally, {attack_path.steps[-1].description}, "
            f"achieving their objective with a threat level of {attack_path.threat_level.value.upper()}."
        )

        return "".join(narrative_parts)

    def _create_timeline(
        self,
        attack_path: AttackPath,
        threat_actor: ThreatActorPersona,
        mitre_mapping: List[MitreTTP],
        temperature: float
    ) -> List[AttackPhase]:
        """Create attack timeline with phases."""
        timeline = []

        for i, (step, ttp) in enumerate(zip(attack_path.steps, mitre_mapping)):
            # Estimate duration based on actor speed and step complexity
            duration = self._estimate_phase_duration(
                step,
                threat_actor,
                i
            )

            # Generate detection methods
            detection_methods = self._generate_detection_methods_for_step(step, ttp)

            # Generate prerequisites
            prerequisites = []
            if i == 0:
                prerequisites = ["Internet access to target", "Target reconnaissance"]
            else:
                prerequisites = [f"Successful completion of Phase {i}"]

            # Generate IOCs
            iocs = self._generate_iocs_for_step(step, ttp)

            phase = AttackPhase(
                phase_number=i + 1,
                ttp=ttp,
                description=step.description,
                duration_estimate=duration,
                cves_exploited=step.vulnerabilities,
                prerequisites=prerequisites,
                indicators_of_compromise=iocs,
                detection_methods=detection_methods
            )

            timeline.append(phase)

        return timeline

    def _estimate_phase_duration(
        self,
        step: AttackStep,
        threat_actor: ThreatActorPersona,
        phase_index: int
    ) -> str:
        """Estimate phase duration based on complexity and actor speed."""
        # Fast actors (speed > 0.7) complete phases quickly
        # Patient actors (speed < 0.3) take longer

        if threat_actor.speed_preference > 0.7:
            # Fast actor (ransomware, script kiddie)
            durations = ["minutes", "1-2 hours", "2-4 hours", "4-8 hours"]
        elif threat_actor.speed_preference < 0.3:
            # Patient actor (APT, nation-state)
            durations = ["1-2 days", "3-5 days", "1-2 weeks", "2-4 weeks"]
        else:
            # Moderate speed
            durations = ["1-2 hours", "4-8 hours", "1-2 days", "2-3 days"]

        # Initial access typically takes longer
        if phase_index == 0:
            return durations[min(2, len(durations) - 1)]

        # Later phases depend on complexity
        complexity_index = min(phase_index, len(durations) - 1)
        return durations[complexity_index]

    def _generate_detection_methods_for_step(
        self,
        step: AttackStep,
        ttp: MitreTTP
    ) -> List[str]:
        """Generate detection methods for attack step."""
        detection_methods = []

        # Map tactics to detection methods
        tactic_detection = {
            "Initial Access": [
                "Web Application Firewall (WAF) logs",
                "IDS/IPS signatures",
                "Network traffic analysis",
                "Endpoint detection and response (EDR)"
            ],
            "Lateral Movement": [
                "Network segmentation monitoring",
                "Abnormal authentication patterns",
                "East-west traffic analysis",
                "Privileged access monitoring"
            ],
            "Privilege Escalation": [
                "Privilege escalation detection rules",
                "System call monitoring",
                "Security event logs (4672, 4673)",
                "Process behavior analysis"
            ],
            "Collection": [
                "Data loss prevention (DLP)",
                "File access monitoring",
                "Database activity monitoring",
                "Abnormal data access patterns"
            ]
        }

        detection_methods.extend(
            tactic_detection.get(ttp.tactic, ["Security monitoring", "SIEM alerts"])
        )

        # Add CVE-specific detection if available
        if step.vulnerabilities:
            detection_methods.append(
                f"Vulnerability exploitation signatures for {step.vulnerabilities[0]}"
            )

        return detection_methods[:3]  # Return top 3

    def _generate_iocs_for_step(
        self,
        step: AttackStep,
        ttp: MitreTTP
    ) -> List[str]:
        """Generate indicators of compromise for step."""
        iocs = []

        step_type_iocs = {
            AttackStepType.ENTRY_POINT: [
                "Unusual HTTP requests with exploit payloads",
                "Unexpected process spawning",
                "New network connections from web server"
            ],
            AttackStepType.EXPLOIT_VULNERABILITY: [
                "Abnormal process execution",
                "Suspicious command-line arguments",
                "Unexpected file modifications"
            ],
            AttackStepType.PRIVILEGE_ESCALATION: [
                "Privilege token manipulation",
                "Unexpected elevation of user rights",
                "Suspicious system service creation"
            ],
            AttackStepType.LATERAL_MOVEMENT: [
                "Unusual remote access sessions",
                "Abnormal authentication from compromised host",
                "New network connections between internal systems"
            ]
        }

        iocs.extend(
            step_type_iocs.get(step.step_type, ["Anomalous system behavior"])
        )

        return iocs[:3]  # Return top 3

    def _calculate_business_impact(
        self,
        attack_path: AttackPath,
        threat_actor: ThreatActorPersona,
        business_context: Optional[Dict],
        temperature: float
    ) -> BusinessImpact:
        """Calculate business impact with AI reasoning."""
        # Simplified calculation - in production would use AI for detailed assessment

        estimated_cost = "Unknown"
        if attack_path.total_cvss > 25:
            estimated_cost = "$2M - $5M"
        elif attack_path.total_cvss > 15:
            estimated_cost = "$500K - $2M"
        else:
            estimated_cost = "$100K - $500K"

        # Check for compliance violations from business context
        compliance_violations = []
        if business_context:
            if business_context.get("pci_scope"):
                compliance_violations.append("PCI-DSS 6.5.1 (Application Vulnerabilities)")
            if business_context.get("hipaa_scope"):
                compliance_violations.append("HIPAA Security Rule 164.308")
            if business_context.get("gdpr_scope"):
                compliance_violations.append("GDPR Article 32 (Security of Processing)")

        # Reputation damage based on threat level
        reputation_damage = {
            "critical": "severe",
            "high": "moderate",
            "medium": "low",
            "low": "minimal"
        }.get(attack_path.threat_level.value, "unknown")

        return BusinessImpact(
            estimated_cost=estimated_cost,
            compliance_violations=compliance_violations,
            reputation_damage=reputation_damage,
            customer_impact=business_context.get("customer_impact", "Unknown") if business_context else "Unknown",
            recovery_time="2-4 weeks" if attack_path.threat_level.value in ["critical", "high"] else "1-2 weeks"
        )

    def _generate_detection_opportunities(
        self,
        attack_path: AttackPath,
        mitre_mapping: List[MitreTTP]
    ) -> List[str]:
        """Generate high-level detection opportunities."""
        opportunities = set()

        for step, ttp in zip(attack_path.steps, mitre_mapping):
            opportunities.add(f"{ttp.tactic}: Monitor for {ttp.ttp_name}")

        return sorted(list(opportunities))

    def _generate_mitigation_priorities(
        self,
        attack_path: AttackPath,
        threat_actor: ThreatActorPersona,
        business_context: Optional[Dict]
    ) -> List[str]:
        """Generate prioritized mitigation recommendations."""
        priorities = []

        # Critical CVEs first
        critical_cves = []
        for step in attack_path.steps:
            if step.cvss_score and step.cvss_score >= 9.0:
                critical_cves.extend(step.vulnerabilities)

        if critical_cves:
            priorities.append(
                f"URGENT: Patch {len(critical_cves)} critical vulnerabilities "
                f"(CVSS ≥ 9.0): {', '.join(critical_cves[:3])}"
            )

        # Network segmentation
        if any(step.step_type == AttackStepType.LATERAL_MOVEMENT for step in attack_path.steps):
            priorities.append(
                "HIGH: Implement network segmentation to prevent lateral movement"
            )

        # Monitoring
        priorities.append(
            f"MEDIUM: Deploy detection controls for {threat_actor.name} TTPs"
        )

        return priorities

    def _calculate_confidence_score(
        self,
        attack_path: AttackPath,
        threat_actor: ThreatActorPersona
    ) -> float:
        """Calculate confidence score for scenario realism."""
        score = 0.8  # Base confidence

        # Higher confidence for paths matching actor capabilities
        if threat_actor.matches_path_complexity(attack_path.path_length):
            score += 0.1

        # Higher confidence for high CVSS paths
        if attack_path.total_cvss > 20:
            score += 0.1

        return min(1.0, score)
