"""Threat actor persona modeling for realistic attack scenario generation.

This module provides threat actor personas with different capabilities, motivations,
and tactics to filter and prioritize attack paths based on adversary characteristics.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from enum import Enum
import logging

from threat_radar.graph.models import AttackPath, ThreatLevel

logger = logging.getLogger(__name__)


class ThreatActorType(str, Enum):
    """Types of threat actors with different capabilities and motivations."""

    APT = "apt"  # Advanced Persistent Threat (nation-state backed)
    RANSOMWARE = "ransomware"  # Ransomware gang (organized crime)
    SCRIPT_KIDDIE = "script-kiddie"  # Low-skill opportunistic attacker
    INSIDER = "insider"  # Internal threat (malicious employee)
    HACKTIVIST = "hacktivist"  # Ideologically motivated group
    NATION_STATE = "nation-state"  # State-sponsored cyber warfare


class SkillLevel(str, Enum):
    """Skill level of threat actors."""

    EXPERT = "expert"  # Nation-state level capabilities
    ADVANCED = "advanced"  # APT groups, sophisticated criminals
    INTERMEDIATE = "intermediate"  # Organized crime, some APTs
    NOVICE = "novice"  # Script kiddies, low-skill attackers


class ResourceLevel(str, Enum):
    """Resources available to threat actor."""

    NATION_STATE = "nation-state"  # Unlimited resources
    ORGANIZED_CRIME = "organized-crime"  # Significant resources
    GROUP = "group"  # Moderate resources
    INDIVIDUAL = "individual"  # Limited resources


@dataclass
class ThreatActorPersona:
    """
    Threat actor persona with capabilities, motivations, and attack preferences.

    Attributes:
        actor_id: Unique identifier for the persona
        actor_type: Type of threat actor
        name: Human-readable name (e.g., "APT28 (Fancy Bear)")
        skill_level: Technical skill level
        resources: Resource availability
        motivations: Primary motivations (espionage, financial, disruption)
        target_preferences: Preferred target types (pci_scope, confidential, etc.)
        ttps: MITRE ATT&CK technique IDs the actor commonly uses
        min_path_complexity: Minimum attack path hops for realistic scenario
        max_path_complexity: Maximum hops attacker would attempt
        requires_public_exploit: Whether actor needs publicly known exploits
        prefers_high_value_targets: Whether actor focuses on critical assets
        stealth_preference: How much actor values staying undetected (0.0-1.0)
        speed_preference: How quickly actor operates (0.0-1.0)
        description: Detailed description of the threat actor
    """

    actor_id: str
    actor_type: ThreatActorType
    name: str
    skill_level: SkillLevel
    resources: ResourceLevel
    motivations: List[str]
    target_preferences: List[str]
    ttps: List[str]
    min_path_complexity: int = 1
    max_path_complexity: int = 10
    requires_public_exploit: bool = False
    prefers_high_value_targets: bool = True
    stealth_preference: float = 0.5  # 0.0 = loud, 1.0 = very stealthy
    speed_preference: float = 0.5  # 0.0 = slow/patient, 1.0 = fast
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert persona to dictionary."""
        return asdict(self)

    def matches_path_complexity(self, path_length: int) -> bool:
        """Check if attack path complexity matches actor capabilities."""
        return self.min_path_complexity <= path_length <= self.max_path_complexity

    def prefers_target(self, target_data: Dict[str, Any]) -> float:
        """
        Calculate preference score (0.0-1.0) for a target based on actor preferences.

        Args:
            target_data: Node data for the target asset

        Returns:
            Preference score (0.0 = no interest, 1.0 = perfect match)
        """
        score = 0.0
        max_score = 0.0

        # Check target preferences
        for preference in self.target_preferences:
            max_score += 1.0

            if preference == "pci_scope" and target_data.get("pci_scope"):
                score += 1.0
            elif preference == "hipaa_scope" and target_data.get("hipaa_scope"):
                score += 1.0
            elif preference == "confidential":
                data_class = target_data.get("data_classification", "").lower()
                if data_class in ["confidential", "restricted", "pci", "phi"]:
                    score += 1.0
            elif preference == "critical":
                criticality = target_data.get("criticality", "").lower()
                if criticality in ["critical", "high"]:
                    score += 1.0
            elif preference == "customer_facing" and target_data.get("customer_facing"):
                score += 1.0
            elif preference == "database":
                function = target_data.get("function", "").lower()
                if "database" in function or "db" in function:
                    score += 1.0
            elif preference == "payment":
                function = target_data.get("function", "").lower()
                if "payment" in function or "transaction" in function:
                    score += 1.0

        # Return normalized score
        return score / max_score if max_score > 0 else 0.5


class ThreatActorModeler:
    """
    Manages threat actor personas and filters attack paths based on actor characteristics.

    Provides pre-built personas for common threat actor types and methods to
    filter/rank attack paths based on actor capabilities and preferences.
    """

    def __init__(self):
        """Initialize with pre-built threat actor personas."""
        self.personas = self._load_persona_library()
        logger.info(f"Loaded {len(self.personas)} threat actor personas")

    def _load_persona_library(self) -> Dict[str, ThreatActorPersona]:
        """
        Load library of pre-built threat actor personas.

        Returns:
            Dictionary mapping actor_id to ThreatActorPersona
        """
        personas = {}

        # 1. APT28 (Fancy Bear) - Russian APT group
        personas["apt28"] = ThreatActorPersona(
            actor_id="apt28",
            actor_type=ThreatActorType.APT,
            name="APT28 (Fancy Bear)",
            skill_level=SkillLevel.EXPERT,
            resources=ResourceLevel.NATION_STATE,
            motivations=["espionage", "intelligence gathering", "disruption"],
            target_preferences=["confidential", "critical", "government", "defense"],
            ttps=[
                "T1190",  # Exploit Public-Facing Application
                "T1078",  # Valid Accounts
                "T1021",  # Remote Services
                "T1071",  # Application Layer Protocol
                "T1087",  # Account Discovery
                "T1083",  # File and Directory Discovery
                "T1005",  # Data from Local System
                "T1041",  # Exfiltration Over C2 Channel
            ],
            min_path_complexity=3,
            max_path_complexity=15,
            requires_public_exploit=False,
            prefers_high_value_targets=True,
            stealth_preference=0.9,  # Very stealthy
            speed_preference=0.3,  # Patient, methodical
            description=(
                "APT28 (Fancy Bear) is a sophisticated Russian nation-state threat actor "
                "attributed to GRU Unit 26165. Known for multi-stage attacks targeting "
                "government, military, and critical infrastructure. Prefers long-term "
                "access and uses custom malware with advanced evasion techniques. "
                "Highly patient and capable of complex multi-hop attacks."
            ),
        )

        # 2. REvil Ransomware Gang - Organized cybercrime
        personas["ransomware"] = ThreatActorPersona(
            actor_id="ransomware",
            actor_type=ThreatActorType.RANSOMWARE,
            name="REvil Ransomware Gang",
            skill_level=SkillLevel.ADVANCED,
            resources=ResourceLevel.ORGANIZED_CRIME,
            motivations=["financial", "extortion"],
            target_preferences=["pci_scope", "customer_facing", "payment", "database"],
            ttps=[
                "T1190",  # Exploit Public-Facing Application
                "T1133",  # External Remote Services
                "T1059",  # Command and Scripting Interpreter
                "T1486",  # Data Encrypted for Impact
                "T1489",  # Service Stop
                "T1490",  # Inhibit System Recovery
                "T1491",  # Defacement
                "T1561",  # Disk Wipe
            ],
            min_path_complexity=1,
            max_path_complexity=5,
            requires_public_exploit=False,
            prefers_high_value_targets=True,
            stealth_preference=0.4,  # Some stealth, but not primary concern
            speed_preference=0.9,  # Fast operations
            description=(
                "REvil (Sodinokibi) is a sophisticated ransomware-as-a-service (RaaS) "
                "operation run by organized criminals. Targets high-revenue organizations "
                "with double-extortion tactics (encryption + data leak threats). "
                "Prefers fast attacks with maximum business impact. Typically demands "
                "payments in millions of dollars. Less concerned with stealth after "
                "initial access is achieved."
            ),
        )

        # 3. Script Kiddie - Low-skill opportunistic attacker
        personas["script_kiddie"] = ThreatActorPersona(
            actor_id="script_kiddie",
            actor_type=ThreatActorType.SCRIPT_KIDDIE,
            name="Script Kiddie (Opportunistic Attacker)",
            skill_level=SkillLevel.NOVICE,
            resources=ResourceLevel.INDIVIDUAL,
            motivations=["notoriety", "financial", "curiosity"],
            target_preferences=["internet_facing", "public"],
            ttps=[
                "T1190",  # Exploit Public-Facing Application (with public exploits)
                "T1110",  # Brute Force
                "T1210",  # Exploitation of Remote Services
                "T1595",  # Active Scanning
            ],
            min_path_complexity=1,
            max_path_complexity=2,
            requires_public_exploit=True,
            prefers_high_value_targets=False,
            stealth_preference=0.1,  # Little to no stealth
            speed_preference=0.8,  # Fast, opportunistic
            description=(
                "Script kiddies are low-skill attackers who use pre-made tools and "
                "publicly available exploits. Limited technical knowledge and resources. "
                "Target low-hanging fruit and internet-facing systems. Use automated "
                "scanning tools and exploit kits. Quickly move on if initial exploit fails. "
                "Pose lower risk but higher volume of attempts."
            ),
        )

        # 4. Malicious Insider - Internal threat
        personas["insider"] = ThreatActorPersona(
            actor_id="insider",
            actor_type=ThreatActorType.INSIDER,
            name="Malicious Insider (Disgruntled Employee)",
            skill_level=SkillLevel.INTERMEDIATE,
            resources=ResourceLevel.INDIVIDUAL,
            motivations=["revenge", "financial", "ideology"],
            target_preferences=["confidential", "database", "critical", "pci_scope"],
            ttps=[
                "T1078",  # Valid Accounts (already has access)
                "T1213",  # Data from Information Repositories
                "T1005",  # Data from Local System
                "T1039",  # Data from Network Shared Drive
                "T1114",  # Email Collection
                "T1020",  # Automated Exfiltration
                "T1048",  # Exfiltration Over Alternative Protocol
                "T1485",  # Data Destruction
            ],
            min_path_complexity=1,
            max_path_complexity=4,
            requires_public_exploit=False,
            prefers_high_value_targets=True,
            stealth_preference=0.6,  # Moderate stealth (has legitimate access)
            speed_preference=0.5,  # Varies by motivation
            description=(
                "Malicious insiders are employees, contractors, or trusted users who "
                "abuse their legitimate access. Can be highly dangerous due to knowledge "
                "of internal systems and existing privileges. Motivations include revenge "
                "(disgruntled employees), financial gain (data theft), or ideology. "
                "Often bypass perimeter security entirely. Detection relies on behavioral "
                "analysis and access monitoring."
            ),
        )

        # 5. Nation-State Actor - State-sponsored cyber warfare
        personas["nation_state"] = ThreatActorPersona(
            actor_id="nation_state",
            actor_type=ThreatActorType.NATION_STATE,
            name="Nation-State Actor (Generic State-Sponsored)",
            skill_level=SkillLevel.EXPERT,
            resources=ResourceLevel.NATION_STATE,
            motivations=["espionage", "sabotage", "strategic advantage", "disruption"],
            target_preferences=[
                "critical",
                "confidential",
                "government",
                "infrastructure",
            ],
            ttps=[
                "T1195",  # Supply Chain Compromise
                "T1189",  # Drive-by Compromise
                "T1566",  # Phishing
                "T1078",  # Valid Accounts
                "T1055",  # Process Injection
                "T1027",  # Obfuscated Files or Information
                "T1070",  # Indicator Removal
                "T1048",  # Exfiltration Over Alternative Protocol
            ],
            min_path_complexity=2,
            max_path_complexity=20,
            requires_public_exploit=False,
            prefers_high_value_targets=True,
            stealth_preference=1.0,  # Maximum stealth
            speed_preference=0.2,  # Extremely patient
            description=(
                "Nation-state actors are state-sponsored groups with extensive resources, "
                "advanced capabilities, and long-term strategic objectives. Capable of "
                "zero-day exploits, supply chain attacks, and sophisticated evasion. "
                "Extremely patient with campaigns lasting months or years. Primary goals "
                "include intelligence gathering, sabotage, and strategic positioning. "
                "Represent highest threat level with virtually unlimited resources."
            ),
        )

        return personas

    def get_persona(self, actor_type: str) -> ThreatActorPersona:
        """
        Get threat actor persona by type or ID.

        Args:
            actor_type: Actor type or ID (e.g., "apt28", "ransomware", "apt")

        Returns:
            ThreatActorPersona instance

        Raises:
            ValueError: If actor type not found
        """
        actor_type_lower = actor_type.lower().replace(" ", "_").replace("-", "_")

        # Direct match
        if actor_type_lower in self.personas:
            return self.personas[actor_type_lower]

        # Try matching by ThreatActorType enum
        for persona in self.personas.values():
            if persona.actor_type.value == actor_type_lower:
                return persona

        # List available types
        available = ", ".join(self.personas.keys())
        raise ValueError(
            f"Unknown threat actor type: {actor_type}. " f"Available types: {available}"
        )

    def list_personas(self) -> List[ThreatActorPersona]:
        """
        Get list of all available threat actor personas.

        Returns:
            List of all ThreatActorPersona instances
        """
        return list(self.personas.values())

    def filter_attack_paths_by_actor(
        self,
        paths: List[AttackPath],
        persona: ThreatActorPersona,
        target_nodes_data: Optional[Dict[str, Dict]] = None,
    ) -> List[AttackPath]:
        """
        Filter attack paths suitable for the given threat actor.

        Filters based on:
        - Path complexity (min/max hops)
        - Exploit availability (public vs. zero-day)
        - Target preferences

        Args:
            paths: List of attack paths to filter
            persona: Threat actor persona
            target_nodes_data: Optional dict mapping target node IDs to node data

        Returns:
            Filtered list of attack paths suitable for the actor
        """
        filtered_paths = []

        for path in paths:
            # Check path complexity
            if not persona.matches_path_complexity(path.path_length):
                logger.debug(
                    f"Path {path.path_id} complexity {path.path_length} "
                    f"outside actor range [{persona.min_path_complexity}, {persona.max_path_complexity}]"
                )
                continue

            # Script kiddies need public exploits
            if persona.requires_public_exploit:
                # In real implementation, would check CVE database for exploit availability
                # For now, assume all high CVSS vulnerabilities have exploits
                has_exploitable_vuln = False
                for step in path.steps:
                    if step.cvss_score and step.cvss_score >= 7.0:
                        has_exploitable_vuln = True
                        break

                if not has_exploitable_vuln:
                    logger.debug(
                        f"Path {path.path_id} lacks publicly exploitable vulnerabilities "
                        f"(required for {persona.name})"
                    )
                    continue

            # Check target preferences if data available
            if target_nodes_data and path.target in target_nodes_data:
                target_data = target_nodes_data[path.target]
                preference_score = persona.prefers_target(target_data)

                # Require at least some interest (>0.3) for high-value-target actors
                if persona.prefers_high_value_targets and preference_score < 0.3:
                    logger.debug(
                        f"Path {path.path_id} target preference score {preference_score:.2f} "
                        f"too low for {persona.name}"
                    )
                    continue

            filtered_paths.append(path)

        logger.info(
            f"Filtered {len(paths)} paths to {len(filtered_paths)} "
            f"suitable for {persona.name}"
        )

        return filtered_paths

    def rank_paths_by_actor_preference(
        self,
        paths: List[AttackPath],
        persona: ThreatActorPersona,
        target_nodes_data: Optional[Dict[str, Dict]] = None,
    ) -> List[AttackPath]:
        """
        Rank attack paths by threat actor preferences.

        Ranking considers:
        - Target preference score
        - Path complexity (shorter for speed, longer for stealth)
        - Threat level (critical targets prioritized)

        Args:
            paths: List of attack paths to rank
            persona: Threat actor persona
            target_nodes_data: Optional dict mapping target node IDs to node data

        Returns:
            Ranked list of attack paths (highest priority first)
        """
        scored_paths = []

        for path in paths:
            score = 0.0

            # Base score from threat level
            if path.threat_level == ThreatLevel.CRITICAL:
                score += 100
            elif path.threat_level == ThreatLevel.HIGH:
                score += 75
            elif path.threat_level == ThreatLevel.MEDIUM:
                score += 50
            else:
                score += 25

            # Target preference score
            if target_nodes_data and path.target in target_nodes_data:
                target_data = target_nodes_data[path.target]
                preference = persona.prefers_target(target_data)
                score += preference * 50  # Up to 50 points

            # Path complexity preference
            # Fast actors prefer shorter paths, patient actors don't mind longer
            complexity_factor = 1.0 - (path.path_length / 20.0)  # Normalize
            if persona.speed_preference > 0.7:  # Fast actor
                score += complexity_factor * 30  # Bonus for short paths
            elif persona.speed_preference < 0.3:  # Patient actor
                score += (
                    1.0 - complexity_factor
                ) * 10  # Slight bonus for longer (more thorough)

            # Exploitability score (already calculated in AttackPath)
            score += path.exploitability * 20  # Up to 20 points

            scored_paths.append((score, path))

        # Sort by score descending
        scored_paths.sort(key=lambda x: x[0], reverse=True)

        ranked_paths = [path for score, path in scored_paths]

        logger.info(
            f"Ranked {len(ranked_paths)} paths for {persona.name} "
            f"(top score: {scored_paths[0][0]:.1f})"
        )

        return ranked_paths

    def get_actor_summary(self, persona: ThreatActorPersona) -> Dict[str, Any]:
        """
        Get summary information about a threat actor.

        Args:
            persona: Threat actor persona

        Returns:
            Dictionary with actor summary information
        """
        return {
            "name": persona.name,
            "type": persona.actor_type.value,
            "skill_level": persona.skill_level.value,
            "resources": persona.resources.value,
            "motivations": persona.motivations,
            "target_preferences": persona.target_preferences,
            "path_complexity_range": [
                persona.min_path_complexity,
                persona.max_path_complexity,
            ],
            "requires_public_exploit": persona.requires_public_exploit,
            "stealth_preference": persona.stealth_preference,
            "speed_preference": persona.speed_preference,
            "common_ttps": persona.ttps[:5],  # Top 5 TTPs
            "description_summary": (
                persona.description[:200] + "..."
                if len(persona.description) > 200
                else persona.description
            ),
        }
