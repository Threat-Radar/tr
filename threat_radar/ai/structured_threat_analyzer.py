"""Structured threat analysis orchestrator integrating graph analysis, threat actors, and AI scenarios.

This module provides the main entry point for comprehensive threat modeling,
combining vulnerability graph analysis, threat actor personas, and AI-powered
scenario generation into cohesive threat model reports.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from pathlib import Path
import logging
import json

from threat_radar.ai.llm_client import LLMClient, get_llm_client
from threat_radar.ai.threat_actor_modeler import ThreatActorModeler, ThreatActorPersona
from threat_radar.ai.attack_scenario_generator import (
    AttackScenarioGenerator,
    AttackScenario,
)
from threat_radar.graph.graph_client import NetworkXClient
from threat_radar.graph.queries import GraphAnalyzer
from threat_radar.graph.models import AttackPath

logger = logging.getLogger(__name__)


@dataclass
class ThreatModelReport:
    """
    Complete threat model report with scenarios and recommendations.

    Attributes:
        target_environment: Name/ID of target environment
        threat_actors_analyzed: List of threat actor names analyzed
        total_attack_paths: Total number of attack paths discovered
        scenarios_generated: Number of scenarios generated
        critical_scenarios: List of critical-severity scenarios
        high_priority_scenarios: List of high-priority scenarios
        all_scenarios: Complete list of all scenarios
        executive_summary: AI-generated executive summary
        recommendations: List of strategic recommendations
        metadata: Additional metadata about the analysis
    """

    target_environment: str
    threat_actors_analyzed: List[str]
    total_attack_paths: int
    scenarios_generated: int
    critical_scenarios: List[AttackScenario] = field(default_factory=list)
    high_priority_scenarios: List[AttackScenario] = field(default_factory=list)
    all_scenarios: List[AttackScenario] = field(default_factory=list)
    executive_summary: str = ""
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "threat_model": {
                "target_environment": self.target_environment,
                "threat_actors_analyzed": self.threat_actors_analyzed,
                "total_attack_paths": self.total_attack_paths,
                "scenarios_generated": self.scenarios_generated,
                "critical_scenarios_count": len(self.critical_scenarios),
                "high_priority_scenarios_count": len(self.high_priority_scenarios),
                "timestamp": self.metadata.get("timestamp", ""),
            },
            "scenarios": [scenario.to_dict() for scenario in self.all_scenarios],
            "executive_summary": self.executive_summary,
            "recommendations": self.recommendations,
            "metadata": self.metadata,
        }

    def get_critical_scenarios(self) -> List[AttackScenario]:
        """Get scenarios with critical threat levels."""
        return [s for s in self.all_scenarios if "critical" in s.attack_path_id.lower()]

    def get_high_priority_scenarios(self) -> List[AttackScenario]:
        """Get high-priority scenarios."""
        return [
            s
            for s in self.all_scenarios
            if s.confidence_score >= 0.8 and s not in self.critical_scenarios
        ]


class StructuredThreatAnalyzer:
    """
    Main orchestrator for AI-powered structured threat modeling.

    Integrates:
    - Graph-based attack path discovery
    - Threat actor persona modeling
    - AI-powered scenario generation
    - Business context-aware risk assessment
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """
        Initialize structured threat analyzer.

        Args:
            llm_client: Pre-configured LLM client (optional)
            provider: AI provider if not using pre-configured client
            model: Model name if not using pre-configured client
        """
        self.llm_client = llm_client or get_llm_client(provider=provider, model=model)
        self.actor_modeler = ThreatActorModeler()
        self.scenario_generator = AttackScenarioGenerator(self.llm_client)

        logger.info("Initialized StructuredThreatAnalyzer")

    def analyze_threat_model(
        self,
        graph_file: str,
        threat_actor_type: Optional[str] = None,
        max_scenarios: int = 10,
        environment_config: Optional[Dict[str, Any]] = None,
        temperature: float = 0.4,
    ) -> ThreatModelReport:
        """
        Perform comprehensive threat modeling analysis.

        Workflow:
        1. Load vulnerability graph
        2. Extract attack paths using graph analysis
        3. Select threat actor persona(s)
        4. Filter/rank paths by actor preferences
        5. Generate AI-powered attack scenarios
        6. Create executive summary and recommendations

        Args:
            graph_file: Path to vulnerability graph (.graphml)
            threat_actor_type: Specific threat actor to analyze (None = all)
            max_scenarios: Maximum number of scenarios to generate
            environment_config: Optional environment/business context
            temperature: LLM temperature for scenario generation

        Returns:
            Complete ThreatModelReport with scenarios and recommendations
        """
        logger.info(f"Starting threat model analysis for {graph_file}")

        # Step 1: Load graph and extract attack paths
        graph_client, attack_paths = self._load_graph_and_find_paths(
            graph_file, max_scenarios * 2  # Get more paths than needed for filtering
        )

        if not attack_paths:
            logger.warning("No attack paths found in graph")
            return self._create_empty_report(
                Path(graph_file).stem, "No viable attack paths discovered"
            )

        logger.info(f"Discovered {len(attack_paths)} attack paths")

        # Step 2: Get target node data for preference scoring
        target_nodes_data = self._extract_target_nodes_data(graph_client, attack_paths)

        # Step 3: Select threat actor persona(s)
        if threat_actor_type:
            personas = [self.actor_modeler.get_persona(threat_actor_type)]
        else:
            # Analyze with top 3 most relevant actors
            personas = self._select_relevant_actors(attack_paths)[:3]

        logger.info(
            f"Analyzing with {len(personas)} threat actor(s): {[p.name for p in personas]}"
        )

        # Step 4: Generate scenarios for each actor
        all_scenarios = []
        for persona in personas:
            scenarios = self._generate_scenarios_for_actor(
                attack_paths,
                persona,
                target_nodes_data,
                max_scenarios // len(personas),  # Distribute scenarios across actors
                environment_config,
                temperature,
            )
            all_scenarios.extend(scenarios)

        # Limit to max_scenarios
        all_scenarios = all_scenarios[:max_scenarios]

        logger.info(f"Generated {len(all_scenarios)} total scenarios")

        # Step 5: Create executive summary
        executive_summary = self._generate_executive_summary(
            all_scenarios, personas, Path(graph_file).stem, temperature
        )

        # Step 6: Generate strategic recommendations
        recommendations = self._generate_recommendations(
            all_scenarios, attack_paths, environment_config
        )

        # Step 7: Categorize scenarios
        critical_scenarios = [
            s
            for s in all_scenarios
            if "critical" in str(s.business_impact.reputation_damage).lower()
            or s.confidence_score >= 0.9
        ]

        high_priority_scenarios = [
            s
            for s in all_scenarios
            if s not in critical_scenarios and s.confidence_score >= 0.8
        ]

        # Step 8: Build report
        from datetime import datetime

        report = ThreatModelReport(
            target_environment=Path(graph_file).stem,
            threat_actors_analyzed=[p.name for p in personas],
            total_attack_paths=len(attack_paths),
            scenarios_generated=len(all_scenarios),
            critical_scenarios=critical_scenarios,
            high_priority_scenarios=high_priority_scenarios,
            all_scenarios=all_scenarios,
            executive_summary=executive_summary,
            recommendations=recommendations,
            metadata={
                "timestamp": datetime.now().isoformat(),
                "graph_file": graph_file,
                "max_scenarios": max_scenarios,
                "ai_provider": self.llm_client.__class__.__name__,
                "environment_config": bool(environment_config),
            },
        )

        logger.info(
            f"Threat model complete: {len(all_scenarios)} scenarios "
            f"({len(critical_scenarios)} critical, {len(high_priority_scenarios)} high priority)"
        )

        return report

    def _load_graph_and_find_paths(
        self, graph_file: str, max_paths: int
    ) -> tuple[NetworkXClient, List[AttackPath]]:
        """Load graph and discover attack paths."""
        # Load graph
        client = NetworkXClient()
        client.load(graph_file)

        logger.info(
            f"Loaded graph: {client.graph.number_of_nodes()} nodes, {client.graph.number_of_edges()} edges"
        )

        # Extract attack paths
        analyzer = GraphAnalyzer(client)
        attack_paths = analyzer.find_shortest_attack_paths(
            max_paths=max_paths, max_length=10
        )

        return client, attack_paths

    def _extract_target_nodes_data(
        self, graph_client: NetworkXClient, attack_paths: List[AttackPath]
    ) -> Dict[str, Dict]:
        """Extract node data for all target nodes."""
        target_nodes_data = {}

        for path in attack_paths:
            if path.target not in target_nodes_data:
                node_data = graph_client.graph.nodes.get(path.target, {})
                target_nodes_data[path.target] = node_data

        return target_nodes_data

    def _select_relevant_actors(
        self, attack_paths: List[AttackPath]
    ) -> List[ThreatActorPersona]:
        """Select most relevant threat actors based on attack paths."""
        # Simple heuristic: select diverse actor types
        personas = self.actor_modeler.list_personas()

        # Prefer actors that match path characteristics
        scored_personas = []
        for persona in personas:
            score = 0

            # Count paths within actor's complexity range
            matching_paths = sum(
                1
                for path in attack_paths
                if persona.matches_path_complexity(path.path_length)
            )

            score += matching_paths * 10

            # Prefer diverse actor types
            if persona.actor_type.value in ["apt", "ransomware", "nation_state"]:
                score += 5

            scored_personas.append((score, persona))

        # Sort by score and return top actors
        scored_personas.sort(key=lambda x: x[0], reverse=True)
        return [persona for score, persona in scored_personas]

    def _generate_scenarios_for_actor(
        self,
        attack_paths: List[AttackPath],
        persona: ThreatActorPersona,
        target_nodes_data: Dict[str, Dict],
        max_scenarios: int,
        environment_config: Optional[Dict],
        temperature: float,
    ) -> List[AttackScenario]:
        """Generate scenarios for a specific threat actor."""
        logger.info(f"Generating scenarios for {persona.name}")

        # Filter paths suitable for this actor
        filtered_paths = self.actor_modeler.filter_attack_paths_by_actor(
            attack_paths, persona, target_nodes_data
        )

        if not filtered_paths:
            logger.warning(f"No suitable paths for {persona.name}")
            return []

        # Rank by actor preferences
        ranked_paths = self.actor_modeler.rank_paths_by_actor_preference(
            filtered_paths, persona, target_nodes_data
        )

        # Generate scenarios for top paths
        scenarios = []
        for path in ranked_paths[:max_scenarios]:
            try:
                # Extract business context for this target
                business_context = None
                if environment_config and path.target in target_nodes_data:
                    business_context = {
                        **target_nodes_data[path.target],
                        **environment_config.get("global_business_context", {}),
                    }

                scenario = self.scenario_generator.generate_scenario(
                    path, persona, business_context, temperature
                )

                scenarios.append(scenario)

            except Exception as e:
                logger.error(
                    f"Failed to generate scenario for path {path.path_id}: {e}"
                )
                continue

        logger.info(f"Generated {len(scenarios)} scenarios for {persona.name}")
        return scenarios

    def _generate_executive_summary(
        self,
        scenarios: List[AttackScenario],
        personas: List[ThreatActorPersona],
        environment_name: str,
        temperature: float,
    ) -> str:
        """Generate AI-powered executive summary."""
        from threat_radar.ai.prompt_templates import create_threat_model_summary_prompt

        # Prepare summary data
        summary_data = {
            "environment_name": environment_name,
            "threat_actors": [p.name for p in personas],
            "total_scenarios": len(scenarios),
            "critical_count": len(
                [
                    s
                    for s in scenarios
                    if "critical" in str(s.business_impact.reputation_damage).lower()
                ]
            ),
            "scenario_summaries": [
                {
                    "threat_actor": s.threat_actor,
                    "narrative_excerpt": (
                        s.narrative[:200] + "..."
                        if len(s.narrative) > 200
                        else s.narrative
                    ),
                    "business_impact": s.business_impact.estimated_cost,
                    "compliance_violations": s.business_impact.compliance_violations,
                }
                for s in scenarios[:5]  # Top 5 scenarios
            ],
        }

        # Generate prompt
        prompt = create_threat_model_summary_prompt(summary_data)

        try:
            # Generate summary with AI
            summary = self.llm_client.generate(prompt, temperature=temperature)
            return summary.strip()
        except Exception as e:
            logger.warning(f"Failed to generate AI summary: {e}")
            # Fallback to template-based summary
            return self._generate_fallback_summary(
                scenarios, personas, environment_name
            )

    def _generate_fallback_summary(
        self,
        scenarios: List[AttackScenario],
        personas: List[ThreatActorPersona],
        environment_name: str,
    ) -> str:
        """Generate template-based summary as fallback."""
        critical_count = len(
            [
                s
                for s in scenarios
                if "critical" in str(s.business_impact.reputation_damage).lower()
            ]
        )

        summary = [
            f"## Executive Summary: Threat Model for {environment_name}\n\n",
            f"This analysis evaluated {len(scenarios)} attack scenarios from the perspective of ",
            f"{len(personas)} threat actor types: {', '.join(p.name for p in personas)}.\n\n",
            f"### Key Findings:\n",
            f"- **Critical Scenarios**: {critical_count} scenarios pose critical business risk\n",
            f"- **Primary Attack Vectors**: ",
        ]

        # Extract common attack vectors
        all_ttps = set()
        for scenario in scenarios[:5]:
            for phase in scenario.timeline:
                all_ttps.add(phase.ttp.tactic)

        summary.append(", ".join(sorted(all_ttps)))
        summary.append("\n")

        # Add recommendation teaser
        summary.append(
            "\n### Immediate Actions Required:\n"
            "See detailed recommendations section for prioritized mitigation strategies."
        )

        return "".join(summary)

    def _generate_recommendations(
        self,
        scenarios: List[AttackScenario],
        attack_paths: List[AttackPath],
        environment_config: Optional[Dict],
    ) -> List[str]:
        """Generate strategic recommendations."""
        recommendations = []

        # Critical vulnerabilities
        all_cves = set()
        for scenario in scenarios:
            for phase in scenario.timeline:
                all_cves.update(phase.cves_exploited)

        if all_cves:
            recommendations.append(
                f"URGENT: Patch {len(all_cves)} vulnerabilities identified in attack scenarios"
            )

        # Network segmentation
        lateral_movement_scenarios = sum(
            1
            for s in scenarios
            if any("Lateral Movement" in p.ttp.tactic for p in s.timeline)
        )

        if lateral_movement_scenarios > 0:
            recommendations.append(
                f"HIGH: Implement network segmentation - {lateral_movement_scenarios} scenarios "
                "involve lateral movement"
            )

        # Threat detection
        unique_actors = len(set(s.threat_actor for s in scenarios))
        recommendations.append(
            f"MEDIUM: Deploy threat detection for {unique_actors} threat actor types analyzed"
        )

        # Compliance
        compliance_violations = set()
        for scenario in scenarios:
            compliance_violations.update(scenario.business_impact.compliance_violations)

        if compliance_violations:
            recommendations.append(
                f"HIGH: Address {len(compliance_violations)} compliance framework violations"
            )

        # Monitoring
        recommendations.append(
            "STRATEGIC: Implement comprehensive security monitoring covering all attack phases"
        )

        return recommendations

    def _create_empty_report(
        self, environment_name: str, reason: str
    ) -> ThreatModelReport:
        """Create empty report when no analysis is possible."""
        from datetime import datetime

        return ThreatModelReport(
            target_environment=environment_name,
            threat_actors_analyzed=[],
            total_attack_paths=0,
            scenarios_generated=0,
            executive_summary=f"Threat modeling analysis could not be completed: {reason}",
            recommendations=["Review vulnerability graph generation process"],
            metadata={
                "timestamp": datetime.now().isoformat(),
                "status": "incomplete",
                "reason": reason,
            },
        )

    def analyze_multiple_actors(
        self,
        graph_file: str,
        actor_types: List[str],
        max_scenarios_per_actor: int = 5,
        environment_config: Optional[Dict] = None,
    ) -> Dict[str, ThreatModelReport]:
        """
        Analyze threat model for multiple threat actors separately.

        Args:
            graph_file: Path to vulnerability graph
            actor_types: List of threat actor types to analyze
            max_scenarios_per_actor: Max scenarios per actor
            environment_config: Optional environment configuration

        Returns:
            Dictionary mapping actor_type to ThreatModelReport
        """
        reports = {}

        for actor_type in actor_types:
            logger.info(f"Analyzing for {actor_type}")
            report = self.analyze_threat_model(
                graph_file=graph_file,
                threat_actor_type=actor_type,
                max_scenarios=max_scenarios_per_actor,
                environment_config=environment_config,
            )
            reports[actor_type] = report

        return reports
