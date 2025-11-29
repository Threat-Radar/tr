"""AI-powered vulnerability prioritization engine"""

from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
import json

from threat_radar.ai.llm_client import LLMClient, get_llm_client
from threat_radar.ai.prompt_templates import create_prioritization_prompt
from threat_radar.ai.vulnerability_analyzer import VulnerabilityAnalysis


@dataclass
class PrioritizedVulnerability:
    """A vulnerability with priority scoring"""

    cve_id: str
    package_name: str
    reason: str
    urgency_score: int  # 0-100


@dataclass
class PriorityLevels:
    """Vulnerabilities grouped by priority level"""

    critical: List[PrioritizedVulnerability]
    high: List[PrioritizedVulnerability]
    medium: List[PrioritizedVulnerability]
    low: List[PrioritizedVulnerability]


@dataclass
class PrioritizedVulnerabilityList:
    """Complete prioritization result"""

    priority_levels: PriorityLevels
    overall_strategy: str
    quick_wins: List[str]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "priority_levels": {
                "critical": [asdict(v) for v in self.priority_levels.critical],
                "high": [asdict(v) for v in self.priority_levels.high],
                "medium": [asdict(v) for v in self.priority_levels.medium],
                "low": [asdict(v) for v in self.priority_levels.low],
            },
            "overall_strategy": self.overall_strategy,
            "quick_wins": self.quick_wins,
            "metadata": self.metadata,
        }

    def get_all_by_urgency(self) -> List[PrioritizedVulnerability]:
        """Get all vulnerabilities sorted by urgency score (highest first)"""
        all_vulns = (
            self.priority_levels.critical
            + self.priority_levels.high
            + self.priority_levels.medium
            + self.priority_levels.low
        )
        return sorted(all_vulns, key=lambda v: v.urgency_score, reverse=True)


class PrioritizationEngine:
    """Prioritizes vulnerabilities using AI-based risk assessment"""

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """
        Initialize prioritization engine.

        Args:
            llm_client: Pre-configured LLM client (optional)
            provider: AI provider if not using pre-configured client
            model: Model name if not using pre-configured client
        """
        self.llm_client = llm_client or get_llm_client(provider=provider, model=model)

    def prioritize_vulnerabilities(
        self, analysis: VulnerabilityAnalysis, temperature: float = 0.2
    ) -> PrioritizedVulnerabilityList:
        """
        Prioritize vulnerabilities based on AI analysis.

        Args:
            analysis: VulnerabilityAnalysis result
            temperature: LLM temperature (lower = more consistent prioritization)

        Returns:
            PrioritizedVulnerabilityList with ranked vulnerabilities
        """
        # Convert analysis to dict for prompt
        analysis_data = analysis.to_dict()

        # Generate prioritization using AI
        prompt = create_prioritization_prompt(analysis_data)

        try:
            response = self.llm_client.generate_json(prompt, temperature=temperature)

            # Parse priority levels
            priority_data = response.get("priority_levels", {})

            priority_levels = PriorityLevels(
                critical=self._parse_priority_list(priority_data.get("critical", [])),
                high=self._parse_priority_list(priority_data.get("high", [])),
                medium=self._parse_priority_list(priority_data.get("medium", [])),
                low=self._parse_priority_list(priority_data.get("low", [])),
            )

            # Build metadata
            metadata = {
                "total_critical": len(priority_levels.critical),
                "total_high": len(priority_levels.high),
                "total_medium": len(priority_levels.medium),
                "total_low": len(priority_levels.low),
                "source_analysis": analysis.metadata,
            }

            return PrioritizedVulnerabilityList(
                priority_levels=priority_levels,
                overall_strategy=response.get("overall_strategy", ""),
                quick_wins=response.get("quick_wins", []),
                metadata=metadata,
            )

        except Exception as e:
            raise RuntimeError(f"Failed to prioritize vulnerabilities: {str(e)}")

    def _parse_priority_list(
        self, priority_data: List[Dict[str, Any]]
    ) -> List[PrioritizedVulnerability]:
        """Parse priority list from API response"""
        # Filter to only expected fields to avoid LLM adding extra fields
        expected_fields = {"cve_id", "package_name", "reason", "urgency_score"}
        filtered_items = [
            {k: v for k, v in item.items() if k in expected_fields}
            for item in priority_data
        ]
        return [PrioritizedVulnerability(**item) for item in filtered_items]

    def get_top_priorities(
        self, prioritized_list: PrioritizedVulnerabilityList, limit: int = 10
    ) -> List[PrioritizedVulnerability]:
        """
        Get top N priorities across all levels.

        Args:
            prioritized_list: PrioritizedVulnerabilityList result
            limit: Maximum number of vulnerabilities to return

        Returns:
            Top priority vulnerabilities by urgency score
        """
        all_sorted = prioritized_list.get_all_by_urgency()
        return all_sorted[:limit]

    def get_critical_and_high(
        self, prioritized_list: PrioritizedVulnerabilityList
    ) -> List[PrioritizedVulnerability]:
        """
        Get all critical and high priority vulnerabilities.

        Args:
            prioritized_list: PrioritizedVulnerabilityList result

        Returns:
            Critical and high priority vulnerabilities
        """
        return (
            prioritized_list.priority_levels.critical
            + prioritized_list.priority_levels.high
        )

    def calculate_remediation_order(
        self, prioritized_list: PrioritizedVulnerabilityList
    ) -> List[str]:
        """
        Calculate recommended remediation order.

        Args:
            prioritized_list: PrioritizedVulnerabilityList result

        Returns:
            List of CVE IDs in recommended remediation order
        """
        all_sorted = prioritized_list.get_all_by_urgency()
        return [v.cve_id for v in all_sorted]
