"""AI integration and prompts for threat analysis"""

from .llm_client import LLMClient, OpenAIClient, OllamaClient, get_llm_client
from .vulnerability_analyzer import VulnerabilityAnalyzer, VulnerabilityAnalysis, VulnerabilityInsight
from .prioritization import PrioritizationEngine, PrioritizedVulnerabilityList, PrioritizedVulnerability
from .remediation_generator import RemediationGenerator, RemediationReport, RemediationPlan

__all__ = [
    # LLM Clients
    "LLMClient",
    "OpenAIClient",
    "OllamaClient",
    "get_llm_client",
    # Vulnerability Analysis
    "VulnerabilityAnalyzer",
    "VulnerabilityAnalysis",
    "VulnerabilityInsight",
    # Prioritization
    "PrioritizationEngine",
    "PrioritizedVulnerabilityList",
    "PrioritizedVulnerability",
    # Remediation
    "RemediationGenerator",
    "RemediationReport",
    "RemediationPlan",
]