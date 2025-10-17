"""Tests for AI integration modules."""
import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from threat_radar.ai.llm_client import LLMClient, OpenAIClient, OllamaClient, get_llm_client
from threat_radar.ai.vulnerability_analyzer import VulnerabilityAnalyzer, VulnerabilityAnalysis
from threat_radar.ai.prioritization import PrioritizationEngine, PrioritizedVulnerabilityList
from threat_radar.ai.remediation_generator import RemediationGenerator, RemediationReport
from threat_radar.ai.prompt_templates import (
    create_analysis_prompt,
    create_prioritization_prompt,
    create_remediation_prompt,
    format_vulnerability_data,
)
from threat_radar.core.grype_integration import GrypeScanResult, GrypeVulnerability


# Sample test data
SAMPLE_VULNERABILITY = GrypeVulnerability(
    id="CVE-2024-1234",
    severity="high",
    package_name="openssl",
    package_version="1.1.1k",
    package_type="deb",
    fixed_in_version="1.1.1w",
    description="Critical security vulnerability in OpenSSL",
    cvss_score=8.5,
    urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
    data_source="NVD",
)

SAMPLE_SCAN_RESULT = GrypeScanResult(
    target="alpine:3.18",
    vulnerabilities=[SAMPLE_VULNERABILITY],
    total_count=1,
    severity_counts={"high": 1},
    scan_metadata={"grype_version": "0.74.0"},
)


class TestLLMClient:
    """Test LLM client implementations."""

    @patch('openai.OpenAI')
    def test_openai_client_generate(self, mock_openai_class):
        """Test OpenAI client text generation."""
        # Mock the OpenAI client response
        mock_client = MagicMock()
        mock_openai_class.return_value = mock_client

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Test response"
        mock_client.chat.completions.create.return_value = mock_response

        # Create client and test
        client = OpenAIClient(api_key="test-key", model="gpt-4")
        result = client.generate("Test prompt")

        assert result == "Test response"
        mock_client.chat.completions.create.assert_called_once()

    @patch('threat_radar.ai.llm_client.requests.post')
    def test_ollama_client_generate(self, mock_post):
        """Test Ollama client text generation."""
        # Mock the requests.post response
        mock_response = MagicMock()
        mock_response.json.return_value = {"response": "Test response from Ollama"}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        # Create client and test
        client = OllamaClient(base_url="http://localhost:11434", model="llama2")
        result = client.generate("Test prompt")

        assert result == "Test response from Ollama"
        mock_post.assert_called_once()

    @patch.dict('os.environ', {'AI_PROVIDER': 'openai', 'OPENAI_API_KEY': 'test-key'})
    @patch('openai.OpenAI')
    def test_get_llm_client_openai(self, mock_openai_class):
        """Test factory function returns OpenAI client."""
        client = get_llm_client()
        assert isinstance(client, OpenAIClient)

    @patch.dict('os.environ', {'AI_PROVIDER': 'ollama'})
    def test_get_llm_client_ollama(self):
        """Test factory function returns Ollama client."""
        client = get_llm_client()
        assert isinstance(client, OllamaClient)


class TestPromptTemplates:
    """Test prompt template generation."""

    def test_format_vulnerability_data(self):
        """Test vulnerability data formatting."""
        vulns = [
            {
                "id": "CVE-2024-1234",
                "package_name": "openssl",
                "package_version": "1.1.1k",
                "severity": "high",
                "cvss_score": 8.5,
                "fixed_in_version": "1.1.1w",
                "description": "Test vulnerability",
            }
        ]

        formatted = format_vulnerability_data(vulns)

        assert "CVE-2024-1234" in formatted
        assert "openssl" in formatted
        assert "HIGH" in formatted

    def test_create_analysis_prompt(self):
        """Test analysis prompt creation."""
        vulns = [
            {
                "id": "CVE-2024-1234",
                "package_name": "openssl",
                "package_version": "1.1.1k",
                "severity": "high",
                "cvss_score": 8.5,
                "fixed_in_version": "1.1.1w",
                "description": "Test vulnerability",
            }
        ]

        prompt = create_analysis_prompt(vulns)

        assert "CVE-2024-1234" in prompt
        assert "exploitability" in prompt.lower()
        assert "attack vectors" in prompt.lower()


class TestVulnerabilityAnalyzer:
    """Test vulnerability analyzer."""

    def test_analyzer_initialization(self):
        """Test analyzer can be initialized with mock client."""
        mock_client = Mock(spec=LLMClient)
        analyzer = VulnerabilityAnalyzer(llm_client=mock_client)

        assert analyzer.llm_client == mock_client

    def test_analyze_scan_result(self):
        """Test analyzing a scan result."""
        # Create mock client
        mock_client = Mock(spec=LLMClient)
        mock_client.generate_json.return_value = {
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2024-1234",
                    "package_name": "openssl",
                    "exploitability": "HIGH",
                    "exploitability_details": "Easily exploitable remotely",
                    "attack_vectors": ["Remote Code Execution", "Network Attack"],
                    "business_impact": "HIGH",
                    "business_impact_details": "Could lead to data breach",
                    "recommendations": ["Upgrade immediately", "Apply patches"],
                }
            ],
            "summary": "1 high-risk vulnerability found",
        }

        analyzer = VulnerabilityAnalyzer(llm_client=mock_client)
        result = analyzer.analyze_scan_result(SAMPLE_SCAN_RESULT)

        assert isinstance(result, VulnerabilityAnalysis)
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].cve_id == "CVE-2024-1234"
        assert result.vulnerabilities[0].exploitability == "HIGH"
        assert result.summary == "1 high-risk vulnerability found"


class TestPrioritizationEngine:
    """Test prioritization engine."""

    def test_prioritize_vulnerabilities(self):
        """Test vulnerability prioritization."""
        # Create mock analysis
        mock_analysis = MagicMock(spec=VulnerabilityAnalysis)
        mock_analysis.to_dict.return_value = {
            "vulnerabilities": [],
            "summary": "Test",
            "metadata": {},
        }
        mock_analysis.metadata = {"total_vulnerabilities": 1}

        # Create mock client
        mock_client = Mock(spec=LLMClient)
        mock_client.generate_json.return_value = {
            "priority_levels": {
                "critical": [
                    {
                        "cve_id": "CVE-2024-1234",
                        "package_name": "openssl",
                        "reason": "High exploitability and business impact",
                        "urgency_score": 95,
                    }
                ],
                "high": [],
                "medium": [],
                "low": [],
            },
            "overall_strategy": "Patch critical vulnerabilities first",
            "quick_wins": ["CVE-2024-1234 has simple upgrade path"],
        }

        engine = PrioritizationEngine(llm_client=mock_client)
        result = engine.prioritize_vulnerabilities(mock_analysis)

        assert isinstance(result, PrioritizedVulnerabilityList)
        assert len(result.priority_levels.critical) == 1
        assert result.priority_levels.critical[0].urgency_score == 95


class TestRemediationGenerator:
    """Test remediation generator."""

    def test_generate_remediation_plan(self):
        """Test remediation plan generation."""
        # Create mock client
        mock_client = Mock(spec=LLMClient)
        mock_client.generate_json.return_value = {
            "remediations": [
                {
                    "cve_id": "CVE-2024-1234",
                    "package_name": "openssl",
                    "current_version": "1.1.1k",
                    "fixed_version": "1.1.1w",
                    "immediate_actions": ["Isolate affected systems"],
                    "upgrade_command": "apt-get install openssl=1.1.1w",
                    "workarounds": ["Disable vulnerable feature"],
                    "testing_steps": ["Verify version", "Run security scan"],
                    "references": ["https://openssl.org/news/secadv"],
                    "estimated_effort": "LOW",
                }
            ],
            "grouped_by_package": {
                "openssl": {
                    "vulnerabilities_count": 1,
                    "recommended_version": "1.1.1w",
                    "upgrade_fixes_all": True,
                }
            },
        }

        generator = RemediationGenerator(llm_client=mock_client)
        result = generator.generate_remediation_plan(SAMPLE_SCAN_RESULT)

        assert isinstance(result, RemediationReport)
        assert len(result.remediations) == 1
        assert result.remediations[0].cve_id == "CVE-2024-1234"
        assert result.remediations[0].estimated_effort == "LOW"
        assert "openssl" in result.grouped_by_package


class TestAIStorage:
    """Test AI storage manager."""

    def test_ai_storage_import(self):
        """Test that AI storage can be imported."""
        from threat_radar.utils.ai_storage import AIAnalysisManager, get_ai_storage

        assert AIAnalysisManager is not None
        assert get_ai_storage is not None

    def test_get_ai_storage(self):
        """Test getting AI storage instance."""
        from threat_radar.utils.ai_storage import get_ai_storage

        storage = get_ai_storage()
        assert storage is not None
        assert hasattr(storage, 'save_analysis')
        assert hasattr(storage, 'list_analyses')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
