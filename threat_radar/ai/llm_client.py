"""LLM client abstraction for AI integration"""

import os
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from tenacity import retry, stop_after_attempt, wait_exponential
import requests


class LLMClient(ABC):
    """Abstract base class for LLM clients"""

    @abstractmethod
    def generate(self, prompt: str, temperature: float = 0.7, max_tokens: int = 2000) -> str:
        """
        Generate a response from the LLM.

        Args:
            prompt: The input prompt
            temperature: Sampling temperature (0.0 to 1.0)
            max_tokens: Maximum tokens to generate

        Returns:
            The generated text response
        """
        pass

    @abstractmethod
    def generate_json(self, prompt: str, temperature: float = 0.7) -> Dict[str, Any]:
        """
        Generate a JSON response from the LLM.

        Args:
            prompt: The input prompt
            temperature: Sampling temperature (0.0 to 1.0)

        Returns:
            Parsed JSON response as dictionary
        """
        pass


class OpenAIClient(LLMClient):
    """OpenAI GPT client implementation"""

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4"):
        """
        Initialize OpenAI client.

        Args:
            api_key: OpenAI API key (defaults to OPENAI_API_KEY env var)
            model: Model name (gpt-4, gpt-3.5-turbo, etc.)
        """
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError(
                "OpenAI package not installed. Install with: pip install openai"
            )

        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError(
                "OpenAI API key not provided. Set OPENAI_API_KEY environment variable "
                "or pass api_key parameter."
            )

        self.model = model
        self.client = OpenAI(api_key=self.api_key)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def generate(self, prompt: str, temperature: float = 0.7, max_tokens: int = 2000) -> str:
        """Generate response using OpenAI API"""
        try:
            # Use max_completion_tokens for newer models (gpt-4 and newer)
            params = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "max_completion_tokens": max_tokens,
            }

            # Some models (like gpt-5-nano) only support temperature=1 (default)
            # Don't add temperature parameter for these models
            if "nano" not in self.model.lower():
                params["temperature"] = temperature

            response = self.client.chat.completions.create(**params)
            return response.choices[0].message.content.strip()
        except Exception as e:
            raise RuntimeError(f"OpenAI API error: {str(e)}")

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def generate_json(self, prompt: str, temperature: float = 0.7) -> Dict[str, Any]:
        """Generate JSON response using OpenAI API"""
        import json

        try:
            params = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"},
            }

            # Some models (like gpt-5-nano) only support temperature=1 (default)
            # Don't add temperature parameter for these models
            if "nano" not in self.model.lower():
                params["temperature"] = temperature

            response = self.client.chat.completions.create(**params)
            content = response.choices[0].message.content.strip()
            return json.loads(content)
        except Exception as e:
            raise RuntimeError(f"OpenAI API error: {str(e)}")


class OllamaClient(LLMClient):
    """Ollama local model client implementation"""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama2"):
        """
        Initialize Ollama client.

        Args:
            base_url: Ollama API endpoint
            model: Model name (llama2, mistral, codellama, etc.)
        """
        self.base_url = base_url.rstrip("/")
        self.model = model

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def generate(self, prompt: str, temperature: float = 0.7, max_tokens: int = 2000) -> str:
        """Generate response using Ollama API"""
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": temperature,
                        "num_predict": max_tokens,
                    },
                },
                timeout=120,
            )
            response.raise_for_status()
            return response.json()["response"].strip()
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Ollama API error: {str(e)}")

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def generate_json(self, prompt: str, temperature: float = 0.7) -> Dict[str, Any]:
        """Generate JSON response using Ollama API"""
        import json

        json_prompt = f"{prompt}\n\nRespond with valid JSON only."

        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": json_prompt,
                    "stream": False,
                    "options": {"temperature": temperature},
                    "format": "json",
                },
                timeout=120,
            )
            response.raise_for_status()
            content = response.json()["response"].strip()
            return json.loads(content)
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Ollama API error: {str(e)}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid JSON response from Ollama: {str(e)}")


def get_llm_client(
    provider: Optional[str] = None,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    endpoint: Optional[str] = None,
) -> LLMClient:
    """
    Factory function to get an LLM client based on configuration.

    Args:
        provider: AI provider ('openai' or 'ollama'). Defaults to AI_PROVIDER env var.
        model: Model name. Defaults to AI_MODEL env var.
        api_key: API key for cloud providers. Defaults to OPENAI_API_KEY env var.
        endpoint: Endpoint URL for local models. Defaults to LOCAL_MODEL_ENDPOINT env var.

    Returns:
        LLMClient instance

    Raises:
        ValueError: If provider is invalid or configuration is missing
    """
    provider = provider or os.getenv("AI_PROVIDER", "openai")
    model = model or os.getenv("AI_MODEL")

    if provider == "openai":
        default_model = model or "gpt-4"
        return OpenAIClient(api_key=api_key, model=default_model)
    elif provider == "ollama":
        default_model = model or "llama2"
        default_endpoint = endpoint or os.getenv("LOCAL_MODEL_ENDPOINT", "http://localhost:11434")
        return OllamaClient(base_url=default_endpoint, model=default_model)
    else:
        raise ValueError(
            f"Invalid AI provider: {provider}. Supported providers: 'openai', 'ollama'"
        )
