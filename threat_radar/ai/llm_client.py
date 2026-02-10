"""LLM client abstraction for AI integration"""

import os
import re
import json
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from tenacity import retry, stop_after_attempt, wait_exponential
import requests


def repair_json(content: str) -> str:
    """
    Repair common JSON syntax errors produced by LLMs.

    Fixes:
    - Trailing commas in arrays: ["a", "b",] -> ["a", "b"]
    - Trailing commas in objects: {"a": 1,} -> {"a": 1}
    - Multiple trailing commas: [1, 2,,] -> [1, 2]
    """
    # Remove trailing commas before closing brackets/braces
    # Pattern: comma followed by optional whitespace and closing bracket/brace
    content = re.sub(r",(\s*[}\]])", r"\1", content)

    # Remove multiple consecutive commas
    content = re.sub(r",(\s*,)+", ",", content)

    return content


class LLMClient(ABC):
    """Abstract base class for LLM clients"""

    @abstractmethod
    def generate(
        self, prompt: str, temperature: float = 0.7, max_tokens: int = 2000
    ) -> str:
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

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o"):
        """
        Initialize OpenAI client.

        Args:
            api_key: OpenAI API key (defaults to OPENAI_API_KEY env var)
            model: Model name (gpt-4o, gpt-4-turbo, gpt-3.5-turbo, etc.)
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

    @retry(
        stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def generate(
        self, prompt: str, temperature: float = 0.7, max_tokens: int = 2000
    ) -> str:
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

    @retry(
        stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def generate_json(self, prompt: str, temperature: float = 0.7) -> Dict[str, Any]:
        """Generate JSON response using OpenAI API"""
        original_content = ""  # Save for error messages
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
            content = response.choices[0].message.content

            # Handle None response
            if content is None:
                raise RuntimeError("OpenAI returned None content")

            content = content.strip()
            original_content = content  # Save original for error messages

            # Handle empty responses
            if not content:
                raise RuntimeError("Empty response from OpenAI")

            # Apply same robust extraction strategies as other providers

            # Strategy 1: Extract from markdown code blocks
            if "```" in content:
                code_blocks = re.findall(
                    r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL
                )
                if code_blocks:
                    content = code_blocks[0].strip()

            # Strategy 2: Find JSON object in the text
            json_match = re.search(r"\{.*\}", content, re.DOTALL)
            if json_match:
                content = json_match.group(0)

            # Strategy 3: If content doesn't start with {, find first {
            if not content.startswith("{"):
                start_idx = content.find("{")
                if start_idx != -1:
                    content = content[start_idx:]

            # Strategy 4: Balance braces if extra data after }
            if content.count("}") > content.count("{"):
                brace_count = 0
                for i, char in enumerate(content):
                    if char == "{":
                        brace_count += 1
                    elif char == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            content = content[: i + 1]
                            break

            # Strategy 5: Repair common JSON syntax errors
            content = repair_json(content)

            # Final validation before parsing
            if not content or not content.strip():
                raise RuntimeError(
                    f"No valid JSON found in response. Original: {original_content[:200]}"
                )

            if not content.startswith("{"):
                raise RuntimeError(
                    f"Response doesn't contain JSON object. Content: {content[:200]}"
                )

            return json.loads(content)
        except json.JSONDecodeError as e:
            preview = (
                original_content[:300]
                if len(original_content) > 300
                else original_content
            )
            raise RuntimeError(
                f"Invalid JSON from OpenAI: {str(e)}\nOriginal response: {preview}"
            )
        except Exception as e:
            # Import BadRequestError for specific error handling
            try:
                from openai import BadRequestError
            except ImportError:
                BadRequestError = type(None)  # Fallback if import fails

            # Catch and enhance BadRequestError with better message
            if isinstance(e, BadRequestError):
                error_msg = str(e)
                # Add helpful context for common JSON mode errors
                if (
                    "does not support" in error_msg.lower()
                    or "json" in error_msg.lower()
                ):
                    raise RuntimeError(
                        f"OpenAI API error: {error_msg}\n\n"
                        f"💡 The model '{self.model}' may not support JSON mode.\n"
                        f"   Recommended models: 'gpt-4o', 'gpt-4-turbo', or 'gpt-3.5-turbo-1106'"
                    )
                else:
                    raise RuntimeError(f"OpenAI API error: {error_msg}")

            if "OpenAI" in str(e) or "response" in str(e).lower():
                raise  # Re-raise our custom errors
            raise RuntimeError(f"OpenAI API error: {str(e)}")


class AnthropicClient(LLMClient):
    """Anthropic Claude client implementation"""

    def __init__(
        self, api_key: Optional[str] = None, model: str = "claude-3-5-sonnet-20241022"
    ):
        """
        Initialize Anthropic client.

        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
            model: Model name (claude-3-5-sonnet-20241022, claude-3-opus-20240229, etc.)
        """
        try:
            from anthropic import Anthropic
        except ImportError:
            raise ImportError(
                "Anthropic package not installed. Install with: pip install anthropic"
            )

        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError(
                "Anthropic API key not provided. Set ANTHROPIC_API_KEY environment variable "
                "or pass api_key parameter."
            )

        self.model = model
        self.client = Anthropic(api_key=self.api_key)

    @retry(
        stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def generate(
        self, prompt: str, temperature: float = 0.7, max_tokens: int = 2000
    ) -> str:
        """Generate response using Anthropic API"""
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text.strip()
        except Exception as e:
            raise RuntimeError(f"Anthropic API error: {str(e)}")

    @retry(
        stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def generate_json(self, prompt: str, temperature: float = 0.7) -> Dict[str, Any]:
        """Generate JSON response using Anthropic API"""
        json_prompt = f"{prompt}\n\nRespond with valid JSON only, no other text."
        original_content = ""

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                temperature=temperature,
                messages=[{"role": "user", "content": json_prompt}],
            )
            content = response.content[0].text

            # Handle None response
            if content is None:
                raise RuntimeError("Claude returned None content")

            content = content.strip()
            original_content = content

            # Handle empty responses
            if not content:
                raise RuntimeError("Empty response from Claude")

            # Try multiple extraction strategies

            # Strategy 1: Extract from markdown code blocks
            if "```" in content:
                code_blocks = re.findall(
                    r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL
                )
                if code_blocks:
                    content = code_blocks[0].strip()

            # Strategy 2: Find JSON object in the text
            json_match = re.search(r"\{.*\}", content, re.DOTALL)
            if json_match:
                content = json_match.group(0)

            # Strategy 3: If content doesn't start with {, find first {
            if not content.startswith("{"):
                start_idx = content.find("{")
                if start_idx != -1:
                    content = content[start_idx:]

            # Strategy 4: Balance braces if extra data after }
            if content.count("}") > content.count("{"):
                brace_count = 0
                for i, char in enumerate(content):
                    if char == "{":
                        brace_count += 1
                    elif char == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            content = content[: i + 1]
                            break

            # Strategy 5: Repair common JSON syntax errors
            content = repair_json(content)

            # Final validation before parsing
            if not content or not content.strip():
                raise RuntimeError(
                    f"No valid JSON found in response. Original: {original_content[:200]}"
                )

            if not content.startswith("{"):
                raise RuntimeError(
                    f"Response doesn't contain JSON object. Content: {content[:200]}"
                )

            return json.loads(content)
        except json.JSONDecodeError as e:
            preview = (
                original_content[:300]
                if len(original_content) > 300
                else original_content
            )
            raise RuntimeError(
                f"Invalid JSON from Claude: {str(e)}\nOriginal response: {preview}"
            )
        except Exception as e:
            if "Claude" in str(e) or "response" in str(e).lower():
                raise
            raise RuntimeError(f"Anthropic API error: {str(e)}")


class OpenRouterClient(LLMClient):
    """OpenRouter unified API client implementation"""

    def __init__(
        self, api_key: Optional[str] = None, model: str = "anthropic/claude-3.5-sonnet"
    ):
        """
        Initialize OpenRouter client.

        Args:
            api_key: OpenRouter API key (defaults to OPENROUTER_API_KEY env var)
            model: Model name (e.g., 'anthropic/claude-3.5-sonnet', 'openai/gpt-4o', etc.)

        Popular models:
            - anthropic/claude-3.5-sonnet
            - anthropic/claude-3-opus
            - openai/gpt-4o
            - openai/gpt-4-turbo
            - google/gemini-pro
            - meta-llama/llama-3.1-70b-instruct
        """
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        if not self.api_key:
            raise ValueError(
                "OpenRouter API key not provided. Set OPENROUTER_API_KEY environment variable "
                "or pass api_key parameter. Get your key at: https://openrouter.ai/keys"
            )

        self.model = model
        self.base_url = "https://openrouter.ai/api/v1"

    @retry(
        stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def generate(
        self, prompt: str, temperature: float = 0.7, max_tokens: int = 2000
    ) -> str:
        """Generate response using OpenRouter API"""
        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/threat-radar",  # Optional, for rankings
                    "X-Title": "Threat Radar",  # Optional, for rankings
                },
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                },
                timeout=120,
            )
            response.raise_for_status()
            data = response.json()

            if "error" in data:
                raise RuntimeError(
                    f"OpenRouter API error: {data['error'].get('message', data['error'])}"
                )

            return data["choices"][0]["message"]["content"].strip()
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"OpenRouter API error: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"OpenRouter error: {str(e)}")

    @retry(
        stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def generate_json(self, prompt: str, temperature: float = 0.7) -> Dict[str, Any]:
        """Generate JSON response using OpenRouter API"""
        json_prompt = f"{prompt}\n\nRespond with valid JSON only, no other text."
        original_content = ""

        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/threat-radar",
                    "X-Title": "Threat Radar",
                },
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": json_prompt}],
                    "temperature": temperature,
                    "response_format": {"type": "json_object"},  # Request JSON mode
                },
                timeout=120,
            )
            response.raise_for_status()
            data = response.json()

            if "error" in data:
                raise RuntimeError(
                    f"OpenRouter API error: {data['error'].get('message', data['error'])}"
                )

            content = data["choices"][0]["message"]["content"]

            # Handle None response
            if content is None:
                raise RuntimeError("OpenRouter returned None content")

            content = content.strip()
            original_content = content

            # Handle empty responses
            if not content:
                raise RuntimeError("Empty response from OpenRouter")

            # Try multiple extraction strategies

            # Strategy 1: Extract from markdown code blocks
            if "```" in content:
                code_blocks = re.findall(
                    r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL
                )
                if code_blocks:
                    content = code_blocks[0].strip()

            # Strategy 2: Find JSON object in the text
            json_match = re.search(r"\{.*\}", content, re.DOTALL)
            if json_match:
                content = json_match.group(0)

            # Strategy 3: If content doesn't start with {, find first {
            if not content.startswith("{"):
                start_idx = content.find("{")
                if start_idx != -1:
                    content = content[start_idx:]

            # Strategy 4: Balance braces if extra data after }
            if content.count("}") > content.count("{"):
                brace_count = 0
                for i, char in enumerate(content):
                    if char == "{":
                        brace_count += 1
                    elif char == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            content = content[: i + 1]
                            break

            # Strategy 5: Repair common JSON syntax errors
            content = repair_json(content)

            # Final validation before parsing
            if not content or not content.strip():
                raise RuntimeError(
                    f"No valid JSON found in response. Original: {original_content[:200]}"
                )

            if not content.startswith("{"):
                raise RuntimeError(
                    f"Response doesn't contain JSON object. Content: {content[:200]}"
                )

            return json.loads(content)
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"OpenRouter API error: {str(e)}")
        except json.JSONDecodeError as e:
            preview = (
                original_content[:300]
                if len(original_content) > 300
                else original_content
            )
            raise RuntimeError(
                f"Invalid JSON from OpenRouter: {str(e)}\nOriginal response: {preview}"
            )
        except Exception as e:
            if "OpenRouter" in str(e) or "response" in str(e).lower():
                raise
            raise RuntimeError(f"OpenRouter error: {str(e)}")


class GrokClient(LLMClient):
    """xAI Grok client implementation"""

    def __init__(self, api_key: Optional[str] = None, model: str = "grok-beta"):
        """
        Initialize Grok client.

        Args:
            api_key: xAI API key (defaults to XAI_API_KEY env var)
            model: Model name (grok-beta, grok-2-1212, etc.)

        Note:
            Get your API key at: https://console.x.ai/
        """
        self.api_key = api_key or os.getenv("XAI_API_KEY")
        if not self.api_key:
            raise ValueError(
                "xAI API key not provided. Set XAI_API_KEY environment variable "
                "or pass api_key parameter. Get your key at: https://console.x.ai/"
            )

        self.model = model
        self.base_url = "https://api.x.ai/v1"

    @retry(
        stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def generate(
        self, prompt: str, temperature: float = 0.7, max_tokens: int = 2000
    ) -> str:
        """Generate response using xAI Grok API"""
        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "stream": False,
                },
                timeout=120,
            )
            response.raise_for_status()
            data = response.json()

            if "error" in data:
                raise RuntimeError(
                    f"Grok API error: {data['error'].get('message', data['error'])}"
                )

            return data["choices"][0]["message"]["content"].strip()
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Grok API error: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Grok error: {str(e)}")

    @retry(
        stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def generate_json(self, prompt: str, temperature: float = 0.7) -> Dict[str, Any]:
        """Generate JSON response using xAI Grok API"""
        json_prompt = f"{prompt}\n\nRespond with valid JSON only, no other text."
        original_content = ""

        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": json_prompt}],
                    "temperature": temperature,
                    "stream": False,
                },
                timeout=120,
            )
            response.raise_for_status()
            data = response.json()

            if "error" in data:
                raise RuntimeError(
                    f"Grok API error: {data['error'].get('message', data['error'])}"
                )

            content = data["choices"][0]["message"]["content"]

            # Handle None response
            if content is None:
                raise RuntimeError("Grok returned None content")

            content = content.strip()
            original_content = content

            # Handle empty responses
            if not content:
                raise RuntimeError("Empty response from Grok")

            # Try multiple extraction strategies

            # Strategy 1: Extract from markdown code blocks
            if "```" in content:
                code_blocks = re.findall(
                    r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL
                )
                if code_blocks:
                    content = code_blocks[0].strip()

            # Strategy 2: Find JSON object in the text
            json_match = re.search(r"\{.*\}", content, re.DOTALL)
            if json_match:
                content = json_match.group(0)

            # Strategy 3: If content doesn't start with {, find first {
            if not content.startswith("{"):
                start_idx = content.find("{")
                if start_idx != -1:
                    content = content[start_idx:]

            # Strategy 4: Balance braces if extra data after }
            if content.count("}") > content.count("{"):
                brace_count = 0
                for i, char in enumerate(content):
                    if char == "{":
                        brace_count += 1
                    elif char == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            content = content[: i + 1]
                            break

            # Strategy 5: Repair common JSON syntax errors
            content = repair_json(content)

            # Final validation before parsing
            if not content or not content.strip():
                raise RuntimeError(
                    f"No valid JSON found in response. Original: {original_content[:200]}"
                )

            if not content.startswith("{"):
                raise RuntimeError(
                    f"Response doesn't contain JSON object. Content: {content[:200]}"
                )

            return json.loads(content)
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Grok API error: {str(e)}")
        except json.JSONDecodeError as e:
            preview = (
                original_content[:300]
                if len(original_content) > 300
                else original_content
            )
            raise RuntimeError(
                f"Invalid JSON from Grok: {str(e)}\nOriginal response: {preview}"
            )
        except Exception as e:
            if "Grok" in str(e) or "response" in str(e).lower():
                raise
            raise RuntimeError(f"Grok error: {str(e)}")


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

    @retry(
        stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def generate(
        self, prompt: str, temperature: float = 0.7, max_tokens: int = 2000
    ) -> str:
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

    @retry(
        stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def generate_json(self, prompt: str, temperature: float = 0.7) -> Dict[str, Any]:
        """Generate JSON response using Ollama API"""
        json_prompt = f"{prompt}\n\nRespond with valid JSON only."
        original_content = ""

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
            content = response.json()["response"]

            # Handle None response
            if content is None:
                raise RuntimeError("Ollama returned None content")

            content = content.strip()
            original_content = content

            # Handle empty responses
            if not content:
                raise RuntimeError("Empty response from Ollama")

            # Try multiple extraction strategies

            # Strategy 1: Extract from markdown code blocks
            if "```" in content:
                code_blocks = re.findall(
                    r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL
                )
                if code_blocks:
                    content = code_blocks[0].strip()

            # Strategy 2: Find JSON object in the text
            json_match = re.search(r"\{.*\}", content, re.DOTALL)
            if json_match:
                content = json_match.group(0)

            # Strategy 3: If content doesn't start with {, find first {
            if not content.startswith("{"):
                start_idx = content.find("{")
                if start_idx != -1:
                    content = content[start_idx:]

            # Strategy 4: Balance braces if extra data after }
            if content.count("}") > content.count("{"):
                brace_count = 0
                for i, char in enumerate(content):
                    if char == "{":
                        brace_count += 1
                    elif char == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            content = content[: i + 1]
                            break

            # Strategy 5: Repair common JSON syntax errors
            content = repair_json(content)

            # Final validation before parsing
            if not content or not content.strip():
                raise RuntimeError(
                    f"No valid JSON found in response. Original: {original_content[:200]}"
                )

            if not content.startswith("{"):
                raise RuntimeError(
                    f"Response doesn't contain JSON object. Content: {content[:200]}"
                )

            return json.loads(content)
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Ollama API error: {str(e)}")
        except json.JSONDecodeError as e:
            preview = (
                original_content[:300]
                if len(original_content) > 300
                else original_content
            )
            raise RuntimeError(
                f"Invalid JSON from Ollama: {str(e)}\nOriginal response: {preview}"
            )
        except Exception as e:
            if "Ollama" in str(e) or "response" in str(e).lower():
                raise
            raise RuntimeError(f"Ollama error: {str(e)}")


def get_llm_client(
    provider: Optional[str] = None,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    endpoint: Optional[str] = None,
) -> LLMClient:
    """
    Factory function to get an LLM client based on configuration.

    Args:
        provider: AI provider ('openai', 'anthropic', 'grok', 'openrouter', or 'ollama'). Defaults to AI_PROVIDER env var.
        model: Model name. Defaults to AI_MODEL env var.
        api_key: API key for cloud providers. Defaults to provider-specific env var.
        endpoint: Endpoint URL for local models. Defaults to LOCAL_MODEL_ENDPOINT env var.

    Returns:
        LLMClient instance

    Raises:
        ValueError: If provider is invalid or configuration is missing

    Examples:
        # OpenAI
        client = get_llm_client(provider="openai", model="gpt-4o")

        # Anthropic
        client = get_llm_client(provider="anthropic", model="claude-3-5-sonnet-20241022")

        # xAI Grok
        client = get_llm_client(provider="grok", model="grok-beta")

        # OpenRouter (access to multiple providers)
        client = get_llm_client(provider="openrouter", model="anthropic/claude-3.5-sonnet")
        client = get_llm_client(provider="openrouter", model="openai/gpt-4o")
        client = get_llm_client(provider="openrouter", model="google/gemini-pro")

        # Ollama (local)
        client = get_llm_client(provider="ollama", model="llama2")
    """
    provider = provider or os.getenv("AI_PROVIDER", "openai")
    model = model or os.getenv("AI_MODEL")

    if provider == "openai":
        default_model = model or "gpt-4o"  # Use gpt-4o by default (supports JSON mode)
        return OpenAIClient(api_key=api_key, model=default_model)
    elif provider == "anthropic":
        default_model = model or "claude-3-5-sonnet-20241022"
        return AnthropicClient(api_key=api_key, model=default_model)
    elif provider == "grok":
        default_model = model or "grok-beta"
        return GrokClient(api_key=api_key, model=default_model)
    elif provider == "openrouter":
        default_model = model or "anthropic/claude-3.5-sonnet"
        return OpenRouterClient(api_key=api_key, model=default_model)
    elif provider == "ollama":
        default_model = model or "llama2"
        default_endpoint = endpoint or os.getenv(
            "LOCAL_MODEL_ENDPOINT", "http://localhost:11434"
        )
        return OllamaClient(base_url=default_endpoint, model=default_model)
    else:
        raise ValueError(
            f"Invalid AI provider: {provider}. Supported providers: 'openai', 'anthropic', 'grok', 'openrouter', 'ollama'"
        )
