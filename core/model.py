# ============================================================================
# FILE: core/model.py
# ============================================================================

from typing import Any, Literal
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_community.llms import Ollama
from langchain_core.language_models.llms import BaseLLM
import os
import httpx
from dotenv import load_dotenv
load_dotenv()
ProviderType = Literal["deepseek", "chatgpt", "claude", "gemini", "grok", "ollama"]


class MultiLLMFactory:
    """Universal LLM Factory supporting 6 providers"""

    @staticmethod
    def create_model(
            provider: ProviderType | None = None,
            temperature: float = 0.1,
            **kwargs: Any
    ) -> BaseChatModel | BaseLLM:
        """
        Create an LLM instance based on provider configuration.

        Args:
            provider: LLM provider name (defaults to env PROVIDER)
            temperature: Model temperature (defaults to 0.1 for deterministic security decisions)
            **kwargs: Additional provider-specific arguments

        Returns:
            Configured LLM instance
        """
        if provider is None:
            provider = os.getenv("PROVIDER", "deepseek").lower()

        api_key = os.getenv("API_KEY")
        if not api_key and provider != "ollama":
            raise ValueError(f"API_KEY required for provider: {provider}")

        match provider:
            case "deepseek":
                return MultiLLMFactory._create_deepseek(api_key, temperature, **kwargs)

            case "chatgpt":
                return MultiLLMFactory._create_chatgpt(api_key, temperature, **kwargs)

            case "claude":
                return MultiLLMFactory._create_claude(api_key, temperature, **kwargs)

            case "gemini":
                return MultiLLMFactory._create_gemini(api_key, temperature, **kwargs)

            case "grok":
                return MultiLLMFactory._create_grok(api_key, temperature, **kwargs)

            case "ollama":
                return MultiLLMFactory._create_ollama(temperature, **kwargs)

            case _:
                raise ValueError(f"Unsupported provider: {provider}")

    @staticmethod
    def _create_deepseek(api_key: str, temperature: float, **kwargs: Any) -> ChatOpenAI:
        """DeepSeek via OpenAI-compatible endpoint"""
        base_url = os.getenv("DEEPSEEK_API_BASE", "https://api.deepseek.com/v1")
        return ChatOpenAI(
            model=kwargs.get("model", "deepseek-chat"),
            api_key=api_key,
            base_url=base_url,
            temperature=temperature,
            http_client=httpx.Client(timeout=60.0)
        )

    @staticmethod
    def _create_chatgpt(api_key: str, temperature: float, **kwargs: Any) -> ChatOpenAI:
        """OpenAI ChatGPT"""
        return ChatOpenAI(
            model=kwargs.get("model", "gpt-4-turbo-preview"),
            api_key=api_key,
            temperature=temperature
        )

    @staticmethod
    def _create_claude(api_key: str, temperature: float, **kwargs: Any) -> ChatAnthropic:
        """Anthropic Claude"""
        return ChatAnthropic(
            model=kwargs.get("model", "claude-3-sonnet-20240229"),
            anthropic_api_key=api_key,
            temperature=temperature
        )

    @staticmethod
    def _create_gemini(api_key: str, temperature: float, **kwargs: Any) -> ChatGoogleGenerativeAI:
        """Google Gemini"""
        return ChatGoogleGenerativeAI(
            model=kwargs.get("model", "gemini-pro"),
            google_api_key=api_key,
            temperature=temperature
        )

    @staticmethod
    def _create_grok(api_key: str, temperature: float, **kwargs: Any) -> ChatOpenAI:
        """xAI Grok via OpenAI-compatible API"""
        return ChatOpenAI(
            model=kwargs.get("model", "grok-beta"),
            api_key=api_key,
            base_url="https://api.x.ai/v1",
            temperature=temperature
        )

    @staticmethod
    def _create_ollama(temperature: float, **kwargs: Any) -> Ollama:
        """Ollama for local inference"""
        return Ollama(
            model=kwargs.get("model", "llama2"),
            temperature=temperature,
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        )

