# ============================================================================
# FILE: core/llm.py
# ============================================================================

from typing import Any
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.language_models.llms import BaseLLM
from core.model import MultiLLMFactory
import os
import re
from utils.logger_config import setup_logging, SecureFormatter
import logging
from dotenv import load_dotenv
load_dotenv()
# 1. Initialize the global configuration
setup_logging()
# 2. Get a logger for this specific file
logger = logging.getLogger(__name__)

class LLMWrapper:
    """Wrapper for LLM connectivity with standardized interface"""

    def __init__(self, temperature: float | None = None):
        self.temperature = temperature or float(os.getenv("TEMPERATURE", "0.1"))
        self.model: BaseChatModel | BaseLLM = MultiLLMFactory.create_model(
            temperature=self.temperature
        )
        self.provider = os.getenv("PROVIDER", "deepseek")

    def _redact_text(self, text: str) -> str:
        """Apply the security patterns to the prompt text before sending to LLM."""
        for pattern, replacement in SecureFormatter.PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def extract_json(self, text):
        # This finds everything between the first { and the last }
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            return match.group(0)
        return text


    def invoke(self, prompt: str, **kwargs: Any) -> str:
        """
        Invoke the LLM with a prompt.

        Args:
            prompt: Input prompt text
            **kwargs: Additional invocation parameters

        Returns:
            Model response as string
        """
        # Redact the prompt BEFORE sending it to the provider
        safe_prompt = self._redact_text(prompt)

        try:
            if isinstance(self.model, BaseChatModel):
                from langchain_core.messages import HumanMessage
                messages = [HumanMessage(content=safe_prompt)]
                response = self.model.invoke(messages, **kwargs)
                logger.info(f"LLMWrapper.invoke.messages : {messages} , response: {response}")
                return self.extract_json(response.content)
            else:
                return self.model.invoke(safe_prompt, **kwargs)
        except Exception as e:
            raise RuntimeError(f"LLM invocation failed ({self.provider}): {e}")

    def get_provider_info(self) -> dict[str, Any]:
        """Get information about the current provider"""
        return {
            "provider": self.provider,
            "temperature": self.temperature,
            "model": getattr(self.model, "model_name", "unknown")
        }

