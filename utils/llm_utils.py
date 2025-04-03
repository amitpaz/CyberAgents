"""Utility functions for creating LLM configurations."""

import copy
import json
import logging
import os

import pytest
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Load environment variables
load_dotenv()

# --- Configuration ---
DEFAULT_OPENAI_MODEL = os.environ.get("OPENAI_MODEL_NAME", "gpt-4o")
DEFAULT_OLLAMA_MODEL = "phi:latest"  # Specify a default local model
OLLAMA_BASE_URL = "http://localhost:11434/v1"  # Default Ollama endpoint

# Determine if running in local LLM mode
USE_LOCAL_LLM = os.getenv("USE_LOCAL_LLM", "false").lower() == "true"
# --- End Configuration ---


class CustomChatOpenAI(ChatOpenAI):
    """Custom ChatOpenAI class that doesn't use temperature for the o3-mini model."""

    @property
    def _invocation_params(self):
        """Get the parameters used to invoke the model."""
        params = super()._invocation_params
        if self.model_name == "o3-mini" and "temperature" in params:
            # Remove temperature for o3-mini model
            del params["temperature"]
        return params

    @property
    def _llm_type(self) -> str:
        """Return type of llm."""
        return "custom_chat_openai"

    def dict(self, **kwargs):
        """Return a dict representation of the instance."""
        result = super().dict(**kwargs)
        if self.model_name == "o3-mini" and "temperature" in result:
            # Remove temperature for o3-mini model in dict serialization
            del result["temperature"]
        return result

    def to_json(self) -> str:
        """Return a JSON representation of the instance."""
        if self.model_name == "o3-mini":
            # Create a copy to avoid modifying the original object
            temp_dict = copy.deepcopy(self.__dict__)
            if "_temperature" in temp_dict:
                del temp_dict["_temperature"]

            clean_dict = {
                "name": None,
                "model_name": self.model_name,
                "class": self.__class__.__name__,
            }
            return json.dumps(clean_dict)
        else:
            clean_dict = {
                "name": None,
                "model_name": self.model_name,
                "temperature": self.temperature,
                "class": self.__class__.__name__,
            }
            return json.dumps(clean_dict)

    # Override _generate method to remove temperature from requests
    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        if self.model_name == "o3-mini" and "temperature" in kwargs:
            del kwargs["temperature"]
        return await super()._agenerate(messages, stop, run_manager, **kwargs)

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        if self.model_name == "o3-mini" and "temperature" in kwargs:
            del kwargs["temperature"]
        return super()._generate(messages, stop, run_manager, **kwargs)


def create_llm() -> CustomChatOpenAI:
    """Creates a ChatOpenAI instance, configured for OpenAI or a local Ollama instance based on USE_LOCAL_LLM env var."""

    model_name: str
    api_key: str
    base_url: str | None = None
    temperature: float = 0.7  # Default temperature

    if USE_LOCAL_LLM:
        logger.info(f"--- Using local LLM via Ollama --- ")
        # Use Ollama configuration
        base_url = os.getenv("OLLAMA_BASE_URL", OLLAMA_BASE_URL)
        model_name = os.getenv("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)
        api_key = "ollama"  # Ollama doesn't require a key
        # Temperature can be kept or adjusted for local models
        temperature = 0.7
        logger.info(f"Model: {model_name}, Base URL: {base_url}")

    else:
        logger.info(f"--- Using remote OpenAI LLM --- ")
        # Use standard OpenAI configuration
        model_name = os.getenv("OPENAI_MODEL_NAME", DEFAULT_OPENAI_MODEL)
        api_key = os.getenv("OPENAI_API_KEY")
        base_url = os.getenv("OPENAI_API_BASE")  # Respect if user wants to proxy OpenAI
        temperature = 0.7

        if not api_key:
            # Use pytest.skip in tests, raise error otherwise
            try:
                pytest.skip("OPENAI_API_KEY not set for remote LLM usage")
            except NameError:
                raise ValueError(
                    "OPENAI_API_KEY environment variable is not set and is required when not using local LLM"
                )
        logger.info(f"Model: {model_name}, Base URL: {base_url or 'Default OpenAI'}")

    # Instantiate using the determined parameters
    # Check if the selected model is 'o3-mini' to apply custom logic
    if model_name == "o3-mini":
        logger.info("Applying custom configuration for o3-mini (no temperature).")
        llm = CustomChatOpenAI(
            model=model_name,
            openai_api_key=api_key,
            openai_api_base=base_url,  # Pass base_url whether local or remote
            # Temperature is omitted by the CustomChatOpenAI class for o3-mini
        )
    else:
        llm = CustomChatOpenAI(
            model=model_name,
            temperature=temperature,
            openai_api_key=api_key,
            openai_api_base=base_url,  # Pass base_url whether local or remote
        )

    return llm
