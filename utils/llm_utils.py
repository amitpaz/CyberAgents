"""Utility functions for creating LLM configurations."""

import copy
import json
import logging
import os

# Import Union for type hinting
from typing import Union

import pytest

# Import crewai LLM wrapper
from crewai import LLM
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Load environment variables
load_dotenv()

# --- Configuration ---
DEFAULT_OPENAI_MODEL = os.environ.get("OPENAI_MODEL_NAME", "gpt-4o")
DEFAULT_OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "phi:latest")  # Read from env
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")

# New Cerebras config
DEFAULT_CEREBRAS_MODEL = os.environ.get(
    "CEREBRAS_MODEL_NAME", "llama-3.3-70b"
)  # Base model name
CEREBRAS_API_BASE_VAR = os.getenv("CEREBRAS_API_BASE")
CEREBRAS_API_KEY_VAR = os.getenv("CEREBRAS_API_KEY")
CEREBRAS_STREAMING_VAR = os.getenv("CEREBRAS_STREAMING", "false").lower() == "true"
CEREBRAS_MAX_TOKENS_VAR = os.getenv("CEREBRAS_MAX_TOKENS")

# Determine LLM mode based on env vars (Priority: Cerebras > Ollama > OpenAI)
USE_CEREBRAS_LLM = os.getenv("USE_CEREBRAS_LLM", "false").lower() == "true"
USE_LOCAL_LLM = (
    os.getenv("USE_LOCAL_LLM", "false").lower() == "true" and not USE_CEREBRAS_LLM
)

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


# Update return type hint
def create_llm() -> Union[CustomChatOpenAI, LLM]:
    """Creates an LLM instance (ChatOpenAI or crewai.LLM) based on environment variables."""

    # Read optional params just once
    streaming = CEREBRAS_STREAMING_VAR  # Assuming same flag name for simplicity
    max_tokens: int | None = None
    if CEREBRAS_MAX_TOKENS_VAR:
        try:
            max_tokens = int(CEREBRAS_MAX_TOKENS_VAR)
        except (ValueError, TypeError):
            logger.warning(
                f"Invalid MAX_TOKENS value '{CEREBRAS_MAX_TOKENS_VAR}'. Ignoring."
            )

    # --- Provider Logic ---
    if USE_CEREBRAS_LLM:
        logger.info("--- Configuring Cerebras LLM --- ")
        api_key = CEREBRAS_API_KEY_VAR
        api_base = CEREBRAS_API_BASE_VAR
        # Use the exact model name from LiteLLM docs examples
        base_model_name = os.getenv("CEREBRAS_MODEL_NAME", "llama3-70b-instruct")
        provider_prefixed_model_name = f"cerebras/{base_model_name}"  # Prefix for CrewAI/LiteLLM provider selection

        if not api_key:
            raise ValueError(
                "CEREBRAS_API_KEY environment variable is required when USE_CEREBRAS_LLM is true"
            )
        if not api_base:  # Base URL is usually needed for non-standard providers
            raise ValueError(
                "CEREBRAS_API_BASE environment variable is required when USE_CEREBRAS_LLM is true"
            )

        logger.info(
            f"Using Provider Model: {provider_prefixed_model_name}, Base URL: {api_base}"
        )

        # Prepare kwargs for crewai.LLM
        llm_config = {
            # Tell LiteLLM which model name to send IN THE API request body
            "model_name": base_model_name,
            # Explicitly pass api_key and base_url
            "api_key": api_key,
            "base_url": api_base,
            "temperature": 0.7,  # Example/Default value
        }
        if streaming:  # Use env var CEREBRAS_STREAMING_VAR
            llm_config["stream"] = True
        if max_tokens is not None:
            llm_config["max_tokens"] = max_tokens

        # Instantiate crewai.LLM for Cerebras
        # Pass the PROVIDER-PREFIXED model name here for provider selection
        return LLM(model=provider_prefixed_model_name, config=llm_config)

    elif USE_LOCAL_LLM:
        logger.info("--- Configuring local LLM via Ollama --- ")
        base_url = os.getenv("OLLAMA_BASE_URL", OLLAMA_BASE_URL)
        base_model_name = os.getenv("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)
        model_name = f"ollama/{base_model_name}"  # Prefix for CrewAI/LiteLLM

        logger.info(f"Using Model: {model_name}, Base URL: {base_url}")

        # Prepare kwargs for crewai.LLM
        llm_config = {
            "base_url": base_url,  # Ollama usually needs base_url specified
            "temperature": 0.7,  # Example value
        }
        # Add optional params if needed for Ollama
        # if streaming: llm_config["stream"] = True
        # if max_tokens is not None: llm_config["max_tokens"] = max_tokens

        # Instantiate crewai.LLM for Ollama
        return LLM(model=model_name, config=llm_config)

    else:  # Default to OpenAI
        logger.info("--- Configuring remote OpenAI LLM --- ")
        model_name = os.getenv("OPENAI_MODEL_NAME", DEFAULT_OPENAI_MODEL)
        api_key = os.getenv("OPENAI_API_KEY")
        api_base = os.getenv("OPENAI_API_BASE")
        temperature = 0.7

        if not api_key or api_key == "dummy-key-for-validation":
            try:
                pytest.skip("OPENAI_API_KEY not set or is dummy for remote LLM usage")
            except NameError:
                raise ValueError(
                    "OPENAI_API_KEY environment variable is not set or is dummy, and is required when not using Ollama or Cerebras"
                )
        logger.info(
            f"Using Model: {model_name}, Base URL: {api_base or 'Default OpenAI'}"
        )

        # Prepare kwargs for ChatOpenAI
        llm_kwargs = {
            "model": model_name,
            "temperature": temperature,
            "openai_api_key": api_key,
            "openai_api_base": api_base,
        }
        # Add optional streaming/max_tokens if needed
        # if streaming: llm_kwargs["streaming"] = True
        # if max_tokens is not None: llm_kwargs["max_tokens"] = max_tokens

        # Instantiate ChatOpenAI (or CustomChatOpenAI for specific models)
        if model_name == "o3-mini":
            logger.info("Applying custom configuration for o3-mini (no temperature).")
            if "temperature" in llm_kwargs:
                del llm_kwargs["temperature"]
            return CustomChatOpenAI(**llm_kwargs)
        else:
            return CustomChatOpenAI(**llm_kwargs)
