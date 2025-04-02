"""Utility functions for creating LLM configurations."""

import os
import copy
import json
import pytest
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get model configuration
MODEL_NAME = os.environ.get("OPENAI_MODEL_NAME", "o3-mini")

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
                "class": self.__class__.__name__
            }
            return json.dumps(clean_dict)
        else:
            clean_dict = {
                "name": None,
                "model_name": self.model_name,
                "temperature": self.temperature,
                "class": self.__class__.__name__
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

def create_llm():
    """Create a custom LLM configuration based on the model name."""
    api_key = os.environ.get("OPENAI_API_KEY")
    api_base = os.environ.get("OPENAI_API_BASE")
    
    if not api_key:
        # Use pytest.skip in tests, raise error otherwise
        try:
            pytest.skip("OPENAI_API_KEY not set")
        except NameError:
            raise ValueError("OPENAI_API_KEY environment variable is not set")

    if MODEL_NAME == "o3-mini":
        return CustomChatOpenAI(
            model=MODEL_NAME,
            openai_api_key=api_key,
            openai_api_base=api_base
        )
    else:
        return CustomChatOpenAI(
            model=MODEL_NAME,
            temperature=0.7,
            openai_api_key=api_key,
            openai_api_base=api_base
        ) 