"""Dummy Tool Template.

This file serves as a template for creating new tools. Replace this description
with a brief explanation of what your tool does.
"""

import logging
from typing import Dict, List, Optional, Any
from langchain.tools import BaseTool
from pydantic import Field

logger = logging.getLogger(__name__)

class DummyTool(BaseTool):
    """A template tool for creating new tools."""

    name: str = "dummy_tool"
    description: str = """
    Dummy tool template. This description should explain what your tool does,
    what inputs it accepts, and what outputs it produces.
    """

    # Define any configuration fields your tool needs
    api_key: Optional[str] = Field(
        default=None, description="API key for external service if needed"
    )
    base_url: str = Field(
        default="https://api.example.com", 
        description="Base URL for API requests"
    )

    def __init__(self, **kwargs):
        """Initialize the tool with optional parameters."""
        super().__init__(**kwargs)
        
        # Set up configuration from kwargs or environment variables
        self.api_key = kwargs.get("api_key")
        self.base_url = kwargs.get("base_url", "https://api.example.com")
        
        if self.api_key:
            logger.info(f"Initialized {self.name} with API configuration")
        else:
            logger.warning(f"Initialized {self.name} without API key")

    def _run(self, query: str) -> str:
        """Execute the tool's main functionality.
        
        Args:
            query: The input string from the user
            
        Returns:
            A string containing the results
        """
        try:
            logger.info(f"Executing {self.name} with query: {query}")
            
            # Parse the input query and call appropriate method
            if query.startswith("example:"):
                param = query[8:].strip()
                return self._example_method(param)
            else:
                return self._process_default_query(query)
        
        except Exception as e:
            logger.exception(f"Error in {self.name}: {e}")
            return f"Error executing {self.name}: {str(e)}"

    def _example_method(self, param: str) -> str:
        """Example method for handling a specific type of query.
        
        Args:
            param: Parameter extracted from the query
            
        Returns:
            Formatted result string
        """
        # Implementation would go here
        return f"Processed parameter: {param}"

    def _process_default_query(self, query: str) -> str:
        """Process a standard query.
        
        Args:
            query: The user's query string
            
        Returns:
            Formatted result string
        """
        # Default query handling would go here
        return f"## Dummy Tool Results\n\n**Query**: `{query}`\n\nThis is a dummy result. Replace this with actual implementation."
        
    def _format_results(self, data: Dict[str, Any]) -> str:
        """Format the results into a readable string.
        
        Args:
            data: The data to format
            
        Returns:
            A formatted string for output
        """
        result = f"## {self.name.title()} Results\n\n"
        
        # Add headers and result data
        result += "| Field | Value |\n"
        result += "| ----- | ----- |\n"
        
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                value = str(value)[:50] + "..." if len(str(value)) > 50 else str(value)
            result += f"| {key} | {value} |\n"
            
        return result 