"""Base agent module for defining common agent functionality."""

from typing import Any, Dict, List

from crewai import Agent
from fastapi import HTTPException
from pydantic import BaseModel, field_validator


class AgentConfig(BaseModel):
    """Configuration for an agent."""

    name: str
    role: str
    goal: str
    backstory: str
    tools: List[str] = []
    verbose: bool = True
    allow_delegation: bool = False

    @field_validator("name", "role", "goal", "backstory")
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        """Validate that fields are not empty or whitespace only."""
        if not v.strip():
            raise ValueError("Field cannot be empty or whitespace only")
        return v.strip()

    @field_validator("tools")
    @classmethod
    def validate_tools(cls, v: List[str]) -> List[str]:
        """Validate tools list format."""
        if v is None:
            return []
        if not isinstance(v, list):
            raise ValueError("Tools must be a list")
        return [tool.strip() for tool in v if tool.strip()]


def create_agent(config: AgentConfig) -> Agent:
    """Create a CrewAI agent based on the provided configuration.

    Args:
        config: Configuration for the agent

    Returns:
        A configured CrewAI agent

    Raises:
        HTTPException: If agent creation fails
    """
    try:
        return Agent(
            name=config.name,
            role=config.role,
            goal=config.goal,
            backstory=config.backstory,
            tools=config.tools,
            verbose=config.verbose,
            allow_delegation=config.allow_delegation,
        )
    except Exception as e:
        error_msg = f"Failed to create agent: {str(e)}"
        raise HTTPException(status_code=500, detail=error_msg)


class BaseAgent:
    """Base class for all agents providing common functionality."""

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize the agent with configuration.

        Args:
            config: Dictionary containing agent configuration
        """
        self.config = config
        self.tools = self._load_tools()

    def _load_tools(self) -> List[Dict[str, Any]]:
        """Load and validate tools from configuration.

        Returns:
            List of tool configurations
        """
        tools = self.config.get("tools", [])
        if not isinstance(tools, list):
            raise ValueError("Tools must be a list")
        return tools

    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process input data and return results.

        Args:
            input_data: Dictionary containing input data

        Returns:
            Dictionary containing processed results
        """
        # Implementation here
        return {}
