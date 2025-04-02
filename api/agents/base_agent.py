from crewai import Agent
from typing import Optional, List
from pydantic import BaseModel, Field, validator
from fastapi import HTTPException


class AgentConfig(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    role: str = Field(..., min_length=1, max_length=100)
    goal: str = Field(..., min_length=1, max_length=500)
    backstory: str = Field(..., min_length=1, max_length=1000)
    tools: Optional[List[str]] = Field(default_factory=list)
    verbose: bool = Field(default=True)
    allow_delegation: bool = Field(default=True)

    @validator("name", "role", "goal", "backstory")
    def validate_non_empty(cls, v):
        if not v.strip():
            raise ValueError("Field cannot be empty or contain only whitespace")
        return v.strip()

    @validator("tools")
    def validate_tools(cls, v):
        if v is None:
            return []
        if not isinstance(v, list):
            raise ValueError("Tools must be a list")
        return [tool.strip() for tool in v if tool.strip()]


def create_agent(config: AgentConfig) -> Agent:
    """
    Create a CrewAI agent based on the provided configuration.

    Args:
        config (AgentConfig): Configuration for the agent

    Returns:
        Agent: A configured CrewAI agent

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
        raise HTTPException(status_code=500, detail=f"Failed to create agent: {str(e)}")
