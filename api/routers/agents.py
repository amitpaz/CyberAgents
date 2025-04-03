"""Router module for agent-related endpoints."""

from typing import Dict, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.agents.base_agent import AgentConfig, BaseAgent, create_agent

router = APIRouter(
    tags=["agents"],
    responses={404: {"description": "Not found"}},
)


class AgentResponse(BaseModel):
    """Response model for agent operations."""

    name: str
    role: str
    goal: str
    status: str


class AgentRouter:
    """Router class for handling agent-related operations."""

    def __init__(self):
        """Initialize the agent router."""
        self.agents: Dict[str, BaseAgent] = {}

    async def create_agent(self, config: Dict) -> Dict:
        """Create a new agent with the given configuration.

        Args:
            config: Dictionary containing agent configuration

        Returns:
            Dictionary containing the created agent's information
        """
        try:
            agent = BaseAgent(config)
            self.agents[config["id"]] = agent
            return {"status": "success", "agent_id": config["id"]}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    async def list_agents(self) -> List[Dict]:
        """List all available agents.

        Returns:
            List of dictionaries containing agent information
        """
        return [{"id": agent_id} for agent_id in self.agents.keys()]


@router.post("/", response_model=AgentResponse)
async def create_new_agent(config: AgentConfig):
    """Create a new agent with the given configuration."""
    try:
        agent = create_agent(config)
        return AgentResponse(
            name=config.name, role=agent.role, goal=agent.goal, status="created"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/", response_model=List[AgentResponse])
async def list_agents():
    """List all available agents.

    Note: This is a placeholder - in a real implementation, you would
    store and retrieve agents from a database.
    """
    return []
