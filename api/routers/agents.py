from fastapi import APIRouter, HTTPException
from typing import List
from pydantic import BaseModel
from ..agents.base_agent import AgentConfig, create_agent

router = APIRouter(
    prefix="/agents",
    tags=["agents"],
    responses={404: {"description": "Not found"}},
)


class AgentResponse(BaseModel):
    name: str
    role: str
    goal: str
    status: str


@router.post("/", response_model=AgentResponse)
async def create_new_agent(config: AgentConfig):
    """
    Create a new agent with the given configuration.
    """
    try:
        agent = create_agent(config)
        return AgentResponse(
            name=agent.name, role=agent.role, goal=agent.goal, status="created"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/", response_model=List[AgentResponse])
async def list_agents():
    """
    List all available agents.
    Note: This is a placeholder - in a real implementation, you would
    store and retrieve agents from a database.
    """
    return []
