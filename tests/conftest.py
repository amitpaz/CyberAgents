"""Test configuration and fixtures."""

import pytest
from fastapi.testclient import TestClient

from api.agents.base_agent import AgentConfig
from api.main import app


@pytest.fixture
def client():
    """Create a test client for the FastAPI application."""
    return TestClient(app)


@pytest.fixture
def sample_agent_config():
    """Create a sample agent configuration for testing."""
    return AgentConfig(
        name="Test Agent",
        role="Test Role",
        goal="Test Goal",
        backstory="Test Backstory",
        tools=[],
        verbose=True,
        allow_delegation=False,
    )
