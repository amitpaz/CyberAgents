"""Test suite for the agent API endpoints and functionality."""

# Removed unused os import
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

# Import the real components - tests will fail if these are not found
from api.agents.base_agent import AgentConfig
from api.main import app

# Initialize the TestClient
client = TestClient(app)

# Assume sample_agent_config fixture exists and provides a Pydantic model
# If not, we need to define a sample config dict here or in the test.


# Remove skip markers and implement tests
def test_create_agent_with_valid_config(sample_agent_config):
    """Test creating an agent with valid configuration."""
    # Use the correct API endpoint prefix
    response = client.post("/api/v1/agents/", json=sample_agent_config.model_dump())
    assert response.status_code == 200
    # Add assertions about the response body if needed, e.g., checking ID or name
    assert "name" in response.json()  # Assuming AgentResponse has name
    assert response.json()["name"] == sample_agent_config.name


def test_create_agent_with_missing_required_fields():
    """Test creating an agent with missing required fields."""
    invalid_config = {"name": "Test Agent"}  # Missing role, goal, backstory
    # Use the correct API endpoint prefix
    response = client.post("/api/v1/agents/", json=invalid_config)
    assert response.status_code == 422  # Expect validation error


def test_create_agent_with_invalid_tools():
    """Test creating an agent with invalid tools format."""
    invalid_config = {
        "name": "Test Agent Tools",
        "role": "Security Analyst",
        "goal": "Analyze security threats",
        "backstory": "Expert in cybersecurity analysis",
        "tools": "invalid_tool_string",  # Tools should be a list of Tool objects/configs
    }
    # Use the correct API endpoint prefix
    response = client.post("/api/v1/agents/", json=invalid_config)
    assert response.status_code == 422  # Expect validation error


def test_list_agents_empty():
    """Test listing agents when no agents exist (assuming clean state)."""
    # Ideally, ensure no agents exist before running this test if state persists
    # Use the correct API endpoint prefix
    response = client.get("/api/v1/agents/")
    assert response.status_code == 200
    # Check if the response is an empty list or structure indicating no agents
    assert response.json() == []  # Or potentially { "agents": [] }


# Keep this validation test as it tests the model directly
def test_agent_config_validation():
    """Test basic AgentConfig model validation."""
    # Test valid config
    try:
        AgentConfig(  # Uses the imported AgentConfig
            name="valid_agent",
            role="Valid Role",
            goal="Valid Goal",
            backstory="Valid Backstory",
            tools=[],
            verbose=True,
            allow_delegation=False,
        )
    except ValidationError as e:
        pytest.fail(f"Valid AgentConfig raised validation error: {e}")
    except Exception as e:
        pytest.fail(f"Unexpected error when testing AgentConfig: {e}")

    # Test invalid config (e.g., missing required field 'name')
    try:
        with pytest.raises(ValidationError):  # Expect pydantic.ValidationError
            AgentConfig(  # Uses the imported AgentConfig
                # name="invalid_agent", # Missing name
                role="Invalid Role",
                goal="Invalid Goal",
                backstory="Invalid Backstory",
                tools=[
                    "invalid_tool_format"
                ],  # Example of potentially invalid tool type
                verbose="not_a_boolean",  # Invalid type for verbose
            )
    except Exception as e:
        pytest.fail(f"Unexpected error in validation test: {e}")
