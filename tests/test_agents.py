"""Test suite for the agents module."""

import pytest
from fastapi.testclient import TestClient

from api.agents.base_agent import AgentConfig
from api.main import app

client = TestClient(app)


def test_create_agent_with_valid_config(sample_agent_config):
    """Test creating an agent with valid configuration.

    Should return 200 status code and match the input configuration.
    """
    response = client.post("/agents/", json=sample_agent_config)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == sample_agent_config["name"]
    assert data["role"] == sample_agent_config["role"]
    assert data["goal"] == sample_agent_config["goal"]
    assert data["status"] == "created"


def test_create_agent_with_missing_required_fields():
    """Test creating an agent with missing required fields.

    Should return 422 status code (validation error).
    """
    invalid_config = {
        "name": "Test Agent",
        # Missing role, goal, and backstory
    }
    response = client.post("/agents/", json=invalid_config)
    assert response.status_code == 422


def test_create_agent_with_invalid_tools():
    """Test creating an agent with invalid tools format.

    Should return 422 status code (validation error).
    """
    invalid_config = {
        "name": "Test Agent",
        "role": "Security Analyst",
        "goal": "Analyze security threats",
        "backstory": "Expert in cybersecurity analysis",
        "tools": "invalid_tool",  # Should be a list
    }
    response = client.post("/agents/", json=invalid_config)
    assert response.status_code == 422


def test_list_agents_empty():
    """Test listing agents when no agents exist.

    Should return 200 status code and empty list.
    """
    response = client.get("/agents/")
    assert response.status_code == 200
    assert response.json() == []


def test_agent_config_validation():
    """Test AgentConfig model validation."""
    # Test valid configuration
    valid_config = AgentConfig(
        name="Test Agent",
        role="Security Analyst",
        goal="Analyze security threats",
        backstory="Expert in cybersecurity analysis",
    )
    assert valid_config.name == "Test Agent"
    assert valid_config.role == "Security Analyst"

    # Test invalid configuration
    with pytest.raises(ValueError):
        AgentConfig(
            name="",  # Empty name should raise validation error
            role="Security Analyst",
            goal="Analyze security threats",
            backstory="Expert in cybersecurity analysis",
        )
