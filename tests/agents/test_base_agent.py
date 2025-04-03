"""Tests for the base agent module."""

import pytest

from api.agents.base_agent import BaseAgent


def test_base_agent_initialization():
    """Test base agent initialization with valid config."""
    config = {
        "id": "test_agent",
        "name": "Test Agent",
        "description": "A test agent",
        "tools": [
            {"name": "tool1", "type": "type1"},
            {"name": "tool2", "type": "type2"},
        ],
    }
    agent = BaseAgent(config)
    assert agent.config == config
    assert len(agent.tools) == 2


def test_base_agent_invalid_tools():
    """Test base agent initialization with invalid tools config."""
    config = {
        "id": "test_agent",
        "name": "Test Agent",
        "description": "A test agent",
        "tools": "invalid",  # Should be a list
    }
    with pytest.raises(ValueError):
        BaseAgent(config)


def test_base_agent_process():
    """Test base agent process method."""
    config = {
        "id": "test_agent",
        "name": "Test Agent",
        "description": "A test agent",
        "tools": [],
    }
    agent = BaseAgent(config)
    result = agent.process({"input": "test"})
    assert isinstance(result, dict)
