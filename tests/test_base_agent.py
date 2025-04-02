"""Test suite for the base agent implementation."""

import pytest
from api.agents.base_agent import AgentConfig, create_agent
from fastapi import HTTPException


def test_agent_config_creation():
    """Test successful agent configuration creation."""
    config = AgentConfig(
        name="Test Agent",
        role="Test Role",
        goal="Test Goal",
        backstory="Test Backstory",
        tools=[],
        verbose=True,
        allow_delegation=False,
    )
    assert config.name == "Test Agent"
    assert config.role == "Test Role"
    assert config.goal == "Test Goal"
    assert config.backstory == "Test Backstory"
    assert config.tools == []
    assert config.verbose is True
    assert config.allow_delegation is False


def test_agent_config_validation_empty_fields():
    """Test agent configuration validation with empty fields."""
    try:
        AgentConfig(name="")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_agent_config_validation_whitespace():
    """Test agent configuration validation with whitespace-only fields."""
    try:
        AgentConfig(name="   ")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_agent_config_tools_validation():
    """Test agent configuration tools validation."""
    config = AgentConfig(
        name="Test Agent",
        role="Test Role",
        goal="Test Goal",
        backstory="Test Backstory",
        tools=None,
        verbose=True,
        allow_delegation=False,
    )
    assert config.tools == []

    config = AgentConfig(
        name="Test Agent",
        role="Test Role",
        goal="Test Goal",
        backstory="Test Backstory",
        tools=[],
        verbose=True,
        allow_delegation=False,
    )
    assert config.tools == []

    try:
        AgentConfig(
            name="Test Agent",
            role="Test Role",
            goal="Test Goal",
            backstory="Test Backstory",
            tools="invalid",
            verbose=True,
            allow_delegation=False,
        )
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_agent_config_field_lengths():
    """Test agent configuration field length constraints."""
    try:
        AgentConfig(
            name="a" * 101,
            role="Test Role",
            goal="Test Goal",
            backstory="Test Backstory",
            tools=[],
            verbose=True,
            allow_delegation=False,
        )
        assert False, "Should have raised ValueError"
    except ValueError:
        pass

    try:
        AgentConfig(
            name="Test Agent",
            role="Test Role",
            goal="a" * 501,
            backstory="Test Backstory",
            tools=[],
            verbose=True,
            allow_delegation=False,
        )
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_create_agent_success():
    """Test successful agent creation."""
    config = AgentConfig(
        name="Test Agent",
        role="Test Role",
        goal="Test Goal",
        backstory="Test Backstory",
        tools=[],
        verbose=True,
        allow_delegation=False,
    )
    agent = create_agent(config)
    assert agent.name == "Test Agent"
    assert agent.role == "Test Role"
    assert agent.goal == "Test Goal"
    assert agent.backstory == "Test Backstory"
    assert agent.tools == []
    assert agent.verbose is True
    assert agent.allow_delegation is False


def test_create_agent_error_handling():
    """Test agent creation error handling."""
    try:
        create_agent(None)
        assert False, "Should have raised HTTPException"
    except HTTPException as e:
        assert e.status_code == 500
        assert "Failed to create agent" in str(e.detail)
