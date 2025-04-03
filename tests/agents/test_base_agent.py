"""Tests for base agent components (like AgentConfig)."""

import pytest
from pydantic import ValidationError

# Import the components to be tested from the correct location
from api.agents.base_agent import AgentConfig


# --- Fixtures ---
@pytest.fixture
def valid_agent_config_dict():
    """Return a dictionary representing a valid agent configuration."""
    return {
        "name": "TestAgent",
        "role": "Tester",
        "goal": "Test the system",
        "backstory": "I am a test agent",
        "tools": [],  # Assuming tools are names or handled by create_agent
        "verbose": True,
        "allow_delegation": False,
    }


@pytest.fixture
def invalid_agent_config_dict():
    """Return a dictionary representing an invalid agent configuration (missing role)."""
    return {
        "name": "TestAgentInvalid",
        # Missing 'role'
        "goal": "Test the system",
        "backstory": "I am a test agent",
    }


# --- AgentConfig Tests ---
def test_agent_config_validation_success(valid_agent_config_dict):
    """Test successful validation of AgentConfig."""
    config = AgentConfig(**valid_agent_config_dict)
    assert config.name == "TestAgent"
    assert config.role == "Tester"
    assert not config.tools


def test_agent_config_validation_failure(invalid_agent_config_dict):
    """Test validation failure for AgentConfig due to missing field."""
    with pytest.raises(ValidationError) as excinfo:
        AgentConfig(**invalid_agent_config_dict)
    assert "role" in str(excinfo.value)


@pytest.mark.parametrize(
    "field, value",
    [
        ("name", " "),
        ("role", "\t"),
        ("goal", ""),
        ("backstory", None),  # Test None separately
        ("backstory", "   "),  # Test whitespace separately
    ],
)
def test_agent_config_empty_or_invalid_fields(valid_agent_config_dict, field, value):
    """Test validation failure for empty, whitespace-only, or invalid type fields."""
    invalid_config = valid_agent_config_dict.copy()
    invalid_config[field] = value

    if value is None:
        # Expect Pydantic's type validation error for None
        with pytest.raises(ValidationError) as exc_info:
            AgentConfig(**invalid_config)
        # Check the specific error details
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == (field,)
        assert errors[0]["type"] == "string_type"
    else:
        # Expect our custom validator's error for empty/whitespace strings
        with pytest.raises(ValueError, match="Field cannot be empty"):
            AgentConfig(**invalid_config)


# --- BaseAgent Tests --- #
# Removed tests trying to instantiate api.agents.base_agent.BaseAgent with config,
# as its __init__ takes no arguments.
# def test_base_agent_initialization(valid_agent_config_dict):
#     pass
# def test_base_agent_invalid_tools():
#     pass
# def test_base_agent_process():
#     pass
