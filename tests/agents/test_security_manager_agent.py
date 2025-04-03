"""Tests for the SecurityManagerAgent."""

import pytest
from agents.security_manager_agent.security_manager_agent import SecurityManagerAgent

def test_security_manager_agent_initialization():
    """Test that the SecurityManagerAgent initializes correctly."""
    try:
        agent_instance = SecurityManagerAgent()
        assert agent_instance is not None
        assert agent_instance.agent is not None
        assert agent_instance.agent.role == "Security Analysis Manager"
        assert agent_instance.agent.allow_delegation is True # Important check
    except ValueError as e:
        pytest.fail(f"SecurityManagerAgent initialization failed: {e}")
    except Exception as e:
        pytest.fail(f"An unexpected error occurred during SecurityManagerAgent initialization: {e}")

# Add more specific tests here later (e.g., testing delegation logic if possible) 