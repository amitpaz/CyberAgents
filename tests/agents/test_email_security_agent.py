"""Tests for the EmailSecurityAgent."""

import pytest
from agents.email_security_agent.email_security_agent import EmailSecurityAgent

def test_email_security_agent_initialization():
    """Test that the EmailSecurityAgent initializes correctly."""
    try:
        agent_instance = EmailSecurityAgent()
        assert agent_instance is not None
        assert agent_instance.agent is not None
        assert agent_instance.agent.role == "Email Security Specialist"
    except ValueError as e:
        pytest.fail(f"EmailSecurityAgent initialization failed: {e}")
    except Exception as e:
        pytest.fail(f"An unexpected error occurred during EmailSecurityAgent initialization: {e}")

# Add more specific tests here later 