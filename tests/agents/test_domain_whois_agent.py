"""Tests for the DomainWhoisAgent."""

import pytest

from agents.domain_whois_agent.domain_whois_agent import DomainWhoisAgent


def test_domain_whois_agent_initialization():
    """Test that the DomainWhoisAgent initializes correctly."""
    try:
        agent_instance = DomainWhoisAgent()
        assert agent_instance is not None
        assert agent_instance.agent is not None
        assert agent_instance.agent.role == "Domain Registrar Analyst"
    except ValueError as e:
        pytest.fail(f"DomainWhoisAgent initialization failed: {e}")
    except Exception as e:
        pytest.fail(
            f"An unexpected error occurred during DomainWhoisAgent initialization: {e}"
        )


# Add more specific tests here later, e.g., mocking the tool
