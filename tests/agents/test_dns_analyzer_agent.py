"""Tests for the DNSAnalyzerAgent."""

import pytest
from agents.dns_analyzer_agent.dns_analyzer_agent import DNSAnalyzerAgent

def test_dns_analyzer_agent_initialization():
    """Test that the DNSAnalyzerAgent initializes correctly."""
    try:
        agent_instance = DNSAnalyzerAgent()
        assert agent_instance is not None
        assert agent_instance.agent is not None
        assert agent_instance.agent.role == "DNS Analyst"
    except ValueError as e:
        pytest.fail(f"DNSAnalyzerAgent initialization failed: {e}")
    except Exception as e:
        pytest.fail(f"An unexpected error occurred during DNSAnalyzerAgent initialization: {e}")

# Add more specific tests here later 