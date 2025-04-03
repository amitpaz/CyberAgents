"""Tests for the ThreatIntelAgent."""

import pytest
import os
from unittest.mock import patch
from agents.threat_intel_agent.threat_intel_agent import ThreatIntelAgent

# Mock the environment variable for testing initialization
@patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test_key", "OPENAI_API_KEY": "test_key"}) 
def test_threat_intel_agent_initialization():
    """Test that the ThreatIntelAgent initializes correctly with mocked API key."""
    try:
        agent_instance = ThreatIntelAgent()
        assert agent_instance is not None
        assert agent_instance.agent is not None
        assert agent_instance.agent.role == "Threat Intelligence Analyst"
    except ValueError as e:
        pytest.fail(f"ThreatIntelAgent initialization failed: {e}")
    except Exception as e:
        pytest.fail(f"An unexpected error occurred during ThreatIntelAgent initialization: {e}")

def test_threat_intel_agent_missing_key():
    """Test that ThreatIntelAgent raises ValueError if VIRUSTOTAL_API_KEY is missing."""
    # Ensure the key is not set for this test
    with patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"}, clear=True):
        if "VIRUSTOTAL_API_KEY" in os.environ:
             del os.environ["VIRUSTOTAL_API_KEY"] # Ensure it's removed
             
        with pytest.raises(ValueError, match="VIRUSTOTAL_API_KEY environment variable is not set"): 
            ThreatIntelAgent()

# Add more specific tests here later 