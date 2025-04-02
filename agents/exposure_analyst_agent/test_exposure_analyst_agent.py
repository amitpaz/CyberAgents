"""Tests for the ExposureAnalystAgent."""

import pytest
import os
from unittest.mock import patch
from agents.exposure_analyst_agent.exposure_analyst_agent import ExposureAnalystAgent

# Mock API keys needed for initialization checks within the agent
@patch.dict(os.environ, {"SHODAN_API_KEY": "test_key", "OPENAI_API_KEY": "test_key"})
# Mock subprocess.run to simulate nmap being found
@patch('subprocess.run') 
def test_exposure_analyst_agent_initialization(mock_subprocess_run): 
    """Test that the ExposureAnalystAgent initializes correctly (with mocks)."""
    # Configure the mock to simulate successful nmap check
    mock_subprocess_run.return_value = None # Or a mock object simulating CompletedProcess
    
    try:
        agent_instance = ExposureAnalystAgent()
        assert agent_instance is not None
        assert agent_instance.agent is not None
        assert agent_instance.agent.role == "Exposure Analyst"
        # Check that tools were potentially added (at least crtsh and asn)
        assert len(agent_instance.agent.tools) >= 2 
        # Check if nmap tool was added (because we mocked its check)
        assert any(tool.name == 'nmap_port_scanner' for tool in agent_instance.agent.tools)
        # Check if shodan tool was added (because we mocked the key)
        assert any(tool.name == 'shodan_host_search' for tool in agent_instance.agent.tools)
        
    except ValueError as e:
        pytest.fail(f"ExposureAnalystAgent initialization failed: {e}")
    except Exception as e:
         pytest.fail(f"An unexpected error occurred during ExposureAnalystAgent initialization: {e}")

# Add more specific tests later 