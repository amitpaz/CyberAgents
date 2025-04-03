"""Tests for the DomainIntelligenceCrew class."""

# import asyncio # Removed unused import
from unittest.mock import MagicMock, patch

import pytest
from crewai import Agent, Crew, Task

# Assuming agents are initialized correctly elsewhere or mocked
from agents.security_manager_agent.security_manager_agent import SecurityManagerAgent

# Import the class to be tested
from main import DomainIntelligenceCrew

# from unittest.mock import Mock # Removed unused import


# --- Fixtures ---


@pytest.fixture
def domain_crew():
    """Initialize DomainIntelligenceCrew using its real discovery mechanism."""
    # Remove patching logic
    # with patch("main.discover_and_load_agents", return_value=mock_agent_classes):
    # Initialize directly, relying on the actual agent discovery
    crew_instance = DomainIntelligenceCrew()
    return crew_instance


# --- Test Cases ---


def test_crew_initialization(domain_crew):
    """Test that the crew initializes with discovered agents and a manager."""
    assert isinstance(domain_crew.crew, Crew)
    # Assert that some agents were discovered (adjust number if known)
    assert len(domain_crew.agents_instances) > 0
    assert domain_crew.manager_agent is not None
    # Check if the manager agent is the correct type
    assert isinstance(domain_crew.manager_agent, SecurityManagerAgent)
    assert "SecurityManagerAgent" in domain_crew.agents_instances


@patch("crewai.Crew.kickoff")
def test_run_analysis_success(mock_kickoff, domain_crew):
    """Test the run_analysis method for successful execution."""
    target_domain = "example.com"
    expected_result = "Analysis complete for example.com"
    mock_kickoff.return_value = expected_result

    # Since create_domain_tasks is called inside run_analysis,
    # ensure the crew object used by kickoff is correctly configured.
    # The fixture already sets up domain_crew.crew

    result = domain_crew.run_analysis(target_domain)

    # Assert the analysis_report key contains the expected result
    assert "analysis_report" in result
    assert result["analysis_report"] == expected_result
    mock_kickoff.assert_called_once()
    # Optionally, assert the tasks passed to the internal crew object
    assert len(domain_crew.crew.tasks) > 0


@patch("crewai.Crew.kickoff", side_effect=Exception("Crew failed"))
def test_run_analysis_failure(mock_kickoff, domain_crew):
    """Test the run_analysis method when kickoff fails."""
    target_domain = "example.com"
    # Call run_analysis and expect it to return an error dictionary
    result = domain_crew.run_analysis(target_domain)
    
    # Assert that an error was returned and contains the expected message
    assert "error" in result
    assert "Crew failed" in result["error"]
    # Assert kickoff was still called
    mock_kickoff.assert_called_once()
