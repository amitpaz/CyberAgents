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
def mock_agents():
    """Create mock CrewAI agents for testing."""
    # Create MagicMocks that simulate the structure expected by the crew

    # Mock Security Manager Agent
    manager_mock_agent = MagicMock(spec=Agent)
    manager_mock_agent.role = "Mock Security Manager"
    manager_mock_agent.goal = "Oversee mock analysis"
    manager_mock_agent.backstory = "Mock manager backstory"
    manager_mock_agent.tools = []
    manager_mock_agent.llm = MagicMock()  # Mock LLM if needed
    manager_mock_agent.allow_delegation = True  # Important for manager

    manager_mock_wrapper = MagicMock(spec=SecurityManagerAgent)
    manager_mock_wrapper.agent = manager_mock_agent
    manager_mock_wrapper.agent_name = "SecurityManagerAgent"

    # Mock Specialist Agent
    agent1_mock_agent = MagicMock(spec=Agent)
    agent1_mock_agent.role = "Mock Specialist One"
    agent1_mock_agent.goal = "Perform mock task one"
    agent1_mock_agent.backstory = "Mock specialist one backstory"
    agent1_mock_agent.tools = [MagicMock(name="MockToolOne")]  # Mock tool
    agent1_mock_agent.llm = MagicMock()
    agent1_mock_agent.allow_delegation = False

    agent1_mock_wrapper = MagicMock()
    agent1_mock_wrapper.agent = agent1_mock_agent
    agent1_mock_wrapper.agent_name = "AgentOne"

    # Return a dictionary mapping names to the *wrapper* instances
    return {
        "SecurityManagerAgent": manager_mock_wrapper,
        "AgentOne": agent1_mock_wrapper,
    }


@pytest.fixture
def domain_crew(mock_agents):
    """Initialize DomainIntelligenceCrew with mock agents by patching discovery."""
    # Create a dictionary mapping agent names to their mock *classes* (or MagicMocks)
    # The structure needs to match what discover_and_load_agents returns.
    # We need to simulate the class, so the __init__ can be called inside DomainIntelligenceCrew.
    mock_agent_classes = {}
    for name, mock_instance in mock_agents.items():
        # Create a mock class that returns the mock instance when called
        mock_class = MagicMock(name=f"{name}Class")
        mock_class.return_value = mock_instance
        mock_agent_classes[name] = mock_class

    # Patch the discovery function to return our mock classes
    with patch("main.discover_and_load_agents", return_value=mock_agent_classes):
        crew_instance = DomainIntelligenceCrew()  # Initialize without args

    # We might need to manually re-inject the *instances* if tests rely on them directly
    # The crew_instance should now have the mocked instances internally after its __init__
    # If tests access crew_instance.agents_instances directly, we need this:
    # crew_instance.agents_instances = mock_agents
    # It depends on how the tests below use the `domain_crew` fixture.
    # Let's assume for now that the internal initialization is sufficient.

    return crew_instance


# --- Test Cases ---


def test_crew_initialization(domain_crew, mock_agents):
    """Test that the crew initializes with the correct agents and manager."""
    assert isinstance(domain_crew.crew, Crew)
    assert len(domain_crew.agents_instances) == len(mock_agents)
    assert domain_crew.manager_agent is not None
    # Check if the manager_agent is the actual mock agent object
    assert domain_crew.manager_agent.agent is mock_agents["SecurityManagerAgent"].agent
    assert "SecurityManagerAgent" in domain_crew.agents_instances


def test_create_domain_tasks(domain_crew, mock_agents):
    """Test the creation of tasks for a domain target."""
    target_domain = "example.com"
    tasks = domain_crew.create_domain_tasks(target_domain)

    assert isinstance(tasks, list)
    # Expecting one task per agent *excluding* the manager
    assert len(tasks) == len(mock_agents) - 1

    for task in tasks:
        assert isinstance(task, Task)
        assert target_domain in task.description
        # Check if the task agent is one of the *inner* CrewAI mock agents
        assert task.agent in [a.agent for a in mock_agents.values()]
        # Ensure manager agent isn't assigned a task directly here
        assert task.agent is not mock_agents["SecurityManagerAgent"].agent


@patch("utils.crew_utils.Crew.kickoff")
def test_run_analysis_success(mock_kickoff, domain_crew):
    """Test the run_analysis method for successful execution."""
    target_domain = "example.com"
    expected_result = "Analysis complete for example.com"
    mock_kickoff.return_value = expected_result

    # Since create_domain_tasks is called inside run_analysis,
    # ensure the crew object used by kickoff is correctly configured.
    # The fixture already sets up domain_crew.crew

    result = domain_crew.run_analysis(target_domain)

    assert result == expected_result
    mock_kickoff.assert_called_once()
    # Optionally, assert the tasks passed to the internal crew object
    assert len(domain_crew.crew.tasks) > 0


@patch("utils.crew_utils.Crew.kickoff", side_effect=Exception("Crew failed"))
def test_run_analysis_failure(mock_kickoff, domain_crew):
    """Test the run_analysis method when kickoff fails."""
    target_domain = "example.com"
    with pytest.raises(Exception, match="Crew failed"):
        domain_crew.run_analysis(target_domain)
    mock_kickoff.assert_called_once()
