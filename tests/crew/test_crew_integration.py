"""Integration tests for the domain analysis crew."""

import asyncio
import logging

import pytest
from crewai import Agent, Crew, Process, Task

# Import Agents
from agents.dns_analyzer_agent.dns_analyzer_agent import DNSAnalyzerAgent
from agents.domain_whois_agent.domain_whois_agent import DomainWhoisAgent
from agents.email_security_agent.email_security_agent import EmailSecurityAgent
from agents.exposure_analyst_agent.exposure_analyst_agent import ExposureAnalystAgent
from agents.security_manager_agent.security_manager_agent import SecurityManagerAgent
from agents.threat_intel_agent.threat_intel_agent import ThreatIntelAgent
from main import DomainIntelligenceCrew

# Import Tools (assuming they are accessible)
# If tools need initialization with API keys, fixtures might be needed
from tools.asn_ip_lookup_tool.asn_ip_lookup_tool import ASNIPLookupTool
from tools.dns_lookup.dns_tool import DNSTool
from tools.email_validation.email_validation_tool import EmailValidationTool
from tools.nmap_port_scan_tool.nmap_port_scan_tool import NmapPortScanTool
from tools.shodan_search.shodan_tool import ShodanHostSearchTool
from tools.subdomain_finder.subdomain_finder_tool import SubdomainFinderTool
from tools.threat_intel_analyzer.threat_tool import ThreatTool
from tools.whois_lookup.whois_tool import WhoisTool

# Removed unused typing imports
# from typing import Any, Dict, List, Optional


# Removed unused BaseTool
# from crewai.tools import BaseTool
# Removed unused langchain imports
# from langchain.schema import messages_from_dict, messages_to_dict


logger = logging.getLogger(__name__)


# --- Fixtures ---
@pytest.fixture(scope="module")
def event_loop():
    """Create an instance of the default event loop for the test module."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="module")
def test_agents():
    """Fixture to provide initialized test agents."""
    try:
        return {
            "dns": DNSAnalyzerAgent(),
            "whois": DomainWhoisAgent(),
            "email": EmailSecurityAgent(),
            "exposure": ExposureAnalystAgent(),
            "threat": ThreatIntelAgent(),
            "manager": SecurityManagerAgent(),
        }
    except Exception as e:
        pytest.fail(f"Failed to initialize agents for testing: {e}")


@pytest.fixture(scope="module")
def test_tools():
    """Fixture to provide initialized test tools."""
    # Note: Tools requiring API keys might fail here if keys are not set
    # Consider using mocks or skipping tests if keys aren't available
    try:
        return {
            "asn": ASNIPLookupTool(),
            "dns": DNSTool(),
            "email": EmailValidationTool(),
            "nmap": NmapPortScanTool(),
            "shodan": ShodanHostSearchTool(),
            "subdomain": SubdomainFinderTool(),
            "threat": ThreatTool(),
            "whois": WhoisTool(),
        }
    except Exception as e:
        logger.warning(f"Failed to initialize some tools (API keys?): {e}")
        return {}  # Return empty dict if tools fail


@pytest.fixture(scope="module")
def domain_intel_crew(test_agents):
    """Fixture to provide an initialized DomainIntelligenceCrew."""
    try:
        # Pass initialized agents to the crew
        crew_instance = DomainIntelligenceCrew(
            agents_list=[agent for agent in test_agents.values()]
        )
        return crew_instance
    except Exception as e:
        pytest.fail(f"Failed to initialize DomainIntelligenceCrew for testing: {e}")


# --- Test Cases ---


@pytest.mark.asyncio
async def test_crew_initialization(domain_intel_crew):
    """Test that the DomainIntelligenceCrew initializes correctly."""
    assert domain_intel_crew is not None
    assert isinstance(domain_intel_crew.crew, Crew)
    assert len(domain_intel_crew.agents_instances) > 0
    assert "SecurityManagerAgent" in domain_intel_crew.agents_instances


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["google.com", "8.8.8.8"])  # Test with domain and IP
async def test_create_domain_tasks(domain_intel_crew, target):
    """Test task creation for a given target."""
    tasks = domain_intel_crew.create_domain_tasks(target)
    assert isinstance(tasks, list)
    assert len(tasks) > 0
    for task in tasks:
        assert isinstance(task, Task)
        assert target in task.description  # Ensure target is in task description
        assert task.agent is not None
        assert isinstance(task.agent, Agent)


@pytest.mark.skip(
    reason="Skipping full crew run due to potential API costs/rate limits"
)
@pytest.mark.asyncio
async def test_run_crew_analysis(domain_intel_crew):
    """Test running the full crew analysis (SKIPPED by default)."""
    target_domain = "example.com"  # Use a safe, common domain
    # Assuming run_analysis is now synchronous based on previous refactoring
    # If it's still async, keep await
    result = domain_intel_crew.run_analysis(target_domain)

    assert result is not None
    assert isinstance(result, str)  # Expecting a string summary report
    assert target_domain in result  # Report should mention the target
    # Add more specific assertions based on expected report format if possible
    logger.info(f"Crew analysis result for {target_domain}:\n{result}")


# Example test for a specific agent's functionality (if applicable)
@pytest.mark.asyncio
async def test_dns_agent_task(test_agents):
    """Test a simple task delegation to the DNS agent."""
    dns_agent_wrapper = test_agents.get("dns")
    manager_agent_wrapper = test_agents.get("manager")
    if not dns_agent_wrapper or not manager_agent_wrapper:
        pytest.skip("Required agents (DNS, Manager) not initialized")

    task = Task(
        description="Perform a DNS lookup for A records on google.com.",
        agent=dns_agent_wrapper.agent,  # Access the underlying crewai Agent
        expected_output="A list of IP addresses for google.com.",
    )

    # Minimal crew to test delegation
    crew = Crew(
        agents=[dns_agent_wrapper.agent, manager_agent_wrapper.agent],
        tasks=[task],
        process=Process.sequential,
        verbose=True,
    )
    # Kickoff is synchronous
    result = crew.kickoff()
    assert result is not None
    assert "google.com" in result
    assert "172.217." in result or "142.250." in result  # Check for known Google IPs
