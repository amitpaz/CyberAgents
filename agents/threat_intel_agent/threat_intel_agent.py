"""Agent responsible for Threat Intelligence analysis."""

import os
import pytest
from crewai import Agent
from tools.threat_tool import ThreatTool
from utils.llm_utils import create_llm
from agents.base_agent import BaseAgent

class ThreatIntelAgent(BaseAgent):
    """Creates and configures the Threat Intelligence analysis agent.

    This agent specializes in assessing the security threat level of a domain
    using external threat intelligence sources like VirusTotal.
    """
    
    def __init__(self):
        """Initializes the agent with its configuration.
        
        Raises:
            ValueError: If VIRUSTOTAL_API_KEY is not set.
        """
        # Check for required API keys
        if not os.environ.get("VIRUSTOTAL_API_KEY"):
            # Raise error if key is missing (skip is only for pytest context)
            raise ValueError("VIRUSTOTAL_API_KEY environment variable is not set and is required for ThreatIntelAgent")
        
        self.agent = Agent(
            role="Threat Intelligence Analyst",
            goal="Analyze security threats associated with a specific domain using external intelligence sources.",
            backstory="A seasoned security analyst specializing in threat intelligence. You leverage external databases like VirusTotal to assess domain reputation, identify malicious associations, and provide a structured threat score and summary.",
            tools=[ThreatTool()],
            llm=create_llm(),
            verbose=True,
            allow_delegation=False
        ) 