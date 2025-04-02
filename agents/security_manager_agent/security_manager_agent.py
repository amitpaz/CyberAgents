"""Agent responsible for managing and orchestrating security analysis tasks."""

from crewai import Agent
from utils.llm_utils import create_llm
from agents.base_agent import BaseAgent

class SecurityManagerAgent(BaseAgent):
    """Creates and configures the Security Manager agent.

    This agent acts as the central orchestrator. It interprets user requests,
    identifies necessary analysis types, delegates tasks to specialist agents,
    and synthesizes their findings into a final report.
    """

    def __init__(self):
        """Initializes the agent with its configuration."""
        self.agent = Agent(
            role="Security Analysis Manager",
            goal=("Understand user requests related to security analysis (primarily domain intelligence). "
                  "Identify the specific information required (e.g., WHOIS, DNS, Threat Intel). "
                  "Dynamically delegate the appropriate analysis tasks to available specialist agents. "
                  "Compile the structured results from each specialist into a cohesive and comprehensive final report."),
            backstory=("An experienced security operations manager responsible for coordinating diverse security analyses. "
                       "You excel at interpreting user needs, identifying the right expert for each task from your available team, "
                       "and integrating disparate findings into actionable intelligence."),
            tools=[], # Relies on delegation
            llm=create_llm(),
            verbose=True,
            allow_delegation=True # Essential for this agent's function
        ) 