"""Agent responsible for DNS analysis."""

from crewai import Agent

from agents.base_agent import BaseAgent
from tools import DNSTool
from utils.llm_utils import create_llm


class DNSAnalyzerAgent(BaseAgent):
    """Creates and configures the DNS analysis agent.

    This agent specializes in retrieving and interpreting various DNS records
    (A, MX, NS, TXT, AAAA, DNSSEC) for a given domain name.
    """

    def __init__(self):
        """Initializes the agent with its configuration."""
        self.agent = Agent(
            role="DNS Analyst",
            goal="Analyze and extract structured DNS records for a specific domain.",
            backstory="An expert in Domain Name System (DNS) infrastructure. You accurately query and interpret various DNS record types (A, MX, NS, TXT, etc.) and DNSSEC status, presenting the information in a clear, structured format.",
            tools=[DNSTool()],
            llm=create_llm(),
            verbose=True,
            allow_delegation=False,
        )
