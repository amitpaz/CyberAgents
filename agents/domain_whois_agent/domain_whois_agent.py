"""Agent responsible for WHOIS analysis."""

from crewai import Agent
from tools.whois_tool import WhoisTool
from utils.llm_utils import create_llm

class DomainWhoisAgent:
    """Creates and configures the WHOIS analysis agent.

    This agent specializes in retrieving and parsing WHOIS registration data
    for a given domain name.
    """
    
    def __init__(self):
        """Initializes the agent with its configuration."""
        self.agent = Agent(
            role="WHOIS Analyst",
            goal="Analyze and extract structured WHOIS data for a specific domain.",
            backstory="An expert specializing in domain registration and ownership data. You meticulously retrieve WHOIS records and parse them into a consistent, structured format, focusing on key details like registrar, creation/expiration dates, and name servers.",
            tools=[WhoisTool()],
            llm=create_llm(),
            verbose=True,
            allow_delegation=False # This agent performs a specific task
        ) 