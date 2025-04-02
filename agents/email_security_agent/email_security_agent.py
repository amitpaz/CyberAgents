"""Agent responsible for Email Security (SPF/DMARC) validation."""

from crewai import Agent
from tools.email_validation_tool import EmailValidationTool # Import the new tool
from utils.llm_utils import create_llm

class EmailSecurityAgent:
    """Creates and configures the Email Security validation agent.

    This agent specializes in validating SPF and DMARC DNS records for a domain
    and providing suggestions for improvement based on best practices.
    """
    
    def __init__(self):
        """Initializes the agent with its configuration."""
        self.agent = Agent(
            role="Email Security Specialist",
            goal="Validate SPF and DMARC DNS records for a specific domain, identify issues, and propose remediation steps.",
            backstory=("An expert in email authentication protocols (SPF, DKIM, DMARC). "
                       "You meticulously check DNS records for proper configuration, analyze policies, "
                       "and provide actionable suggestions to improve email deliverability and security posture."),
            tools=[EmailValidationTool()], # Use the new tool
            llm=create_llm(),
            verbose=True,
            allow_delegation=False # This agent performs a specific task
        ) 