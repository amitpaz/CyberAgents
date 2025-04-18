"""Agent responsible for assessing cloud security posture using Prowler.

This agent evaluates security configurations in cloud environments (AWS, Azure, GCP)
to identify misconfigurations, vulnerabilities, and compliance issues.
"""

import logging

# Import necessary components
from crewai import Agent

from agents.base_agent import BaseAgent
from tools.prowler_scan.prowler_scan_tool import ProwlerScanTool
from utils.llm_utils import create_llm

logger = logging.getLogger(__name__)


class CloudSecurityAgent(BaseAgent):
    """Agent specialized in cloud security posture assessment.

    Uses the ProwlerScanTool to evaluate cloud environments for security issues
    and compliance with best practices and standards.
    """

    def __init__(self):
        """Initialize the Cloud Security Agent."""
        super().__init__()
        self.agent_name = "CloudSecurityAgent"
        self.agent_role = "Cloud Security Posture Analyst"
        self.agent_goal = (
            "Evaluate cloud environments for security misconfigurations, vulnerabilities, "
            "and compliance issues using the Prowler scanner."
        )
        self.agent_backstory = (
            "An expert in cloud security with deep knowledge of AWS, Azure, and GCP security "
            "best practices. You specialize in identifying security risks in cloud deployments, "
            "assessing compliance with industry standards (CIS, HIPAA, GDPR, etc.), and "
            "providing remediation guidance to strengthen security posture."
        )
        self.agent_tools = [ProwlerScanTool()]
        logger.info("Cloud Security Agent initialized")

        # Initialize the crewai Agent
        self.agent = Agent(
            role=self.agent_role,
            goal=self.agent_goal,
            backstory=self.agent_backstory,
            tools=self.agent_tools,
            llm=create_llm(),
            verbose=True,
            allow_delegation=False,
        ) 