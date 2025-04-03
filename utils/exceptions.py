"""Custom exceptions for the CyberAgents project."""


class RateLimitExceededError(Exception):
    """Exception raised when an API rate limit is exceeded."""

    def __init__(self, message="Rate limit exceeded. Please try again later."):
        self.message = message
        super().__init__(self.message)


class AgentError(Exception):
    """Base class for agent-related errors."""

    def __init__(self, message: str, agent_name: str = "Unknown"):
        """Initialize AgentError.

        Args:
            message: The error message.
            agent_name: The name of the agent where the error occurred.
        """
        self.agent_name = agent_name
        super().__init__(f"Agent [{agent_name}]: {message}")


class ToolError(Exception):
    """Base class for tool-related errors."""

    pass
