# AppSec Engineer Agent

The AppSec Engineer Agent is designed to identify security vulnerabilities in code by leveraging static code analysis tools like Semgrep. It can analyze code snippets or entire repositories to detect security issues, code quality problems, and potential vulnerabilities.

## Features

- Automatic language detection for provided code
- Static code analysis using Semgrep with security-focused rule sets
- Support for direct code input or GitHub repository analysis
- Automated cleanup of cloned repositories after analysis
- Configurable rate limiting, code size limits, and scan timeouts
- Integration with the Defect Review Agent for remediation recommendations

## Usage

The agent can be used in two primary modes:

1. **Direct code analysis**: Submit code directly to the agent for immediate assessment
2. **Repository analysis**: Provide a GitHub repository URL for comprehensive scanning

### Example: Direct Code Analysis

```python
from crewai import Crew
from agents.appsec_engineer_agent import AppSecEngineerAgent
from crewai.tasks import Task

# Initialize the AppSec Engineer Agent
appsec_agent = AppSecEngineerAgent()

# Create a task to analyze code
code_snippet = """
def user_login(username, password):
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    return db.execute(query)
"""

analysis_task = Task(
    description="Analyze this code for security vulnerabilities",
    agent=appsec_agent.agent,
    context={"code": code_snippet}
)

# Create and run a crew with the agent and task
crew = Crew(
    agents=[appsec_agent.agent],
    tasks=[analysis_task]
)

# Execute the crew to get the analysis result
result = crew.kickoff()
print(result)
```

### Example: Repository Analysis

```python
from crewai import Crew
from agents.appsec_engineer_agent import AppSecEngineerAgent
from crewai.tasks import Task

# Initialize the AppSec Engineer Agent
appsec_agent = AppSecEngineerAgent()

# Create a task to analyze repository
repo_analysis_task = Task(
    description="Analyze this repository for security vulnerabilities",
    agent=appsec_agent.agent,
    context={"repository_url": "https://github.com/username/repo"}
)

# Create and run a crew with the agent and task
crew = Crew(
    agents=[appsec_agent.agent],
    tasks=[repo_analysis_task]
)

# Execute the crew to get the analysis result
result = crew.kickoff()
print(result)
```

## Configuration

The agent's behavior is configured via the `agent.yaml` file, adhering to the CrewAI agent schema:

### Required Configuration

- `role`: Defines the agent's role as an "Application Security Engineer"
- `goal`: Describes the agent's purpose of analyzing code for vulnerabilities
- `backstory`: Provides context about the agent's expertise and approach
- `tools`: Lists the tools used by the agent (e.g., "semgrep_code_scanner")
- `allow_delegation`: Controls whether the agent can delegate to other agents

### Optional Configuration

- `verbose`: Enables detailed logging (default: true)
- `memory`: Enables agent memory capabilities (default: false)
- `max_iterations`: Maximum iterations for the agent (default: 15)
- `max_rpm`: Maximum requests per minute (default: 10)
- `cache`: Enables result caching (default: true)

### Agent-Specific Settings

- `supported_languages`: List of languages the agent can analyze
- `max_code_size`: Maximum size of code to analyze (in KB)

## Integration with Defect Review Agent

When vulnerabilities are found, the AppSec Engineer Agent can delegate to the Defect Review Agent, which provides specific remediation guidance for each issue. This handoff ensures that issues are properly analyzed for risk and mitigation strategies.

Example of multi-agent workflow:

```python
from crewai import Crew
from agents.appsec_engineer_agent import AppSecEngineerAgent
from agents.defect_review_agent import DefectReviewAgent
from crewai.tasks import Task

# Initialize agents
appsec_agent = AppSecEngineerAgent()
defect_agent = DefectReviewAgent()

# Create tasks
code_analysis_task = Task(
    description="Analyze this code for security vulnerabilities",
    agent=appsec_agent.agent,
    context={"code": vulnerable_code}
)

remediation_task = Task(
    description="Provide remediation guidance for the identified vulnerabilities",
    agent=defect_agent.agent,
    context={},
    depends_on=[code_analysis_task]
)

# Create a crew with agents and tasks
crew = Crew(
    agents=[appsec_agent.agent, defect_agent.agent],
    tasks=[code_analysis_task, remediation_task]
)

# Run the analysis and remediation workflow
result = crew.kickoff()
``` 