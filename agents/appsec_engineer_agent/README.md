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
from agents.appsec_engineer_agent import AppSecEngineerAgent

agent = AppSecEngineerAgent()
code = """
def user_login(username, password):
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    return db.execute(query)
"""
results = await agent.analyze_code(code)
print(results)
```

### Example: Repository Analysis

```python
from agents.appsec_engineer_agent import AppSecEngineerAgent

agent = AppSecEngineerAgent()
results = await agent.analyze_repository("https://github.com/username/repo")
print(results)
```

## Configuration

The agent supports the following configuration options:

- `rate_limit`: Maximum number of scans per time period
- `max_code_size`: Maximum size of code to analyze (in KB)
- `supported_languages`: List of languages to analyze (["python", "javascript", "java", "go", "ruby", "php", "c", "cpp"])
- `max_scan_time`: Maximum time for scan execution (in seconds)
- `semgrep_rules`: Custom Semgrep rules to apply during analysis

## Integration with Defect Review Agent

When vulnerabilities are found, the AppSec Engineer Agent automatically forwards them to the Defect Review Agent, which provides specific remediation guidance for each issue. 