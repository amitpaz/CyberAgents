# Defect Review Agent

The Defect Review Agent analyzes security vulnerabilities identified by the AppSec Engineer Agent and provides detailed remediation guidance and code examples for fixing the issues.

## Features

- Analyzes security findings to understand the vulnerability context
- Generates specific remediation suggestions based on best practices
- Provides code examples showing how to fix vulnerabilities
- Prioritizes critical and high severity issues
- Customizes recommendations based on the programming language

## Usage

The Defect Review Agent is designed to work in conjunction with the AppSec Engineer Agent. While it can be used independently, its primary function is to receive and analyze findings from the AppSec Engineer Agent.

### Example: Manual Review

```python
from agents.defect_review_agent import DefectReviewAgent

agent = DefectReviewAgent()
findings = {
    "scan_id": "12345",
    "findings": [
        {
            "rule_id": "sql-injection",
            "message": "Possible SQL injection vulnerability",
            "severity": "high",
            "path": "app/db.py",
            "line": 42,
            "code": "query = \"SELECT * FROM users WHERE id = \" + user_input"
        }
    ]
}

code = """
def get_user(user_input):
    query = "SELECT * FROM users WHERE id = " + user_input
    return db.execute(query)
"""

remediation = await agent.review_vulnerabilities(findings, code)
print(remediation)
```

## Integration with AppSec Engineer Agent

The AppSec Engineer Agent automatically forwards findings to the Defect Review Agent when vulnerabilities are detected. You don't need to manually connect these agents in normal operation.

## Configuration

The agent supports the following configuration options:

- `max_suggestions_per_finding`: Maximum number of remediation suggestions to provide per finding
- `prioritize_critical`: Whether to prioritize critical and high severity findings
- `include_code_examples`: Whether to include code examples in remediation suggestions

## Future Development

The Defect Review Agent is currently a placeholder implementation. Future versions will include:

1. AI-powered remediation suggestion generation
2. Integration with security knowledge bases
3. Language-specific remediation strategies
4. Interactive remediation workflow
