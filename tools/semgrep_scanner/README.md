# Semgrep Scanner Tool

A tool for scanning code for security vulnerabilities using Semgrep, a static analysis engine for finding bugs, detecting vulnerabilities, and enforcing code standards.

## Features

- Automatically detect programming language from code content or file extension
- Scan code snippets or files for security vulnerabilities
- Detect a wide range of security issues including:
  - SQL injection
  - Cross-site scripting (XSS)
  - Command injection
  - Path traversal
  - Insecure deserialization
  - Hardcoded credentials
  - And many more
- Generate detailed reports with severity levels and categorization
- Link findings to CWE and OWASP Top 10 references

## Installation

The Semgrep Scanner Tool requires Semgrep to be installed:

```bash
pip install semgrep
```

## Usage

### Direct Usage

```python
from tools.semgrep_scanner import SemgrepTool, SemgrepInput

# Initialize the tool
semgrep_tool = SemgrepTool()

# Example: Scan a code snippet
code = """
def vulnerable_function(user_input):
    query = "SELECT * FROM users WHERE id = " + user_input
    return db.execute(query)
"""

result = await semgrep_tool.run(
    code=code,
    language="python",
    rules=["p/security-audit", "p/owasp-top-ten"]
)

# Print findings
print(f"Found {len(result['findings'])} issues:")
for finding in result['findings']:
    print(f"- {finding['rule_id']} ({finding['severity'].upper()}): {finding['message']}")
    print(f"  Line {finding['line']}: {finding['code'].strip()}")
```

### Usage with CrewAI

```python
from crewai import Agent, Task, Crew
from tools.semgrep_scanner import SemgrepTool

# Create an agent with the Semgrep Scanner tool
security_agent = Agent(
    name="Security Engineer",
    role="Analyze code for security vulnerabilities",
    goal="Find and report all security issues in the provided code",
    backstory="You are an expert in application security with extensive knowledge of secure coding practices.",
    tools=[SemgrepTool()]
)

# Create a task
code_review_task = Task(
    description="""
    Analyze the following code for security vulnerabilities:
    
    ```python
    def process(user_data):
        os.system("echo " + user_data)
        query = "SELECT * FROM users WHERE name = '" + user_data + "'"
        return db.execute(query)
    ```
    
    Use the semgrep_scanner tool to find any security issues.
    """,
    agent=security_agent
)

# Create a crew and run the task
crew = Crew(agents=[security_agent], tasks=[code_review_task])
result = crew.kickoff()
print(result)
```

## Configuration

The tool supports the following configuration options:

- `code`: Code snippet to scan for vulnerabilities
- `file_path`: Path to file or directory to scan
- `language`: Programming language of the code (auto-detected if not specified)
- `rules`: Semgrep rule sets to use for scanning (defaults to ["p/security-audit", "p/owasp-top-ten"])
- `max_timeout`: Maximum execution time in seconds (defaults to 300)

## Supported Languages

The tool can detect and scan code in the following languages:

- Python
- JavaScript (including TypeScript, JSX, and TSX)
- Java
- Go
- Ruby
- PHP
- C
- C++

## Output Format

The tool returns a dictionary with the following structure:

```python
{
    "findings": [
        {
            "rule_id": "sql-injection",
            "message": "SQL Injection vulnerability",
            "severity": "high",
            "path": "app.py",
            "line": 10,
            "code": "query = 'SELECT * FROM users WHERE id = ' + user_input",
            "cwe": ["CWE-89"],
            "owasp": ["A1:2017"]
        },
        # More findings...
    ],
    "severity_summary": {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "info": 0
    },
    "stats": {
        "total_findings": 1,
        "files_scanned": 1,
        "scan_time": 0.35
    }
}
``` 