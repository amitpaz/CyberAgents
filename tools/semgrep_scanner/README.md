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
- Support for local policy files as well as Semgrep registry rules
- Policy synchronization utility to fetch and manage rules from the official Semgrep repository

## Installation

The Semgrep Scanner Tool requires Semgrep to be installed:

```bash
pip install semgrep
```

### Syncing Policies

To use local policies, you need to first sync them from the Semgrep open source repository:

```bash
# Sync policies for all supported languages
python -m tools.semgrep_scanner.utils.policy_sync

# Sync policies for specific languages
python -m tools.semgrep_scanner.utils.policy_sync python javascript
```

## Usage

### Direct Usage

```python
from tools.semgrep_scanner import SemgrepTool, SemgrepInput

# Initialize the tool
semgrep_tool = SemgrepTool()

# Example: Scan a code snippet using Semgrep registry rules
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

# Example: Scan using local policies
result = await semgrep_tool.run(
    code=code,
    language="python",
    use_local_policies=True,
    policy_preference="local"  # Use only local policies
)

# Example: Scan using both registry and local policies
result = await semgrep_tool.run(
    code=code,
    language="python",
    rules=["p/security-audit"],
    use_local_policies=True,
    policy_preference="both"  # Use both local and registry policies
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
- `use_local_policies`: Whether to use local policies from the policies directory (defaults to False)
- `policy_preference`: Which policies to use (defaults to "both")
  - "local": Use only local policies 
  - "registry": Use only Semgrep registry policies
  - "both": Use both local and registry policies

## Local Policies

The tool supports using local Semgrep policy files stored in the `policies/knowledge/{language}` directory. These policies are synchronized from the official Semgrep repository but can be modified or extended as needed.

### Policy Sync Utility

The Policy Sync Utility (`tools.semgrep_scanner.utils.policy_sync`) provides the following functionality:

- Synchronize policies from the official Semgrep repository
- Filter policies by language
- Prioritize security-related policies
- Track synchronization metadata
- Support for syncing specific languages

To use the policy sync utility programmatically:

```python
from tools.semgrep_scanner.utils import sync_all_policies, sync_language_policies, get_sync_status

# Sync all supported languages
result = sync_all_policies()
print(f"Synchronized {result['total_policies']} policies")

# Sync specific languages
result = sync_language_policies(["python", "javascript"])
print(f"Synchronized {result['total_policies']} policies")

# Get sync status
status = get_sync_status()
print(f"Last sync: {status['last_sync']}")
print(f"Total policies: {status['total_policies']}")
```

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
    },
    "policy_config": {
        "registry_rules": ["p/security-audit", "p/owasp-top-ten"],
        "local_rules": ["/path/to/local/python_rules.yml"],
        "policy_preference": "both"
    }
} 