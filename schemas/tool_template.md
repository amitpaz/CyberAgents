# Tool Template

## Tool Information

**Name**: \[Tool Name\]

**Version**: \[Tool Version\]

**Author**: \[Author Name/Team\]

**Category**: \[Security/Analysis/Utility/etc.\]

**Description**:
A comprehensive description of the tool, explaining its purpose, primary functionality, and the problem it aims to solve. Include relevant background information and why this tool is necessary or beneficial to the CyberAgents ecosystem.

## Prerequisites

- Python 3.8+
- Required packages: \[list required packages\]
- External dependencies: \[list any external dependencies like system packages\]

## Installation

```bash
# Install via Poetry (recommended)
poetry add [package-name]

# Or via pip
pip install [package-name]
```

## Configuration

### Required Configuration

```yaml
# Example configuration in agent.yaml or config file
[tool_name]:
  api_key: YOUR_API_KEY
  base_url: https://api.example.com/v1
  timeout: 30
```

### Optional Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `timeout` | int | 60 | Request timeout in seconds |
| `retries` | int | 3 | Number of retry attempts |
| `log_level` | string | "INFO" | Logging level |

## Usage

### Basic Usage

```python
from tools.example_tool import ExampleTool

# Initialize the tool
tool = ExampleTool(api_key="your-api-key", base_url="https://api.example.com/v1")

# Run the tool
results = tool.scan(target="example.com", options={"depth": 3})
print(results)
```

### Advanced Usage

```python
# Example of advanced configuration
tool = ExampleTool(
    api_key="your-api-key",
    base_url="https://api.example.com/v1",
    timeout=120,
    custom_headers={"X-Custom-Header": "value"},
    proxy="http://proxy.example.com:8080",
)

# Run with advanced options
results = tool.scan(
    target="example.com",
    options={
        "depth": 3,
        "scan_type": "deep",
        "include_subdomains": True,
        "exclude_paths": ["/admin", "/api"],
    },
)

# Process results
for finding in results.findings:
    print(f"Found issue: {finding.title} - Severity: {finding.severity}")
```

## Integration with Agents

```python
from crewai import Agent, Task
from tools.example_tool import ExampleTool

# Create tool instance
example_tool = ExampleTool(api_key="your-api-key")

# Create agent with tool
security_agent = Agent(
    role="Security Analyst",
    goal="Identify security vulnerabilities in web applications",
    backstory="You are an expert in web application security...",
    tools=[example_tool],
)

# Create task using the tool
analysis_task = Task(
    description="Analyze the target website for security vulnerabilities",
    agent=security_agent,
    expected_output="A comprehensive security report",
    tools=[example_tool],
)
```

## Command Line Interface

This tool can also be used directly from the command line:

```bash
# Basic usage
example-tool scan --target example.com

# With additional options
example-tool scan --target example.com --depth 3 --output-format json --output-file results.json

# Get help
example-tool --help
example-tool scan --help
```

## API Reference

### Main Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `scan()` | target (str), options (dict) | ScanResult | Performs a security scan on the target |
| `analyze_results()` | results (ScanResult) | AnalysisReport | Analyzes the scan results |
| `export_report()` | report (AnalysisReport), format (str) | str or bytes | Exports the report in the specified format |

### Data Models

#### ScanResult

```python
class ScanResult:
    id: str  # Unique identifier for the scan
    target: str  # Scanned target
    timestamp: datetime  # When the scan was performed
    duration: float  # Duration of the scan in seconds
    findings: List[Finding]  # List of findings
    status: str  # Status of the scan (success, error, etc.)
    errors: List[str]  # Any errors encountered during the scan
```

#### Finding

```python
class Finding:
    id: str  # Unique identifier for the finding
    title: str  # Title of the finding
    description: str  # Detailed description
    severity: str  # Severity level (critical, high, medium, low, info)
    cvss_score: float  # CVSS score if applicable
    affected_component: str  # Component affected
    remediation: str  # Suggested remediation steps
    references: List[str]  # References for further reading
```

## Error Handling

```python
try:
    results = tool.scan(target="example.com")
except ApiRateLimitError:
    # Handle rate limiting
    print("Rate limit exceeded, trying again later...")
except AuthenticationError:
    # Handle authentication issues
    print("Authentication failed, check your API key")
except ConnectionTimeoutError:
    # Handle timeout
    print("Connection timed out, check network or increase timeout")
except Exception as e:
    # Handle other exceptions
    print(f"An unexpected error occurred: {str(e)}")
```

## Best Practices

1. **Authentication**: Always store API keys and credentials securely. Never hardcode them in your scripts.
1. **Rate Limiting**: Implement proper rate limiting and backoff mechanisms to avoid API bans.
1. **Error Handling**: Always implement proper error handling to gracefully manage failures.
1. **Logging**: Configure appropriate logging levels based on your environment.
1. **Caching**: Use caching for repetitive operations to improve performance.

## Troubleshooting

### Common Issues

1. **Connection Errors**

   - Check your internet connection
   - Verify API endpoint URL
   - Ensure firewall is not blocking connections

1. **Authentication Failures**

   - Verify API key is correct and active
   - Check if account has necessary permissions

1. **Timeout Errors**

   - Increase timeout setting
   - Verify target is accessible
   - Consider breaking large scans into smaller operations

## Changelog

### v1.0.0 (YYYY-MM-DD)

- Initial release
- Feature A
- Feature B

### v0.9.0 (YYYY-MM-DD)

- Beta release
- Fixed issue X
- Enhanced feature Y

## License

\[Specify the license here, e.g., MIT, Apache 2.0, etc.\]

## Contact

For support, feature requests, or bug reports, please contact:

- Email: \[support email\]
- GitHub: \[GitHub repository\]
- Discord: \[Discord channel\]
