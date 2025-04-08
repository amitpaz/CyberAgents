# Email Security Validation Tool

## Tool Information

**Name**: Email Security Validator

**Version**: 1.0.0

**Author**: CyberAgents Team

**Category**: Email Security/Verification

**Description**:
The Email Security Validation Tool examines a domain's email security posture by checking for the presence and validity of Sender Policy Framework (SPF) and Domain-based Message Authentication, Reporting & Conformance (DMARC) records. These DNS-based email authentication methods help prevent email spoofing, phishing, and other email-based attacks. This tool provides security professionals with insights into a domain's email security configuration, identifies missing or misconfigured records, and offers recommendations for improving email security posture.

## Prerequisites

- Python 3.8+
- Required packages: dnspython, crewai, pydantic
- External dependencies: None

## Installation

```bash
# Install via Poetry (recommended)
poetry add dnspython

# Or via pip
pip install dnspython
```

## Configuration

### Required Configuration

No specific configuration is required for this tool.

### Optional Configuration

No optional configuration parameters are available for this tool.

## Usage

### Basic Usage

```python
from tools.email_validation.email_validation_tool import EmailValidationTool

# Initialize the tool
tool = EmailValidationTool()

# Validate email security for a domain
results = tool._run(domain="example.com")
print(results)
```

### Advanced Usage

```python
from tools.email_validation.email_validation_tool import EmailValidationTool
import json

# Initialize the tool
tool = EmailValidationTool()

# Validate email security
results = tool._run(domain="example.com")

# Process SPF results
spf_results = results.get("spf", {})
print("SPF Record Analysis:")
if spf_results.get("valid"):
    print(f"✅ Valid SPF record found: {spf_results.get('record')}")
else:
    print("❌ No valid SPF record found")
print(f"Suggestion: {spf_results.get('suggestion')}")

# Process DMARC results
dmarc_results = results.get("dmarc", {})
print("\nDMARC Record Analysis:")
if dmarc_results.get("valid"):
    print(f"✅ Valid DMARC record found: {dmarc_results.get('record')}")
else:
    print("❌ No valid DMARC record found")
print(f"Suggestion: {dmarc_results.get('suggestion')}")

# Generate security score
security_score = 0
if spf_results.get("valid"):
    security_score += 50
    # Additional points for strict SPF policy
    if "-all" in str(spf_results.get("record", "")):
        security_score += 10

if dmarc_results.get("valid"):
    security_score += 50
    # Additional points for strict DMARC policy
    record = str(dmarc_results.get("record", ""))
    if "p=reject" in record:
        security_score += 15
    elif "p=quarantine" in record:
        security_score += 10

print(f"\nEmail Security Score: {security_score}/125")
print(
    f"Security Rating: {'Good' if security_score > 100 else 'Fair' if security_score > 60 else 'Poor'}"
)

# Export results to JSON
with open(f"{domain.replace('.', '_')}_email_security.json", "w") as f:
    json.dump(results, f, indent=2)
```

## Integration with Agents

```python
from crewai import Agent, Task
from tools.email_validation.email_validation_tool import EmailValidationTool

# Create tool instance
email_validation_tool = EmailValidationTool()

# Create agent with tool
security_agent = Agent(
    role="Email Security Specialist",
    goal="Assess and improve email security posture",
    backstory="You are an expert in email security and authentication protocols...",
    tools=[email_validation_tool],
)

# Create task using the tool
email_security_task = Task(
    description="Analyze the email security configuration of example.com and provide recommendations",
    agent=security_agent,
    expected_output="A comprehensive email security assessment with actionable recommendations",
    tools=[email_validation_tool],
)
```

## Command Line Interface

While this tool doesn't have a direct CLI equivalent, you can use standard DNS tools:

```bash
# Check SPF record
dig +short TXT example.com | grep "v=spf1"

# Check DMARC record
dig +short TXT _dmarc.example.com
```

## API Reference

### Main Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `_run()` | domain (str) | Dict\[str, Any\] | Performs a synchronous email security validation |
| `_arun()` | domain (str) | Dict\[str, Any\] | Performs an asynchronous validation (delegates to sync method) |

### Data Models

#### EmailValidationInput

```python
class EmailValidationInput(BaseModel):
    domain: str  # Domain name to validate SPF and DMARC for
```

#### Return Format

```python
{
    "spf": {
        "record": str,  # The SPF record text (or None if not found)
        "valid": bool,  # Whether a valid SPF record was found
        "suggestion": str,  # Suggestions for improving the SPF record
        "error": str,  # Error message if applicable
    },
    "dmarc": {
        "record": str,  # The DMARC record text (or None if not found)
        "valid": bool,  # Whether a valid DMARC record was found
        "suggestion": str,  # Suggestions for improving the DMARC record
        "error": str,  # Error message if applicable
    },
}
```

## Error Handling

```python
try:
    results = tool._run(domain="example.com")

    # Check for errors in SPF validation
    if "error" in results.get("spf", {}):
        print(f"SPF validation error: {results['spf']['error']}")

    # Check for errors in DMARC validation
    if "error" in results.get("dmarc", {}):
        print(f"DMARC validation error: {results['dmarc']['error']}")

except Exception as e:
    print(f"An unexpected error occurred: {str(e)}")
```

## Best Practices

1. **Regular Auditing**: Email security configurations should be audited regularly.
1. **Policy Enforcement**: Progress from monitoring (p=none) to enforcement (p=quarantine, p=reject) once confident.
1. **Comprehensive Configuration**: Implement both SPF and DMARC for effective email security.
1. **Gradual Implementation**: Start with permissive policies and gradually tighten as monitoring confirms no legitimate email is affected.
1. **Monitoring**: Enable reporting in DMARC to receive feedback about authentication failures.

## Troubleshooting

### Common Issues

1. **Missing Records**

   - Verify DNS setup with your domain registrar or DNS provider
   - Ensure DNS propagation has completed (can take up to 48 hours)
   - Check for syntax errors in record formatting

1. **Misconfigured SPF**

   - Avoid using multiple SPF records (only the first is processed)
   - Ensure SPF record ends with an appropriate qualifier (e.g., -all, ~all)
   - Avoid exceeding the 10 DNS lookup limit in SPF records

1. **Misconfigured DMARC**

   - DMARC record must be published at \_dmarc.domain.com
   - Required tags include v=DMARC1 and p=
   - Consider starting with p=none for monitoring before enforcement

## Changelog

### v1.0.0 (2023-12-01)

- Initial release
- Support for SPF and DMARC validation
- Suggestions for improving email security configuration
- Integration with CrewAI

## License

MIT License

## Contact

For support, feature requests, or bug reports, please contact:

- GitHub: [CyberAgents Repository](https://github.com/your-org/cyberagents)
