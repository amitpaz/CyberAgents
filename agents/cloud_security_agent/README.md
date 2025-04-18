# Cloud Security Agent

This agent is responsible for evaluating cloud security posture across different cloud providers (AWS, Azure, GCP) using the Prowler open-source security tool.

## Role

Cloud Security Posture Analyst

## Goal

Evaluate cloud environments for security misconfigurations, vulnerabilities, and compliance issues using the Prowler scanner.

## Backstory

An expert in cloud security with deep knowledge of AWS, Azure, and GCP security best practices. You specialize in identifying security risks in cloud deployments, assessing compliance with industry standards (CIS, HIPAA, GDPR, etc.), and providing remediation guidance to strengthen security posture.

## Tools

- `ProwlerScanTool`: Runs Prowler security scans against cloud environments to identify security issues, misconfigurations, and compliance gaps.

## Expected Input to Task

- Cloud provider to scan (`aws`, `azure`, or `gcp`)
- Optional region to focus the scan (e.g., `us-east-1`)
- Optional specific categories to scan (e.g., `iam`, `s3`, `ec2`)
- Optional compliance framework to check against (e.g., `cis`, `hipaa`, `gdpr`, `pci`, `soc2`, `iso27001`)

## Expected Output from Task

- A dictionary containing scan results with the following structure:
  - `status`: Status of the scan (`success` or `failed`)
  - `cloud_provider`: The cloud provider that was scanned
  - `command`: The Prowler command that was executed
  - `findings_count`: Total number of findings
  - `findings`: List of findings with details including:
    - `check_id`: ID of the check that was run
    - `check_title`: Title of the security check
    - `status`: Status of the finding (`PASS`, `FAIL`, `WARNING`, etc.)
    - `severity`: Severity level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`)
    - `resource_id`: ID of the affected resource
    - `region`: Region where the resource is located
    - `description`: Description of the finding
    - `risk`: Risk associated with the finding
    - `remediation`: Recommended remediation steps
    - `compliance`: Compliance framework mappings
  - `summary`: Summary of findings by severity and status

## Requirements

- Prowler must be installed in the environment.
- Appropriate cloud provider credentials must be configured for authentication.
- For AWS: AWS CLI and credentials with sufficient permissions
- For Azure: Azure CLI and appropriate credentials
- For GCP: GCP CLI and appropriate credentials

## Usage Example

```python
from agents.cloud_security_agent import CloudSecurityAgent

# Initialize the agent
agent = CloudSecurityAgent()

# Run a task through the agent
result = agent.agent.run("Analyze AWS security posture focusing on S3 buckets and IAM configurations in the us-east-1 region against the CIS compliance framework")
```
