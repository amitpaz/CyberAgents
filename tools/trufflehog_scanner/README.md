# TruffleHog Scanner Tool

A tool for scanning Git repositories for secrets, API keys, credentials, and other sensitive information using TruffleHog.

## Overview

The TruffleHog Scanner Tool provides an interface to the popular TruffleHog secret scanner, allowing you to search Git repositories for accidentally committed secrets and sensitive information.

## Features

- **Multiple Repository Types**: Scan GitHub, GitLab, or local repositories
- **Secret Detection**: Find passwords, API keys, tokens, and other sensitive data
- **Custom Rules**: Support for custom regex patterns to detect organization-specific secrets
- **Policy Integration**: Load patterns from policy files to enhance detection
- **Detailed Reporting**: Generate formatted reports of findings with context

## Usage

```python
from tools.trufflehog_scanner import TruffleHogScannerTool

# Initialize the tool
scanner = TruffleHogScannerTool()

# Scan a GitHub repository
results = scanner._run("github:username/repository")

# Scan a GitLab repository
results = scanner._run("gitlab:username/repository")

# Scan a local repository
results = scanner._run("local:/path/to/repository")
```

## Prerequisites

The tool requires TruffleHog and Git to be installed on the system:

```bash
# Install TruffleHog
pip install trufflehog

# Ensure Git is installed
git --version
```

## How It Works

1. The tool parses the input to determine the repository type and location
2. For remote repositories, it clones the repository to a temporary directory
3. It then executes TruffleHog on the repository with appropriate options
4. Results are processed and formatted into a readable report
5. Temporary files and directories are cleaned up automatically

## Detection Capabilities

TruffleHog Scanner can detect:

- API keys and tokens
- Authentication credentials
- Private keys (SSH, RSA, PGP)
- Database connection strings
- Other high-entropy strings that may be secrets

## Dependencies

- Python 3.8+
- TruffleHog
- Git
- langchain
- pydantic

## Credits

This tool is part of the CyberAgents project and is typically used by the Git Exposure Analyst Agent for identifying security risks in code repositories.

TruffleHog itself is an open-source project developed by Truffle Security. 