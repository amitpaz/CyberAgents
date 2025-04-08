# TruffleHog Scanner Tool

A tool that integrates with [TruffleHog](https://github.com/trufflesecurity/trufflehog), a powerful secret scanning utility designed to find leaked credentials, API keys, and other sensitive information in Git repositories.

## Overview

The TruffleHog Scanner Tool allows agents to scan GitHub and GitLab repositories, as well as local directories, for exposed secrets and sensitive data. It provides an easy-to-use interface to TruffleHog's powerful scanning capabilities, making it simple to identify potential security risks.

## Features

- **Multi-Repository Support**: Scan GitHub repositories, GitLab repositories, or local repositories
- **Comprehensive Secret Detection**: Identifies a wide range of sensitive information including:
  - API keys
  - Authentication tokens
  - Passwords
  - Private keys
  - Database credentials
  - And more
- **Custom Rules Support**: Can apply custom detection rules for organization-specific patterns
- **Detailed Reporting**: Provides context for each finding, including file location and commit information
- **Non-Intrusive**: Operates in read-only mode, ensuring code integrity

## Usage

### Basic Usage

```python
from tools.trufflehog_scanner.trufflehog_scanner_tool import TruffleHogScannerTool

# Initialize the scanner
scanner = TruffleHogScannerTool()

# Scan a GitHub repository
github_results = scanner.run("github:owner/repository")

# Scan a GitLab repository
gitlab_results = scanner.run("gitlab:owner/repository")

# Scan a local repository
local_results = scanner.run("local:/path/to/repository")
```

### Input Format

The tool accepts a repository target in one of the following formats:

- `github:<owner>/<repo>` - For scanning GitHub repositories
- `gitlab:<owner>/<repo>` - For scanning GitLab repositories
- `local:<path>` - For scanning local repositories

### Output Format

The tool returns a Markdown-formatted report containing:

1. A summary of findings
2. Detailed information about each detected secret
3. Severity assessment
4. Recommendations for remediation

## Requirements

- TruffleHog must be installed on the system
- Git must be installed on the system
- Network access (for GitHub/GitLab repository scanning)

## Installation

To use this tool, ensure TruffleHog is installed:

```bash
# Install TruffleHog using Go
go install github.com/trufflesecurity/trufflehog/v3@latest

# Alternatively, install using Homebrew (macOS)
brew install trufflesecurity/trufflehog/trufflehog
```

## Advanced Configuration

The tool includes built-in patterns for secret detection, but can be enhanced with custom patterns through policy files. Default patterns detect common security issues like:

- AWS access keys
- Google API keys
- GitHub tokens
- SSH private keys
- Database connection strings
- Many more standard credential formats

## Example

Input:
```
github:ExampleOrg/vulnerable-repo
```

Output:
```
## TruffleHog Scan Results

**Repository**: ExampleOrg/vulnerable-repo

### Summary
- **Secrets Found**: 3
- **High Severity**: 2
- **Medium Severity**: 1

### Detailed Findings

1. **AWS Secret Key** (High Severity)
   - File: config/aws.js
   - Line: 12
   - Commit: a1b2c3d4e5f6g7h8i9j0
   - Author: dev@example.com
   - Committed: 2023-01-15
   - Recommendation: Revoke this key immediately and rotate all AWS credentials

2. **Database Password** (High Severity)
   - File: app/database.py
   - Line: 45
   - Commit: b2c3d4e5f6g7h8i9j0k1
   - Author: dev@example.com
   - Committed: 2023-02-20
   - Recommendation: Change database password and update all instances

3. **Private API Token** (Medium Severity)
   - File: test/api_test.js
   - Line: 67
   - Commit: c3d4e5f6g7h8i9j0k1l2
   - Author: tester@example.com
   - Committed: 2023-02-10
   - Recommendation: Revoke token and use environment variables for testing
``` 