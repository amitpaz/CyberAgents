# Security Policy

## Supported Versions

We support security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Requirements

### Static Code Analysis
- All code must pass Semgrep static analysis with no critical or high severity findings
- Semgrep scans are automatically run on all pull requests
- Any security findings must be addressed before merging

### Dependency Management
- Dependencies are automatically scanned for vulnerabilities using Dependabot
- Critical and high severity vulnerabilities must be addressed within 7 days
- Medium severity vulnerabilities must be addressed within 30 days
- Low severity vulnerabilities should be addressed in the next regular release

### Code Review Requirements
- All pull requests must be reviewed by at least one maintainer
- Security-sensitive changes must be reviewed by at least two maintainers
- Code must follow security best practices and guidelines

## Reporting a Vulnerability

We use GitHub's security features to manage security vulnerabilities:

1. For non-sensitive security issues, please open a [GitHub Issue](https://github.com/NaorPenso/CyberAgents/issues/new) with the label "security".

2. For sensitive security vulnerabilities, please use [GitHub's Security Advisories](https://github.com/NaorPenso/CyberAgents/security/advisories/new) to report the vulnerability privately.

We appreciate your efforts to responsibly disclose your findings and will make our best effort to address the issue quickly.

## Security Tools

### Static Analysis
- Semgrep: Used for static code analysis
  - Configuration: `.semgrep.yml` 
  - Includes comprehensive rules for Python and Bash scripts
  - Local scanning: 
    - Run `./scripts/run_semgrep.sh` to scan all files
    - Run `./scripts/run_semgrep.sh --python` for Python-specific scans
    - Run `./scripts/run_semgrep.sh --bash` for Bash-specific scans
    - Run `./scripts/run_semgrep.sh --help` for more options

### Dependency Scanning
- Dependabot: Used for dependency vulnerability scanning
- Configuration: `.github/dependabot.yml`

### CI/CD Security
- GitHub Actions: Used for automated security checks
- Configuration: `.github/workflows/pr-validation.yml`
- Runs Semgrep on all Python and Bash files in PRs 