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

Please report security vulnerabilities to security@cyberagents.com.

We will acknowledge receipt of your vulnerability report within 48 hours and provide a more detailed response within 7 days indicating the next steps in handling your report.

## Security Tools

### Static Analysis
- Semgrep: Used for static code analysis
- Configuration: `.semgrep.yml`

### Dependency Scanning
- Dependabot: Used for dependency vulnerability scanning
- Configuration: `.github/dependabot.yml`

### CI/CD Security
- GitHub Actions: Used for automated security checks
- Configuration: `.github/workflows/pr-validation.yml` 