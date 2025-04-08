# CyberAgents Tools

This directory contains various tools used by the CyberAgents system to perform cybersecurity analysis, threat detection, and vulnerability scanning tasks.

## Overview

The tools in this directory are designed to be used by AI agents to perform specific security-related tasks. Each tool implements a standard interface, making them easy to integrate with the agent framework.

## Available Tools

| Tool | Description |
|------|-------------|
| asn_ip_lookup_tool | Looks up ASN information for IP addresses |
| base64_tool | Encodes and decodes Base64 data |
| cve_lookup | Searches for CVE (Common Vulnerabilities and Exposures) information |
| dns_lookup | Performs DNS lookups to resolve domain names |
| domain_analyzer | Analyzes domains for security issues |
| dummy | Template for creating new tools |
| email_validation | Validates email addresses and checks for security issues |
| github_search | Searches GitHub repositories for exposed secrets and sensitive information |
| hash_tool | Generates and verifies cryptographic hashes |
| metadata_extractor | Extracts metadata from files |
| nmap_port_scan_tool | Performs network port scans using Nmap |
| security_news | Retrieves security news and updates |
| semgrep_scanner | Scans code for security vulnerabilities using Semgrep |
| shodan_search | Searches Shodan for information about exposed systems |
| ssl_certificate | Analyzes SSL/TLS certificates |
| subdomain_finder | Discovers subdomains for a given domain |
| text_analysis | Analyzes text for security-related information |
| threat_intel_analyzer | Analyzes threat intelligence data |
| trufflehog_scanner | Scans repositories for secrets using TruffleHog |
| whois_lookup | Performs WHOIS lookups for domain information |

## Tool Structure

Each tool follows a standard structure:

```
tools/
├── tool_name/
│   ├── README.md             # Documentation for the tool
│   ├── __init__.py           # Exports the tool class
│   └── tool_name_tool.py     # Contains the tool implementation
```

Tests for each tool are located in the `tests/tools/` directory.

## Creating New Tools

To create a new tool, use the `dummy` tool as a template. Copy the directory structure and customize it for your specific needs. See the `dummy/README.md` file for detailed instructions.

## Tool Interface

All tools implement a standard interface, inheriting from either `langchain.tools.BaseTool` or `crewai.tools.BaseTool`. This ensures consistent usage across the system and allows for easy integration with the agent framework.

A typical tool implementation includes:

1. A descriptive class name ending with "Tool"
2. A `name` property that uniquely identifies the tool
3. A clear `description` that explains what the tool does
4. An `_run` method that implements the tool's functionality
5. Optionally, an `_arun` method for asynchronous operation

## Dependencies

Different tools may have different dependencies. Each tool's README specifies its specific requirements. Make sure to install the necessary dependencies before using a tool. 