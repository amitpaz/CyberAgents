# CVE Lookup Tool

## Tool Information

**Name**: CVE Lookup Tool

**Version**: 1.0.0

**Author**: CyberAgents Team

**Category**: Vulnerability Management/Security Research

**Description**:
The CVE Lookup Tool is designed to retrieve detailed information about Common Vulnerabilities and Exposures (CVEs) from public vulnerability databases. It provides critical details including vulnerability descriptions, severity scores, affected systems, exploit availability, and remediation guidance. This tool is essential for security professionals to assess risks associated with specific vulnerabilities, prioritize patching efforts, and understand potential impacts on systems.

## Prerequisites

- Python 3.8+
- Required packages: requests, pydantic
- External dependencies: None

## Installation

Install the required packages using Poetry.

```bash
poetry add requests
```

## Configuration

### Required Configuration

No specific configuration is required for this tool.

### Optional Configuration

- `api_key`: Optional API key for accessing premium vulnerability databases
- `max_results`: Maximum number of results to return when searching by keyword
- `sources`: List of vulnerability databases to query (default: NVD)

## Usage

### Basic Usage

Initialize the tool and look up information about specific CVEs by providing their ID (e.g., CVE-2021-44228) to retrieve comprehensive vulnerability details.

### Advanced Usage

Search for vulnerabilities affecting specific products or vendors, filter results by severity or time period, or batch query multiple CVEs to generate vulnerability reports.

## Integration with Agents

This tool can be integrated with CrewAI agents as part of a vulnerability management workflow to assess risks associated with specific CVEs and prioritize remediation efforts.

## Command Line Interface

The tool provides CVE lookup functionality through a simple interface for querying vulnerability databases.

### Running Locally

You can run the CVE Lookup Tool directly using the following commands:

```bash
# Look up a specific CVE by ID
poetry run python -m tools.cve_lookup.cve_tool --cve_id CVE-2021-44228

# Search for CVEs by keyword
poetry run python -m tools.cve_lookup.cve_tool --keyword "log4j"

# Limit number of results for keyword search
poetry run python -m tools.cve_lookup.cve_tool --keyword "spring" --max_results 10

# Specify sources to query
poetry run python -m tools.cve_lookup.cve_tool --cve_id CVE-2021-44228 --sources "nvd,cve"

# Output to JSON file
poetry run python -m tools.cve_lookup.cve_tool --cve_id CVE-2021-44228 --output results.json

# Use with API key (if configured)
VULNERABILITY_API_KEY="your_api_key" poetry run python -m tools.cve_lookup.cve_tool --cve_id CVE-2021-44228
```

For alternative CVE lookup from the command line:

```bash
# Using curl to query the NVD API
curl -X GET "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228" -H "apiKey: YOUR_API_KEY"

# Search by keyword
curl -X GET "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=log4j" -H "apiKey: YOUR_API_KEY"

# Using nvd-cli (if installed)
pip install nvdlib
nvd-cli cve CVE-2021-44228

# Using standard Linux tools to query and format
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228" | jq
```

## API Reference

### Main Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `_run()` | cve_id (str), keyword (str), max_results (int), sources (List\[str\]) | Dict\[str, Any\] | Performs CVE lookups synchronously |
| `_arun()` | cve_id (str), keyword (str), max_results (int), sources (List\[str\]) | Dict\[str, Any\] | Performs CVE lookups asynchronously |

### Data Models

#### CVELookupInput

Input model accepting parameters for:

- cve_id: Specific CVE identifier to look up
- keyword: Optional search term for finding related vulnerabilities
- max_results: Maximum number of results when searching by keyword
- sources: List of vulnerability databases to query

#### Return Format

Returns a dictionary containing:

- cve_details: Dictionary with CVE information including ID, description, severity
- cvss_score: CVSS score and vector string
- affected_systems: List of affected products and versions
- references: List of reference URLs
- remediation: Remediation guidance if available
- error: Any error message (if applicable)

## Error Handling

Handle errors by checking for the presence of an "error" key in the results dictionary returned by the tool.

## Best Practices

1. **Data Freshness**: Vulnerability databases are updated regularly; ensure the tool queries the latest data
1. **Search Scope**: Be specific with search terms to avoid overwhelming results
1. **Severity Assessment**: Consider both CVSS scores and real-world impact when prioritizing vulnerabilities
1. **Context Awareness**: Evaluate vulnerabilities in the context of your specific environment and compensating controls
1. **API Rate Limiting**: Be mindful of rate limits when making multiple requests to public APIs

## Troubleshooting

### Common Issues

1. **API Access Limitations**

   - Implement backoff mechanisms for rate-limited APIs
   - Consider using multiple data sources for redundancy
   - Cache results for frequently requested CVEs

1. **Incomplete Data**

   - Not all vulnerability databases have the same level of detail
   - Cross-reference information across multiple sources
   - Look for supplementary information in security advisories

1. **Connectivity Issues**

   - Implement retry logic for API requests
   - Set reasonable timeouts
   - Consider implementing a local cache for offline access

## Changelog

### v1.0.0 (2023-12-01)

- Initial release
- Support for NVD database queries
- CVE detail retrieval and keyword search
- CVSS score parsing and interpretation
- Integration with CrewAI

## License

MIT License

## Contact

For support, feature requests, or bug reports, please contact:

- GitHub: [CyberAgents Repository](https://github.com/your-org/cyberagents)
