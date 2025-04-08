# Subdomain Finder Tool

## Tool Information

**Name**: Subdomain Finder (crt.sh)

**Version**: 1.0.0

**Author**: CyberAgents Team

**Category**: Reconnaissance/Domain Intelligence

**Description**:
The Subdomain Finder Tool discovers subdomains of a target domain using certificate transparency logs from crt.sh. Certificate Transparency (CT) logs are public records of SSL/TLS certificates that have been issued by certificate authorities. This tool leverages these logs to identify subdomains that have been issued certificates, providing valuable reconnaissance data for security assessments. By identifying subdomains, security professionals can expand their attack surface mapping and potentially discover forgotten or unsecured assets.

## Prerequisites

- Python 3.8+
- Required packages: requests, crewai, pydantic
- External dependencies: None

## Installation

Install the required packages using Poetry or pip.

## Configuration

### Required Configuration

No specific configuration is required for this tool.

### Optional Configuration

No optional configuration parameters are available for this tool.

## Usage

### Basic Usage

Initialize the tool and find subdomains for a domain by providing the target domain name to the tool.

### Advanced Usage

Process the results to extract and organize the subdomains, optionally sorting them by subdomain level or exporting to a file for further analysis.

## Integration with Agents

This tool can be integrated with CrewAI agents as part of a reconnaissance specialist agent's toolkit to discover and analyze subdomains of target organizations.

## Command Line Interface

While this tool doesn't have a direct CLI equivalent, you can use the crt.sh website or curl to get similar information by querying the crt.sh API.

## API Reference

### Main Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `_run()` | domain (str) | Dict\[str, Any\] | Performs a synchronous subdomain search using crt.sh |
| `_arun()` | domain (str) | Dict\[str, Any\] | Performs an asynchronous subdomain search (delegates to sync method) |

### Data Models

#### SubdomainInput

Input model accepting a domain parameter for the parent domain to find subdomains for.

#### Return Format

Returns a dictionary containing the domain that was searched, a list of subdomains found, the source of the data (crt.sh), and any error messages if applicable.

## Error Handling

Properly handle errors by checking for the presence of an "error" key in the results dictionary returned by the tool.

## Best Practices

1. **Domain Validation**: Always provide a properly formatted domain to avoid errors.
1. **Rate Limiting**: Be mindful of making too many consecutive requests to crt.sh.
1. **Subdomain Processing**: Filter out wildcard subdomains and normalize subdomain names.
1. **Complementary Tools**: Combine with other subdomain discovery methods for comprehensive results.
1. **Data Verification**: Verify discovered subdomains are still active with additional tools like DNS resolvers.

## Troubleshooting

### Common Issues

1. **Connection Problems**

   - Check your internet connection
   - Verify crt.sh is accessible from your network
   - Try using a proxy if direct access is blocked

1. **No Results Found**

   - Domain may not have any certificates in CT logs
   - Try using alternative subdomain discovery methods
   - Check if the domain is correct

1. **Timeout Errors**

   - crt.sh may be experiencing high load
   - Try again later or with a longer timeout
   - Consider implementing retry logic

## Changelog

### v1.0.0 (2023-12-01)

- Initial release
- Support for querying crt.sh certificate transparency logs
- Filtering and sorting of subdomain results
- Integration with CrewAI

## License

MIT License

## Contact

For support, feature requests, or bug reports, please contact:

- GitHub: [CyberAgents Repository](https://github.com/your-org/cyberagents)
