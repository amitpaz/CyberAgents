# Shodan Host Search Tool

## Tool Information

**Name**: Shodan Host Search

**Version**: 1.0.0

**Author**: CyberAgents Team

**Category**: Reconnaissance/Intelligence

**Description**:
The Shodan Host Search Tool provides an interface to query Shodan's API for information about internet-connected devices and services associated with a specific domain. Shodan is a search engine for Internet-connected devices, allowing users to discover servers, IoT devices, webcams, and more. This tool enhances CyberAgents reconnaissance capabilities by providing detailed information about a target organization's internet footprint, including open ports, running services, and potential vulnerabilities.

## Prerequisites

- Python 3.8+
- Required packages: shodan, crewai, pydantic
- External dependencies: Valid Shodan API key

## Installation

Install the required packages using Poetry.

```bash
poetry add shodan
```

## Configuration

### Required Configuration

```yaml
# Example configuration in agent.yaml or config file
shodan_search:
  api_key: YOUR_SHODAN_API_KEY  # Or use environment variable SHODAN_API_KEY
```

### Optional Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `api_key` | str | None | Shodan API key (can be set via environment variable) |

## Usage

### Basic Usage

Initialize the tool and search for information about hosts associated with a domain by providing the domain name.

### Advanced Usage

Process the results to extract IP addresses, ports, organization information, and other details about hosts discovered through Shodan.

## Integration with Agents

This tool can be integrated with CrewAI agents as part of a reconnaissance specialist's toolkit to discover internet-facing services and potential vulnerabilities.

## Command Line Interface

While this tool is primarily designed as a programmable API, you can use the Shodan CLI directly for more advanced search capabilities.

### Running Locally

You can run the Shodan Host Search Tool directly using the following commands:

```bash
# Set your Shodan API key as an environment variable
export SHODAN_API_KEY="your_api_key_here"

# Basic domain search
poetry run python -m tools.shodan_search.shodan_tool --domain example.com

# Run with specific options
poetry run python -m tools.shodan_search.shodan_tool --domain example.com --output_file results.json
```

You can also use the official Shodan CLI for more advanced queries:

```bash
# Install the Shodan CLI
pip install shodan

# Initialize with your API key
shodan init YOUR_API_KEY

# Search for a domain
shodan search hostname:example.com

# Download information about a specific IP
shodan host 93.184.216.34

# Search for specific services
shodan search "apache country:US"

# Count results for a search
shodan count apache

# Get summary information for a search
shodan stats apache
```

## API Reference

### Main Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `_run()` | domain (str) | Dict\[str, Any\] | Performs a synchronous search for hosts associated with a domain |
| `_arun()` | domain (str) | Dict\[str, Any\] | Performs an asynchronous search (delegates to sync method) |
| `_check_api()` | None | bool | Internal method to verify API key and connection |

### Data Models

#### ShodanHostInput

Input model accepting a domain parameter for the domain to search for associated hosts in Shodan.

#### Return Format

Returns a dictionary containing the domain that was searched, the query used, total results count, a list of hosts found with their details, and the source of the data.

## Error Handling

Properly handle errors by checking for the presence of an "error" key in the results dictionary returned by the tool.

## Best Practices

1. **API Key Security**: Never hardcode your Shodan API key. Use environment variables or secure configuration management.
1. **Rate Limiting**: Be aware of Shodan API limits. The free tier has restrictions on the number of queries.
1. **Domain Validation**: Always validate domain input to prevent errors or potential injection attacks.
1. **Error Handling**: Implement proper error handling for API connection issues, rate limiting, and invalid inputs.
1. **Data Filtering**: For large domains with many results, consider filtering or limiting results to the most relevant.

## Troubleshooting

### Common Issues

1. **API Key Errors**

   - Verify your API key is correct
   - Check if your API subscription is active
   - Ensure the environment variable is correctly set

1. **No Results Found**

   - Try different domain variations (with/without www)
   - Consider that Shodan may not have indexed all hosts
   - Use alternative search syntax if needed

1. **Rate Limiting**

   - If you encounter rate limits, implement backoff mechanisms
   - Consider upgrading your Shodan plan for more queries

## Changelog

### v1.0.0 (2023-12-01)

- Initial release
- Basic host search functionality
- Support for environment variable configuration
- Integration with CrewAI

## License

MIT License

## Contact

For support, feature requests, or bug reports, please contact:

- GitHub: [CyberAgents Repository](https://github.com/your-org/cyberagents)
