# ASN/IP Lookup Tool

## Tool Information

**Name**: ASN/IP Lookup Tool

**Version**: 1.0.0

**Author**: CyberAgents Team

**Category**: Network Intelligence/Reconnaissance

**Description**:
The ASN/IP Lookup Tool provides information about Autonomous System Numbers (ASNs), IP network blocks (CIDRs), and organization ownership for IP addresses or domain names. An ASN is a unique identifier assigned to a network or collection of networks operated by a single organization. This tool enhances network reconnaissance capabilities by revealing the network infrastructure behind IP addresses, helping security professionals understand network topology, identify related IP ranges, and determine organizational ownership of internet resources.

## Prerequisites

- Python 3.8+
- Required packages: ipwhois, crewai, pydantic
- External dependencies: None

## Installation

Install the required packages using Poetry.

```bash
poetry add ipwhois
```

## Configuration

### Required Configuration

No specific configuration is required for this tool.

### Optional Configuration

No optional configuration parameters are available for this tool.

## Usage

### Basic Usage

Initialize the tool and perform ASN/IP lookups by providing an IP address to the tool.

### Advanced Usage

Process the results to extract organization information, ASN details, and network blocks. For domain names, first resolve them to IP addresses before performing the lookup.

## Integration with Agents

This tool can be integrated with CrewAI agents as part of a network intelligence analyst's toolkit to map network infrastructure and identify organizational ownership of IP addresses.

## Command Line Interface

While this tool doesn't have a direct CLI equivalent, you can use standard whois tools and DNS resolvers to obtain similar information.

### Running Locally

You can run the ASN/IP Lookup Tool directly using the following commands:

```bash
# Lookup information for an IP address
poetry run python -m tools.asn_ip_lookup_tool.asn_ip_tool --ip_address 8.8.8.8

# Lookup information for a domain (will be resolved to IP first)
poetry run python -m tools.asn_ip_lookup_tool.asn_ip_tool --target example.com

# Output to JSON file
poetry run python -m tools.asn_ip_lookup_tool.asn_ip_tool --ip_address 8.8.8.8 --output results.json
```

For similar functionality using standard command-line tools:

```bash
# Using whois for ASN lookup
whois -h whois.radb.net -- '-i origin AS15169'

# Using whois to query an IP address
whois 8.8.8.8

# Using the 'dig' command for IP resolution
dig +short example.com

# Using 'jq' to format JSON output
whois -h whois.radb.net -- '-i origin AS15169' | jq
```

## API Reference

### Main Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `_run()` | ip_address (str) | Dict\[str, Any\] | Performs a synchronous ASN/IP lookup |
| `_arun()` | ip_address/target (str) | Dict\[str, Any\] | Performs an asynchronous lookup, supporting both IP addresses and domain names |

### Data Models

#### ASNIPInput

Input model accepting an ip_address parameter for the IP address to look up ASN and network information for.

#### Return Format for \_run()

Returns a dictionary containing the IP address queried, ASN information, organization ownership details, network blocks, and any error messages if applicable.

#### Return Format for \_arun()

Returns a dictionary containing the input target, resolved IP address, ASN information, organization name, CIDR notation, and any error messages if applicable.

## Error Handling

Properly handle errors by checking for the presence of an "error" key in the results dictionary returned by the tool.

## Best Practices

1. **Input Validation**: Always provide valid IP addresses to avoid errors.
1. **Domain Resolution**: For domain names, first resolve to IP addresses using DNS.
1. **Performance**: WHOIS queries can be slow; implement caching for frequent lookups.
1. **Error Handling**: Handle timeout and connection errors with proper retry logic.
1. **Data Interpretation**: ASN data can be inconsistent across different regions and registries.

## Troubleshooting

### Common Issues

1. **Rate Limiting**

   - WHOIS servers may implement rate limiting
   - Implement backoff mechanisms for bulk queries
   - Consider using a commercial API for high-volume lookups

1. **Data Consistency**

   - Different regional registries format data differently
   - Some fields may be empty or formatted inconsistently
   - Consider normalizing data for consistent processing

1. **DNS Resolution Issues**

   - Failed domain resolution may indicate DNS issues
   - Try alternative DNS resolvers
   - Verify domain name is correct

## Changelog

### v1.0.0 (2023-12-01)

- Initial release
- Support for IP address lookups
- Domain name resolution and lookup
- Integration with CrewAI

## License

MIT License

## Contact

For support, feature requests, or bug reports, please contact:

- GitHub: [CyberAgents Repository](https://github.com/your-org/cyberagents)
