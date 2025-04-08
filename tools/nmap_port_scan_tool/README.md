# Nmap Port Scan Tool

## Tool Information

**Name**: Nmap Port Scanner

**Version**: 1.0.0

**Author**: CyberAgents Team

**Category**: Network Security/Reconnaissance

**Description**:
The Nmap Port Scan Tool is a powerful network scanning utility that leverages the industry-standard Nmap scanner to discover hosts, open ports, running services, and service versions on target systems. This tool is essential for network reconnaissance activities, vulnerability assessments, and security audits. It provides detailed information about network services that can be used to identify potential security weaknesses, outdated software, or misconfigured services.

## Prerequisites

- Python 3.8+
- Required packages: python-nmap, crewai, pydantic
- External dependencies: Nmap must be installed on the system

## Installation

Install the required packages using Poetry.

```bash
poetry add python-nmap
```

Nmap must be installed on the system according to your operating system.

## Configuration

### Required Configuration

```yaml
# Example configuration in agent.yaml or config file
nmap_port_scanner:
  # No required configuration parameters
```

### Optional Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ports` | str | "21,22,23,25,80,110,135,139,443,445,3389,8080" | Comma-separated list of ports or ranges to scan |
| `arguments` | str | "-sV -T4" | Additional Nmap arguments for customizing scan behavior |

## Usage

### Basic Usage

Initialize the tool and scan targets by providing an IP address, hostname, or network range.

### Advanced Usage

Perform scans with custom port ranges and arguments, then process the results to extract information about hosts, open ports, and running services.

## Integration with Agents

This tool can be integrated with CrewAI agents as part of a network security analyst's toolkit to identify open ports and services on target systems.

## Command Line Interface

The tool is a wrapper around the Nmap command-line utility, which can also be used directly for more advanced scanning options.

### Running Locally

You can run the Nmap Port Scan Tool directly using the following commands:

```bash
# Basic scan of a single host
poetry run python -m tools.nmap_port_scan_tool.nmap_scanner --targets 192.168.1.1

# Scan multiple hosts
poetry run python -m tools.nmap_port_scan_tool.nmap_scanner --targets "192.168.1.1,192.168.1.2"

# Scan a network range
poetry run python -m tools.nmap_port_scan_tool.nmap_scanner --targets 192.168.1.0/24

# Scan specific ports
poetry run python -m tools.nmap_port_scan_tool.nmap_scanner --targets example.com --ports "22,80,443"

# Advanced scan with custom arguments
poetry run python -m tools.nmap_port_scan_tool.nmap_scanner --targets example.com --arguments "-sV -T4 -A"
```

You can also use the Nmap command directly for more control:

```bash
# Install Nmap if not already installed
# On Ubuntu/Debian
sudo apt-get install nmap

# On macOS
brew install nmap

# On Windows (using Chocolatey)
choco install nmap

# Basic Nmap scan
nmap 192.168.1.1

# Service version detection
nmap -sV example.com

# Comprehensive scan
nmap -A example.com

# Scan specific ports
nmap -p 22,80,443 example.com
```

## API Reference

### Main Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `_run()` | targets (str), ports (Optional\[str\]), arguments (Optional\[str\]) | Dict\[str, Any\] | Performs a synchronous Nmap scan |
| `_arun()` | targets (str), ports (Optional\[str\]), arguments (Optional\[str\]) | Dict\[str, Any\] | Performs an asynchronous Nmap scan |
| `_check_nmap()` | None | bool | Internal method to verify Nmap installation |

### Data Models

#### NmapInput

Input model that accepts parameters for target hosts, ports to scan, and additional Nmap arguments.

#### Return Format

Returns a dictionary containing scan information, host details, port and service information, and summary statistics about the scan.

## Error Handling

Properly handle errors by checking for the presence of an "error" key in the results dictionary returned by the tool.

## Best Practices

1. **Permission**: Always ensure you have explicit permission to scan targets. Unauthorized scanning may be illegal.
1. **Rate Limiting**: Use scan timing options like `-T2` or `-T3` to avoid overwhelming target systems.
1. **Scope Management**: Limit scan scope to necessary targets and ports to minimize network impact.
1. **Input Validation**: The tool validates inputs, but always provide well-formed target addresses and port ranges.
1. **Security**: Be aware that Nmap scans can be detected by intrusion detection systems and may trigger alerts.

## Troubleshooting

### Common Issues

1. **Installation Problems**

   - Verify Nmap is correctly installed using `nmap -V`
   - Check that python-nmap is installed with Poetry
   - Ensure proper permissions for executing Nmap

1. **Scan Failures**

   - Network connectivity issues between scanner and target
   - Firewalls blocking scan traffic
   - Rate limiting or blocking by target systems
   - Try with different scan options or slower timing (`-T2`)

1. **Incomplete Results**

   - Some ports may be filtered by firewalls
   - Host may be dropping or rejecting packets
   - Try service detection (`-sV`) or different scan types

## Changelog

### v1.0.0 (2023-12-01)

- Initial release
- Support for target, port, and argument configuration
- Structured output for easy processing
- Integration with CrewAI

## License

MIT License

## Contact

For support, feature requests, or bug reports, please contact:

- GitHub: [CyberAgents Repository](https://github.com/your-org/cyberagents)
