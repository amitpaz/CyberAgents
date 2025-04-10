# SSL Certificate Tool

## Tool Information

**Name**: SSL Certificate Tool

**Version**: 1.0.0

**Author**: CyberAgents Team

**Category**: Network Security/Cryptography

**Description**:
The SSL Certificate Tool is designed to analyze and validate SSL/TLS certificates from websites and servers. It provides detailed information about certificate attributes, validity periods, issuer details, key algorithms, and potential security issues. This tool helps security professionals assess the security posture of web applications by identifying certificate vulnerabilities, expiration risks, and configuration problems that could lead to man-in-the-middle attacks or service disruptions.

## Prerequisites

- Python 3.8+
- Required packages: cryptography, pyOpenSSL, requests
- External dependencies: OpenSSL

## Installation

Install the required packages using Poetry.

```bash
poetry add cryptography pyOpenSSL requests
```

## Configuration

### Required Configuration

No specific configuration is required for this tool.

### Optional Configuration

- `check_revocation`: Boolean flag to enable certificate revocation checking
- `check_trust_chain`: Boolean flag to validate the certificate trust chain
- `timeout`: Connection timeout in seconds

## Usage

### Basic Usage

Initialize the tool and verify the SSL/TLS certificate for a domain by providing the hostname to check the certificate's validity, expiration date, and basic attributes.

### Advanced Usage

Perform comprehensive certificate security analysis including trust chain validation, revocation checking, and crypto algorithm assessment to identify potential vulnerabilities in the certificate configuration.

## Integration with Agents

This tool can be integrated with CrewAI agents as part of a security assessment workflow to evaluate the SSL/TLS security of web applications and identify potential certificate-related risks.

## Command Line Interface

The tool provides certificate analysis functionality through a simple interface for examining SSL/TLS configurations.

### Running Locally

You can run the SSL Certificate Tool directly using the following commands:

```bash
# Basic certificate check for a domain
poetry run python -m tools.ssl_certificate.ssl_tool --hostname example.com

# Specify a different port
poetry run python -m tools.ssl_certificate.ssl_tool --hostname example.com --port 443

# Enable revocation checking
poetry run python -m tools.ssl_certificate.ssl_tool --hostname example.com --check_revocation true

# Enable trust chain validation
poetry run python -m tools.ssl_certificate.ssl_tool --hostname example.com --check_trust_chain true

# Set a custom timeout
poetry run python -m tools.ssl_certificate.ssl_tool --hostname example.com --timeout 30

# Output to JSON file
poetry run python -m tools.ssl_certificate.ssl_tool --hostname example.com --output results.json
```

For alternative SSL certificate checking from the command line:

```bash
# Using OpenSSL
# View certificate details
openssl s_client -connect example.com:443 -showcerts

# View certificate information
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -text

# Check expiration date
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -dates

# Check certificate subject
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -subject

# View the certificate chain
openssl s_client -connect example.com:443 -showcerts

# Using sslyze for comprehensive checks (if installed)
pip install sslyze
sslyze example.com

# On Windows using PowerShell
Invoke-WebRequest -Uri https://example.com | Select -ExpandProperty Certificate
```

## API Reference

### Main Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `_run()` | hostname (str), port (int), check_revocation (bool), check_trust_chain (bool), timeout (int) | Dict\[str, Any\] | Analyzes certificate synchronously |
| `_arun()` | hostname (str), port (int), check_revocation (bool), check_trust_chain (bool), timeout (int) | Dict\[str, Any\] | Analyzes certificate asynchronously |

### Data Models

#### SSLCertificateInput

Input model accepting parameters for:

- hostname: The domain to check the certificate for
- port: The port to connect on (default: 443)
- check_revocation: Whether to check certificate revocation status
- check_trust_chain: Whether to validate the certificate trust chain
- timeout: Connection timeout in seconds

#### Return Format

Returns a dictionary containing:

- certificate_details: Dictionary with certificate attributes
- validity: Dictionary with not_before and not_after dates
- issuer: Dictionary with issuer details
- subject: Dictionary with subject details
- key_info: Dictionary with key algorithm and strength
- extensions: List of certificate extensions
- issues: List of identified security issues
- grade: Overall security grade (A-F)
- error: Any error message (if applicable)

## Error Handling

Handle errors by checking for the presence of an "error" key in the results dictionary returned by the tool.

## Best Practices

1. **Regular Monitoring**: Check certificates regularly for expiration and revocation
1. **Trust Chain Validation**: Always validate the complete certificate trust chain
1. **Algorithm Standards**: Ensure certificates use modern cryptographic algorithms (RSA 2048+, ECDSA, SHA-256+)
1. **Hostname Verification**: Verify that certificates match the intended hostname
1. **Certificate Transparency**: Check if certificates appear in public Certificate Transparency logs

## Troubleshooting

### Common Issues

1. **Connection Problems**

   - Verify network connectivity to the target server
   - Check if the server is listening on the specified port
   - Ensure there are no firewalls blocking the connection

1. **Trust Chain Issues**

   - Missing intermediate certificates
   - Self-signed certificates
   - Certificate authority not recognized

1. **Certificate Validation Failures**

   - Expired certificates
   - Hostname mismatch
   - Revoked certificates
   - Weak cryptographic algorithms

## Changelog

### v1.0.0 (2023-12-01)

- Initial release
- Support for basic certificate validation
- Trust chain verification
- Security grading based on certificate attributes
- Integration with CrewAI

## License

MIT License

## Contact

For support, feature requests, or bug reports, please contact:

- GitHub: [CyberAgents Repository](https://github.com/your-org/cyberagents)
