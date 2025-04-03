# DNS Lookup Tool

## Overview

The DNS Lookup tool is a Python-based utility that performs DNS record queries for domains. It supports various record types and provides standardized output for analysis.

## Features

- Multiple DNS record type support (A, AAAA, MX, TXT, etc.)
- Configurable DNS resolvers
- Error handling and reporting
- Standardized output format

## Usage

```python
from tools.dns_lookup import lookup

# Basic A record lookup
result = lookup("example.com")

# Specific record type lookup
result = lookup("example.com", record_type="MX")
```

## Supported Record Types

- A (IPv4 address)
- AAAA (IPv6 address)
- MX (Mail exchange)
- TXT (Text records)
- NS (Nameserver)
- CNAME (Canonical name)
- SOA (Start of authority)
- PTR (Pointer)

## Output Format

The tool returns a dictionary containing:

- Domain name
- Record type
- List of records found
- Error information (if any)

## Error Handling

The tool handles various error conditions:

- Invalid domains
- Non-existent records
- DNS resolution failures
- Network timeouts

## Dependencies

- dnspython>=2.4.2

## Security Considerations

- DNS queries may be logged by DNS servers
- Consider using encrypted DNS (DoH/DoT) for sensitive queries
- Implement rate limiting for bulk queries

## Example Output

```json
{
    "domain": "example.com",
    "record_type": "A",
    "records": ["93.184.216.34"]
}
```
