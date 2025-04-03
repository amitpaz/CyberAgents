# WHOIS Lookup Tool

## Overview

The WHOIS Lookup tool is a Python-based utility that retrieves domain registration information using the WHOIS protocol. It provides detailed information about domain ownership, registration dates, and nameservers.

## Features

- Domain registration information retrieval
- Configurable timeout settings
- Error handling and reporting
- Standardized output format

## Usage

```python
from tools.whois_lookup import lookup

# Basic usage
result = lookup("example.com")

# With custom timeout
result = lookup("example.com", timeout=60)
```

## Output Format

The tool returns a dictionary containing the following information:

- Domain name
- Registrar information
- WHOIS server
- Nameservers
- Creation date
- Expiration date
- Last update date
- Contact information (when available)

## Error Handling

The tool handles various error conditions:

- Network timeouts
- Invalid domains
- Rate limiting
- Unavailable WHOIS servers

## Dependencies

- python-whois>=0.8.0
- requests>=2.31.0

## Security Considerations

- Rate limiting may apply from WHOIS servers
- Some registrars may restrict access to WHOIS data
- Consider implementing caching for frequent lookups

## Example Output

```json
{
    "domain_name": "EXAMPLE.COM",
    "registrar": "RESERVED-INTERNET ASSIGNED NUMBERS AUTHORITY",
    "whois_server": "whois.iana.org",
    "name_servers": ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"],
    "creation_date": "1995-08-14 04:00:00",
    "expiration_date": "2024-08-13 04:00:00",
    "updated_date": "2023-08-14 07:01:44"
}
```
