# Threat Intelligence Analyzer Tool

## Overview

The Threat Intelligence Analyzer tool integrates multiple threat intelligence sources to analyze domains for potential security threats. It combines data from VirusTotal, WHOIS records, and other sources to provide a comprehensive threat assessment.

## Features

- VirusTotal integration
- WHOIS-based threat analysis
- Threat scoring system
- Indicator of compromise detection
- Multi-source intelligence correlation
- Actionable recommendations

## Usage

```python
from tools.threat_intel_analyzer import ThreatIntelAnalyzer

# Initialize analyzer with API keys
analyzer = ThreatIntelAnalyzer({"virustotal": "your-api-key-here"})

# Analyze domain
result = analyzer.analyze("example.com", whois_data)
```

## Analysis Components

### Threat Scoring

The tool calculates a threat score based on:

- VirusTotal reputation
- Domain age and registration patterns
- Privacy protection usage
- Historical malicious activity
- Suspicious indicators

### Intelligence Sources

- VirusTotal
- WHOIS data
- Historical threat data
- Domain reputation services

### Indicator Detection

Identifies various threat indicators:

- Malicious activity reports
- Suspicious domain patterns
- Recent registrations
- Privacy protection usage
- Known bad actors

## Output Format

The tool returns a dictionary containing:

- Threat score (0-100)
- List of threat indicators
- Intelligence sources used
- Security recommendations

## Dependencies

- requests>=2.31.0
- python-whois>=0.8.0
- vt-py>=0.18.0

## Security Considerations

- API key management and rotation
- Rate limiting for external services
- Data caching for efficiency
- Error handling for service outages

## Example Output

```json
{
    "threat_score": 70,
    "indicators": [
        "Recently registered domain",
        "Privacy protection enabled",
        "Malicious activity reported"
    ],
    "sources": [
        "VirusTotal"
    ],
    "recommendations": [
        "High threat level detected - immediate action recommended"
    ]
}
```
