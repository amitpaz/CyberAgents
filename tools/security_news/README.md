# Security News Tool

## Tool Information

**Name**: Security News Tool

**Version**: 1.0.0

**Author**: CyberAgents Team

**Category**: Information Gathering/Cyber Intelligence

**Description**:
The Security News Tool is designed to fetch and aggregate the latest cybersecurity news from trusted sources. It provides up-to-date information on security vulnerabilities, breaches, threats, and industry developments. This tool is crucial for security professionals to stay informed about emerging threats and security trends that may impact their organization or clients.

## Prerequisites

- Python 3.8+
- Required packages: requests, beautifulsoup4, feedparser, pydantic
- External dependencies: None

## Installation

Install the required packages using Poetry.

```bash
poetry add requests beautifulsoup4 feedparser
```

## Configuration

### Required Configuration

No specific configuration is required for this tool.

### Optional Configuration

- `sources`: List of RSS feeds or websites to scrape for security news.
- `max_results`: Maximum number of news items to return.
- `days_back`: Number of days back to fetch news from.

## Usage

### Basic Usage

Initialize the tool and fetch the latest security news without any specific filtering to get a broad overview of current security events and vulnerabilities.

### Advanced Usage

Apply filters by keyword, source, or date range to focus on specific topics or areas of interest, such as ransomware attacks, zero-day vulnerabilities, or industry-specific threats.

## Integration with Agents

This tool can be integrated with CrewAI agents for a threat intelligence specialist to gather and analyze the latest security news relevant to specific organizations or industries.

## Command Line Interface

The tool provides functionality to fetch and parse security news from various sources.

### Running Locally

You can run the Security News Tool directly using the following commands:

```bash
# Fetch latest security news (no filter)
poetry run python -m tools.security_news.news_tool

# Search for specific keyword
poetry run python -m tools.security_news.news_tool --query "ransomware"

# Limit number of results
poetry run python -m tools.security_news.news_tool --max_results 10

# Fetch news from specific sources
poetry run python -m tools.security_news.news_tool --sources "theregister.com,krebsonsecurity.com"

# Fetch news from past days
poetry run python -m tools.security_news.news_tool --days_back 7

# Combined filters with output to file
poetry run python -m tools.security_news.news_tool --query "zero-day" --max_results 20 --days_back 3 --output news.json
```

Alternative methods for security news from the command line:

```bash
# Using RSS readers such as 'newsboat'
newsboat -u security_feeds.txt

# Using curl to fetch an RSS feed and parse with xmllint
curl -s https://www.cisa.gov/news.xml | xmllint --format -

# Using a command line news aggregator like 'news-cli'
news cybersecurity
```

## API Reference

### Main Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `_run()` | query (optional), sources (optional), max_results (optional), days_back (optional) | Dict\[str, Any\] | Fetches security news synchronously |
| `_arun()` | query (optional), sources (optional), max_results (optional), days_back (optional) | Dict\[str, Any\] | Fetches security news asynchronously |

### Data Models

#### SecurityNewsInput

Input model accepting optional parameters for:

- query: Keywords to search for
- sources: List of news sources to include
- max_results: Maximum number of results to return
- days_back: Number of days back to fetch news from

#### Return Format

Returns a dictionary containing a list of news items with title, source, date, summary, and URL.

## Error Handling

Handle errors by checking for the presence of an "error" key in the results dictionary returned by the tool.

## Best Practices

1. **Source Verification**: Always verify the credibility of news sources before integrating them.
1. **Regular Updates**: Security news becomes outdated quickly; refresh frequently.
1. **Filter Noise**: Set appropriate filters to reduce noise and focus on relevant news.
1. **Cross-Verification**: Cross-verify critical security news from multiple sources.
1. **Context Analysis**: Analyze news in the context of your organization's threat landscape.

## Troubleshooting

### Common Issues

1. **Rate Limiting**

   - Implement backoff mechanisms between requests
   - Randomize request timing
   - Respect website robots.txt guidelines

1. **Parsing Errors**

   - Different news sites format content differently
   - HTML structure may change frequently
   - Use multiple parsing strategies as fallbacks

1. **Network Issues**

   - Implement retry logic
   - Set reasonable timeouts
   - Consider using a caching mechanism

## Changelog

### v1.0.0 (2023-12-01)

- Initial release
- Support for RSS feeds and direct website scraping
- Filtering by keyword, source, and date
- Integration with CrewAI

## License

MIT License

## Contact

For support, feature requests, or bug reports, please contact:

- GitHub: [CyberAgents Repository](https://github.com/your-org/cyberagents)
