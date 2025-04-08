# GitHub Search Tool

A tool for searching GitHub repositories and code for potential exposed secrets, API keys, credentials, and other sensitive information.

## Overview

The GitHub Search Tool provides an interface to search GitHub repositories, code, and user profiles through the GitHub API, with a special focus on identifying accidentally exposed secrets and sensitive information.

## Features

- **Repository Search**: Search for repositories based on specific criteria
- **Code Search**: Find code snippets that may contain sensitive information such as API keys, passwords, etc.
- **User Search**: Retrieve information about GitHub users
- **Rate Limit Handling**: Intelligently manages GitHub API rate limits

## Usage

```python
from tools.git_search import GitHubSearchTool

# Initialize the tool
github_tool = GitHubSearchTool()

# Search repositories
results = github_tool._run("repo:username/repository")

# Search code for potential secrets
results = github_tool._run("code:password")

# Search user information
results = github_tool._run("user:username")
```

## Configuration

The tool requires a GitHub API token for optimal usage. Set the environment variable `GITHUB_TOKEN` to your GitHub personal access token before using the tool to avoid rate limiting.

```bash
export GITHUB_TOKEN=your_github_token_here
```

## Rate Limiting

The tool includes a rate limiter to handle GitHub API rate limits intelligently. When rate limits are approached, the tool will wait until reset times before continuing to make requests.

## Patterns Detected

The tool searches for common patterns that might indicate exposed secrets, including:

- API keys and tokens
- Passwords and credentials
- Private keys (SSH, RSA, etc.)
- Authentication headers
- Database connection strings
- And more

## Dependencies

- Python 3.8+
- requests
- langchain
- pydantic

## Credits

This tool is part of the CyberAgents project and is typically used by the Git Exposure Analyst Agent for identifying security risks in code repositories. 