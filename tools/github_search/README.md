# GitHub Search Tool

A simple tool for searching GitHub repositories through the GitHub API.

## Features

- Search for repositories by various criteria (language, stars, topics, etc.)
- Look up specific repositories by name
- Get repositories belonging to a user or organization
- Results formatted as Markdown for easy readability

## Usage

### Basic Usage

```python
from tools.github_search.github_search_tool import GitHubSearchTool

# Initialize the tool
github_tool = GitHubSearchTool()

# Search for a specific repository
result = github_tool.run("repo:NaorPenso/CyberAgents")
print(result)

# Get repositories for a user
result = github_tool.run("user:NaorPenso")
print(result)

# Search for repositories with criteria
result = github_tool.run("language:python stars:>10000")
print(result)
```

### Search Types

The tool supports these search formats:

1. **Specific repository lookup**:
   ```python
   result = github_tool.run("repo:owner/repository")
   ```

2. **User/Organization repositories**:
   ```python
   result = github_tool.run("user:username")
   result = github_tool.run("org:organization")
   ```

3. **General repository search**:
   ```python
   result = github_tool.run("search terms language:python stars:>1000")
   ```

## Configuration

The tool can be configured with:

- `GITHUB_TOKEN` environment variable - GitHub Personal Access Token for authentication
- `GITHUB_API_BASE_URL` environment variable - Custom GitHub API URL (default: https://api.github.com)

## Testing

Run the test to verify that the CyberAgents repository exists under NaorPenso:

```bash
poetry run python -m tools.github_search.test_github_search
```

## Dependencies

- requests
- langchain.tools
- pydantic 