"""
Simple GitHub Search Tool

This tool provides a straightforward interface to search GitHub repositories
using the GitHub API's search endpoints.
"""

import os
import requests
import logging
from typing import Dict, List, Optional, Any
from langchain.tools import BaseTool
from pydantic import Field

logger = logging.getLogger(__name__)

class GitHubRateLimiter:
    """Minimal rate limiter for GitHub API to avoid hitting limits."""
    pass

class GitHubSearchTool(BaseTool):
    """A simple tool for searching GitHub repositories."""

    name: str = "github_search"
    description: str = """
    Searches GitHub repositories using the GitHub API. 
    Can search by language, stars, topics, and other criteria.
    Returns formatted results in Markdown.
    """

    github_token: Optional[str] = Field(
        default_factory=lambda: os.getenv("GITHUB_TOKEN")
    )
    api_base_url: str = Field(
        default_factory=lambda: os.getenv(
            "GITHUB_API_BASE_URL", "https://api.github.com"
        )
    )

    def __init__(self, **kwargs):
        """Initialize GitHub Search Tool with optional token."""
        super().__init__(**kwargs)
        self.github_token = kwargs.get("github_token", os.getenv("GITHUB_TOKEN"))
        self.api_base_url = kwargs.get(
            "api_base_url", os.getenv("GITHUB_API_BASE_URL", "https://api.github.com")
        )
        
        if self.github_token:
            logger.info(f"GitHub Search Tool initialized with API URL: {self.api_base_url}")
        else:
            logger.warning("GitHub Search Tool initialized without GitHub token")

    def _run(self, query: str) -> str:
        """Execute a GitHub search query and return formatted results."""
        query = query.strip()
        
        try:
            logger.info(f"GitHub Search Tool query: {query}")
            
            # Handle different query types
            if query.startswith("repo:"):
                # Search for a specific repository
                repo = query[5:]
                return self._search_repository(repo)
            elif query.startswith("user:") or query.startswith("org:"):
                # Search for repositories belonging to a user/organization
                owner = query.split(":", 1)[1].strip()
                return self._search_user_repos(owner)
            else:
                # Treat as a general repository search query
                return self._search_repositories(query)
        
        except Exception as e:
            logger.exception(f"Error in GitHub search: {e}")
            return f"Error executing GitHub search: {str(e)}"

    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers for GitHub API requests."""
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        return headers

    def _search_repository(self, repo: str) -> str:
        """Search for a specific repository by name."""
        if "/" not in repo:
            return "Error: Repository must be in the format 'owner/repo'"
        
        url = f"{self.api_base_url}/repos/{repo}"
        response = requests.get(url, headers=self._get_headers())
        
        if response.status_code == 404:
            return f"Repository '{repo}' not found."
        
        if response.status_code != 200:
            return f"Error: GitHub API returned status code {response.status_code}"
        
        repo_data = response.json()
        
        return self._format_repository_result(repo_data)

    def _search_user_repos(self, owner: str) -> str:
        """Search for repositories belonging to a user or organization."""
        url = f"{self.api_base_url}/users/{owner}/repos"
        params = {"sort": "updated", "per_page": 10}
        response = requests.get(url, headers=self._get_headers(), params=params)
        
        if response.status_code == 404:
            # Try organization endpoint
            url = f"{self.api_base_url}/orgs/{owner}/repos"
            response = requests.get(url, headers=self._get_headers(), params=params)
            
            if response.status_code == 404:
                return f"User or organization '{owner}' not found."
        
        if response.status_code != 200:
            return f"Error: GitHub API returned status code {response.status_code}"
        
        repos = response.json()
        
        return self._format_user_repos_result(owner, repos)

    def _search_repositories(self, query: str) -> str:
        """Search for repositories using the GitHub search API."""
        url = f"{self.api_base_url}/search/repositories"
        params = {"q": query, "sort": "stars", "order": "desc", "per_page": 10}
        
        response = requests.get(url, headers=self._get_headers(), params=params)
        
        if response.status_code != 200:
            return f"Error: GitHub API returned status code {response.status_code}"
        
        search_results = response.json()
        
        return self._format_search_results(query, search_results)

    def _format_repository_result(self, repo: Dict[str, Any]) -> str:
        """Format a single repository result as markdown."""
        result = f"## Repository: {repo.get('full_name')}\n\n"
        result += f"**Description**: {repo.get('description', 'No description')}\n\n"
        result += f"**URL**: {repo.get('html_url')}\n"
        result += f"**Stars**: {repo.get('stargazers_count', 0):,}\n"
        result += f"**Forks**: {repo.get('forks_count', 0):,}\n"
        result += f"**Language**: {repo.get('language', 'Not specified')}\n"
        result += f"**Created**: {repo.get('created_at', 'Unknown')}\n"
        result += f"**Last Updated**: {repo.get('updated_at', 'Unknown')}\n"
        
        return result

    def _format_user_repos_result(self, owner: str, repos: List[Dict[str, Any]]) -> str:
        """Format repositories from a user or organization as markdown."""
        if not repos:
            return f"No repositories found for '{owner}'."
        
        result = f"## Repositories for {owner}\n\n"
        result += f"Found {len(repos)} repositories.\n\n"
        result += "| Repository | Stars | Language | Description |\n"
        result += "| ---------- | ----- | -------- | ----------- |\n"
        
        for repo in repos:
            name = repo.get('name', 'N/A')
            stars = repo.get('stargazers_count', 0)
            language = repo.get('language', 'N/A')
            description = repo.get('description', 'No description')
            
            # Truncate description if too long
            if description and len(description) > 80:
                description = description[:77] + "..."
                
            result += f"| [{name}]({repo.get('html_url', '#')}) | {stars:,} | {language} | {description} |\n"
            
        return result

    def _format_search_results(self, query: str, search_results: Dict[str, Any]) -> str:
        """Format search results as markdown."""
        items = search_results.get('items', [])
        total_count = search_results.get('total_count', 0)
        
        result = f"## GitHub Search Results\n\n"
        result += f"**Query**: `{query}`\n\n"
        result += f"Found {total_count:,} repositories. Showing top {len(items)}.\n\n"
        
        if not items:
            return result + "No matching repositories found."
            
        result += "| Repository | Stars | Language | Description |\n"
        result += "| ---------- | ----- | -------- | ----------- |\n"
        
        for repo in items:
            name = repo.get('full_name', 'N/A')
            stars = repo.get('stargazers_count', 0)
            language = repo.get('language', 'N/A')
            description = repo.get('description', 'No description')
            
            # Truncate description if too long
            if description and len(description) > 80:
                description = description[:77] + "..."
                
            result += f"| [{name}]({repo.get('html_url', '#')}) | {stars:,} | {language} | {description} |\n"
            
        return result 