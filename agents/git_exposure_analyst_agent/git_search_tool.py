"""Tool for searching GitHub repositories for potential secret exposures.

This tool uses the GitHub API to search repositories, code, and commits
for patterns that might indicate secret exposure.
"""

import logging
import re
import os
from typing import Dict, List, Optional

import requests
from langchain.tools import BaseTool

logger = logging.getLogger(__name__)


class GitHubSearchTool(BaseTool):
    """Tool for searching GitHub for potential exposed secrets and sensitive information.
    
    Uses the GitHub API to search code, repositories, and commits for patterns
    that could indicate exposed secrets or credentials.
    """
    
    name = "github_search_tool"
    description = (
        "Searches GitHub repositories and code for potential exposed secrets, "
        "API keys, credentials, and other sensitive information."
    )
    
    def __init__(self):
        """Initialize the GitHub search tool.
        
        Loads GitHub API token from environment variables and sets up the tool.
        """
        super().__init__()
        self.github_token = os.environ.get("GITHUB_API_TOKEN")
        self.api_base_url = "https://api.github.com"
        self.headers = {}
        
        if self.github_token:
            self.headers = {
                "Authorization": f"token {self.github_token}",
                "Accept": "application/vnd.github.v3+json"
            }
        else:
            logger.warning(
                "GITHUB_API_TOKEN not found in environment variables. "
                "Running with limited rate limits."
            )
            self.headers = {"Accept": "application/vnd.github.v3+json"}
    
    def _run(self, query: str) -> str:
        """Execute GitHub search based on the given query.
        
        Args:
            query: String containing the search query and parameters.
                  Format: "type:search_string" where type can be:
                  - repo: Search for repositories
                  - code: Search for code containing patterns
                  - user: Search for user information
                  
        Returns:
            A string containing the search results in a formatted report.
        """
        # Parse the query type and search string
        if ":" not in query:
            return "Please provide a query in the format 'type:search_string'"
        
        query_parts = query.split(":", 1)
        search_type = query_parts[0].strip().lower()
        search_string = query_parts[1].strip()
        
        if search_type == "repo":
            return self._search_repositories(search_string)
        elif search_type == "code":
            return self._search_code(search_string)
        elif search_type == "user":
            return self._search_user(search_string)
        else:
            return f"Unsupported search type: {search_type}. Use 'repo', 'code', or 'user'."
    
    def _search_repositories(self, query: str) -> str:
        """Search for GitHub repositories matching the query.
        
        Args:
            query: Repository search query string
            
        Returns:
            Formatted results of repository search
        """
        try:
            logger.info(f"Searching GitHub repositories with query: {query}")
            response = requests.get(
                f"{self.api_base_url}/search/repositories",
                headers=self.headers,
                params={"q": query, "per_page": 10}
            )
            response.raise_for_status()
            data = response.json()
            
            if data["total_count"] == 0:
                return f"No repositories found matching query: {query}"
            
            repos = data["items"]
            result = f"### GitHub Repository Search Results\n\n"
            result += f"Found {data['total_count']} repositories matching: {query}\n\n"
            
            for i, repo in enumerate(repos[:10], 1):
                result += f"{i}. [{repo['full_name']}]({repo['html_url']})\n"
                result += f"   Description: {repo['description'] or 'No description'}\n"
                result += f"   Stars: {repo['stargazers_count']} | Forks: {repo['forks_count']}\n"
                result += f"   Last updated: {repo['updated_at']}\n\n"
            
            if data["total_count"] > 10:
                result += f"...and {data['total_count'] - 10} more repositories.\n"
            
            return result
            
        except requests.RequestException as e:
            logger.error(f"GitHub API error during repository search: {e}")
            return f"Error searching GitHub repositories: {str(e)}"
    
    def _search_code(self, query: str) -> str:
        """Search for code in GitHub repositories matching the query.
        
        This is particularly useful for finding exposed secrets by searching
        for patterns like 'api_key', 'password', etc.
        
        Args:
            query: Code search query string
            
        Returns:
            Formatted results of code search
        """
        try:
            logger.info(f"Searching GitHub code with query: {query}")
            response = requests.get(
                f"{self.api_base_url}/search/code",
                headers=self.headers,
                params={"q": query, "per_page": 10}
            )
            response.raise_for_status()
            data = response.json()
            
            if data["total_count"] == 0:
                return f"No code matches found for query: {query}"
            
            code_matches = data["items"]
            result = f"### GitHub Code Search Results\n\n"
            result += f"Found {data['total_count']} code matches for: {query}\n\n"
            
            for i, match in enumerate(code_matches[:10], 1):
                result += f"{i}. [{match['repository']['full_name']}:{match['path']}]({match['html_url']})\n"
                result += f"   File: {match['name']}\n"
                result += f"   Repository: {match['repository']['full_name']}\n\n"
            
            if data["total_count"] > 10:
                result += f"...and {data['total_count'] - 10} more code matches.\n"
            
            result += "\n**Note:** Review these files manually for potential secret exposure."
            return result
            
        except requests.RequestException as e:
            logger.error(f"GitHub API error during code search: {e}")
            return f"Error searching GitHub code: {str(e)}"
    
    def _search_user(self, query: str) -> str:
        """Search for GitHub users matching the query.
        
        Args:
            query: User search query string
            
        Returns:
            Formatted results of user search
        """
        try:
            logger.info(f"Searching GitHub users with query: {query}")
            response = requests.get(
                f"{self.api_base_url}/search/users",
                headers=self.headers,
                params={"q": query, "per_page": 10}
            )
            response.raise_for_status()
            data = response.json()
            
            if data["total_count"] == 0:
                return f"No users found matching query: {query}"
            
            users = data["items"]
            result = f"### GitHub User Search Results\n\n"
            result += f"Found {data['total_count']} users matching: {query}\n\n"
            
            for i, user in enumerate(users[:10], 1):
                result += f"{i}. [{user['login']}]({user['html_url']})\n"
                result += f"   Type: {user['type']}\n\n"
            
            if data["total_count"] > 10:
                result += f"...and {data['total_count'] - 10} more users.\n"
            
            return result
            
        except requests.RequestException as e:
            logger.error(f"GitHub API error during user search: {e}")
            return f"Error searching GitHub users: {str(e)}"
    
    async def _arun(self, query: str) -> str:
        """Async implementation - for this tool, just calls the sync version."""
        return self._run(query) 