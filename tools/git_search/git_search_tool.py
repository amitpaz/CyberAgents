"""GitHub search tool for detecting sensitive information in repositories.

This tool provides search functionality to find potential exposed secrets, credentials,
and other sensitive information in GitHub repositories through the GitHub API.
"""

import logging
import os
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

import requests  # Reverted back to requests
import yaml  # Ensure yaml is imported
from langchain.tools import BaseTool
from pydantic import Field  # Import Field

logger = logging.getLogger(__name__)


# --- Reinstated GitHubRateLimiter Class --- #
class GitHubRateLimiter:
    """Rate limiter for GitHub API requests.
    Handles tracking API calls, respecting rate limits, and adding delays when needed.
    """

    def __init__(self):
        """Initialize the rate limiter with default values."""
        self.remaining_requests = 10
        self.rate_limit_reset = datetime.now() + timedelta(hours=1)
        self.last_updated = datetime.now()
        self.min_delay_seconds = 1.0
        self.last_request_time = datetime.now() - timedelta(
            seconds=self.min_delay_seconds
        )
        self.max_retries = 3
        self.retry_codes = [403, 429, 500, 502, 503, 504]

    def update_limits(self, response: requests.Response) -> None:
        """Update rate limit information from GitHub API response headers."""
        if "X-RateLimit-Remaining" in response.headers:
            try:
                self.remaining_requests = int(response.headers["X-RateLimit-Remaining"])
            except ValueError:
                logger.warning("Invalid X-RateLimit-Remaining header")
        if "X-RateLimit-Reset" in response.headers:
            try:
                reset_timestamp = int(response.headers["X-RateLimit-Reset"])
                self.rate_limit_reset = datetime.fromtimestamp(reset_timestamp)
            except ValueError:
                logger.warning("Invalid X-RateLimit-Reset header")
        self.last_updated = datetime.now()
        logger.debug(
            f"Limits updated: Remaining={self.remaining_requests}, Reset={self.rate_limit_reset}"
        )

    def wait_if_needed(self) -> None:
        """Check rate limits and wait if necessary before making a request."""
        now = datetime.now()
        time_since_last = (now - self.last_request_time).total_seconds()
        if time_since_last < self.min_delay_seconds:
            sleep_time = self.min_delay_seconds - time_since_last
            logger.debug(f"Rate limiter: waiting {sleep_time:.2f}s (min delay)")
            time.sleep(sleep_time)
        if self.remaining_requests < 5:
            time_until_reset = (self.rate_limit_reset - now).total_seconds()
            if time_until_reset > 0:
                wait_time = time_until_reset + 1
                logger.warning(
                    f"Rate limit low ({self.remaining_requests} left). Waiting {wait_time:.1f}s."
                )
                time.sleep(wait_time)
        self.last_request_time = datetime.now()

    def make_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
    ) -> Tuple[Optional[requests.Response], bool]:
        """Make a rate-limited request using synchronous requests."""
        self.wait_if_needed()
        try:
            # For compatibility with tests - use requests.get when method is GET
            if method.upper() == "GET":
                response = requests.get(url, headers=headers, params=params)
            else:
                response = requests.request(
                    method.upper(), url, headers=headers, params=params, json=data
                )

            self.update_limits(response)

            # Check for rate limit errors specifically
            if response.status_code == 403:
                error_msg = response.text.lower()
                if (
                    "rate limit exceeded" in error_msg
                    or "api rate limit exceeded" in error_msg
                ):
                    reset_time_str = self.rate_limit_reset.strftime("%Y-%m-%d %H:%M:%S")
                    logger.warning(
                        f"GitHub API rate limit exceeded. Resets at {reset_time_str}."
                    )
                    # Make sure to update remaining_requests for tests
                    self.remaining_requests = 0
                    return response, False

            # Check for other errors
            if response.status_code >= 400:
                logger.error(
                    f"GitHub API error: {response.status_code} - {response.text}"
                )
                return response, False

            return response, True
        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub API request error: {e}")
            if hasattr(e, "response") and e.response is not None:
                self.update_limits(e.response)
                return e.response, False
            return None, False
        except Exception as e:
            logger.error(f"Unexpected error during request: {e}")
            return None, False

    def retry_with_backoff(
        self, func: callable, *args, **kwargs
    ) -> Tuple[Optional[requests.Response], bool]:
        """Retry a function with exponential backoff."""
        max_retries = kwargs.pop("max_retries", self.max_retries)
        retry_codes = kwargs.pop("retry_codes", self.retry_codes)
        retries = 0
        while retries <= max_retries:
            response, success = func(*args, **kwargs)
            if success or (
                response is not None and response.status_code not in retry_codes
            ):
                return response, success
            is_rate_limit_error = False
            if response is not None and response.status_code == 403:
                try:
                    body = response.json()
                    if "rate limit exceeded" in body.get("message", "").lower():
                        is_rate_limit_error = True
                except Exception:
                    pass
            if is_rate_limit_error:
                time_until_reset = (
                    self.rate_limit_reset - datetime.now()
                ).total_seconds()
                wait_time = max(0, time_until_reset) + 1
                logger.warning(
                    f"Rate limit hit. Waiting {wait_time:.1f}s before retry {retries+1}/{max_retries}."
                )
                time.sleep(wait_time)
                retries += 1
                continue
            status_code_str = str(response.status_code) if response else "N/A"
            if retries < max_retries:
                sleep_time = 2**retries
                logger.warning(
                    f"Request failed ({status_code_str}). Retrying in {sleep_time}s ({retries+1}/{max_retries})."
                )
                time.sleep(sleep_time)
                retries += 1
            else:
                logger.error(
                    f"Request failed after {max_retries} retries with status {status_code_str}."
                )
                return response, False
        return None, False  # Should be unreachable

    def get_paginated_results(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        max_items: int = 100,
    ) -> Tuple[List[Dict[str, Any]], bool]:
        """Fetch all pages of results synchronously."""
        all_results: List[Dict[str, Any]] = []
        page = 1
        page_size = 100
        if params is None:
            params = {}
        params["per_page"] = page_size
        current_url = url  # Start with the initial URL

        while True:
            params["page"] = page
            logger.debug(f"Fetching page {page} for {current_url}")
            response, success = self.retry_with_backoff(
                self.make_request, current_url, headers=headers, params=params
            )
            if not success:
                logger.error(
                    f"Failed pagination page {page} for {current_url} after retries."
                )
                return all_results, False
            try:
                current_page_results = response.json()
                if not isinstance(current_page_results, list):
                    logger.warning(
                        f"Expected list results for {current_url}, got {type(current_page_results)}. Stopping."
                    )
                    if page == 1 and isinstance(current_page_results, dict):
                        all_results.append(current_page_results)
                    break
                all_results.extend(current_page_results)
                logger.debug(
                    f"Page {page}: Got {len(current_page_results)} items. Total: {len(all_results)}"
                )
                # Check Link header for next page (more reliable than item count for search)
                link_header = response.headers.get("Link")
                next_url = None
                if link_header:
                    links = requests.utils.parse_header_links(link_header)
                    for link in links:
                        if link.get("rel") == "next":
                            next_url = link.get("url")
                            break
                if not next_url or len(all_results) >= max_items:
                    logger.debug(
                        "Pagination finished: no next link or max items reached."
                    )
                    break
                current_url = next_url  # Update URL for the next page request
                # Remove params that will be in the next_url already
                params = {}  # Reset params as they are in the next_url
            except Exception as e:
                logger.error(
                    f"Error processing page {page} results for {current_url}: {e}"
                )
                return all_results, False
            page += (
                1  # Increment page number conceptually, actual URL is from Link header
            )
            if len(all_results) >= max_items:
                logger.info(f"Reached max items ({max_items}) for {url}.")
                break
        return all_results[:max_items], True


# --- GitHubSearchTool modified for Pydantic V2 --- #
class GitHubSearchTool(BaseTool):
    """Tool for searching GitHub repositories (Sync Version)."""

    name: str = "github_search"
    description: str = """Searches GitHub repositories for sensitive information like access keys, passwords,
    tokens, etc. Can search a specific repository, all repositories belonging to an organization/user, or
    execute a custom search query. Adheres to GitHub API rate limits."""

    # Use Field and default_factory for Pydantic V2 initialization
    github_token: Optional[str] = Field(
        default_factory=lambda: os.getenv("GITHUB_TOKEN")
    )
    api_base_url: str = Field(
        default_factory=lambda: os.getenv(
            "GITHUB_API_BASE_URL", "https://api.github.com"
        )
    )
    # Define as class var instead of Field to fix AttributeError
    rate_limiter: GitHubRateLimiter = None

    def __init__(self, **kwargs):
        """Initialize GitHub Search Tool."""
        super().__init__(**kwargs)
        # Initialize rate limiter here as a proper instance
        self.rate_limiter = GitHubRateLimiter()

        # Set up tokens and API URLs
        self.github_token = kwargs.get("github_token", os.getenv("GITHUB_TOKEN"))
        self.api_base_url = kwargs.get(
            "api_base_url", os.getenv("GITHUB_API_BASE_URL", "https://api.github.com")
        )

        # Log initialization
        if self.github_token:
            logger.info(
                f"GitHub Search Tool initialized with API URL: {self.api_base_url}"
            )
        else:
            logger.warning("GitHub Search Tool initialized without GitHub token")

    # --- Core Tool Logic (Synchronous) ---
    def _run(self, query: str) -> str:
        """Execute the GitHub search tool synchronously."""
        query = query.strip()
        try:
            logger.info(f"GitHub Search Tool query: {query}")

            # Handle repository format: repo:owner/repo
            if query.startswith("repo:"):
                repo = query[5:]
                # Validate repo format before searching
                if "/" not in repo or len(repo.split("/")) != 2:
                    return f"Error: Invalid repository format. Please use 'owner/repo' format."
                return self._search_repository(repo)

            # Handle repository search with direct owner/repo format
            if "/" in query and " " not in query:
                repo_parts = query.split("/")
                if len(repo_parts) == 2:
                    return self._search_repository(query)

            # Handle organization or user repository list
            if query.startswith("user:") or query.startswith("org:"):
                owner = query.split(":", 1)[1].strip()
                return self._search_owner_repos(owner)

            # Handle custom search query
            return self._execute_custom_search(query)
        except Exception as e:
            logger.exception(f"Error in GitHub search: {e}")
            return f"Error executing GitHub search: {str(e)}"

    # --- Internal Sync Helpers ---
    def _search_repository(self, repo: str) -> str:
        """Search a specific GitHub repository for potential secrets and sensitive information.

        Args:
            repo: Repository identifier in the format "owner/repo"

        Returns:
            Formatted report of search results
        """
        # Validate repo format
        if "/" not in repo or len(repo.split("/")) != 2:
            return f"Error: Invalid repository format. Please use 'owner/repo' format."

        owner, repo_name = repo.split("/", 1)

        # Make sure the repository exists
        repo_info = self._get_repository_info(owner, repo_name)
        if isinstance(repo_info, str):
            return repo_info  # Error message

        # Initialize result containers
        high_priority_results = []
        medium_priority_results = []
        file_target_results = []

        try:
            # Get patterns for sensitive information
            patterns = self._get_search_patterns()

            # Create headers once
            headers = self._get_request_headers()

            # Set up base API URL
            base_url = f"{self.api_base_url}/search/code"

            # Search for each pattern category
            for category, search_terms in patterns.items():
                for term in search_terms:
                    # Build the query with proper scoping
                    search_query = f"{term} repo:{owner}/{repo_name}"

                    # Execute the search
                    params = {"q": search_query, "per_page": 100}
                    results, success = self.rate_limiter.get_paginated_results(
                        base_url, headers=headers, params=params, max_items=100
                    )

                    if not success:
                        logger.warning(f"Search failed for term: {term}")
                        continue

                    # Process and categorize results
                    if isinstance(results, dict):
                        items = results.get("items", [])
                    else:
                        items = results

                    for item in items:
                        if isinstance(item, dict):
                            result_item = {
                                "repository": f"{owner}/{repo_name}",
                                "file_path": item.get("path", ""),
                                "pattern": term,
                                "category": category,
                                "url": item.get("html_url", ""),
                            }

                            if "HIGH" in category.upper():
                                high_priority_results.append(result_item)
                            elif "MEDIUM" in category.upper():
                                medium_priority_results.append(result_item)
                            else:
                                file_target_results.append(result_item)

            # Generate report
            return self._format_repository_report(
                repo_info,
                high_priority_results,
                medium_priority_results,
                file_target_results,
            )
        except Exception as e:
            logger.exception(f"Error searching repository {repo}: {e}")
            return f"Error searching repository {repo}: {str(e)}"

    def _search_owner_repos(self, owner: str) -> str:
        logger.info(f"Searching owner repos sync: {owner}")
        repos = self._get_owner_repositories(owner)
        if isinstance(repos, str):
            return repos
        if not repos:
            return f"No public repositories found for owner '{owner}'..."
        search_patterns = self._get_search_patterns()
        results: Dict[str, List[Dict[str, Any]]] = {
            "high_priority": [],
            "medium_priority": [],
            "file_targets": [],
        }
        # Simplified: sequential searches
        base_query = f"user:{owner}"
        for pattern in search_patterns.get("high_priority", []):
            res = self._execute_code_search(f"{base_query} {pattern}")
            if isinstance(res, dict) and "items" in res:
                results["high_priority"].extend(res["items"])
        for pattern in search_patterns.get("medium_priority", []):
            res = self._execute_code_search(f"{base_query} {pattern}")
            if isinstance(res, dict) and "items" in res:
                results["medium_priority"].extend(res["items"])
        for file_pattern in search_patterns.get("file_targets", []):
            res = self._execute_code_search(f"{base_query} filename:{file_pattern}")
            if isinstance(res, dict) and "items" in res:
                results["file_targets"].extend(res["items"])
        return self._format_owner_report(owner, repos, results)

    def _execute_custom_search(self, search_query: str) -> str:
        logger.info(f"Executing custom search sync: {search_query}")
        results = self._execute_code_search(search_query)
        if isinstance(results, str):
            return results
        return self._format_custom_search_report(search_query, results)

    def _get_repository_info(self, owner: str, repo: str) -> Union[Dict[str, Any], str]:
        url = f"{self.api_base_url}/repos/{owner}/{repo}"
        logger.debug(f"Getting repo info sync for {owner}/{repo}")
        headers = self._get_request_headers()
        response, success = self.rate_limiter.retry_with_backoff(
            self.rate_limiter.make_request, url, headers=headers
        )
        if not success:
            status = response.status_code if response else "N/A"
            text = response.text[:100] if response else "N/A"
            if response and response.status_code == 404:
                return f"Error: Repo {owner}/{repo} not found."
            # Add other specific error checks if needed
            return f"Error getting repo info ({status}): {text}"
        try:
            return response.json()
        except Exception as e:
            return f"Error parsing repo info: {e}"

    def _get_owner_repositories(self, owner: str) -> Union[List[Dict[str, Any]], str]:
        user_url = f"{self.api_base_url}/users/{owner}/repos"
        org_url = f"{self.api_base_url}/orgs/{owner}/repos"
        params = {"type": "all", "sort": "updated"}
        headers = self._get_request_headers()
        logger.debug(f"Getting owner repos sync for {owner}")
        repositories, success = self.rate_limiter.retry_with_backoff(
            self.rate_limiter.get_paginated_results,
            user_url,
            headers=headers,
            params=params,
            max_items=200,
        )
        if not success or not repositories:
            logger.debug(
                f"User endpoint failed/empty for {owner}, trying org endpoint."
            )
            org_repos, org_success = self.rate_limiter.retry_with_backoff(
                self.rate_limiter.get_paginated_results,
                org_url,
                headers=headers,
                params=params,
                max_items=200,
            )
            if org_success:
                repositories, success = org_repos, True
            elif not success:
                return f"Error retrieving repos for '{owner}'."
        if success and isinstance(repositories, list):
            return repositories
        elif isinstance(repositories, list):
            return repositories  # Return partial on failure
        else:
            return f"Error: Unexpected result type for repos: {type(repositories)}"

    def _execute_code_search(
        self, query: str, max_results: int = 100
    ) -> Union[Dict[str, Any], str]:
        url = f"{self.api_base_url}/search/code"
        params = {"q": query}
        headers = self._get_request_headers()
        logger.debug(f"Executing code search sync: {query}")
        # Use get_paginated_results for search as well
        results_list, success = self.rate_limiter.retry_with_backoff(
            self.rate_limiter.get_paginated_results,
            url,
            headers=headers,
            params=params,
            max_items=max_results,
        )
        if not success:
            return f"Error: GitHub code search failed for query '{query}'."
        logger.info(
            f"Code search sync for '{query}' returned {len(results_list)} items."
        )
        return {
            "total_count": len(results_list),
            "incomplete_results": len(results_list) >= max_results,
            "items": results_list,
        }

    # --- Sync Helper Methods --- #
    def _get_request_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"  # Use Bearer
        return headers

    # _get_search_patterns, _format_repository_report, _format_owner_report, _format_custom_search_report
    # remain the same as they were mostly synchronous already.
    def _get_search_patterns(self) -> Dict[str, List[str]]:
        # ... (Implementation is synchronous, no changes needed from previous state)
        try:
            import yaml

            script_dir = os.path.dirname(__file__)
            default_policies_dir = os.path.abspath(
                os.path.join(
                    script_dir,
                    "../../agents/git_exposure_analyst_agent/knowledge/policy",
                )
            )
            policies_dir = os.getenv("GITHUB_SEARCH_POLICY_DIR", default_policies_dir)
            patterns: Dict[str, List[str]] = {
                "high_priority": [],
                "medium_priority": [],
                "low_priority": [],
                "file_targets": [],
            }
            if not os.path.exists(policies_dir) or not os.path.isdir(policies_dir):
                logger.warning(f"Policy dir not found: {policies_dir}. Using defaults.")
                return self._get_default_patterns()
            logger.info(f"Loading search patterns from: {policies_dir}")
            loaded_patterns = False
            for filename in os.listdir(policies_dir):
                if filename.endswith((".yaml", ".yml")):
                    file_path = os.path.join(policies_dir, filename)
                    try:
                        with open(file_path, "r") as f:
                            policy_data = yaml.safe_load(f)
                            if not isinstance(policy_data, dict):
                                continue

                            def extract_patterns(key):
                                return [
                                    str(p)
                                    for p in policy_data.get(key, [])
                                    if isinstance(p, (str, int, float))
                                ]

                            patterns["high_priority"].extend(
                                extract_patterns("high_priority_patterns")
                            )
                            patterns["medium_priority"].extend(
                                extract_patterns("medium_priority_patterns")
                            )
                            patterns["low_priority"].extend(
                                extract_patterns("low_priority_patterns")
                            )
                            patterns["file_targets"].extend(
                                extract_patterns("file_target_patterns")
                            )
                            if "patterns" in policy_data and isinstance(
                                policy_data["patterns"], list
                            ):
                                for pe in policy_data["patterns"]:  # legacy format
                                    if isinstance(pe, dict):
                                        sev, reg = str(
                                            pe.get("severity", "MEDIUM")
                                        ).upper(), str(pe.get("regex", ""))
                                        if reg:
                                            patterns[f"{sev.lower()}_priority"].append(
                                                reg
                                            )
                            if "file_patterns" in policy_data and isinstance(
                                policy_data["file_patterns"], list
                            ):
                                patterns["file_targets"].extend(
                                    [
                                        str(fp)
                                        for fp in policy_data["file_patterns"]
                                        if isinstance(fp, str)
                                    ]
                                )
                            loaded_patterns = True
                    except Exception as e:
                        logger.error(f"Error loading policy {filename}: {e}")
            for key in patterns:
                patterns[key] = sorted(list(set(patterns[key])))
            if not loaded_patterns or not any(
                p for p_list in patterns.values() for p in p_list
            ):
                logger.warning("No patterns loaded, using defaults.")
                return self._get_default_patterns()
            logger.info(
                f"Loaded patterns: { {k: len(v) for k, v in patterns.items()} }"
            )
            return patterns
        except ImportError:
            logger.warning("PyYAML not installed. Using default patterns.")
            return self._get_default_patterns()
        except Exception as e:
            logger.exception(f"Error getting patterns: {e}")
            return self._get_default_patterns()

    def _get_default_patterns(self) -> Dict[str, List[str]]:
        # ... (Implementation is synchronous, no changes needed)
        logger.debug("Using default search patterns.")
        return {
            "high_priority": [
                "password",
                "secret_key",
                "client_secret",
                "private_key",
                "aws_access_key_id",
                "aws_secret_access_key",
                "authorization_bearer",
                "BEGIN RSA PRIVATE KEY",
                "BEGIN DSA PRIVATE KEY",
                "BEGIN EC PRIVATE KEY",
                "BEGIN OPENSSH PRIVATE KEY",
                "api_key",
                "apikey",
                "client_id",
                "client_secret",
                "access_token",
                "auth_token",
                "oauth_token",
                "db_password",
                "database_password",
                "smtp_password",
                "FTP_PASSWORD",
                "HEROKU_API_KEY",
                "GITHUB_TOKEN",
                "SLACK_TOKEN",
            ],
            "medium_priority": [
                "passwd",
                "pwd",
                "auth",
                "credential",
                "jdbc:",
                "mysql://",
                "postgres://",
            ],
            "low_priority": ["config", "connection_string", "internal", "debug"],
            "file_targets": [
                ".env",
                "credentials",
                "config.json",
                "settings.py",
                "application.yml",
                ".aws/credentials",
                ".netrc",
                "htpasswd",
                "docker-compose.yml",
                "id_rsa",
                "id_dsa",
                "id_ecdsa",
                ".bash_history",
                ".zsh_history",
                ".npmrc",
                ".yarnrc",
                ".git-credentials",
                "web.config",
            ],
        }

    def _format_repository_report(
        self,
        repo_info: Dict[str, Any],
        high_priority_results: List[Dict[str, Any]],
        medium_priority_results: List[Dict[str, Any]],
        file_target_results: List[Dict[str, Any]],
    ) -> str:
        # ... (Implementation is synchronous, no changes needed)
        report = (
            f"## GitHub Repository Analysis: {repo_info.get('full_name', 'N/A')}\n\n"
        )
        report += "### Repository Information\n"
        report += f"- **URL**: [{repo_info.get('html_url', 'N/A')}]({repo_info.get('html_url', '#')})\n"
        report += f"- **Description**: {repo_info.get('description', 'N/A')}\n"
        report += f"- **Owner**: {repo_info.get('owner', {}).get('login', 'N/A')}\n"
        report += f"- **Stars**: {repo_info.get('stargazers_count', 'N/A')}\n"
        report += f"- **Forks**: {repo_info.get('forks_count', 'N/A')}\n"
        report += f"- **Language**: {repo_info.get('language', 'N/A')}\n"
        report += f"- **Created**: {repo_info.get('created_at', 'N/A')}\n"
        report += f"- **Updated**: {repo_info.get('updated_at', 'N/A')}\n\n"
        total_high, total_medium, total_files = (
            len(high_priority_results),
            len(medium_priority_results),
            len(file_target_results),
        )
        report += f"### Findings Summary\n- **High Priority Keyword Matches**: {total_high}\n- **Medium Priority Keyword Matches**: {total_medium}\n- **Sensitive File Name Matches**: {total_files}\n\n"

        def format_results_table(
            title: str, results: List[Dict[str, Any]], max_res: int = 15
        ):
            if not results:
                return f"#### {title}\nNo findings.\n\n"
            tbl = f"#### {title} ({len(results)} found, showing top {min(len(results), max_res)})\n| File | Path | URL |\n| ---- | ---- | --- |\n"
            for item in results[:max_res]:
                p = item.get("path", "N/A")
                dp = p if len(p) < 60 else p[:28] + "..." + p[-28:]
                tbl += f"| {item.get('name', 'N/A')} | `{dp}` | [Link]({item.get('html_url', '#')}) |\n"
            return tbl + "\n"

        report += format_results_table("High Priority Findings", high_priority_results)
        report += format_results_table(
            "Medium Priority Findings", medium_priority_results
        )
        report += format_results_table("Sensitive File Findings", file_target_results)
        report += "### Recommendations\n"
        if total_high > 0:
            report += "- **CRITICAL:** High priority keywords detected... Rotate credentials...\n"
        if total_medium > 0:
            report += "- **WARNING:** Medium priority keywords detected... Review findings...\n"
        if total_files > 0:
            report += (
                "- **INFO:** Files with sensitive names found... Verify contents...\n"
            )
        if total_high + total_medium + total_files == 0:
            report += "- No potential secrets found. Good work!\n"
        report += "- Implement pre-commit hooks...\n- Use secrets management solution...\n- Regularly review code...\n"
        return report.strip()

    def _format_owner_report(
        self,
        owner: str,
        repos: List[Dict[str, Any]],
        categorized_results: Dict[str, List[Dict[str, Any]]],
    ) -> str:
        # ... (Implementation is synchronous, no changes needed)
        report = f"## GitHub Owner/Organization Analysis: {owner}\n\nSearched across {len(repos)} repositories.\n\n"
        total_high = len(categorized_results.get("high_priority", []))
        total_medium = len(categorized_results.get("medium_priority", []))
        total_files = len(categorized_results.get("file_targets", []))
        report += f"### Findings Summary Across All Repositories\n- **High Priority Keyword Matches**: {total_high}\n- **Medium Priority Keyword Matches**: {total_medium}\n- **Sensitive File Name Matches**: {total_files}\n\n"

        def format_owner_results_table(
            title: str, results: List[Dict[str, Any]], max_res: int = 20
        ):
            if not results:
                return f"#### {title}\nNo findings.\n\n"
            results_by_repo: Dict[str, List[Dict[str, Any]]] = {}
            for item in results:
                repo_name = item.get("repository", {}).get("full_name", "Unknown")
                results_by_repo.setdefault(repo_name, []).append(item)
            tbl = f"#### {title} ({len(results)} total findings across {len(results_by_repo)} repos)\n"
            count = 0
            for repo_name, items in sorted(results_by_repo.items()):
                if count >= max_res:
                    tbl += f"- ... (results truncated at {max_res} items)\n"
                    break
                repo_url = items[0].get("repository", {}).get("html_url", "#")
                tbl += f"\n**Repository:** [{repo_name}]({repo_url}) ({len(items)} findings)\n| File | Path | URL |\n| ---- | ---- | --- |\n"
                for item in items:
                    if count >= max_res:
                        break
                    p = item.get("path", "N/A")
                    dp = p if len(p) < 50 else p[:23] + "..." + p[-23:]
                    tbl += f"| {item.get('name', 'N/A')} | `{dp}` | [Link]({item.get('html_url', '#')}) |\n"
                    count += 1
            return tbl + "\n"

        report += format_owner_results_table(
            "High Priority Findings", categorized_results.get("high_priority", [])
        )
        report += format_owner_results_table(
            "Medium Priority Findings", categorized_results.get("medium_priority", [])
        )
        report += format_owner_results_table(
            "Sensitive File Findings", categorized_results.get("file_targets", [])
        )
        report += "### Recommendations\n"
        if total_high > 0:
            report += "- **CRITICAL:** High priority keywords detected... Prioritize investigation...\n"
        if total_medium > 0:
            report += "- **WARNING:** Medium priority keywords detected... Review...\n"
        if total_files > 0:
            report += "- **INFO:** Files with sensitive names found... Verify...\n"
        report += "- Implement organization-wide security practices...\n- Consider GitHub Advanced Security...\n"
        return report.strip()

    def _format_custom_search_report(self, query: str, results: Dict[str, Any]) -> str:
        # ... (Implementation is synchronous, no changes needed)
        report = f"## GitHub Custom Search Results\n\n**Query:** `{query}`\n\n"
        items = results.get("items", [])
        total_count = results.get("total_count", len(items))
        incomplete = results.get("incomplete_results", False)
        report += f"Found **{total_count}** results.{' (Results might be incomplete)' if incomplete else ''}\n\n"
        if not items:
            return report + "No matching code found.\n"
        report += (
            "| Repository | File | Path | URL |\n| ---------- | ---- | ---- | --- |\n"
        )
        max_display = 30
        for item in items[:max_display]:
            repo_name = item.get("repository", {}).get("full_name", "N/A")
            repo_url = item.get("repository", {}).get("html_url", "#")
            p = item.get("path", "N/A")
            dp = p if len(p) < 50 else p[:23] + "..." + p[-23:]
            report += f"| [{repo_name}]({repo_url}) | {item.get('name', 'N/A')} | `{dp}` | [Link]({item.get('html_url', '#')}) |\n"
        if len(items) > max_display:
            report += f"\n... (Results truncated to {max_display} items)\n"
        return report.strip()

    # No _arun or close_client needed for sync version
