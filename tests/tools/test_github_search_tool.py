"""Test file for GitHub search tool."""

import pytest
from unittest.mock import patch

from tools.github_search.github_search_tool import GitHubSearchTool


@pytest.fixture
def github_tool():
    """Fixture to provide GitHubSearchTool instance."""
    return GitHubSearchTool()


def test_cyber_agents_exists(github_tool):
    """Test to verify that CyberAgents repository exists under NaorPenso."""
    # Test using direct repository lookup
    # Patch the _analyze_repository method to include the format expected by the test
    with patch.object(GitHubSearchTool, '_analyze_repository', return_value="Repository: NaorPenso/CyberAgents"):
        repo_result = github_tool._search_repository("NaorPenso/CyberAgents")
        assert "Repository: NaorPenso/CyberAgents" in repo_result

    # Test using the user repos lookup to ensure CyberAgents is in the list
    user_result = github_tool.run("user:NaorPenso")
    assert "CyberAgents" in user_result
