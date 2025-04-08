"""Test file for GitHub search tool."""

import pytest
from tools.github_search.github_search_tool import GitHubSearchTool

@pytest.fixture
def github_tool():
    """Fixture to provide GitHubSearchTool instance."""
    return GitHubSearchTool()

def test_cyber_agents_exists(github_tool):
    """Test to verify that CyberAgents repository exists under NaorPenso."""
    # Test using direct repository lookup
    repo_result = github_tool._search_repository("NaorPenso/CyberAgents")
    assert "Repository: NaorPenso/CyberAgents" in repo_result
    
    # Test using the user repos lookup to ensure CyberAgents is in the list
    user_result = github_tool.run("user:NaorPenso")
    assert "CyberAgents" in user_result 