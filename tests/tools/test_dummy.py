"""Test file for the Dummy Tool.

This file demonstrates the standard structure for tool tests.
"""

import pytest
from unittest.mock import patch, MagicMock
from tools.dummy.dummy import DummyTool

@pytest.fixture
def dummy_tool():
    """Fixture to provide DummyTool instance."""
    return DummyTool()

def test_example_method(dummy_tool):
    """Test the example method functionality."""
    result = dummy_tool._example_method("test-parameter")
    assert result == "Processed parameter: test-parameter"
    assert isinstance(result, str)

def test_process_default_query(dummy_tool):
    """Test the default query processing."""
    query = "standard query"
    result = dummy_tool._process_default_query(query)
    assert query in result
    assert "Dummy Tool Results" in result
    assert isinstance(result, str)

def test_run_with_example_query(dummy_tool):
    """Test the tool execution with an example query format."""
    result = dummy_tool._run("example:test-parameter")
    assert result == "Processed parameter: test-parameter"

def test_run_with_standard_query(dummy_tool):
    """Test the tool execution with a standard query."""
    result = dummy_tool._run("standard query")
    assert "standard query" in result
    assert "Dummy Tool Results" in result

def test_with_mock_external_service():
    """Test with a mocked external service."""
    # This is just a placeholder test - in real tools, you'd mock external services
    # Setup a tool with a mock API key
    tool_with_api = DummyTool(api_key="test-api-key")
    assert tool_with_api.api_key == "test-api-key"
    assert tool_with_api.base_url == "https://api.example.com"

def test_format_results(dummy_tool):
    """Test the result formatting function."""
    data = {
        "key1": "value1",
        "key2": "value2",
        "key3": {"nested": "data"}
    }
    
    result = dummy_tool._format_results(data)
    
    assert "Dummy_Tool Results" in result
    assert "key1" in result
    assert "value1" in result
    assert "key2" in result
    assert "key3" in result 