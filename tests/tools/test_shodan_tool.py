"""Tests for the ShodanHostSearchTool, including input validation."""

import pytest
import os
from unittest.mock import patch, MagicMock
from tools.shodan_tool import ShodanHostSearchTool, ShodanHostInput
import shodan # Import shodan for APIError

# Use parametrize for different key scenarios
@pytest.mark.parametrize(
    "api_key_env, expect_api_init",
    [
        ("fake_shodan_key", True), # Simulate key exists
        (None, False),           # Simulate key missing
    ]
)
@patch('tools.shodan_tool.shodan.Shodan') # Mock the client class
def test_tool_initialization(mock_shodan_client, api_key_env, expect_api_init):
    """Test tool initialization with and without API key."""
    mock_shodan_instance = MagicMock()
    mock_shodan_client.return_value = mock_shodan_instance
    # Mock the info() call to prevent actual API validation
    mock_shodan_instance.info.return_value = {'test': 'info'}
    
    env_vars = {}
    if api_key_env:
        env_vars["SHODAN_API_KEY"] = api_key_env
        
    with patch.dict(os.environ, env_vars, clear=True):
        tool = ShodanHostSearchTool()

    assert tool.name == "shodan_host_search"
    assert "Shodan" in tool.description
    assert tool.input_schema == ShodanHostInput
    
    if expect_api_init:
        assert tool.api is not None
        assert tool.api_key == api_key_env
        mock_shodan_client.assert_called_once_with(api_key_env)
        mock_shodan_instance.info.assert_called_once() # Verify validation was attempted
    else:
        assert tool.api is None
        assert tool.api_key is None
        mock_shodan_client.assert_not_called()

@patch.dict(os.environ, {"SHODAN_API_KEY": "fake_shodan_key"}, clear=True)
@patch('tools.shodan_tool.shodan.Shodan')
def test_run_valid_domain(mock_shodan_client):
    """Test running the tool with a valid domain."""
    mock_shodan_instance = MagicMock()
    mock_shodan_client.return_value = mock_shodan_instance
    mock_shodan_instance.info.return_value = {'test': 'info'} # For init
    
    # Mock the search results
    mock_shodan_instance.search.return_value = {
        'total': 1,
        'matches': [{'ip_str': '1.2.3.4', 'port': 80, 'hostnames': ['test.example.com']}]
    }

    tool = ShodanHostSearchTool()
    assert tool.api is not None # Ensure init succeeded
    
    domain = "example.com"
    result = tool._run(domain=domain)
    
    assert "error" not in result
    assert result["domain"] == domain
    assert result["total_results"] == 1
    assert len(result["hosts"]) == 1
    assert result["hosts"][0]["ip_str"] == '1.2.3.4'
    mock_shodan_instance.search.assert_called_once()
    # Check query format used in search
    assert f'hostname:{domain}' in mock_shodan_instance.search.call_args[0][0]
    

# Parameterize tests for various invalid inputs
@pytest.mark.parametrize(
    "invalid_input, description",
    [
        ("domain<script>.com", "XSS attempt"),
        ("dom;ain.com", "Command injection attempt (semicolon)"),
        ("dom ain.com", "Domain with space"),
        ("../../etc/passwd", "Path traversal attempt"),
        ("-leadinghyphen.com", "Leading hyphen in label"),
        ("trailinghyphen-.com", "Trailing hyphen in label"), # Should fail validation
        ("", "Empty string"),
        ("a" * 600, "Domain exceeding length limit"),
        (".com", "Missing domain part"),
        (None, "None input"),
        (123, "Integer input"),
    ]
)
@patch.dict(os.environ, {"SHODAN_API_KEY": "fake_shodan_key"}, clear=True)
@patch('tools.shodan_tool.shodan.Shodan') # Still need mock for init
def test_run_invalid_inputs(mock_shodan_client, invalid_input, description):
    """Test running the tool with various invalid inputs."""
    # Mock init calls
    mock_shodan_instance = MagicMock()
    mock_shodan_client.return_value = mock_shodan_instance
    mock_shodan_instance.info.return_value = {'test': 'info'}
    
    tool = ShodanHostSearchTool()
    assert tool.api is not None # Ensure init succeeded
    
    result = tool._run(domain=invalid_input)
    
    print(f"Testing {description}: Input='{invalid_input}', Result='{result}'") # Debugging output
    assert "error" in result
    assert isinstance(result["error"], str)
    assert "Invalid domain format" in result["error"]
    assert str(invalid_input) in result["error"]
    mock_shodan_instance.search.assert_not_called() # Ensure API search was not called

@patch.dict(os.environ, {}, clear=True) # No key set
def test_run_without_api_key():
    """Test running the tool when API key is not configured."""
    tool = ShodanHostSearchTool()
    assert tool.api is None
    result = tool._run(domain="example.com")
    assert "error" in result
    assert "API key not configured" in result["error"] 