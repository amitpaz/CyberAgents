"""Tests for the SubdomainFinderTool, including input validation."""

import pytest
from unittest.mock import patch, MagicMock
from tools.subdomain_finder_tool import SubdomainFinderTool, SubdomainInput

@pytest.fixture
def subdomain_tool():
    """Fixture to create an instance of the SubdomainFinderTool."""
    return SubdomainFinderTool()

def test_tool_initialization(subdomain_tool):
    """Test basic tool attributes."""
    assert subdomain_tool.name == "subdomain_finder_crtsh"
    assert "crt.sh" in subdomain_tool.description
    assert subdomain_tool.input_schema == SubdomainInput

# Mock successful request for valid domain tests
@patch('requests.get')
def test_run_valid_domain(mock_get, subdomain_tool):
    """Test running the tool with a valid domain."""
    mock_response = MagicMock()
    # Simulate a minimal valid JSON response from crt.sh
    mock_response.json.return_value = [
        {"name_value": "test.example.com"}, 
        {"name_value": "sub.example.com"}
    ]
    mock_response.status_code = 200
    mock_response.text = '[{"name_value": "test.example.com"}]' # Needed for null check
    mock_get.return_value = mock_response
    
    domain = "example.com"
    result = subdomain_tool._run(domain=domain)
    
    assert "error" not in result
    assert result["domain"] == domain
    assert isinstance(result["subdomains"], list)
    mock_get.assert_called_once()
    # Check if the URL construction looks right
    assert domain in mock_get.call_args[0][0]
    assert "output=json" in mock_get.call_args[0][0]

# Parameterize tests for various invalid inputs
@pytest.mark.parametrize(
    "invalid_input, description",
    [
        ("domain<script>.com", "XSS attempt"),
        ("dom;ain.com", "Command injection attempt (semicolon)"),
        ("dom ain.com", "Domain with space"),
        ("../../etc/passwd", "Path traversal attempt"),
        (".leadingdot.com", "Leading dot in label"),
        ("trailingdot.", "Trailing dot"),
        ("-leadinghyphen.com", "Leading hyphen in label"),
        ("trailinghyphen-.com", "Trailing hyphen in label"),
        ("", "Empty string"),
        ("a" * 600, "Domain exceeding length limit"),
        (".com", "Missing domain part"),
        (None, "None input"),
        (123, "Integer input"),
    ]
)
def test_run_invalid_inputs(subdomain_tool, invalid_input, description):
    """Test running the tool with various invalid inputs."""
    result = subdomain_tool._run(domain=invalid_input)
    
    print(f"Testing {description}: Input='{invalid_input}', Result='{result}'") # Debugging output
    assert "error" in result
    assert isinstance(result["error"], str)
    # Check if the error message indicates invalid input
    assert "Invalid domain format" in result["error"]
    # Check if the original invalid input is reflected in the error message (optional but good)
    assert str(invalid_input) in result["error"]

# Explicit test for None, although covered by parametrize
def test_run_none_input(subdomain_tool):
    """Test running the tool with None as input."""
    result = subdomain_tool._run(domain=None)
    assert "error" in result
    assert "Invalid domain format" in result["error"]

# Explicit test for empty string, although covered by parametrize
def test_run_empty_string_input(subdomain_tool):
    """Test running the tool with an empty string as input."""
    result = subdomain_tool._run(domain="")
    assert "error" in result
    assert "Invalid domain format" in result["error"] 