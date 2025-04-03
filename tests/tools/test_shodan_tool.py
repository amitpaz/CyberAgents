"""Tests for the Shodan Search Tool."""

import os
import socket
from unittest.mock import MagicMock, patch

import pytest

# Ensure shodan library is available or mock it
try:
    import shodan
except ImportError:
    shodan = None  # Mock shodan if not installed

from tools.shodan_search.shodan_tool import ShodanHostSearchTool

# Constants for testing
TEST_TARGET_IP = "8.8.8.8"
TEST_TARGET_DOMAIN = "google.com"
TEST_API_KEY = "fake_shodan_api_key"
EXPECTED_IP_FOR_DOMAIN = "142.250.180.142"  # Example

# Mock Shodan API responses
# Example host response for 8.8.8.8
MOCK_HOST_RESPONSE = {
    "ip_str": "8.8.8.8",
    "org": "Google LLC",
    "asn": "AS15169",
    "isp": "Google LLC",
    "os": None,
    "ports": [53, 443],
    "hostnames": ["dns.google"],
    "vulns": [],  # Simplified
    "location": {"country_name": "United States", "city": "Mountain View"},
    "last_update": "2024-04-03T10:00:00Z",
    "tags": ["cloud"],
    "data": [
        {
            "port": 53,
            "transport": "udp",
            "_shodan": {"module": "dns-udp"},
            "product": None,
        },
        {
            "port": 443,
            "transport": "tcp",
            "ssl": {"versions": ["TLSv1.2", "TLSv1.3"]},
            "_shodan": {"module": "https"},
            "product": "Google Frontend",
        },
    ],
}

MOCK_SEARCH_RESPONSE = {"matches": [MOCK_HOST_RESPONSE], "total": 1}


def mock_host_result():
    """Return a realistic mock Shodan host result."""
    # ... (rest of function)


def mock_shodan_api_error():
    """Simulate a Shodan APIError."""
    raise shodan.APIError("Invalid API key")


# Fixture to provide ShodanTool instance with mocked API
@pytest.fixture
def shodan_tool():
    with patch.dict(os.environ, {"SHODAN_API_KEY": TEST_API_KEY}):
        with patch("shodan.Shodan") as MockShodanAPI:
            # Mock the Shodan API client instance
            mock_api_instance = MagicMock()
            MockShodanAPI.return_value = mock_api_instance
            # Create the tool instance, passing the mock
            tool = ShodanHostSearchTool()
            # Attach the mock API instance for assertions later
            tool._mock_api = mock_api_instance
            return tool


# Fixture to provide the mocked Shodan API instance
@pytest.fixture
def mock_shodan_api(shodan_tool):
    return shodan_tool._mock_api


# --- Initialization Tests ---
def test_tool_initialization_success(shodan_tool, mock_shodan_api):
    """Test successful initialization when API key is present."""
    assert shodan_tool.name == "Shodan Host Search"
    assert shodan_tool.description is not None
    assert shodan_tool.args_schema is not None
    assert shodan_tool.api is not None
    assert shodan_tool.is_available is True
    mock_shodan_api.assert_not_called()  # API methods not called during init


@patch.dict(os.environ, {}, clear=True)  # Ensure API key is NOT set
def test_tool_initialization_no_api_key():
    """Test initialization when SHODAN_API_KEY is missing."""
    with patch("shodan.Shodan") as MockShodanAPI:
        tool = ShodanHostSearchTool()
        assert tool.api is None
        assert tool.is_available is False
        assert "API key missing" in tool.description
        MockShodanAPI.assert_not_called()


# --- Availability Test ---
def test_tool_availability(shodan_tool):
    """Test the is_available property."""
    # Case 1: API key is present (mocked)
    assert shodan_tool.is_available is True

    # Case 2: API key is missing
    with patch.dict(os.environ, {}, clear=True):
        tool_unavailable = ShodanHostSearchTool()
        assert tool_unavailable.is_available is False


# --- Execution Tests (_arun) ---


@pytest.mark.asyncio
async def test_arun_shodan_unavailable():
    """Test running the tool when Shodan API is not available."""
    with patch.dict(os.environ, {}, clear=True):
        tool = ShodanHostSearchTool()
        result = await tool._arun(target=TEST_TARGET_IP)
        assert "error" in result
        assert "Shodan tool is not available" in result["error"]


@pytest.mark.asyncio
@patch("socket.gethostbyname", return_value=TEST_TARGET_IP)
async def test_arun_success_domain_target(
    mock_gethostbyname, shodan_tool, mock_shodan_api
):
    """Test successful run with a domain target."""
    # Mock the Shodan API's host method
    mock_shodan_api.host.return_value = MOCK_HOST_RESPONSE

    result = await shodan_tool._arun(target=TEST_TARGET_DOMAIN)

    # Assertions for successful result processing
    assert "error" not in result
    assert result["ip"] == TEST_TARGET_IP
    assert result["organization"] == "Google LLC"
    assert result["asn"] == "AS15169"
    assert "dns.google" in result["hostnames"]
    assert 53 in result["ports"]
    assert "Google Frontend" in result["services"][1]["product"]

    mock_gethostbyname.assert_called_once_with(TEST_TARGET_DOMAIN)
    mock_shodan_api.host.assert_called_once_with(TEST_TARGET_IP)


@pytest.mark.asyncio
async def test_arun_success_ip_target(shodan_tool, mock_shodan_api):
    """Test successful run with an IP target."""
    mock_shodan_api.host.return_value = MOCK_HOST_RESPONSE

    result = await shodan_tool._arun(target=TEST_TARGET_IP)

    assert "error" not in result
    assert result["ip"] == TEST_TARGET_IP
    mock_shodan_api.host.assert_called_once_with(TEST_TARGET_IP)


@pytest.mark.asyncio
@patch("socket.gethostbyname", side_effect=socket.gaierror("DNS error"))
async def test_arun_dns_failure(mock_gethostbyname, shodan_tool, mock_shodan_api):
    """Test handling of DNS resolution failure for domain targets."""
    result = await shodan_tool._arun(target="invalid-domain-for-dns.tld")
    assert "error" in result
    assert "Could not resolve domain" in result["error"]
    mock_gethostbyname.assert_called_once()
    mock_shodan_api.host.assert_not_called()


@pytest.mark.asyncio
async def test_arun_shodan_api_error(shodan_tool, mock_shodan_api):
    """Test handling of errors from the Shodan API."""
    error_message = "Invalid API key"
    mock_shodan_api.host.side_effect = mock_shodan_api_error

    result = await shodan_tool._arun(target=TEST_TARGET_IP)

    assert "error" in result
    assert "Shodan API error" in result["error"]
    assert error_message in result["error"]
    mock_shodan_api.host.assert_called_once_with(TEST_TARGET_IP)


@pytest.mark.asyncio
async def test_arun_unexpected_error(shodan_tool, mock_shodan_api):
    """Test handling of unexpected errors during processing."""
    error_message = "Something went wrong during processing"
    # Simulate error after successful API call
    mock_shodan_api.host.return_value = MOCK_HOST_RESPONSE
    # Patch a helper method used in processing to raise an error
    with patch(
        "tools.shodan_search.shodan_tool.ShodanHostSearchTool._parse_host_data",
        side_effect=Exception(error_message),
    ):
        result = await shodan_tool._arun(target=TEST_TARGET_IP)

    assert "error" in result
    assert "Unexpected error processing Shodan data" in result["error"]
    assert error_message in result["error"]
    mock_shodan_api.host.assert_called_once_with(TEST_TARGET_IP)
