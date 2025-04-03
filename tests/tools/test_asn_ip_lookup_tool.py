"""Tests for the ASNIPLookupTool."""

import socket
from unittest.mock import MagicMock, patch

import pytest

from tools.asn_ip_lookup_tool.asn_ip_lookup_tool import ASNIPLookupTool

# Constants for testing
TEST_DOMAIN = "google.com"
TEST_IP = "8.8.8.8"
TEST_INVALID_TARGET = "invalid-"
EXPECTED_IP_FOR_DOMAIN = "142.250.180.142"  # Example, may change
EXPECTED_ASN_FOR_IP = 15169
EXPECTED_ASN_NAME = "GOOGLE"


@pytest.fixture
def asn_tool():
    """Create an instance of ASNIPLookupTool for testing."""
    return ASNIPLookupTool()


def test_tool_initialization(asn_tool):
    """Test the tool initializes correctly."""
    assert asn_tool.name == "ASN/IP Lookup Tool"
    assert asn_tool.description is not None
    assert asn_tool.args_schema is not None


@pytest.mark.asyncio
@patch("tools.asn_ip_lookup_tool.asn_ip_lookup_tool.IPWhois")
async def test_lookup_ip(mock_ipwhois, asn_tool):
    """Test looking up an IP address."""
    # Mock the IPWhois lookup
    mock_instance = MagicMock()
    mock_instance.lookup_rdap.return_value = {
        "asn": str(EXPECTED_ASN_FOR_IP),
        "asn_description": EXPECTED_ASN_NAME,
        "network": {"cidr": "8.8.8.0/24", "name": "LVLT-GOGL-8-8-8"},
        "objects": {"ORG-GOOG-1": {"contact": {"name": "Google LLC"}}},
    }
    mock_ipwhois.return_value = mock_instance

    result = await asn_tool._arun(target=TEST_IP)

    assert isinstance(result, dict)
    assert result["target"] == TEST_IP
    assert result["ip_address"] == TEST_IP
    assert result["asn"] == EXPECTED_ASN_FOR_IP
    assert EXPECTED_ASN_NAME in result["asn_name"]
    assert "Google LLC" in result["organization"]
    mock_ipwhois.assert_called_once_with(TEST_IP)
    mock_instance.lookup_rdap.assert_called_once()


@pytest.mark.asyncio
@patch("tools.asn_ip_lookup_tool.asn_ip_lookup_tool.socket.gethostbyname")
@patch("tools.asn_ip_lookup_tool.asn_ip_lookup_tool.IPWhois")
async def test_lookup_domain(mock_ipwhois, mock_gethostbyname, asn_tool):
    """Test looking up a domain name."""
    # Mock DNS resolution
    mock_gethostbyname.return_value = EXPECTED_IP_FOR_DOMAIN

    # Mock the IPWhois lookup
    mock_instance = MagicMock()
    mock_instance.lookup_rdap.return_value = {
        "asn": str(EXPECTED_ASN_FOR_IP),
        "asn_description": EXPECTED_ASN_NAME,
        "network": {"cidr": "142.250.0.0/15", "name": "GOOGLE"},
        "objects": {"ORG-GOOG-1": {"contact": {"name": "Google LLC"}}},
    }
    mock_ipwhois.return_value = mock_instance

    result = await asn_tool._arun(target=TEST_DOMAIN)

    assert isinstance(result, dict)
    assert result["target"] == TEST_DOMAIN
    assert result["ip_address"] == EXPECTED_IP_FOR_DOMAIN
    assert result["asn"] == EXPECTED_ASN_FOR_IP
    assert EXPECTED_ASN_NAME in result["asn_name"]
    assert "Google LLC" in result["organization"]
    mock_gethostbyname.assert_called_once_with(TEST_DOMAIN)
    mock_ipwhois.assert_called_once_with(EXPECTED_IP_FOR_DOMAIN)
    mock_instance.lookup_rdap.assert_called_once()


@pytest.mark.asyncio
async def test_invalid_target(asn_tool):
    """Test handling of an invalid target."""
    result = await asn_tool._arun(target=TEST_INVALID_TARGET)
    assert "error" in result
    assert "Invalid target" in result["error"]


@pytest.mark.asyncio
@patch("tools.asn_ip_lookup_tool.asn_ip_lookup_tool.socket.gethostbyname")
async def test_dns_failure(mock_gethostbyname, asn_tool):
    """Test handling of DNS resolution failure."""
    mock_gethostbyname.side_effect = socket.gaierror("DNS resolution failed")

    result = await asn_tool._arun(target="nonexistent-domain-dsfgdfg.com")

    assert "error" in result
    assert "Could not resolve domain" in result["error"]
    mock_gethostbyname.assert_called_once_with("nonexistent-domain-dsfgdfg.com")


@pytest.mark.asyncio
@patch("tools.asn_ip_lookup_tool.asn_ip_lookup_tool.IPWhois")
async def test_ipwhois_failure(mock_ipwhois, asn_tool):
    """Test handling of IPWhois lookup failure."""
    mock_instance = MagicMock()
    mock_instance.lookup_rdap.side_effect = Exception("RDAP lookup failed")
    mock_ipwhois.return_value = mock_instance

    result = await asn_tool._arun(target=TEST_IP)

    assert "error" in result
    assert "Failed to perform IP lookup" in result["error"]
    assert "RDAP lookup failed" in result["error"]
    mock_ipwhois.assert_called_once_with(TEST_IP)
    mock_instance.lookup_rdap.assert_called_once()


@pytest.mark.asyncio
@patch("tools.asn_ip_lookup_tool.asn_ip_lookup_tool.IPWhois")
async def test_ipwhois_partial_data(mock_ipwhois, asn_tool):
    """Test handling when IPWhois returns partial data."""
    mock_instance = MagicMock()
    # Return data missing ASN description and organization
    mock_instance.lookup_rdap.return_value = {
        "asn": str(EXPECTED_ASN_FOR_IP),
        "network": {"cidr": "8.8.8.0/24", "name": "LVLT-GOGL-8-8-8"},
        "objects": {},
    }
    mock_ipwhois.return_value = mock_instance

    result = await asn_tool._arun(target=TEST_IP)

    assert result["asn"] == EXPECTED_ASN_FOR_IP
    assert result["asn_name"] == "N/A"
    assert result["organization"] == "N/A"
