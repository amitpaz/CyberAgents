"""Tests for the ASNIPLookupTool."""

import pytest
from tools.asn_ip_lookup_tool import ASNIPLookupTool
from unittest.mock import patch, MagicMock

# Example IP for testing
TEST_IP = "8.8.8.8"

@pytest.fixture
def asn_tool():
    return ASNIPLookupTool()

def test_tool_initialization(asn_tool):
    """Test tool initializes correctly."""
    assert asn_tool.name == "asn_ip_lookup"
    assert asn_tool.description is not None
    assert asn_tool.input_schema is not None

# Mock the IPWhois object and its lookup_whois method
@patch('tools.asn_ip_lookup_tool.IPWhois')
def test_run_successful_lookup(mock_ipwhois, asn_tool):
    """Test a successful run of the tool with mocked IPWhois."""
    mock_instance = MagicMock()
    mock_instance.lookup_whois.return_value = {
        'asn': '15169',
        'asn_cidr': '8.8.8.0/24',
        'asn_description': 'GOOGLE - Google LLC, US',
        'asn_registry': 'arin',
        'nets': [{'name': 'GOOGLE'}]
    }
    mock_ipwhois.return_value = mock_instance

    result = asn_tool._run(ip_address=TEST_IP)

    assert "error" not in result
    assert result["ip_address"] == TEST_IP
    assert result["asn"] == "15169"
    assert result["organization_name"] == "GOOGLE"
    mock_ipwhois.assert_called_once_with(TEST_IP)
    mock_instance.lookup_whois.assert_called_once_with(inc_raw=False)

@patch('tools.asn_ip_lookup_tool.IPWhois')
def test_run_lookup_failure(mock_ipwhois, asn_tool):
    """Test a failed run of the tool with mocked IPWhois."""
    mock_instance = MagicMock()
    mock_instance.lookup_whois.side_effect = Exception("WHOIS lookup failed")
    mock_ipwhois.return_value = mock_instance

    result = asn_tool._run(ip_address="invalid-ip")

    assert "error" in result
    # Check for the validation error message, not the underlying exception
    assert "Invalid IP address format provided" in result["error"]
    assert "invalid-ip" in result["error"]
    mock_instance.lookup_whois.assert_not_called()

# Add more specific invalid IP tests
@pytest.mark.parametrize(
    "invalid_ip, description",
    [
        ("", "Empty string"),
        ("not-an-ip", "Non-IP string"),
        ("256.256.256.256", "Invalid IPv4"),
        ("::ffff::1", "Malformed IPv6"),
        ("192.168.1.1; ls", "Command injection attempt"),
        (None, "None input"),
        (127001, "Integer input"),
    ]
)
@patch('tools.asn_ip_lookup_tool.IPWhois') # Still need mock even if not called
def test_run_invalid_ip_inputs(mock_ipwhois, asn_tool, invalid_ip, description):
    """Test various invalid IP address formats."""
    mock_instance = MagicMock()
    mock_ipwhois.return_value = mock_instance
    
    result = asn_tool._run(ip_address=invalid_ip)
    
    print(f"Testing {description}: Input='{invalid_ip}', Result='{result}'") # Debugging output
    assert "error" in result
    assert isinstance(result["error"], str)
    assert "Invalid IP address format" in result["error"]
    assert str(invalid_ip) in result["error"]
    # Ensure the underlying library was not called
    mock_instance.lookup_whois.assert_not_called()