"""Tests for the NmapPortScanTool."""

import pytest
from tools.nmap_port_scan_tool import NmapPortScanTool
from unittest.mock import patch, MagicMock, PropertyMock
import subprocess # Import subprocess for mocking
import nmap # Import nmap for errors

@pytest.fixture
def nmap_tool_init_mock(mocker):
    """Fixture to mock successful Nmap initialization."""
    mocker.patch('subprocess.run', return_value=None) # Simulate nmap found
    mocker.patch('nmap.PortScanner', return_value=MagicMock()) # Mock the scanner object
    return NmapPortScanTool()

@pytest.fixture
def nmap_tool_init_fail_mock(mocker):
    """Fixture to mock failed Nmap initialization."""
    mocker.patch('subprocess.run', side_effect=FileNotFoundError)
    return NmapPortScanTool()

def test_tool_initialization_success(nmap_tool_init_mock):
    """Test tool initializes correctly when nmap is found."""
    assert nmap_tool_init_mock.name == "nmap_port_scanner"
    assert nmap_tool_init_mock.description is not None
    assert nmap_tool_init_mock.input_schema is not None
    assert nmap_tool_init_mock.nm is not None # Should have the mocked scanner

def test_tool_initialization_failure(nmap_tool_init_fail_mock):
    """Test tool initialization fails gracefully when nmap is not found."""
    assert nmap_tool_init_fail_mock.nm is None

def test_run_nmap_not_available(nmap_tool_init_fail_mock):
    """Test _run returns error if nmap is not available."""
    result = nmap_tool_init_fail_mock._run(targets="127.0.0.1")
    assert "error" in result
    assert "Nmap is not installed" in result["error"]

# Mock the actual scan method
@patch('subprocess.run', return_value=None) # Simulate nmap found during init
@patch('nmap.PortScanner')
def test_run_successful_scan(mock_port_scanner, mock_subprocess_run):
    """Test a successful nmap scan run."""
    # Configure the mock PortScanner instance and its methods
    mock_scanner_instance = MagicMock()
    mock_port_scanner.return_value = mock_scanner_instance
    
    # Simulate scan results
    mock_scanner_instance.all_hosts.return_value = ['127.0.0.1']
    mock_scanner_instance.__getitem__.return_value = {
        'state': 'up',
        'all_protocols': lambda: ['tcp'],
        'tcp': {
            80: {'state': 'open', 'name': 'http', 'product': 'nginx', 'version': '1.18.0'},
            22: {'state': 'closed'} # Example of a closed port
        }
    }

    tool = NmapPortScanTool()
    result = tool._run(targets="127.0.0.1", ports="22,80")

    assert "error" not in result
    assert len(result["hosts"]) == 1
    host_result = result["hosts"][0]
    assert host_result["host"] == "127.0.0.1"
    assert "tcp" in host_result["protocols"]
    assert len(host_result["protocols"]["tcp"]) == 1 # Only open ports are added
    assert host_result["protocols"]["tcp"][0]["port"] == 80
    assert host_result["protocols"]["tcp"][0]["name"] == "http"
    mock_scanner_instance.scan.assert_called_once_with(hosts="127.0.0.1", ports="22,80", arguments="-sV -T4")

@patch('subprocess.run', return_value=None) # Simulate nmap found during init
@patch('nmap.PortScanner')
def test_run_scan_error(mock_port_scanner, mock_subprocess_run):
    """Test handling of nmap scan errors."""
    mock_scanner_instance = MagicMock()
    mock_port_scanner.return_value = mock_scanner_instance
    mock_scanner_instance.scan.side_effect = nmap.PortScannerError("Nmap failed")

    tool = NmapPortScanTool()
    result = tool._run(targets="10.0.0.1")
    
    assert "error" in result
    assert "Nmap scanning error" in result["error"]
    mock_scanner_instance.scan.assert_called_once() 