"""Tests for the NmapPortScanTool."""

import pytest
from tools.nmap_port_scan_tool import NmapPortScanTool, sanitize_nmap_arguments
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
    
    # --- Corrected Mock Setup --- 
    # Simulate the structure returned by python-nmap
    # self.nm[host] should return an object with state() and all_protocols()
    mock_host_data = MagicMock()
    mock_host_data.state.return_value = 'up' # Method call
    mock_host_data.all_protocols.return_value = ['tcp'] # Method call
    
    # self.nm[host][proto] should return the port dictionary
    mock_host_data.__getitem__.return_value = {
         80: {'state': 'open', 'name': 'http', 'product': 'nginx', 'version': '1.18.0'},
         22: {'state': 'closed'} 
    }
    
    # Configure the main mock scanner's __getitem__ to return the host data mock
    mock_scanner_instance.__getitem__.return_value = mock_host_data
    # --- End Corrected Mock Setup --- 
    
    # Simulate all_hosts()
    mock_scanner_instance.all_hosts.return_value = ['127.0.0.1']

    tool = NmapPortScanTool()
    # Ensure tool initialization succeeded (relevant if using fixtures later)
    assert tool.nm is not None 
    
    result = tool._run(targets="127.0.0.1", ports="22,80")

    assert "error" not in result
    assert "hosts" in result
    assert len(result["hosts"]) == 1
    host_result = result["hosts"][0]
    assert host_result["host"] == '127.0.0.1'
    assert host_result["status"] == 'up'
    assert "tcp" in host_result["protocols"]
    assert len(host_result["protocols"]["tcp"]) == 1 # Only open ports are added
    assert host_result["protocols"]["tcp"][0]["port"] == 80
    assert host_result["protocols"]["tcp"][0]["name"] == 'http'
    
    # Check that nm.scan was called using the imported helper
    mock_scanner_instance.scan.assert_called_once_with(
        hosts="127.0.0.1", 
        ports="22,80", 
        arguments=sanitize_nmap_arguments(None) # Use imported helper directly
    )

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

# --- Tests for Input Validation --- 

@pytest.mark.parametrize(
    "invalid_target, desc",
    [
        ("", "Empty target"),
        ("target; rm -rf", "Command injection"),
        ("target<script>", "XSS attempt"),
        ("../", "Path traversal"),
        (None, "None target"),
        (12345, "Integer target"),
    ]
)
@patch('subprocess.run', return_value=None) # Mock init
@patch('nmap.PortScanner') # Mock scanner class
def test_run_invalid_target_inputs(mock_scanner, mock_run, invalid_target, desc):
    """Test invalid target formats."""
    tool = NmapPortScanTool()
    assert tool.nm is not None # Ensure init mock worked
    result = tool._run(targets=invalid_target)
    
    assert "error" in result
    assert "Invalid target format" in result["error"]
    mock_scanner.return_value.scan.assert_not_called()

@pytest.mark.parametrize(
    "invalid_ports, desc",
    [
        ("abc", "Non-numeric ports"),
        ("80,443,abc", "Mixed valid/invalid ports"),
        ("1-", "Incomplete range"),
        ("-100", "Incomplete range 2"),
        ("1-abc", "Invalid range"),
        ("65536", "Port out of range (basic validation)"), # Basic regex allows it, Nmap would fail
        ("80;443", "Semicolon in ports"),
        (123, "Integer ports"),
    ]
)
@patch('subprocess.run', return_value=None)
@patch('nmap.PortScanner')
def test_run_invalid_port_inputs(mock_scanner, mock_run, invalid_ports, desc):
    """Test invalid port formats."""
    tool = NmapPortScanTool()
    assert tool.nm is not None
    result = tool._run(targets="127.0.0.1", ports=invalid_ports)
    
    assert "error" in result
    assert "Invalid ports format" in result["error"]
    mock_scanner.return_value.scan.assert_not_called()

@pytest.mark.parametrize(
    "dangerous_args, desc",
    [
        ("-oN output.txt", "Output flag -oN"),
        ("--script=vuln", "Script flag"),
        ("-T4 ; ls", "Command injection"),
        ("`reboot`", "Backtick command injection"),
        ("$(reboot)", "Dollar paren command injection"),
        ("--interactive", "Interactive flag"),
        (123, "Integer arguments"), # Should revert to default
    ]
)
@patch('subprocess.run', return_value=None)
@patch('nmap.PortScanner')
def test_run_argument_sanitization(mock_scanner, mock_run, dangerous_args, desc):
    """Test that dangerous arguments are sanitized and default is used."""
    mock_scan_instance = MagicMock()
    mock_scanner.return_value = mock_scan_instance
    tool = NmapPortScanTool()
    assert tool.nm is not None

    # Run with dangerous args
    tool._run(targets="127.0.0.1", arguments=dangerous_args)

    # Check that scan was called, but with the default sanitized arguments
    mock_scan_instance.scan.assert_called_once()
    call_args = mock_scan_instance.scan.call_args
    assert call_args[1]['arguments'] == "-sV -T4" # Check sanitized default

@patch('subprocess.run', return_value=None)
@patch('nmap.PortScanner')
def test_run_safe_arguments_passed(mock_scanner, mock_run):
    """Test that safe custom arguments are passed through."""
    mock_scan_instance = MagicMock()
    mock_scanner.return_value = mock_scan_instance
    tool = NmapPortScanTool()
    assert tool.nm is not None
    
    safe_args = "-sS -Pn -T5 --top-ports 100"
    tool._run(targets="127.0.0.1", arguments=safe_args)
    
    mock_scan_instance.scan.assert_called_once()
    call_args = mock_scan_instance.scan.call_args
    assert call_args[1]['arguments'] == safe_args # Check safe args passed 