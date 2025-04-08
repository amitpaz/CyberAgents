"""Tests for the NmapPortScanTool."""

from unittest.mock import MagicMock, PropertyMock, patch

import nmap  # Import nmap for errors
import pytest

from tools import NmapPortScanTool
from tools.nmap_port_scan_tool.nmap_port_scan_tool import sanitize_nmap_arguments

# Constants for testing
TEST_TARGET = "127.0.0.1"
TEST_PORTS = "22,80,443"
TEST_SCAN_TYPE = "T4"
TEST_ARGUMENTS = "-sV --script=default"


@pytest.fixture
def nmap_tool_init_mock(mocker):
    """Fixture to mock successful Nmap initialization."""
    mocker.patch("subprocess.run", return_value=None)  # Simulate nmap found
    mocker.patch(
        "nmap.PortScanner", return_value=MagicMock()
    )  # Mock the scanner object
    return NmapPortScanTool()


@pytest.fixture
def nmap_tool_init_fail_mock(mocker):
    """Fixture to mock failed Nmap initialization."""
    mocker.patch("subprocess.run", side_effect=FileNotFoundError)
    return NmapPortScanTool()


def test_tool_initialization_success(nmap_tool_init_mock):
    """Test tool initializes correctly when nmap is found."""
    assert nmap_tool_init_mock.name == "nmap_port_scanner"
    assert nmap_tool_init_mock.description is not None
    assert nmap_tool_init_mock.input_schema is not None
    assert nmap_tool_init_mock.nm is not None  # Should have the mocked scanner


def test_tool_initialization_failure(nmap_tool_init_fail_mock):
    """Test tool initialization fails gracefully when nmap is not found."""
    assert nmap_tool_init_fail_mock.nm is None


def test_run_nmap_not_available(nmap_tool_init_fail_mock):
    """Test _run returns error if nmap is not available."""
    result = nmap_tool_init_fail_mock._run(targets="127.0.0.1")
    assert "error" in result
    assert "Nmap is not installed" in result["error"]


# Mock the actual scan method
@patch("subprocess.run", return_value=None)  # Simulate nmap found during init
@patch("nmap.PortScanner")
def test_run_successful_scan(mock_port_scanner, mock_subprocess_run):
    """Test a successful nmap scan run."""
    # Configure the mock PortScanner instance and its methods
    mock_scanner_instance = MagicMock()
    mock_port_scanner.return_value = mock_scanner_instance

    # --- Corrected Mock Setup ---
    # Simulate the structure returned by python-nmap
    # self.nm[host] should return an object with state() and all_protocols()
    mock_host_data = MagicMock()
    mock_host_data.state.return_value = "up"  # Method call
    mock_host_data.all_protocols.return_value = ["tcp"]  # Method call

    # self.nm[host][proto] should return the port dictionary
    mock_host_data.__getitem__.return_value = {
        80: {"state": "open", "name": "http", "product": "nginx", "version": "1.18.0"},
        22: {"state": "closed"},
    }

    # Configure the main mock scanner's __getitem__ to return the host data mock
    mock_scanner_instance.__getitem__.return_value = mock_host_data
    # --- End Corrected Mock Setup ---

    # Simulate all_hosts()
    mock_scanner_instance.all_hosts.return_value = ["127.0.0.1"]

    tool = NmapPortScanTool()
    # Ensure tool initialization succeeded (relevant if using fixtures later)
    assert tool.nm is not None

    result = tool._run(targets="127.0.0.1", ports="22,80")

    assert "error" not in result
    assert "hosts" in result
    assert len(result["hosts"]) == 1
    host_result = result["hosts"][0]
    assert host_result["host"] == "127.0.0.1"
    assert host_result["status"] == "up"
    assert "tcp" in host_result["protocols"]
    assert len(host_result["protocols"]["tcp"]) == 1  # Only open ports are added
    assert host_result["protocols"]["tcp"][0]["port"] == 80
    assert host_result["protocols"]["tcp"][0]["name"] == "http"

    # Check that nm.scan was called using the imported helper
    mock_scanner_instance.scan.assert_called_once_with(
        hosts="127.0.0.1",
        ports="22,80",
        arguments=sanitize_nmap_arguments(None),  # Use imported helper directly
    )


@patch("subprocess.run", return_value=None)  # Simulate nmap found during init
@patch("nmap.PortScanner")
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
    ],
)
@patch("subprocess.run", return_value=None)  # Mock init
@patch("nmap.PortScanner")  # Mock scanner class
def test_run_invalid_target_inputs(mock_scanner, mock_run, invalid_target, desc):
    """Test invalid target formats."""
    tool = NmapPortScanTool()
    assert tool.nm is not None  # Ensure init mock worked
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
        (
            "65536",
            "Port out of range (basic validation)",
        ),  # Basic regex allows it, Nmap would fail
        ("80;443", "Semicolon in ports"),
        (123, "Integer ports"),
    ],
)
@patch("subprocess.run", return_value=None)
@patch("nmap.PortScanner")
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
        (123, "Integer arguments"),  # Should revert to default
    ],
)
@patch("subprocess.run", return_value=None)
@patch("nmap.PortScanner")
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
    assert call_args[1]["arguments"] == "-sV -T4"  # Check sanitized default


@patch("subprocess.run", return_value=None)
@patch("nmap.PortScanner")
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
    assert call_args[1]["arguments"] == safe_args  # Check safe args passed


# Fixture to create an instance of the tool
@pytest.fixture
def nmap_tool():
    # Mock nmap.PortScanner during initialization to avoid real Nmap calls
    with patch("nmap.PortScanner", return_value=MagicMock()) as mock_scanner:
        tool = NmapPortScanTool()
        # Attach the mock scanner to the tool instance for assertion
        tool._mock_scanner = mock_scanner
        return tool


# Mock PortScanner object to be used in tests
@pytest.fixture
def mock_scanner_instance(nmap_tool):
    # Return the mocked scanner instance created in the nmap_tool fixture
    return nmap_tool.nm  # Access the underlying mock scanner


# --- Initialization Tests ---
@patch("nmap.PortScanner", side_effect=nmap.nmap.PortScannerError("Nmap not found"))
def test_tool_initialization_nmap_not_found(mock_scanner):
    """Test initialization when Nmap executable is not found."""
    tool = NmapPortScanTool()
    assert tool.nm is None  # Check internal attribute directly


# Test tool availability directly by checking internal state
def test_tool_availability(nmap_tool):
    """Test the tool's availability based on internal state (nm object)."""
    # Case 1: Tool initialized successfully (nmap_tool fixture)
    assert nmap_tool.nm is not None  # Assume fixture provides initialized tool

    # Case 2: Tool failed initialization (mock nmap not found)
    with patch(
        "nmap.PortScanner", side_effect=nmap.nmap.PortScannerError("Nmap not found")
    ):
        failed_tool = NmapPortScanTool()
        assert failed_tool.nm is None


# --- Execution Tests (_arun) ---


@pytest.mark.asyncio
async def test_arun_nmap_unavailable(nmap_tool):
    """Test running the tool when Nmap is not available."""
    nmap_tool.nm = None  # Simulate Nmap not being available
    result = await nmap_tool._arun(target=TEST_TARGET)
    assert "error" in result
    assert "Nmap Port Scanner tool is not available" in result["error"]


@pytest.mark.asyncio
async def test_arun_successful_scan(nmap_tool, mock_scanner_instance):
    """Test a successful scan execution."""
    # Configure the mock scanner's behavior
    mock_scan_results = {
        "scan": {
            TEST_TARGET: {
                "status": {"state": "up"},
                "tcp": {
                    80: {
                        "state": "open",
                        "name": "http",
                        "product": "nginx",
                        "version": "1.18.0",
                    },
                    443: {"state": "closed", "name": "https"},
                },
            }
        },
        "nmap": {"scanstats": {"elapsed": "5.00"}},
    }
    # Mock the scan method and the dictionary-like access
    mock_scanner_instance.scan.return_value = mock_scan_results["scan"]
    mock_scanner_instance.__getitem__.side_effect = lambda key: mock_scan_results[
        "scan"
    ][key]
    # Mock scan_info() which might be implicitly used by scan() in some versions or for details
    type(mock_scanner_instance).scaninfo = PropertyMock(
        return_value={"tcp": {"method": "syn"}}
    )
    # Mock all_hosts() behavior
    mock_scanner_instance.all_hosts.return_value = [TEST_TARGET]

    result = await nmap_tool._arun(
        target=TEST_TARGET,
        ports=TEST_PORTS,
        scan_type=TEST_SCAN_TYPE,
        arguments=TEST_ARGUMENTS,
    )

    assert "error" not in result
    assert result["target"] == TEST_TARGET
    assert result["status"] == "up"
    assert len(result["ports"]) == 2  # 80 (open), 443 (closed)
    assert result["ports"][0]["port"] == 80
    assert result["ports"][0]["state"] == "open"
    assert result["ports"][0]["service"] == "http"
    assert result["ports"][0]["product"] == "nginx"
    assert result["ports"][0]["version"] == "1.18.0"
    assert result["ports"][1]["port"] == 443
    assert result["ports"][1]["state"] == "closed"

    # Verify nmap.PortScanner().scan was called correctly
    expected_args = f"-sV --script=default -{TEST_SCAN_TYPE}"
    mock_scanner_instance.scan.assert_called_once_with(
        hosts=TEST_TARGET, ports=TEST_PORTS, arguments=expected_args
    )


@pytest.mark.asyncio
async def test_arun_target_down(nmap_tool, mock_scanner_instance):
    """Test when the target host is down."""
    mock_scan_results = {
        "scan": {TEST_TARGET: {"status": {"state": "down"}}},
        "nmap": {"scanstats": {"elapsed": "2.00"}},
    }
    mock_scanner_instance.scan.return_value = mock_scan_results["scan"]
    mock_scanner_instance.__getitem__.side_effect = lambda key: mock_scan_results[
        "scan"
    ][key]
    type(mock_scanner_instance).scaninfo = PropertyMock(return_value={})
    mock_scanner_instance.all_hosts.return_value = [TEST_TARGET]

    result = await nmap_tool._arun(target=TEST_TARGET)

    assert "error" not in result
    assert result["target"] == TEST_TARGET
    assert result["status"] == "down"
    assert len(result["ports"]) == 0
    mock_scanner_instance.scan.assert_called_once()


@pytest.mark.asyncio
async def test_arun_nmap_error(nmap_tool, mock_scanner_instance):
    """Test handling of errors during the Nmap scan process."""
    error_message = "Failed to resolve target hostname"
    mock_scanner_instance.scan.side_effect = nmap.PortScannerError(error_message)

    result = await nmap_tool._arun(target="invalid.hostname")

    assert "error" in result
    assert "Nmap scan failed" in result["error"]
    assert error_message in result["error"]
    mock_scanner_instance.scan.assert_called_once()


@pytest.mark.asyncio
async def test_arun_unexpected_error(nmap_tool, mock_scanner_instance):
    """Test handling of unexpected errors during processing."""
    error_message = "Something unexpected happened"
    # Simulate an error *after* scan completes, during result processing
    mock_scanner_instance.scan.return_value = {}  # Simulate empty scan results first
    mock_scanner_instance.all_hosts.side_effect = Exception(error_message)

    result = await nmap_tool._arun(target=TEST_TARGET)

    assert "error" in result
    assert "Unexpected error processing Nmap results" in result["error"]
    assert error_message in result["error"]
    # Scan might have been called, but processing failed
    mock_scanner_instance.scan.assert_called_once()
