"""Tests for the Semgrep Scanner tool."""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from agents.appsec_engineer_agent.appsec_engineer_agent import SemgrepRunner
from tools.semgrep_scanner.semgrep_scanner import SemgrepTool

# --- Constants and Fixtures ---
TEST_CODE_SNIPPET = """
def hello():
    print("Hello, world!")
"""

TEST_REPO_URL = "https://github.com/example/test-repo"
TEST_TARGET_PATH = "/tmp/test-scan"
TEST_LANGUAGE = "python"
TEST_RULES = ["p/python", "p/security"]  # Example rules

# Sample successful Semgrep JSON output
SUCCESS_OUTPUT = {
    "results": [
        {
            "check_id": "test-rule",
            "path": "test.py",
            "start": {"line": 2},
            "end": {"line": 2},
            "extra": {
                "message": "Test finding",
                "severity": "WARNING",
                "lines": '    print("Hello, world!")',
                "metadata": {"cwe": "CWE-123"},
            },
        }
    ],
    "errors": [],
    "paths": {
        "_comment": "<add path info here>",
        "scanned": ["test.py"],
    },
    "version": "1.x.x",
}

# Sample error output from Semgrep
ERROR_STDERR = "Error: Invalid rule file specified."


@pytest.fixture
def semgrep_runner():
    return SemgrepRunner(rules=TEST_RULES, max_scan_time=60)


@pytest.fixture
def semgrep_tool():
    return SemgrepTool()


# --- SemgrepRunner Tests ---


def test_runner_initialization(semgrep_runner):
    """Test SemgrepRunner initialization."""
    assert semgrep_runner.rules == TEST_RULES
    assert semgrep_runner.max_scan_time == 60


def test_prepare_rules_arg(semgrep_runner):
    """Test preparation of the --config argument."""
    rules_arg = semgrep_runner._prepare_rules_arg()
    expected_arg = ",".join(TEST_RULES)
    assert rules_arg == expected_arg


@patch("subprocess.run")
def test_runner_scan_code_success(mock_run, semgrep_runner):
    """Test successful code scanning with SemgrepRunner."""
    mock_process = MagicMock()
    mock_process.returncode = 1  # Semgrep returns 1 for findings
    mock_process.stdout = json.dumps(SUCCESS_OUTPUT)
    mock_process.stderr = ""
    mock_run.return_value = mock_process

    result = semgrep_runner.scan_code(TEST_TARGET_PATH, language=TEST_LANGUAGE)

    assert "error" not in result
    assert "results" in result
    assert len(result["results"]) == 1
    assert result["results"][0]["check_id"] == "test-rule"

    # Verify subprocess call
    mock_run.assert_called_once()
    args, kwargs = mock_run.call_args
    assert "semgrep" in args[0]
    assert f"--config={semgrep_runner._prepare_rules_arg()}" in args[0]
    assert f"--lang={TEST_LANGUAGE}" in args[0]
    assert TEST_TARGET_PATH in args[0]
    assert kwargs["timeout"] == 60


@patch("subprocess.run")
def test_runner_scan_code_semgrep_error(mock_run, semgrep_runner):
    """Test SemgrepRunner handling Semgrep execution errors."""
    mock_process = MagicMock()
    mock_process.returncode = 2  # Error code other than 0 or 1
    mock_process.stdout = ""
    mock_process.stderr = ERROR_STDERR
    mock_run.return_value = mock_process

    result = semgrep_runner.scan_code(TEST_TARGET_PATH)

    assert "error" in result
    assert ERROR_STDERR in result["error"]
    assert "findings" not in result  # Or ensure findings is empty


@patch("subprocess.run")
def test_runner_scan_code_timeout(mock_run, semgrep_runner):
    """Test SemgrepRunner handling scan timeouts."""
    mock_run.side_effect = subprocess.TimeoutExpired("semgrep", 60)

    result = semgrep_runner.scan_code(TEST_TARGET_PATH)

    assert "error" in result
    assert "timed out" in result["error"]


@patch("subprocess.run")
def test_runner_scan_code_json_error(mock_run, semgrep_runner):
    """Test SemgrepRunner handling invalid JSON output."""
    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = "{invalid json"  # Malformed JSON
    mock_process.stderr = ""
    mock_run.return_value = mock_process

    result = semgrep_runner.scan_code(TEST_TARGET_PATH)

    assert "error" in result
    assert "Failed to parse Semgrep output" in result["error"]


# --- SemgrepTool Tests ---


def test_tool_info(semgrep_tool):
    """Test basic tool information."""
    assert semgrep_tool.name == "Semgrep Security Scanner"
    assert semgrep_tool.description is not None
    assert semgrep_tool.args_schema is not None


@pytest.mark.asyncio
@patch("tools.semgrep_scanner.semgrep_scanner.SemgrepRunner.scan_code")
@patch("tools.semgrep_scanner.semgrep_scanner.tempfile.NamedTemporaryFile")
async def test_tool_scan_snippet_success(mock_tempfile, mock_scan, semgrep_tool):
    """Test successful scanning of a code snippet."""
    # Mock the temporary file creation
    mock_file = MagicMock()
    mock_file.name = "/tmp/fake_semgrep_file.py"
    mock_tempfile.return_value.__enter__.return_value = mock_file

    # Mock the runner's scan result
    mock_scan.return_value = SUCCESS_OUTPUT

    result_str = await semgrep_tool._arun(code_snippet=TEST_CODE_SNIPPET)
    result = json.loads(result_str)

    assert "error" not in result
    assert "results" in result
    assert len(result["results"]) == 1

    mock_tempfile.assert_called_once_with(mode="w", suffix=".py", delete=False)
    mock_file.write.assert_called_once_with(TEST_CODE_SNIPPET)
    mock_scan.assert_called_once_with(mock_file.name, language="python")


@pytest.mark.asyncio
@patch("tools.semgrep_scanner.semgrep_scanner.SemgrepRunner.scan_code")
@patch("tools.semgrep_scanner.semgrep_scanner.shutil.rmtree")
@patch("tools.semgrep_scanner.semgrep_scanner.git.Repo.clone_from")
@patch("tools.semgrep_scanner.semgrep_scanner.tempfile.mkdtemp")
async def test_tool_scan_repo_success(
    mock_mkdtemp, mock_clone, mock_rmtree, mock_scan, semgrep_tool
):
    """Test successful scanning of a Git repository."""
    mock_mkdtemp.return_value = TEST_TARGET_PATH
    mock_scan.return_value = SUCCESS_OUTPUT

    result_str = await semgrep_tool._arun(repo_url=TEST_REPO_URL)
    result = json.loads(result_str)

    assert "error" not in result
    assert "results" in result

    mock_mkdtemp.assert_called_once()
    mock_clone.assert_called_once_with(TEST_REPO_URL, TEST_TARGET_PATH)
    mock_scan.assert_called_once_with(TEST_TARGET_PATH, language=None)
    mock_rmtree.assert_called_once_with(TEST_TARGET_PATH)


@pytest.mark.asyncio
async def test_tool_invalid_input(semgrep_tool):
    """Test tool handling when neither snippet nor repo URL is provided."""
    result_str = await semgrep_tool._arun()
    result = json.loads(result_str)
    assert "error" in result
    assert "Either code_snippet or repo_url must be provided" in result["error"]


@pytest.mark.asyncio
@patch(
    "tools.semgrep_scanner.semgrep_scanner.git.Repo.clone_from",
    side_effect=Exception("Git clone failed"),
)
@patch(
    "tools.semgrep_scanner.semgrep_scanner.tempfile.mkdtemp",
    return_value=TEST_TARGET_PATH,
)
@patch("tools.semgrep_scanner.semgrep_scanner.shutil.rmtree")  # Ensure cleanup mock
async def test_tool_repo_clone_failure(
    mock_rmtree, mock_mkdtemp, mock_clone, semgrep_tool
):
    """Test tool handling when repository cloning fails."""
    result_str = await semgrep_tool._arun(repo_url=TEST_REPO_URL)
    result = json.loads(result_str)
    assert "error" in result
    assert "Failed to clone repository" in result["error"]
    assert "Git clone failed" in result["error"]
    mock_rmtree.assert_called_once_with(
        TEST_TARGET_PATH
    )  # Ensure cleanup still attempted


@pytest.mark.asyncio
@patch(
    "tools.semgrep_scanner.semgrep_scanner.SemgrepRunner.scan_code",
    return_value={"error": ERROR_STDERR},
)
@patch("tools.semgrep_scanner.semgrep_scanner.tempfile.NamedTemporaryFile")
async def test_tool_scan_failure(mock_tempfile, mock_scan, semgrep_tool):
    """Test tool handling when the underlying scan fails."""
    mock_file = MagicMock()
    mock_file.name = "/tmp/fake_semgrep_file.py"
    mock_tempfile.return_value.__enter__.return_value = mock_file

    result_str = await semgrep_tool._arun(code_snippet=TEST_CODE_SNIPPET)
    result = json.loads(result_str)

    assert "error" in result
    assert ERROR_STDERR in result["error"]


# --- SemgrepMetadata Tests (Example) ---


@pytest.mark.skip(reason="SemgrepMetadata class does not exist")
def test_metadata_parsing():
    """Test parsing metadata from a finding."""
    # finding_extra = SUCCESS_OUTPUT["results"][0]["extra"]
    # metadata = SemgrepMetadata.from_finding(finding_extra)
    # assert metadata.cwe == "CWE-123"
    # assert metadata.owasp is None  # Not present in sample data
    pass  # Skip test body


def mock_subprocess_run(*args, **kwargs):
    """Mock subprocess.run to simulate different Semgrep outcomes."""
    # ... (rest of function)


def create_mock_process(stdout="", stderr="", returncode=0):
    """Create a MagicMock representing a completed process."""
    mock_proc = MagicMock()
    mock_proc.stdout = stdout
    mock_proc.stderr = stderr
    mock_proc.returncode = returncode
    return mock_proc
