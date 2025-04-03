"""Tests for the Semgrep Scanner Tool."""

import os
import json
import pytest
import asyncio
from unittest.mock import patch, MagicMock, mock_open

from tools.semgrep_scanner import SemgrepTool, SemgrepInput


@pytest.fixture
def semgrep_tool():
    """Create a SemgrepTool instance for testing."""
    return SemgrepTool()


class TestSemgrepInput:
    """Test the SemgrepInput validation logic."""
    
    def test_valid_code_input(self):
        """Test that input with code is valid."""
        input_model = SemgrepInput(
            code="def test(): pass",
            language="python"
        )
        assert input_model.code == "def test(): pass"
        assert input_model.language == "python"
    
    def test_valid_file_path_input(self):
        """Test that input with file_path is valid."""
        input_model = SemgrepInput(
            file_path="/path/to/file.py",
            language="python"
        )
        assert input_model.file_path == "/path/to/file.py"
        assert input_model.language == "python"
    
    def test_valid_both_inputs(self):
        """Test that input with both code and file_path is valid."""
        input_model = SemgrepInput(
            code="def test(): pass",
            file_path="/path/to/file.py"
        )
        assert input_model.code == "def test(): pass"
        assert input_model.file_path == "/path/to/file.py"
    
    def test_invalid_no_inputs(self):
        """Test that input with neither code nor file_path is invalid."""
        with pytest.raises(ValueError) as exc_info:
            SemgrepInput()
        assert "Either code or file_path must be provided" in str(exc_info.value)


class TestSemgrepTool:
    """Test the SemgrepTool functionality."""
    
    def test_initialization(self, semgrep_tool):
        """Test that the tool initializes correctly."""
        assert semgrep_tool.name == "semgrep_scanner"
        assert semgrep_tool.description is not None
        assert semgrep_tool.input_schema == SemgrepInput
    
    def test_detect_language_from_filename(self, semgrep_tool):
        """Test language detection from filename."""
        # Python file
        result = semgrep_tool._detect_language("print('hello')", "test.py")
        assert result == "python"
        
        # JavaScript file
        result = semgrep_tool._detect_language("console.log('hello')", "test.js")
        assert result == "javascript"
        
        # Unknown extension
        result = semgrep_tool._detect_language("print('hello')", "test.xyz")
        assert result == "python"  # Should detect from content
    
    def test_detect_language_from_content(self, semgrep_tool):
        """Test language detection from code content."""
        # Python code
        python_code = """
        import os
        from pathlib import Path
        
        def hello():
            print("Hello, world!")
        """
        assert semgrep_tool._detect_language(python_code) == "python"
        
        # JavaScript code
        js_code = """
        import React from 'react';
        
        const hello = () => {
            console.log("Hello, world!");
        };
        """
        assert semgrep_tool._detect_language(js_code) == "javascript"
        
        # Empty code
        assert semgrep_tool._detect_language("") == "unknown"
    
    @patch("subprocess.run")
    async def test_run_with_code(self, mock_run, semgrep_tool):
        """Test running the tool with code input."""
        # Mock subprocess.run
        process_mock = MagicMock()
        process_mock.returncode = 0
        process_mock.stdout = json.dumps({
            "results": [
                {
                    "check_id": "sql-injection",
                    "path": "code.py",
                    "start": {"line": 2},
                    "extra": {
                        "message": "SQL Injection vulnerability",
                        "severity": "high",
                        "lines": "query = \"SELECT * FROM users WHERE id = \" + user_input",
                        "metadata": {"cwe": ["CWE-89"], "owasp": ["A1:2017"]}
                    }
                }
            ],
            "stats": {"files_scanned": 1, "total_time": 0.5}
        })
        mock_run.return_value = process_mock
        
        # Test code
        code = """
        def vulnerable_function(user_input):
            query = "SELECT * FROM users WHERE id = " + user_input
            return db.execute(query)
        """
        
        # Mock tempfile and shutil
        with patch("tempfile.mkdtemp", return_value="/tmp/semgrep_test"), \
             patch("os.path.join", return_value="/tmp/semgrep_test/code.py"), \
             patch("builtins.open", mock_open()), \
             patch("os.path.exists", return_value=True), \
             patch("shutil.rmtree"):
            
            # Run the tool
            result = await semgrep_tool.run(
                code=code,
                language="python"
            )
        
        # Verify subprocess.run was called correctly
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert args[0][0] == "semgrep"
        assert "--json" in args[0]
        assert f"--config=p/security-audit,p/owasp-top-ten" in args[0]
        assert "--lang=python" in args[0]
        
        # Verify the result structure
        assert "findings" in result
        assert len(result["findings"]) == 1
        assert "severity_summary" in result
        assert result["severity_summary"]["high"] == 1
        assert "stats" in result
        assert result["stats"]["total_findings"] == 1
        
        # Verify finding details
        finding = result["findings"][0]
        assert finding["rule_id"] == "sql-injection"
        assert finding["severity"] == "high"
        assert finding["line"] == 2
        assert "SQL Injection" in finding["message"]
    
    @patch("subprocess.run")
    async def test_run_with_file_path(self, mock_run, semgrep_tool):
        """Test running the tool with file_path input."""
        # Mock subprocess.run
        process_mock = MagicMock()
        process_mock.returncode = 0
        process_mock.stdout = json.dumps({"results": [], "stats": {"files_scanned": 1, "total_time": 0.3}})
        mock_run.return_value = process_mock
        
        # Run the tool
        result = await semgrep_tool.run(
            file_path="/path/to/file.py",
            language="python"
        )
        
        # Verify subprocess.run was called correctly
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert args[0][0] == "semgrep"
        assert "--json" in args[0]
        assert f"--config=p/security-audit,p/owasp-top-ten" in args[0]
        assert "--lang=python" in args[0]
        assert "/path/to/file.py" in args[0]
        
        # Verify the result structure
        assert "findings" in result
        assert len(result["findings"]) == 0
        assert "severity_summary" in result
        assert "stats" in result
    
    @patch("subprocess.run")
    async def test_run_with_error(self, mock_run, semgrep_tool):
        """Test running the tool with an error."""
        # Mock subprocess.run to return an error
        process_mock = MagicMock()
        process_mock.returncode = 2
        process_mock.stderr = "Error: something went wrong"
        mock_run.return_value = process_mock
        
        # Test code
        code = "print('hello')"
        
        # Mock tempfile and shutil
        with patch("tempfile.mkdtemp", return_value="/tmp/semgrep_test"), \
             patch("os.path.join", return_value="/tmp/semgrep_test/code.py"), \
             patch("builtins.open", mock_open()), \
             patch("os.path.exists", return_value=True), \
             patch("shutil.rmtree"):
            
            # Run the tool
            result = await semgrep_tool.run(code=code)
        
        # Verify the error is in the result
        assert "error" in result
        assert result["error"] == "Error: something went wrong"
        assert "findings" in result
        assert len(result["findings"]) == 0
    
    @patch("subprocess.run")
    async def test_run_with_timeout(self, mock_run, semgrep_tool):
        """Test running the tool with a timeout."""
        # Mock subprocess.run to raise TimeoutExpired
        mock_run.side_effect = subprocess.TimeoutExpired("semgrep", 30)
        
        # Test code
        code = "print('hello')"
        
        # Mock tempfile and shutil
        with patch("tempfile.mkdtemp", return_value="/tmp/semgrep_test"), \
             patch("os.path.join", return_value="/tmp/semgrep_test/code.py"), \
             patch("builtins.open", mock_open()), \
             patch("os.path.exists", return_value=True), \
             patch("shutil.rmtree"):
            
            # Run the tool with a short timeout
            result = await semgrep_tool.run(
                code=code,
                max_timeout=30
            )
        
        # Verify the timeout error is in the result
        assert "error" in result
        assert "timed out" in result["error"]
        assert "findings" in result
        assert len(result["findings"]) == 0
    
    def test_process_findings(self, semgrep_tool):
        """Test processing of raw Semgrep results."""
        # Mock Semgrep results
        raw_results = {
            "results": [
                {
                    "check_id": "sql-injection",
                    "path": "app.py",
                    "start": {"line": 10},
                    "extra": {
                        "message": "SQL Injection vulnerability",
                        "severity": "high",
                        "lines": "query = 'SELECT * FROM users WHERE id = ' + user_input",
                        "metadata": {"cwe": ["CWE-89"], "owasp": ["A1:2017"]}
                    }
                },
                {
                    "check_id": "xss",
                    "path": "web.py",
                    "start": {"line": 20},
                    "extra": {
                        "message": "XSS vulnerability",
                        "severity": "medium",
                        "lines": "html = '<div>' + user_input + '</div>'",
                        "metadata": {"cwe": ["CWE-79"], "owasp": ["A7:2017"]}
                    }
                }
            ],
            "stats": {"files_scanned": 2, "total_time": 0.75}
        }
        
        # Process the results
        processed = semgrep_tool._process_findings(raw_results)
        
        # Verify the processed results
        assert "findings" in processed
        assert len(processed["findings"]) == 2
        assert "severity_summary" in processed
        assert processed["severity_summary"]["high"] == 1
        assert processed["severity_summary"]["medium"] == 1
        assert "stats" in processed
        assert processed["stats"]["total_findings"] == 2
        assert processed["stats"]["files_scanned"] == 2
        assert processed["stats"]["scan_time"] == 0.75
        
        # Verify finding details
        finding = processed["findings"][0]
        assert finding["rule_id"] == "sql-injection"
        assert finding["message"] == "SQL Injection vulnerability"
        assert finding["severity"] == "high"
        assert finding["path"] == "app.py"
        assert finding["line"] == 10
        assert "CWE-89" in finding["cwe"]
        assert "A1:2017" in finding["owasp"] 