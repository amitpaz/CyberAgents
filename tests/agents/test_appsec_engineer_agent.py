"""Tests for the AppSec Engineer Agent."""

import os
import unittest
import asyncio
from unittest.mock import patch, MagicMock, mock_open
import pytest
import json

from agents.appsec_engineer_agent import AppSecEngineerAgent
from agents.appsec_engineer_agent.appsec_engineer_agent import CodeLanguageDetector, SemgrepRunner


@pytest.fixture
def appsec_agent():
    """Create an AppSec Engineer Agent for testing."""
    # Mock configuration to avoid filesystem operations
    test_config = {
        "rate_limit": 100,  # High limit for tests
        "max_code_size": 500,
        "supported_languages": ["python", "javascript", "java"],
        "max_scan_time": 30,
        "semgrep_rules": ["p/test"],
        "temp_dir": "/tmp/test-appsec"
    }
    
    with patch("agents.appsec_engineer_agent.appsec_engineer_agent.AppSecEngineerAgent._load_config") as mock_load:
        mock_load.return_value = test_config
        with patch("os.makedirs"):  # Mock directory creation
            agent = AppSecEngineerAgent()
    
    return agent


class TestCodeLanguageDetector:
    """Test the CodeLanguageDetector class functionality."""

    def test_detect_language_from_filename(self):
        """Test language detection from filename."""
        # Python file
        result = CodeLanguageDetector.detect_language("print('hello')", "test.py")
        assert result == "python"
        
        # JavaScript file
        result = CodeLanguageDetector.detect_language("console.log('hello')", "test.js")
        assert result == "javascript"
        
        # Java file
        result = CodeLanguageDetector.detect_language("System.out.println('hello');", "Test.java")
        assert result == "java"
        
        # Unknown extension
        result = CodeLanguageDetector.detect_language("print('hello')", "test.xyz")
        assert result == "python"  # Should detect from content
        
        # No filename
        result = CodeLanguageDetector.detect_language("print('hello')")
        assert result == "python"  # Should detect from content

    def test_detect_language_from_content(self):
        """Test language detection from code content."""
        # Python code
        python_code = """
        import os
        from pathlib import Path
        
        def hello():
            print("Hello, world!")
            
        class MyClass:
            def __init__(self):
                pass
        """
        assert CodeLanguageDetector.detect_language(python_code) == "python"
        
        # JavaScript code
        js_code = """
        import React from 'react';
        
        const hello = () => {
            console.log("Hello, world!");
        };
        
        function App() {
            const value = 42;
            let name = "User";
            return <div>{name}</div>;
        }
        """
        assert CodeLanguageDetector.detect_language(js_code) == "javascript"
        
        # Java code
        java_code = """
        package com.example;
        
        import java.util.List;
        
        public class Hello {
            private String name;
            
            public Hello(String name) {
                this.name = name;
            }
            
            public void sayHello() {
                System.out.println("Hello, " + name);
            }
        }
        """
        assert CodeLanguageDetector.detect_language(java_code) == "java"
        
        # Empty code
        assert CodeLanguageDetector.detect_language("") == "unknown"
        
        # Ambiguous code
        ambiguous_code = "x = 1;"  # Could be many languages
        assert CodeLanguageDetector.detect_language(ambiguous_code) != "unknown"  # Should make a best guess


class TestSemgrepRunner:
    """Test the SemgrepRunner class functionality."""
    
    def test_initialization(self):
        """Test that the runner initializes correctly."""
        runner = SemgrepRunner(["p/test", "p/owasp-top-ten"], 60)
        assert runner.rules == ["p/test", "p/owasp-top-ten"]
        assert runner.max_scan_time == 60
    
    def test_prepare_rules_arg(self):
        """Test the preparation of rules argument."""
        runner = SemgrepRunner(["p/test", "p/owasp-top-ten"])
        result = runner._prepare_rules_arg()
        assert result == "p/test,p/owasp-top-ten"
    
    @patch("subprocess.run")
    def test_scan_code_success(self, mock_run):
        """Test successful code scanning."""
        # Mock a successful subprocess run
        process_mock = MagicMock()
        process_mock.returncode = 0
        process_mock.stdout = json.dumps({"results": []})
        mock_run.return_value = process_mock
        
        runner = SemgrepRunner(["p/test"])
        result = runner.scan_code("/path/to/code", "python")
        
        # Verify subprocess.run was called correctly
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert args[0][0] == "semgrep"
        assert "--config=p/test" in args[0]
        assert "--lang=python" in args[0]
        assert kwargs["timeout"] == 300
        
        # Verify result parsing
        assert "results" in result
    
    @patch("subprocess.run")
    def test_scan_code_with_findings(self, mock_run):
        """Test code scanning with security findings."""
        # Mock subprocess run with findings
        findings = {
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
                }
            ]
        }
        
        process_mock = MagicMock()
        process_mock.returncode = 1  # Semgrep returns 1 when findings exist
        process_mock.stdout = json.dumps(findings)
        mock_run.return_value = process_mock
        
        runner = SemgrepRunner(["p/test"])
        result = runner.scan_code("/path/to/code")
        
        # Verify result contains findings
        assert "results" in result
        assert len(result["results"]) == 1
        assert result["results"][0]["check_id"] == "sql-injection"
    
    @patch("subprocess.run")
    def test_scan_code_error(self, mock_run):
        """Test handling of errors during code scanning."""
        # Mock subprocess error
        process_mock = MagicMock()
        process_mock.returncode = 2  # Error code
        process_mock.stderr = "Error: something went wrong"
        mock_run.return_value = process_mock
        
        runner = SemgrepRunner(["p/test"])
        result = runner.scan_code("/path/to/code")
        
        # Verify error handling
        assert "error" in result
        assert result["error"] == "Error: something went wrong"
        assert "findings" in result
        assert len(result["findings"]) == 0
    
    @patch("subprocess.run")
    def test_scan_code_timeout(self, mock_run):
        """Test handling of timeouts during code scanning."""
        # Mock timeout
        mock_run.side_effect = subprocess.TimeoutExpired("semgrep", 30)
        
        runner = SemgrepRunner(["p/test"], max_scan_time=30)
        result = runner.scan_code("/path/to/code")
        
        # Verify timeout handling
        assert "error" in result
        assert "timed out" in result["error"]
        assert "findings" in result
        assert len(result["findings"]) == 0
    
    @patch("subprocess.run")
    def test_scan_code_json_error(self, mock_run):
        """Test handling of JSON parsing errors."""
        # Mock invalid JSON output
        process_mock = MagicMock()
        process_mock.returncode = 0
        process_mock.stdout = "{ invalid json"
        mock_run.return_value = process_mock
        
        runner = SemgrepRunner(["p/test"])
        result = runner.scan_code("/path/to/code")
        
        # Verify JSON error handling
        assert "error" in result
        assert "Failed to parse" in result["error"]
        assert "findings" in result
        assert len(result["findings"]) == 0


class TestAppSecEngineerAgent:
    """Test the AppSec Engineer Agent functionality."""
    
    def test_initialization(self, appsec_agent):
        """Test that the agent initializes correctly."""
        assert appsec_agent is not None
        assert appsec_agent.config["rate_limit"] == 100
        assert appsec_agent.config["max_code_size"] == 500
        assert "python" in appsec_agent.config["supported_languages"]
        assert isinstance(appsec_agent.semgrep, SemgrepRunner)
    
    @patch("agents.appsec_engineer_agent.appsec_engineer_agent.CodeLanguageDetector.detect_language")
    def test_analyze_code_success(self, mock_detect, appsec_agent):
        """Test successful code analysis."""
        mock_detect.return_value = "python"
        
        test_code = """
        def vulnerable_function(user_input):
            query = "SELECT * FROM users WHERE id = " + user_input
            return execute_query(query)
        """
        
        # Mock findings
        mock_findings = {
            "findings": [
                {
                    "rule_id": "sql-injection",
                    "message": "SQL Injection vulnerability",
                    "severity": "high",
                    "path": "code.py",
                    "line": 3,
                    "code": "query = \"SELECT * FROM users WHERE id = \" + user_input"
                }
            ],
            "severity_summary": {"high": 1},
            "scan_id": "test-scan-id",
            "language": "python"
        }
        
        with patch("agents.appsec_engineer_agent.appsec_engineer_agent.RateLimiter.acquire") as mock_acquire:
            mock_acquire.return_value = asyncio.Future()
            mock_acquire.return_value.set_result(True)
            
            with patch("agents.appsec_engineer_agent.appsec_engineer_agent.AppSecEngineerAgent._process_scan_results") as mock_process:
                mock_process.return_value = mock_findings
                
                with patch("agents.appsec_engineer_agent.appsec_engineer_agent.SemgrepRunner.scan_code") as mock_scan:
                    mock_scan.return_value = {"results": []}
                    
                    with patch("agents.appsec_engineer_agent.appsec_engineer_agent.AppSecEngineerAgent._forward_to_defect_review") as mock_forward:
                        mock_forward.return_value = asyncio.Future()
                        mock_forward.return_value.set_result(None)
                        
                        with patch("os.makedirs"), patch("os.path.join", return_value="/tmp/test/code.py"), \
                             patch("builtins.open", mock_open()), patch("shutil.rmtree"), \
                             patch("uuid.uuid4", return_value="test-scan-id"):
                            
                            # Run the test
                            loop = asyncio.get_event_loop()
                            result = loop.run_until_complete(appsec_agent.analyze_code(test_code, filename="code.py"))
        
        # Verify results
        assert result == mock_findings
        assert "scan_metadata" in result
        assert result["scan_metadata"]["scan_id"] == "test-scan-id"
        assert result["scan_metadata"]["language"] == "python"
        
        # Verify method calls
        mock_detect.assert_called_once()
        mock_scan.assert_called_once()
        mock_process.assert_called_once()
        mock_forward.assert_called_once()
    
    @patch("agents.appsec_engineer_agent.appsec_engineer_agent.RateLimiter.acquire")
    def test_analyze_code_rate_limit_exceeded(self, mock_acquire, appsec_agent):
        """Test code analysis with rate limit exceeded."""
        # Mock rate limiter to deny
        future = asyncio.Future()
        future.set_result(False)
        mock_acquire.return_value = future
        
        # Run the test
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(appsec_agent.analyze_code("test code"))
        
        # Verify rate limit error
        assert "error" in result
        assert "Rate limit exceeded" in result["error"]
    
    @patch("agents.appsec_engineer_agent.appsec_engineer_agent.RateLimiter.acquire")
    def test_analyze_code_size_limit(self, mock_acquire, appsec_agent):
        """Test code size limit enforcement."""
        # Mock rate limiter to allow
        future = asyncio.Future()
        future.set_result(True)
        mock_acquire.return_value = future
        
        # Generate code larger than the limit (500KB)
        large_code = "x = 1\n" * 500000  # More than 500KB
        
        # Run the test
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(appsec_agent.analyze_code(large_code))
        
        # Verify size limit error
        assert "error" in result
        assert "exceeds maximum size" in result["error"]
    
    @patch("agents.appsec_engineer_agent.appsec_engineer_agent.RateLimiter.acquire")
    @patch("agents.appsec_engineer_agent.appsec_engineer_agent.CodeLanguageDetector.detect_language")
    def test_analyze_code_unsupported_language(self, mock_detect, mock_acquire, appsec_agent):
        """Test code analysis with unsupported language."""
        # Mock rate limiter to allow
        future = asyncio.Future()
        future.set_result(True)
        mock_acquire.return_value = future
        
        # Mock language detection to return unsupported language
        mock_detect.return_value = "rust"  # Not in supported_languages
        
        # Run the test
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(appsec_agent.analyze_code("fn main() {}"))
        
        # Verify language support error
        assert "error" in result
        assert "not supported" in result["error"]
    
    @patch("agents.appsec_engineer_agent.appsec_engineer_agent.RateLimiter.acquire")
    @patch("subprocess.run")
    def test_repository_analysis_success(self, mock_run, mock_acquire, appsec_agent):
        """Test successful repository analysis."""
        # Mock rate limiter to allow
        future = asyncio.Future()
        future.set_result(True)
        mock_acquire.return_value = future
        
        # Mock subprocess.run for git clone
        process_mock = MagicMock()
        process_mock.returncode = 0
        process_mock.stdout = "{}"
        mock_run.return_value = process_mock
        
        # Mock findings
        mock_findings = {
            "findings": [
                {
                    "rule_id": "sql-injection",
                    "message": "SQL Injection vulnerability",
                    "severity": "high",
                    "path": "app.py",
                    "line": 10,
                    "code": "query = \"SELECT * FROM users WHERE id = \" + user_input"
                }
            ],
            "severity_summary": {"high": 1},
            "scan_id": "test-scan-id"
        }
        
        with patch("agents.appsec_engineer_agent.appsec_engineer_agent.AppSecEngineerAgent._is_valid_github_url", return_value=True), \
             patch("agents.appsec_engineer_agent.appsec_engineer_agent.AppSecEngineerAgent._get_directory_size", return_value=1000), \
             patch("agents.appsec_engineer_agent.appsec_engineer_agent.AppSecEngineerAgent._process_scan_results") as mock_process, \
             patch("agents.appsec_engineer_agent.appsec_engineer_agent.SemgrepRunner.scan_code"), \
             patch("agents.appsec_engineer_agent.appsec_engineer_agent.AppSecEngineerAgent._forward_to_defect_review") as mock_forward, \
             patch("os.path.join"), patch("os.path.isfile", return_value=True), \
             patch("builtins.open", mock_open(read_data="line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\n")), \
             patch("uuid.uuid4", return_value="test-scan-id"), \
             patch("shutil.rmtree"):
            
            # Set up mock_process
            mock_process.return_value = mock_findings
            
            # Set up mock_forward
            mock_forward.return_value = asyncio.Future()
            mock_forward.return_value.set_result(None)
            
            # Run the test
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(appsec_agent.analyze_repository("https://github.com/user/repo"))
        
        # Verify results
        assert result == mock_findings
        assert "scan_metadata" in result
        assert result["scan_metadata"]["scan_id"] == "test-scan-id"
        assert result["scan_metadata"]["repository"] == "https://github.com/user/repo"
        
        # Verify method calls
        assert mock_run.called
        assert mock_process.called
        assert mock_forward.called
    
    def test_github_url_validation(self, appsec_agent):
        """Test GitHub URL validation logic."""
        # Valid URLs
        assert appsec_agent._is_valid_github_url("https://github.com/user/repo")
        assert appsec_agent._is_valid_github_url("http://github.com/user/repo")
        assert appsec_agent._is_valid_github_url("https://github.com/user/repo-name")
        
        # Invalid URLs
        assert not appsec_agent._is_valid_github_url("https://gitlab.com/user/repo")
        assert not appsec_agent._is_valid_github_url("https://github.com/user")
        assert not appsec_agent._is_valid_github_url("https://github.com/user/repo/issues")
        assert not appsec_agent._is_valid_github_url("not a url")
        assert not appsec_agent._is_valid_github_url("")
    
    def test_process_scan_results(self, appsec_agent):
        """Test the processing of scan results."""
        # Mock semgrep results
        semgrep_results = {
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
            ]
        }
        
        # Process the results
        result = appsec_agent._process_scan_results(semgrep_results, "test-scan-id", "python")
        
        # Verify the processed results
        assert "scan_id" in result
        assert result["scan_id"] == "test-scan-id"
        assert "findings" in result
        assert len(result["findings"]) == 2
        assert "severity_summary" in result
        assert result["severity_summary"]["high"] == 1
        assert result["severity_summary"]["medium"] == 1
        assert result["language"] == "python"
        
        # Verify finding details
        finding = result["findings"][0]
        assert finding["rule_id"] == "sql-injection"
        assert finding["message"] == "SQL Injection vulnerability"
        assert finding["severity"] == "high"
        assert finding["path"] == "app.py"
        assert finding["line"] == 10
        assert finding["code"] == "query = 'SELECT * FROM users WHERE id = ' + user_input"
        assert "CWE-89" in finding["cwe"]
        assert "A1:2017" in finding["owasp"]
    
    def test_process_scan_results_with_error(self, appsec_agent):
        """Test processing of scan results with error."""
        # Mock error results
        error_results = {
            "error": "Semgrep error: something went wrong"
        }
        
        # Process the results
        result = appsec_agent._process_scan_results(error_results, "test-scan-id", "python")
        
        # Verify error is preserved
        assert "error" in result
        assert result["error"] == "Semgrep error: something went wrong"
        assert "findings" in result
        assert len(result["findings"]) == 0
        assert "severity_summary" in result
        assert result["severity_summary"]["critical"] == 0 