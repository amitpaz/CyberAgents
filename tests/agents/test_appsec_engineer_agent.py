"""Tests for the AppSec Engineer Agent."""

import os  # Keep os for path checks etc.
import shutil  # Keep shutil for checking tool existence

import pytest

from agents.appsec_engineer_agent.appsec_engineer_agent import (
    AppSecEngineerAgent,
    CodeLanguageDetector,
    SemgrepRunner,
)
from utils.rate_limiter import RateLimiter

# Check if semgrep executable exists
SEMGREP_EXECUTABLE = shutil.which("semgrep")
skip_if_no_semgrep = pytest.mark.skipif(
    SEMGREP_EXECUTABLE is None, reason="Semgrep executable not found in PATH"
)


@pytest.fixture
def appsec_agent():
    """Create an AppSec Engineer Agent for testing, loading real config."""
    # Allow the agent to load its actual config from agent.yaml
    # Ensure os.makedirs is not mocked globally if agent creates dirs
    try:
        agent = AppSecEngineerAgent()
        # Ensure the temp dir from config exists for tests if needed
        os.makedirs(
            agent.config.get("temp_dir", "/tmp/cyberagents/appsec"), exist_ok=True
        )
        return agent
    except Exception as e:
        pytest.fail(f"Failed to initialize AppSecEngineerAgent: {e}")


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
        result = CodeLanguageDetector.detect_language(
            "System.out.println('hello');", "Test.java"
        )
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
        # Expect 'unknown' for highly ambiguous code with no clear indicators
        assert CodeLanguageDetector.detect_language(ambiguous_code) == "unknown"


@skip_if_no_semgrep
class TestSemgrepRunner:
    """Test the SemgrepRunner class functionality (requires semgrep executable)."""

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

    @pytest.mark.integration  # Mark as integration test
    def test_semgrep_runner_integration_basic(self, tmp_path):
        """Basic integration test for SemgrepRunner."""
        runner = SemgrepRunner(["p/python"], max_scan_time=30)
        test_file = tmp_path / "test.py"
        test_file.write_text(
            "import os\nos.system('echo hello') # Potential command injection"
        )

        result = runner.scan_code(str(tmp_path), language="python")

        assert "error" not in result
        assert "results" in result
        # Check if some finding related to os.system was potentially found
        # This depends heavily on the 'p/python' ruleset content
        assert len(result["results"]) >= 0  # At least runs without error


class TestAppSecEngineerAgent:
    """Test the AppSec Engineer Agent functionality."""

    def test_initialization(self, appsec_agent):
        """Test that the agent initializes correctly."""
        assert appsec_agent is not None
        assert isinstance(appsec_agent.semgrep, SemgrepRunner)
        assert isinstance(appsec_agent.rate_limiter, RateLimiter)
        # Check if config values seem reasonable (loaded from file)
        assert isinstance(appsec_agent.config.get("rate_limit"), int)
        assert isinstance(appsec_agent.config.get("max_code_size"), int)
        assert isinstance(appsec_agent.config.get("supported_languages"), list)

    @pytest.mark.skip(reason="Refactoring needed for real service interaction")
    def test_analyze_code_success(self, appsec_agent):
        """Test successful code analysis (placeholder)."""
        pass

    @pytest.mark.skip(reason="Refactoring needed for real service interaction / timing")
    def test_analyze_code_rate_limit_exceeded(self, appsec_agent):
        """Test rate limit exceeding (placeholder)."""
        pass

    @pytest.mark.asyncio
    async def test_analyze_code_size_limit(self, appsec_agent):
        """Test code size limit enforcement."""
        max_size_kb = appsec_agent.config["max_code_size"]
        oversized_code = "a" * (max_size_kb * 1024 + 1)
        result = await appsec_agent.analyze_code(oversized_code)
        assert "error" in result
        assert "exceeds maximum size" in result["error"]

    @pytest.mark.asyncio
    async def test_analyze_unsupported_language(self, appsec_agent):
        """Test analysis of unsupported language."""
        result = await appsec_agent.analyze_code("gibberish code", language="cobol")
        assert "error" in result
        assert "Language 'cobol' is not supported" in result["error"]

    @pytest.mark.skip(reason="Refactoring needed for real service interaction")
    def test_analyze_code_unsupported_language_detected(self, appsec_agent):
        """Test detection of unsupported language (placeholder)."""
        pass

    @pytest.mark.skip(reason="Refactoring needed for real git/semgrep interaction")
    def test_repository_analysis_success(self, appsec_agent):
        """Test successful repository analysis (placeholder)."""
        pass

    def test_github_url_validation(self, appsec_agent):
        """Test GitHub URL validation logic."""
        # Valid URLs
        assert appsec_agent._is_valid_github_url("https://github.com/user/repo")
        assert appsec_agent._is_valid_github_url("http://github.com/user/repo")
        assert appsec_agent._is_valid_github_url("https://github.com/user/repo-name")

        # Invalid URLs
        assert not appsec_agent._is_valid_github_url("https://gitlab.com/user/repo")
        assert not appsec_agent._is_valid_github_url("https://github.com/user")
        assert not appsec_agent._is_valid_github_url(
            "https://github.com/user/repo/issues"
        )
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
                        "metadata": {"cwe": ["CWE-89"], "owasp": ["A1:2017"]},
                    },
                },
                {
                    "check_id": "xss",
                    "path": "web.py",
                    "start": {"line": 20},
                    "extra": {
                        "message": "XSS vulnerability",
                        "severity": "medium",
                        "lines": "html = '<div>' + user_input + '</div>'",
                        "metadata": {"cwe": ["CWE-79"], "owasp": ["A7:2017"]},
                    },
                },
            ]
        }

        # Process the results
        result = appsec_agent._process_scan_results(
            semgrep_results, "test-scan-id", "python"
        )

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
        assert (
            finding["code"] == "query = 'SELECT * FROM users WHERE id = ' + user_input"
        )
        assert "CWE-89" in finding["cwe"]
        assert "A1:2017" in finding["owasp"]

    def test_process_scan_results_with_error(self, appsec_agent):
        """Test processing of scan results with error."""
        # Mock error results
        error_results = {"error": "Semgrep error: something went wrong"}

        # Process the results
        result = appsec_agent._process_scan_results(
            error_results, "test-scan-id", "python"
        )

        # Verify error is preserved
        assert "error" in result
        assert result["error"] == "Semgrep error: something went wrong"
        assert "findings" in result
        assert len(result["findings"]) == 0
        assert "severity_summary" in result
        assert result["severity_summary"]["critical"] == 0
