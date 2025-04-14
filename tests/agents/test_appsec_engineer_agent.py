"""Tests for the AppSec Engineer Agent."""

import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest
import yaml

from agents.appsec_engineer_agent.appsec_engineer_agent import (
    AppSecEngineerAgent,
    AppSecEngineerAgentConfig,
    CodeLanguageDetector,
)


@pytest.fixture
def valid_config():
    """Create a valid agent configuration."""
    return {
        "role": "Test AppSec Engineer",
        "goal": "Test code for security vulnerabilities",
        "backstory": "I am a test security engineer",
        "tools": ["semgrep_code_scanner"],
        "allow_delegation": True,
        "verbose": True,
        "memory": False,
        "max_iterations": 5,
        "max_rpm": 10,
        "cache": True,
        "max_scan_time": 60,
        "max_code_size": 200,
        "rules": ["p/security-audit"],
    }


@pytest.fixture
def mock_semgrep_scanner():
    """Mock the SemgrepCodeScanner tool."""
    with mock.patch("agents.appsec_engineer_agent.appsec_engineer_agent.SemgrepCodeScanner") as mock_scanner:
        scanner_instance = mock.MagicMock()
        mock_scanner.return_value = scanner_instance
        yield scanner_instance


@pytest.fixture
def mock_agent():
    """Mock the CrewAI Agent class."""
    with mock.patch("agents.appsec_engineer_agent.appsec_engineer_agent.Agent") as mock_agent:
        agent_instance = mock.MagicMock()
        mock_agent.return_value = agent_instance
        yield mock_agent


class TestCodeLanguageDetector:
    """Tests for the CodeLanguageDetector class."""

    def test_detect_language_from_filename(self):
        """Test detecting language from a filename."""
        # Test Python detection
        assert CodeLanguageDetector.detect_language("", "test.py") == "python"
        # Test JavaScript detection
        assert CodeLanguageDetector.detect_language("", "test.js") == "javascript"
        # Test Java detection
        assert CodeLanguageDetector.detect_language("", "test.java") == "java"
        # Test unknown extension
        assert CodeLanguageDetector.detect_language("", "test.xyz") == "unknown"

    def test_detect_language_from_content(self):
        """Test detecting language from code content."""
        # Test Python detection
        python_code = """
        import os
        from pathlib import Path
        
        def main():
            print("Hello, world!")
        """
        assert CodeLanguageDetector.detect_language(python_code) == "python"
        
        # Test JavaScript detection
        js_code = """
        const fs = require('fs');
        
        function main() {
            console.log("Hello, world!");
        }
        """
        assert CodeLanguageDetector.detect_language(js_code) == "javascript"


def test_config_validation(valid_config):
    """Test that the configuration validation works."""
    # Valid configuration
    config = AppSecEngineerAgentConfig(**valid_config)
    assert config.role == valid_config["role"]
    assert config.goal == valid_config["goal"]
    assert config.tools == valid_config["tools"]
    
    # Invalid configuration - missing required field
    invalid_config = valid_config.copy()
    del invalid_config["role"]
    with pytest.raises(ValueError):
        AppSecEngineerAgentConfig(**invalid_config)
    
    # Invalid configuration - empty tools list
    invalid_config = valid_config.copy()
    invalid_config["tools"] = []
    with pytest.raises(ValueError):
        AppSecEngineerAgentConfig(**invalid_config)
    
    # Invalid configuration - missing required tool
    invalid_config = valid_config.copy()
    invalid_config["tools"] = ["some_other_tool"]
    with pytest.raises(ValueError):
        AppSecEngineerAgentConfig(**invalid_config)


def test_agent_initialization_with_temp_config(valid_config, mock_semgrep_scanner, mock_agent):
    """Test agent initialization with a temporary config file."""
    # Create a temporary config file
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".yaml", delete=False) as temp_file:
        yaml.dump(valid_config, temp_file)
        temp_file_path = temp_file.name
    
    try:
        # Initialize agent with the temp config
        with mock.patch("agents.appsec_engineer_agent.appsec_engineer_agent.validate_yaml_against_schema") as mock_validate:
            mock_validate.return_value = {"is_valid": True}
            agent = AppSecEngineerAgent(config_path=temp_file_path)
            
            # Verify agent was initialized correctly
            assert agent.config.role == valid_config["role"]
            assert agent.config.goal == valid_config["goal"]
            assert "semgrep_code_scanner" in agent.tools
            
            # Verify the Agent was created with the right parameters
            call_args = mock_agent.call_args[1]
            assert call_args["role"] == valid_config["role"]
            assert call_args["goal"] == valid_config["goal"]
            assert call_args["backstory"] == valid_config["backstory"]
    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)


def test_analyze_code_size_limit(valid_config, mock_semgrep_scanner, mock_agent):
    """Test code size limit when analyzing code."""
    # Create a temporary config file
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".yaml", delete=False) as temp_file:
        yaml.dump(valid_config, temp_file)
        temp_file_path = temp_file.name
    
    try:
        # Initialize agent with the temp config
        with mock.patch("agents.appsec_engineer_agent.appsec_engineer_agent.validate_yaml_against_schema") as mock_validate:
            mock_validate.return_value = {"is_valid": True}
            agent = AppSecEngineerAgent(config_path=temp_file_path)
            
            # Create code larger than the size limit (200 KB)
            large_code = "x" * (agent.config.max_code_size * 1024 + 1)
            
            # Analyze code
            result = agent.analyze_code(large_code)
            
            # Verify the result contains an error about code size
            assert "error" in result
            assert f"Code size exceeds limit of {agent.config.max_code_size} KB" in result["error"]
            
            # Mock scanner should not have been called
            mock_semgrep_scanner.scan_code.assert_not_called()
    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)


def test_analyze_code_success(valid_config, mock_semgrep_scanner, mock_agent):
    """Test successful code analysis."""
    # Create a temporary config file
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".yaml", delete=False) as temp_file:
        yaml.dump(valid_config, temp_file)
        temp_file_path = temp_file.name
    
    try:
        # Mock scanner results
        mock_findings = [
            {
                "rule_id": "test-rule",
                "message": "Test vulnerability",
                "severity": "high",
            }
        ]
        mock_semgrep_scanner.scan_code.return_value = {"findings": mock_findings}
        mock_semgrep_scanner.generate_report.return_value = {
            "summary": "Found 1 security issue",
            "findings_count": 1,
            "severity_summary": {"high": 1},
        }
        
        # Initialize agent with the temp config
        with mock.patch("agents.appsec_engineer_agent.appsec_engineer_agent.validate_yaml_against_schema") as mock_validate:
            mock_validate.return_value = {"is_valid": True}
            agent = AppSecEngineerAgent(config_path=temp_file_path)
            
            # Create some valid code
            code = "def test(): pass"
            
            # Analyze code
            with mock.patch("pathlib.Path.mkdir") as mock_mkdir, \
                 mock.patch("builtins.open", mock.mock_open()), \
                 mock.patch("shutil.rmtree"):
                result = agent.analyze_code(code)
                
                # Verify the result
                assert "findings" in result
                assert result["findings"] == mock_findings
                assert "report" in result
                assert result["report"]["findings_count"] == 1
    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)


def test_generate_vulnerability_report(valid_config, mock_semgrep_scanner, mock_agent):
    """Test generating a vulnerability report."""
    # Create a temporary config file
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".yaml", delete=False) as temp_file:
        yaml.dump(valid_config, temp_file)
        temp_file_path = temp_file.name
    
    try:
        # Mock scanner results
        mock_findings = [
            {
                "rule_id": "test-rule",
                "message": "Test vulnerability",
                "severity": "high",
            }
        ]
        mock_report = {
            "summary": "Found 1 security issue",
            "findings_count": 1,
            "severity_summary": {"high": 1},
        }
        mock_semgrep_scanner.generate_report.return_value = mock_report
        
        # Initialize agent with the temp config
        with mock.patch("agents.appsec_engineer_agent.appsec_engineer_agent.validate_yaml_against_schema") as mock_validate:
            mock_validate.return_value = {"is_valid": True}
            agent = AppSecEngineerAgent(config_path=temp_file_path)
            
            # Generate report without existing report
            result = agent.generate_vulnerability_report({"findings": mock_findings})
            
            # Verify the result
            assert result["status"] == "success"
            assert result["report"] == mock_report
            
            # Generate report with existing report
            result = agent.generate_vulnerability_report({"findings": mock_findings, "report": mock_report})
            
            # Verify the result (should use existing report)
            assert result["status"] == "success"
            assert result["report"] == mock_report
            # Should only call generate_report once
            assert mock_semgrep_scanner.generate_report.call_count == 1
    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)
