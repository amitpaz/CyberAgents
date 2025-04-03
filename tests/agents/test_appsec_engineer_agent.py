"""Tests for the AppSec Engineer Agent."""

import os
import unittest
from unittest.mock import patch, MagicMock
import pytest

from agents.appsec_engineer_agent import AppSecEngineerAgent


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


class TestAppSecEngineerAgent:
    """Test the AppSec Engineer Agent functionality."""
    
    def test_initialization(self, appsec_agent):
        """Test that the agent initializes correctly."""
        assert appsec_agent is not None
        assert appsec_agent.config["rate_limit"] == 100
        assert appsec_agent.config["max_code_size"] == 500
        assert "python" in appsec_agent.config["supported_languages"]
    
    @patch("agents.appsec_engineer_agent.appsec_engineer_agent.CodeLanguageDetector.detect_language")
    def test_language_detection(self, mock_detect, appsec_agent):
        """Test language detection functionality."""
        mock_detect.return_value = "python"
        
        test_code = """
        def vulnerable_function(user_input):
            query = "SELECT * FROM users WHERE id = " + user_input
            return execute_query(query)
        """
        
        with patch("agents.appsec_engineer_agent.appsec_engineer_agent.RateLimiter.acquire") as mock_acquire:
            mock_acquire.return_value = True
            with patch("agents.appsec_engineer_agent.appsec_engineer_agent.AppSecEngineerAgent._process_scan_results") as mock_process:
                mock_process.return_value = {"findings": []}
                with patch("agents.appsec_engineer_agent.appsec_engineer_agent.SemgrepRunner.scan_code") as mock_scan:
                    mock_scan.return_value = {}
                    with patch("os.makedirs"), patch("os.path.join", return_value="/tmp/test"), \
                         patch("builtins.open", unittest.mock.mock_open()), patch("shutil.rmtree"):
                        # Call the analyze_code method
                        loop = asyncio.get_event_loop()
                        result = loop.run_until_complete(appsec_agent.analyze_code(test_code))
        
        # Verify language detection was called
        mock_detect.assert_called_once()
    
    @patch("agents.appsec_engineer_agent.appsec_engineer_agent.RateLimiter.acquire")
    @patch("subprocess.run")
    def test_repository_analysis(self, mock_run, mock_acquire, appsec_agent):
        """Test repository analysis functionality."""
        # Mock rate limiter to always allow
        mock_acquire.return_value = True
        
        # Mock subprocess.run for git clone
        process_mock = MagicMock()
        process_mock.returncode = 0
        process_mock.stdout = "{}"
        mock_run.return_value = process_mock
        
        with patch("agents.appsec_engineer_agent.appsec_engineer_agent.AppSecEngineerAgent._is_valid_github_url", return_value=True), \
             patch("agents.appsec_engineer_agent.appsec_engineer_agent.AppSecEngineerAgent._get_directory_size", return_value=1000), \
             patch("agents.appsec_engineer_agent.appsec_engineer_agent.AppSecEngineerAgent._process_scan_results") as mock_process, \
             patch("shutil.rmtree"):
            
            mock_process.return_value = {"findings": []}
            
            # Call analyze_repository
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(appsec_agent.analyze_repository("https://github.com/user/repo"))
        
        # Verify git clone was attempted
        assert mock_run.called
        # Verify result processing happened
        assert mock_process.called
    
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
    
    @patch("agents.appsec_engineer_agent.appsec_engineer_agent.RateLimiter.acquire")
    def test_code_size_limit(self, mock_acquire, appsec_agent):
        """Test code size limit enforcement."""
        mock_acquire.return_value = True
        
        # Generate code larger than the limit (500KB)
        large_code = "x = 1\n" * 500000  # More than 500KB
        
        # Test that code size limit is enforced
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(appsec_agent.analyze_code(large_code))
        
        assert "error" in result
        assert "exceeds maximum size" in result["error"] 