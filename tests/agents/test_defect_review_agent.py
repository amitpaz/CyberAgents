"""Tests for the Defect Review Agent."""

import pytest
import asyncio
from agents.defect_review_agent import DefectReviewAgent


@pytest.fixture
def defect_agent():
    """Create a Defect Review Agent for testing."""
    return DefectReviewAgent()


@pytest.fixture
def sample_findings():
    """Create sample security findings for testing."""
    return {
        "scan_id": "test-scan-123",
        "findings": [
            {
                "rule_id": "sql-injection",
                "message": "Possible SQL injection vulnerability",
                "severity": "high",
                "path": "app/db.py",
                "line": 42,
                "code": "query = \"SELECT * FROM users WHERE id = \" + user_input"
            },
            {
                "rule_id": "xss",
                "message": "Possible cross-site scripting vulnerability",
                "severity": "medium",
                "path": "app/views.py",
                "line": 27,
                "code": "return render_template('page.html', content=user_input)"
            }
        ],
        "severity_summary": {
            "critical": 0,
            "high": 1,
            "medium": 1,
            "low": 0,
            "info": 0
        }
    }


class TestDefectReviewAgent:
    """Test the Defect Review Agent functionality."""
    
    def test_initialization(self, defect_agent):
        """Test that the agent initializes correctly."""
        assert defect_agent is not None
    
    def test_review_vulnerabilities(self, defect_agent, sample_findings):
        """Test the review_vulnerabilities method returns expected structure."""
        # Run the review_vulnerabilities method
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(defect_agent.review_vulnerabilities(sample_findings))
        
        # Verify the structure of the result
        assert "scan_id" in result
        assert result["scan_id"] == "test-scan-123"
        assert "remediation_suggestions" in result
        assert len(result["remediation_suggestions"]) == 2
        
        # Verify the structure of the suggestions
        for suggestion in result["remediation_suggestions"]:
            assert "rule_id" in suggestion
            assert "severity" in suggestion
            assert "message" in suggestion
            assert "recommendation" in suggestion
            assert "code_example" in suggestion 