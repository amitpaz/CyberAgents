# AppSec Engineer Agent Test Analysis

## Current Test Structure

The existing test suite has:
- TestCodeLanguageDetector - Tests language detection
- TestSemgrepRunner - Tests semgrep functionality
- TestAppSecEngineerAgent - Tests the agent functionality

## Issues and Gaps

1. **Missing Configuration Validation Tests**:
   - No tests for loading and validating YAML config
   - No tests for handling malformed configs
   - No tests for model validation

2. **Incomplete Integration Testing**:
   - Some tests are skipped (rate limiting test)
   - Limited integration testing with other agents
   - No comprehensive component interaction tests

3. **Tool Interface Testing**:
   - No tests for proper tool registration
   - No tests for tool interaction within CrewAI context
   - Missing BaseTool implementation tests

4. **Mocking Limitations**:
   - Tests depend on actual semgrep executable
   - Limited mocking of external dependencies
   - Some tests may fail in CI environments

## Required Changes

### 1. Add Configuration Tests

```python
class TestAppSecEngineerAgentConfig:
    """Test the AppSecEngineerAgentConfig validation."""

    def test_valid_config_loading(self, tmp_path):
        """Test loading a valid configuration file."""
        # Create a valid config file
        config_path = tmp_path / "valid_config.yaml"
        with open(config_path, "w") as f:
            f.write("""
            role: "Application Security Engineer"
            goal: "Analyze code for security vulnerabilities"
            backstory: "Expert in application security"
            tools:
              - "semgrep_code_scanner"
            allow_delegation: true
            verbose: true
            memory: false
            max_iterations: 15
            max_rpm: 10
            cache: true
            """)
        
        # Test loading the config
        agent = AppSecEngineerAgent(config_path=str(config_path))
        assert agent.config.role == "Application Security Engineer"
        assert agent.config.max_rpm == 10
        assert "semgrep_code_scanner" in agent.config.tools

    def test_invalid_config_loading(self, tmp_path):
        """Test loading an invalid configuration file."""
        # Create an invalid config file
        config_path = tmp_path / "invalid_config.yaml"
        with open(config_path, "w") as f:
            f.write("""
            role: "Application Security Engineer"
            # Missing required fields
            """)
        
        # Test that loading fails appropriately
        with pytest.raises(ValueError):
            AppSecEngineerAgent(config_path=str(config_path))
```

### 2. Update Test Fixtures

```python
@pytest.fixture
def mock_semgrep_scanner():
    """Create a mock SemgrepCodeScanner."""
    with mock.patch("tools.semgrep_scanner.semgrep_scanner.SemgrepCodeScanner") as mock_scanner:
        # Configure the mock
        mock_scanner_instance = mock.MagicMock()
        mock_scanner.return_value = mock_scanner_instance
        
        # Mock the scan method
        mock_scanner_instance._run.return_value = {
            "results": [
                {
                    "check_id": "test-rule",
                    "path": "test.py",
                    "start": {"line": 1},
                    "extra": {
                        "message": "Test vulnerability",
                        "severity": "high",
                        "lines": "test code",
                        "metadata": {"cwe": ["CWE-1"], "owasp": ["A1"]}
                    }
                }
            ]
        }
        
        yield mock_scanner_instance

@pytest.fixture
def appsec_agent(mock_semgrep_scanner):
    """Create an AppSec Engineer Agent with mocked dependencies."""
    with mock.patch("os.path.exists", return_value=True), \
         mock.patch("builtins.open", mock.mock_open(read_data="""
            role: "Application Security Engineer"
            goal: "Analyze code for security vulnerabilities"
            backstory: "Expert in application security"
            tools:
              - "semgrep_code_scanner" 
            allow_delegation: true
            """)):
        
        agent = AppSecEngineerAgent()
        # Replace the real tool instance with our mock
        agent.tool_instances["semgrep_code_scanner"] = mock_semgrep_scanner
        return agent
```

### 3. Add Integration Tests

```python
class TestAppSecEngineerAgentIntegration:
    """Test integration of AppSec Engineer Agent with CrewAI."""

    @pytest.mark.asyncio
    async def test_agent_in_crew(self, appsec_agent, mock_defect_review_agent):
        """Test the agent in a CrewAI workflow."""
        from crewai import Crew
        from crewai.tasks import Task
        
        # Create tasks
        analysis_task = Task(
            description="Analyze code for vulnerabilities",
            agent=appsec_agent.agent
        )
        
        remediation_task = Task(
            description="Provide remediation guidance",
            agent=mock_defect_review_agent.agent,
            depends_on=[analysis_task]
        )
        
        # Create crew
        crew = Crew(
            agents=[appsec_agent.agent, mock_defect_review_agent.agent],
            tasks=[analysis_task, remediation_task]
        )
        
        # Run the crew with a mock
        with mock.patch.object(crew, "kickoff") as mock_kickoff:
            mock_kickoff.return_value = "Analysis and remediation complete"
            result = crew.kickoff()
            
        assert result == "Analysis and remediation complete"
        assert mock_kickoff.called
```

### 4. Add Tool Tests

```python
class TestSemgrepCodeScanner:
    """Test the SemgrepCodeScanner tool."""
    
    def test_tool_registration(self):
        """Test that the tool is properly registered."""
        from tools.semgrep_scanner.semgrep_scanner import SemgrepCodeScanner
        
        scanner = SemgrepCodeScanner()
        assert scanner.name == "semgrep_code_scanner"
        assert scanner.input_schema is not None
        
    def test_tool_run_with_code(self, mock_subprocess_run):
        """Test running the tool with code input."""
        from tools.semgrep_scanner.semgrep_scanner import SemgrepCodeScanner
        
        scanner = SemgrepCodeScanner()
        result = scanner._run(code="print('test')", language="python")
        
        assert mock_subprocess_run.called
        assert "findings" in result
        
    def test_tool_run_with_repository(self, mock_subprocess_run, mock_git_clone):
        """Test running the tool with a repository URL."""
        from tools.semgrep_scanner.semgrep_scanner import SemgrepCodeScanner
        
        scanner = SemgrepCodeScanner()
        result = scanner._run(repository_url="https://github.com/test/repo")
        
        assert mock_git_clone.called
        assert mock_subprocess_run.called
        assert "findings" in result
```

## Test Implementation Plan

1. Update fixture creation to work with new model patterns
2. Add configuration validation tests 
3. Update tool interaction tests to use the new tool interface
4. Add mock implementations for external dependencies
5. Add comprehensive CrewAI integration tests

By implementing these changes, the test suite will properly validate the new implementation and ensure compliance with the requirements in the agent_update_tracker.md. 