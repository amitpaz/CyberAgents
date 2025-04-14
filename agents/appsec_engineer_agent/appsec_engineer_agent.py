"""
AppSec Engineer Agent for security code scanning and vulnerability detection.

This agent is capable of analyzing code for security vulnerabilities using
Semgrep as the primary scanning tool. It can process code provided directly
or clone and scan GitHub repositories.
"""

import logging
import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import ClassVar, Dict, List, Optional, Any, cast

import yaml
from crewai import Agent
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    ValidationError,
    field_validator,
    model_validator,
)

from agents.base_agent import BaseAgent
from tools.semgrep_scanner import SemgrepCodeScanner
from utils.validation_utils import is_valid_url, validate_yaml_against_schema


logger = logging.getLogger(__name__)


# Pydantic models for configuration validation
class LLMConfig(BaseModel):
    """Configuration for the LLM used by the agent."""

    model: Optional[str] = None
    temperature: Optional[float] = Field(None, ge=0, le=2)
    api_key: Optional[str] = None
    base_url: Optional[HttpUrl] = None
    
    model_config = ConfigDict(extra="forbid")


class FunctionCallingLLM(BaseModel):
    """Configuration for the function calling LLM."""

    model: Optional[str] = None
    temperature: Optional[float] = Field(None, ge=0, le=2)
    
    model_config = ConfigDict(extra="forbid")


class FileAnalysisLimits(BaseModel):
    """Limits for file analysis operations."""

    max_file_size: int = Field(5242880, ge=1)  # 5MB default
    allowed_extensions: Optional[List[str]] = None
    disallowed_extensions: Optional[List[str]] = None
    
    model_config = ConfigDict(extra="forbid")


class SecurityContext(BaseModel):
    """Security context and permissions for the agent."""

    allowed_domains: Optional[List[str]] = None
    max_request_size: int = Field(1048576, ge=1)  # 1MB default
    timeout: int = Field(30, ge=1)
    allow_internet_access: bool = False
    logging_level: str = Field(
        "INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$"
    )
    allow_code_execution: bool = False
    allow_ocr: bool = False
    allow_file_analysis: bool = False
    file_analysis_limits: Optional[FileAnalysisLimits] = None
    
    model_config = ConfigDict(extra="forbid")


class AppSecEngineerAgentConfig(BaseModel):
    """Configuration model for the AppSec Engineer Agent."""

    # Required fields
    role: str = Field(..., description="The role of the agent")
    goal: str = Field(..., description="The goal of the agent")
    backstory: str = Field(..., description="The backstory of the agent")
    tools: List[str] = Field(..., description="List of tools the agent can use")
    allow_delegation: bool = Field(..., description="Whether the agent can delegate tasks")

    # Optional fields
    verbose: bool = Field(True, description="Whether to enable verbose output")
    memory: bool = Field(False, description="Whether to enable memory for the agent")
    max_iterations: int = Field(5, ge=1, description="Maximum number of iterations")
    max_rpm: int = Field(10, ge=1, description="Maximum requests per minute")
    cache: bool = Field(True, description="Whether to enable caching")

    # Semgrep-specific settings
    max_scan_time: int = Field(60, ge=1, description="Maximum scan time in seconds")
    max_code_size: int = Field(200, ge=1, description="Maximum code size in KB")
    rules: List[str] = Field(
        default_factory=lambda: ["p/security-audit", "p/owasp-top-ten"],
        description="Semgrep rule sets to use for scanning"
    )

    # LLM Configuration
    llm_config: Optional[LLMConfig] = None
    function_calling_llm: Optional[FunctionCallingLLM] = None
    
    # Security settings
    security_context: Optional[SecurityContext] = None

    @field_validator('tools')
    def validate_tools(cls, v):
        if not v:
            raise ValueError("Tools list cannot be empty")
        if "semgrep_code_scanner" not in v:
            raise ValueError("AppSecEngineerAgent requires 'semgrep_code_scanner' tool")
        return v
    
    @model_validator(mode='after')
    def validate_model(self):
        # Additional validation can be added here
        return self
    
    model_config = ConfigDict(extra="forbid")


class CodeLanguageDetector:
    """Detects the programming language of a code snippet."""

    # Common file extensions by language
    EXTENSIONS = {
        "python": [".py"],
        "javascript": [".js", ".jsx", ".ts", ".tsx"],
        "java": [".java"],
        "go": [".go"],
        "ruby": [".rb"],
        "php": [".php"],
        "c": [".c", ".h"],
        "cpp": [".cpp", ".hpp", ".cc", ".cxx", ".h"],
    }

    # Common language patterns
    PATTERNS = {
        "python": [
            r"import\s+[\w\.]+",
            r"from\s+[\w\.]+\s+import",
            r"def\s+\w+\s*\(.*\):",
            r"class\s+\w+\s*(\(.*\))?:",
            r"print\(",
        ],
        "javascript": [
            r"const\s+\w+\s*=",
            r"let\s+\w+\s*=",
            r"function\s+\w+\s*\(.*\)\s*{",
            r"import\s+.*\s+from\s+['\"]",
            r"export\s+",
            r"=>\s*{",
            r"React",
        ],
        "java": [
            r"public\s+class",
            r"private\s+\w+\s+\w+\s*\(",
            r"package\s+[\w\.]+;",
            r"import\s+[\w\.]+;",
        ],
        "go": [
            r"package\s+\w+",
            r"func\s+\w+\s*\(.*\)\s*.*{",
            r"import\s+\([\s\S]*?\)",
            r"type\s+\w+\s+struct\s*{",
        ],
        "ruby": [
            r"require\s+['\"][\w\/]+['\"]",
            r"def\s+\w+",
            r"class\s+\w+(\s+<\s+\w+)?",
            r"module\s+\w+",
        ],
        "php": [
            r"<\?php",
            r"function\s+\w+\s*\(.*\)\s*{",
            r"namespace\s+[\w\\]+;",
            r"use\s+[\w\\]+",
        ],
        "c": [
            r"#include\s+[<\"][\w\.]+[>\"]",
            r"int\s+main\s*\(.*\)\s*{",
            r"\w+\s+\w+\s*\(.*\)\s*{",
            r"struct\s+\w+\s*{",
        ],
        "cpp": [
            r"#include\s+[<\"][\w\.]+[>\"]",
            r"namespace\s+\w+\s*{",
            r"class\s+\w+\s*{",
            r"std::",
            r"template\s*<",
        ],
    }

    @classmethod
    def detect_language(cls, code: str, filename: Optional[str] = None) -> str:
        """
        Detect the programming language of the provided code.

        Args:
            code: The code to analyze
            filename: Optional filename that may contain extension hints

        Returns:
            The detected language or "unknown" if detection fails
        """
        # Try to detect from filename extension first
        if filename:
            _, ext = os.path.splitext(filename)
            if ext:
                for lang, extensions in cls.EXTENSIONS.items():
                    if ext.lower() in extensions:
                        return lang

        # Count pattern matches for each language
        matches = {lang: 0 for lang in cls.PATTERNS}
        for lang, patterns in cls.PATTERNS.items():
            for pattern in patterns:
                matches[lang] += len(re.findall(pattern, code))

        # Return the language with the most matches
        if matches:
            best_match = max(matches.items(), key=lambda x: x[1])
            if best_match[1] > 0:
                return best_match[0]

        return "unknown"


class AppSecEngineerAgent(BaseAgent):
    """AppSec Engineer Agent for code vulnerability analysis.
    
    This agent leverages Semgrep to detect vulnerabilities in code and provides
    analysis and remediation suggestions.
    """
    
    name: ClassVar[str] = "AppSecEngineerAgent"
    description: ClassVar[str] = "Security engineer specialized in code scanning and vulnerability detection"
    schema_path: ClassVar[str] = "schemas/agent_schema.yaml"
    
    def __init__(self, config_path: str = None):
        """Initialize the AppSec Engineer Agent.
        
        Args:
            config_path: Path to the agent configuration YAML file.
                If not provided, will look for 'agent.yaml' in the agent's directory.
        """
        super().__init__()
        
        # Set default config path if not provided
        if not config_path:
            agent_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(agent_dir, "agent.yaml")
        
        # Load and validate configuration
        self.config = self._load_config(config_path)
        
        # Initialize tools
        self.tools = {}
        self._initialize_tools()
        
        # Initialize agent
        self.agent = self._create_agent()
    
    def _load_config(self, config_path: str) -> AppSecEngineerAgentConfig:
        """Load and validate the agent configuration.
        
        Args:
            config_path: Path to the configuration YAML file.
            
        Returns:
            Validated AppSecEngineerAgentConfig object.
            
        Raises:
            FileNotFoundError: If the configuration file is not found.
            ValidationError: If the configuration is invalid.
        """
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        # Get path to schema
        schema_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            self.schema_path
        )
        
        # Validate YAML against schema if schema exists
        if os.path.exists(schema_path):
            try:
                with open(config_path, "r") as file:
                    config_data = yaml.safe_load(file)
                
                validation_result = validate_yaml_against_schema(
                    config_data, schema_path
                )
                
                if not validation_result.get("is_valid", False):
                    logger.error(
                        f"Invalid configuration: {validation_result.get('errors', 'Unknown error')}"
                    )
                    raise ValueError(
                        f"Invalid configuration: {validation_result.get('errors', 'Unknown error')}"
                    )
            except Exception as e:
                logger.error(f"Error validating configuration against schema: {str(e)}")
                # Continue with Pydantic validation as fallback
        
        with open(config_path, "r") as file:
            config_data = yaml.safe_load(file)
        
        try:
            # Process environment variables if needed
            if "api_key" in config_data.get("llm_config", {}) and \
               config_data["llm_config"]["api_key"].startswith("$"):
                env_var = config_data["llm_config"]["api_key"][1:]
                config_data["llm_config"]["api_key"] = os.environ.get(env_var)
            
            config = AppSecEngineerAgentConfig(**config_data)
            return config
        except ValidationError as e:
            logger.error(f"Invalid configuration: {e}")
            raise
    
    def _initialize_tools(self):
        """Initialize the tools required by the agent."""
        # Initialize SemgrepCodeScanner
        self.tools["semgrep_code_scanner"] = SemgrepCodeScanner(
            max_scan_time=self.config.max_scan_time,
            rules=self.config.rules
        )
    
    def _create_agent(self) -> Agent:
        """Create and configure the CrewAI agent.
        
        Returns:
            Configured CrewAI Agent
        """
        agent_config = {
            "role": self.config.role,
            "goal": self.config.goal,
            "backstory": self.config.backstory,
            "verbose": self.config.verbose,
            "allow_delegation": self.config.allow_delegation,
            "tools": [self.tools["semgrep_code_scanner"]],
            "memory": self.config.memory,
            "max_iterations": self.config.max_iterations,
            "max_rpm": self.config.max_rpm,
            "cache": self.config.cache
        }
        
        # Add LLM config if specified
        if self.config.llm_config:
            agent_config["llm_config"] = {
                k: v for k, v in self.config.llm_config.model_dump().items() 
                if v is not None
            }
        
        # Add function calling LLM if specified
        if self.config.function_calling_llm:
            agent_config["function_calling_llm"] = {
                k: v for k, v in self.config.function_calling_llm.model_dump().items() 
                if v is not None
            }
        
        return Agent(**agent_config)
    
    def analyze_code(self, code: str, language: str = None) -> Dict:
        """Analyze code for vulnerabilities using Semgrep.
        
        Args:
            code: The source code to analyze.
            language: Optional language hint for Semgrep.
            
        Returns:
            Dictionary containing analysis results or error message.
        """
        if not code:
            return {"error": "No code provided for analysis"}
        
        if "semgrep_code_scanner" not in self.tools:
            return {"error": "Semgrep tool not available"}
        
        try:
            # Create a temporary directory for the code
            temp_dir = Path(f"/tmp/appsec_scan_{uuid.uuid4()}")
            temp_dir.mkdir(parents=True, exist_ok=True)
            
            # Determine filename based on language
            filename = f"code.{language}" if language else "code.txt"
            file_path = temp_dir / filename
            
            # Write code to file
            with open(file_path, "w") as f:
                f.write(code)
            
            # Run semgrep scan
            scanner = cast(SemgrepCodeScanner, self.tools["semgrep_code_scanner"])
            
            # Check code size limit
            code_size_kb = len(code) / 1024
            if code_size_kb > self.config.max_code_size:
                return {
                    "error": (
                        f"Code size exceeds limit of {self.config.max_code_size} KB "
                        f"(actual: {code_size_kb:.2f} KB)"
                    )
                }
            
            # Use the scan_code method
            scan_result = scanner.scan_code(str(file_path), language)
            
            # Generate a formatted report
            if "findings" in scan_result:
                scan_result["report"] = scanner.generate_report(scan_result["findings"])
            
            # Clean up
            shutil.rmtree(temp_dir)
            
            return scan_result
        except Exception as e:
            logger.error(f"Error analyzing code: {e}")
            return {"error": f"Error analyzing code: {str(e)}"}
    
    def analyze_repository(self, repo_url: str) -> Dict:
        """Analyze a Git repository for vulnerabilities.
        
        Args:
            repo_url: URL to the Git repository.
            
        Returns:
            Dictionary containing analysis results or error message.
        """
        if not repo_url:
            return {"error": "No repository URL provided"}
        
        if not is_valid_url(repo_url):
            return {"error": "Invalid repository URL"}
        
        if "semgrep_code_scanner" not in self.tools:
            return {"error": "Semgrep tool not available"}
        
        try:
            # Create a temporary directory for the repository
            temp_dir = Path(f"/tmp/appsec_repo_{uuid.uuid4()}")
            temp_dir.mkdir(parents=True, exist_ok=True)
            
            # Clone the repository
            result = subprocess.run(
                ["git", "clone", repo_url, str(temp_dir)],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                return {"error": f"Failed to clone repository: {result.stderr}"}
            
            # Run semgrep scan
            scanner = cast(SemgrepCodeScanner, self.tools["semgrep_code_scanner"])
            
            # Use the scan_directory method
            scan_result = scanner.scan_directory(str(temp_dir))
            
            # Generate a formatted report
            if "findings" in scan_result:
                scan_result["report"] = scanner.generate_report(scan_result["findings"])
            
            # Clean up
            shutil.rmtree(temp_dir)
            
            return scan_result
        except subprocess.TimeoutExpired:
            return {"error": "Repository cloning timed out"}
        except Exception as e:
            logger.error(f"Error analyzing repository: {e}")
            return {"error": f"Error analyzing repository: {str(e)}"}
            
    def generate_vulnerability_report(self, results: Dict) -> Dict:
        """
        Generate a comprehensive report of vulnerability findings.
        
        Args:
            results: Scan results from analyze_code or analyze_repository
            
        Returns:
            Dictionary with formatted report
        """
        if "error" in results:
            return {"error": results["error"], "status": "error"}
            
        if "findings" not in results:
            return {
                "error": "No findings in scan results",
                "status": "error"
            }
            
        # If report is already generated, return it
        if "report" in results:
            return {
                "report": results["report"],
                "status": "success"
            }
            
        # Otherwise, generate a new report
        scanner = cast(SemgrepCodeScanner, self.tools["semgrep_code_scanner"])
        report = scanner.generate_report(results["findings"])
        
        return {
            "report": report,
            "status": "success"
        }

    def get_task_result(self, task: Any) -> Dict:
        """
        Process the result of a CrewAI task.

        Args:
            task: The completed task

        Returns:
            Dictionary with processed results
        """
        # Extract the task output and format it for return
        try:
            return {
                "result": task.output,
                "status": "success"
            }
        except Exception as e:
            logger.exception(f"Error processing task result: {str(e)}")
            return {
                "error": f"Error processing task result: {str(e)}",
                "status": "error"
            }

    def delegate_to_defect_review(self, findings: List[Dict]) -> Dict:
        """
        Delegate vulnerability findings to a Defect Review Agent for deeper analysis.
        
        Args:
            findings: List of vulnerability findings from Semgrep scan
            
        Returns:
            Dictionary with review results or error
        """
        if not self.config.allow_delegation:
            return {"error": "Delegation not allowed by configuration"}
            
        if not findings:
            return {"error": "No findings to review"}
            
        try:
            # In a real implementation, this would create a task for the Defect Review Agent
            # For now, we'll just return a placeholder
            return {
                "message": "Delegated to Defect Review Agent",
                "status": "delegated",
                "findings_count": len(findings)
            }
        except Exception as e:
            logger.exception(f"Error delegating to Defect Review Agent: {str(e)}")
            return {
                "error": f"Error delegating to Defect Review Agent: {str(e)}",
                "status": "error"
            }
