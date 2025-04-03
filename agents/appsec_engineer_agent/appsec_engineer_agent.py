"""
AppSec Engineer Agent for security code scanning and vulnerability detection.

This agent is capable of analyzing code for security vulnerabilities using
Semgrep as the primary scanning tool. It can process code provided directly
or clone and scan GitHub repositories.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from crewai import Agent

from agents.base_agent import BaseAgent
from utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


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


class SemgrepRunner:
    """Handles running Semgrep scans on code."""

    def __init__(self, rules: List[str] = [], max_scan_time: int = 300):
        """
        Initialize the Semgrep runner. Finds the semgrep executable path.

        Args:
            rules: List of Semgrep rule sets to use
            max_scan_time: Maximum scan time in seconds
        """
        self.rules = rules
        self.max_scan_time = max_scan_time
        # Find the semgrep executable
        self.semgrep_executable = shutil.which("semgrep")
        if not self.semgrep_executable:
            logger.warning("Semgrep executable not found in PATH. Scans will fail.")
            # Or raise an error: raise FileNotFoundError("Semgrep executable not found")

    def _prepare_rules_arg(self) -> str:
        """Prepare the rules argument for Semgrep command."""
        return ",".join(self.rules)

    def scan_code(self, code_path: str, language: Optional[str] = None) -> Dict:
        """
        Run Semgrep scan on the provided code.

        Args:
            code_path: Path to the code to scan
            language: Optional language to force for Semgrep

        Returns:
            Dictionary with scan results
        """
        if not self.semgrep_executable:
            return {"error": "Semgrep executable not found.", "findings": []}

        # Prepare command using the found executable path
        cmd = [
            self.semgrep_executable,
            "--json",
            "-q",  # Quiet mode
        ]
        # Add config explicitly: use rules if provided, otherwise use "auto"
        if self.rules:
            cmd.append(f"--config={self._prepare_rules_arg()}")
        else:
            cmd.append("--config=auto") # Use auto configuration if no rules specified

        # Add language if specified
        if language and language != "unknown":
            cmd.append(f"--lang={language}")

        # Add path to scan
        cmd.append(code_path)

        # Log the exact command being run
        logger.info(f"Executing Semgrep command: {cmd}")

        try:
            # Run with timeout
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.max_scan_time
            )

            if result.returncode != 0 and result.returncode != 1:
                # Semgrep returns 1 when it finds issues, which is normal
                logger.error(f"Semgrep error: {result.stderr}")
                return {"error": result.stderr, "findings": []}

            # Parse JSON output
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse Semgrep output: {result.stdout}")
                return {"error": "Failed to parse Semgrep output", "findings": []}

        except subprocess.TimeoutExpired:
            return {
                "error": f"Semgrep scan timed out after {self.max_scan_time} seconds",
                "findings": [],
            }
        except Exception as e:
            logger.exception(f"Error running Semgrep: {str(e)}")
            return {"error": f"Error running Semgrep: {str(e)}", "findings": []}


class AppSecEngineerAgent(BaseAgent):
    """
    Application Security Engineer Agent that identifies security vulnerabilities in code.

    This agent uses Semgrep to scan code for security issues, and can analyze both
    direct code input and GitHub repositories.
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the AppSec Engineer Agent.

        Args:
            config: Optional configuration overrides
        """
        super().__init__()

        # Load config
        self.config = self._load_config()
        if config:
            self.config.update(config)

        # Set up rate limiter
        self.rate_limiter = RateLimiter(
            max_requests=self.config["rate_limit"],
            time_window=3600,  # Renamed max_calls->max_requests, time_period->time_window
        )

        # Initialize Semgrep runner
        self.semgrep = SemgrepRunner(
            rules=self.config["semgrep_rules"],
            max_scan_time=self.config["max_scan_time"],
        )

        # Ensure temp directory exists
        try:
            os.makedirs(self.config["temp_dir"], exist_ok=True)
        except OSError as e:
            logger.warning(
                f"Could not create temp directory {self.config['temp_dir']}: {e}. "
                f"Repository scanning might fail."
            )

        # Initialize the CrewAI Agent
        self.agent = Agent(
            role="Application Security Engineer",
            goal=(
                "Analyze code and repositories for security vulnerabilities using "
                "Semgrep, identify potential risks, and collaborate with Defect "
                "Review Agent for remediation."
            ),
            backstory=(
                "You are a highly skilled Application Security Engineer with "
                "expertise in static code analysis. Your primary function is "
                "to proactively identify security flaws in software during the "
                "development lifecycle. You leverage powerful tools like Semgrep "
                "to scan code written in various languages, focusing on common "
                "vulnerability patterns (OWASP Top 10, security audits). You "
                "meticulously analyze scan results, determine the severity of "
                "findings, and communicate them clearly. You coordinate with "
                "the Defect Review Agent to ensure vulnerabilities are "
                "properly documented, prioritized, and tracked."
            ),
            verbose=True,
            allow_delegation=True,  # Allows coordination with Defect Review Agent
            # tools=[self.analyze_code_tool, self.analyze_repository_tool] # Define tools if using CrewAI tools framework
            # llm=self.get_llm() # Assuming a method to get the LLM
        )

    def _load_config(self) -> Dict:
        """
        Load the agent configuration from agent.yaml.

        Returns:
            Dictionary with configuration
        """
        # Get the directory where this file is located
        current_dir = Path(__file__).parent
        config_path = current_dir / "agent.yaml"

        with open(config_path, "r") as file:
            yaml_content = yaml.safe_load(file)

        return yaml_content.get("config", {})

    async def analyze_code(
        self, code: str, language: Optional[str] = None, filename: Optional[str] = None
    ) -> Dict:
        """
        Analyze code for security vulnerabilities.

        Args:
            code: The code to analyze
            language: Optional language override
            filename: Optional filename for context

        Returns:
            Dictionary with analysis results
        """
        # Check rate limit
        try:
            await self.rate_limiter.acquire()
        except Exception as e:
            logger.warning(f"Rate limit hit for code analysis: {e}")
            return {"error": str(e)}

        # Check code size
        if len(code) > self.config["max_code_size"] * 1024:
            return {
                "error": f"Code exceeds maximum size of {self.config['max_code_size']} KB"
            }

        # Detect language if not provided
        detected_language = language or CodeLanguageDetector.detect_language(
            code, filename
        )

        # Check if language is supported
        if (
            detected_language != "unknown"
            and detected_language not in self.config["supported_languages"]
        ):
            return {"error": f"Language '{detected_language}' is not supported"}

        # Create temporary file with the code
        scan_id = str(uuid.uuid4())
        temp_dir = os.path.join(self.config["temp_dir"], scan_id)
        os.makedirs(temp_dir, exist_ok=True)

        try:
            # Determine proper file extension
            extension = ".txt"
            if detected_language != "unknown":
                extensions = CodeLanguageDetector.EXTENSIONS.get(detected_language, [])
                if extensions:
                    extension = extensions[0]

            # Use provided filename or create a default one
            if filename:
                file_path = os.path.join(temp_dir, filename)
            else:
                file_path = os.path.join(temp_dir, f"code{extension}")

            # Write code to file
            with open(file_path, "w") as file:
                file.write(code)

            # Run Semgrep scan
            start_time = time.time()
            results = self.semgrep.scan_code(temp_dir, detected_language)
            scan_time = time.time() - start_time

            # Process results
            findings = self._process_scan_results(results, scan_id, detected_language)

            # Forward findings to Defect Review Agent if there are any
            if findings["findings"]:
                await self._forward_to_defect_review(findings, code)

            # Add metadata
            findings["scan_metadata"] = {
                "scan_id": scan_id,
                "language": detected_language,
                "scan_time": scan_time,
                "code_size": len(code),
            }

            return findings

        finally:
            # Clean up
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.error(f"Failed to clean up temporary directory: {str(e)}")

    async def analyze_repository(
        self, repo_url: str, branch: Optional[str] = None
    ) -> Dict:
        """
        Clone and analyze a GitHub repository.

        Args:
            repo_url: URL of the GitHub repository
            branch: Optional branch to analyze

        Returns:
            Dictionary with analysis results
        """
        # Check rate limit
        try:
            await self.rate_limiter.acquire()
        except Exception as e:
            logger.warning(f"Rate limit hit for repository analysis: {e}")
            return {"error": str(e)}

        # Validate GitHub URL
        if not self._is_valid_github_url(repo_url):
            return {"error": "Invalid GitHub repository URL"}

        # Create temporary directory for the repository
        scan_id = str(uuid.uuid4())
        temp_dir = os.path.join(self.config["temp_dir"], scan_id)

        try:
            # Clone repository
            clone_result = self._clone_repository(repo_url, temp_dir, branch)
            if "error" in clone_result:
                return clone_result

            # Check repository size
            repo_size = self._get_directory_size(temp_dir)
            if repo_size > self.config["max_code_size"] * 1024:
                return {
                    "error": f"Repository exceeds maximum size of {self.config['max_code_size']} KB"
                }

            # Run Semgrep scan using its default config ('auto' if rules are empty)
            start_time = time.time()
            # Don't pass specific rules, let scan_code use its default (--config=auto)
            results = self.semgrep.scan_code(temp_dir)
            scan_time = time.time() - start_time

            # Process results
            findings = self._process_scan_results(results, scan_id)

            # Add metadata
            findings["scan_metadata"] = {
                "scan_id": scan_id,
                "repository": repo_url,
                "branch": branch or "default",
                "scan_time": scan_time,
                "repository_size": repo_size,
            }

            # Forward findings to Defect Review Agent if there are any
            if findings["findings"]:
                # We can't forward the entire repo, so we'll extract vulnerable code
                for finding in findings["findings"]:
                    if "path" in finding and "line" in finding:
                        file_path = os.path.join(temp_dir, finding["path"])
                        if os.path.isfile(file_path):
                            try:
                                with open(file_path, "r") as file:
                                    code_lines = file.readlines()

                                # Extract context around the vulnerability
                                start_line = max(0, finding["line"] - 5)
                                end_line = min(len(code_lines), finding["line"] + 5)
                                context = "".join(code_lines[start_line:end_line])

                                finding["code_context"] = context
                            except Exception as e:
                                logger.error(
                                    f"Failed to extract code context: {str(e)}"
                                )

                await self._forward_to_defect_review(findings, None)

            return findings

        finally:
            # Clean up
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.error(f"Failed to clean up repository directory: {str(e)}")

    def _is_valid_github_url(self, url: str) -> bool:
        """Check if the provided URL is a valid GitHub repository URL."""
        github_pattern = r"^https?://github\.com/[\w-]+/[\w.-]+/?$"
        return bool(re.match(github_pattern, url))

    def _clone_repository(
        self, repo_url: str, target_dir: str, branch: Optional[str] = None
    ) -> Dict:
        """
        Clone a GitHub repository into the target directory.

        Args:
            repo_url: URL of the GitHub repository
            target_dir: Directory where the repository should be cloned
            branch: Optional branch to clone

        Returns:
            Dictionary with status of the operation
        """
        try:
            # Prepare clone command
            cmd = ["git", "clone"]

            # Add branch specification if provided
            if branch:
                cmd.extend(["--branch", branch])

            # Add depth to limit clone size
            cmd.extend(["--depth", "1"])

            # Add repository URL and target directory
            cmd.extend([repo_url, target_dir])

            # Run git clone
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes timeout for cloning
            )

            if result.returncode != 0:
                return {"error": f"Failed to clone repository: {result.stderr}"}

            return {"status": "success"}

        except subprocess.TimeoutExpired:
            return {"error": "Repository cloning timed out"}
        except Exception as e:
            return {"error": f"Error cloning repository: {str(e)}"}

    def _get_directory_size(self, directory: str) -> int:
        """
        Calculate the total size of a directory in bytes.

        Args:
            directory: Path to the directory

        Returns:
            Size in bytes
        """
        total_size = 0
        for dirpath, _, filenames in os.walk(directory):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                total_size += os.path.getsize(file_path)
        return total_size

    def _process_scan_results(
        self, results: Dict, scan_id: str, language: Optional[str] = None
    ) -> Dict:
        """
        Process raw Semgrep scan results into a structured format.

        Args:
            results: Raw Semgrep results
            scan_id: Unique identifier for the scan
            language: Detected programming language

        Returns:
            Structured findings dictionary
        """
        processed_results = {
            "scan_id": scan_id,
            "findings": [],
            "severity_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "language": language,
        }

        # Check if there was an error
        if "error" in results:
            processed_results["error"] = results["error"]
            return processed_results

        # Process findings
        if "results" in results:
            for result in results["results"]:
                finding = {
                    "rule_id": result.get("check_id", "unknown"),
                    "message": result.get("extra", {}).get(
                        "message", "No description available"
                    ),
                    "severity": result.get("extra", {}).get("severity", "info"),
                    "path": result.get("path", "unknown"),
                    "line": result.get("start", {}).get("line", 0),
                    "code": result.get("extra", {}).get("lines", ""),
                    "cwe": result.get("extra", {}).get("metadata", {}).get("cwe", []),
                    "owasp": result.get("extra", {})
                    .get("metadata", {})
                    .get("owasp", []),
                }

                # Update severity counter
                severity = finding["severity"].lower()
                if severity in processed_results["severity_summary"]:
                    processed_results["severity_summary"][severity] += 1
                else:
                    processed_results["severity_summary"]["info"] += 1

                processed_results["findings"].append(finding)

        return processed_results

    async def _forward_to_defect_review(
        self, findings: Dict, code: Optional[str]
    ) -> None:
        """
        Forward findings to the Defect Review Agent if significant issues are found.

        Args:
            findings: Processed scan results
            code: The code snippet that was scanned, if available
        """
        # Check if there are any high-severity findings
        high_severity = any(
            finding["severity"] == "ERROR" for finding in findings.get("findings", [])
        )

        if high_severity:
            # TODO: Implement communication logic with Defect Review Agent
            # For now, just log the intention
            logger.info(
                f"High severity findings detected in scan {findings.get('scan_id')}. "
                "Forwarding to Defect Review Agent (not implemented yet)."
            )
            # Example placeholder:
            # defect_review_agent.review_findings(findings, code)
            pass
