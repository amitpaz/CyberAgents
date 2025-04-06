"""Tool for scanning git repositories for secrets using TruffleHog.

This tool provides a wrapper around the TruffleHog scanner, which is designed
to detect secrets, API keys, and credentials in git repositories.
"""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Union

from langchain.tools import BaseTool

logger = logging.getLogger(__name__)


class TruffleHogScannerTool(BaseTool):
    """Tool for scanning git repositories for secrets using TruffleHog.
    
    Provides interfaces for scanning both local and remote repositories
    to detect potential secrets, API keys, and credentials.
    """
    
    name = "trufflehog_scanner_tool"
    description = (
        "Scans git repositories for exposed secrets, API keys, credentials, "
        "and other sensitive information using TruffleHog."
    )
    
    def __init__(self):
        """Initialize the TruffleHog scanner tool."""
        super().__init__()
        self._check_trufflehog_installation()
    
    def _check_trufflehog_installation(self):
        """Check if TruffleHog is installed and available in the PATH."""
        try:
            result = subprocess.run(
                ["trufflehog", "--version"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                check=False
            )
            if result.returncode != 0:
                logger.warning(
                    "TruffleHog may not be installed or not available in PATH. "
                    "Tool functionality will be limited."
                )
        except FileNotFoundError:
            logger.warning(
                "TruffleHog not found. Please install it with: "
                "'pip install trufflehog' or 'brew install trufflehog'"
            )
    
    def _run(self, query: str) -> str:
        """Execute TruffleHog scan based on the given query.
        
        Args:
            query: String containing the scan parameters.
                  Format: "type:target" where type can be:
                  - github: Scan a GitHub repository (e.g., github:username/repo)
                  - local: Scan a local repository path (e.g., local:/path/to/repo)
                  - file: Scan a specific file (e.g., file:/path/to/file)
                  
        Returns:
            A string containing the scan results in a formatted report.
        """
        # Parse the query type and target
        if ":" not in query:
            return "Please provide a query in the format 'type:target'"
        
        query_parts = query.split(":", 1)
        scan_type = query_parts[0].strip().lower()
        target = query_parts[1].strip()
        
        if scan_type == "github":
            return self._scan_github_repo(target)
        elif scan_type == "local":
            return self._scan_local_repo(target)
        elif scan_type == "file":
            return self._scan_file(target)
        else:
            return f"Unsupported scan type: {scan_type}. Use 'github', 'local', or 'file'."
    
    def _scan_github_repo(self, repo: str) -> str:
        """Scan a GitHub repository for secrets.
        
        Args:
            repo: GitHub repository in the format 'username/repository'
            
        Returns:
            Formatted results of the scan
        """
        logger.info(f"Scanning GitHub repository: {repo}")
        
        # Convert to full GitHub URL if needed
        if not repo.startswith("https://") and not repo.startswith("git@"):
            repo_url = f"https://github.com/{repo}.git"
        else:
            repo_url = repo
            
        with tempfile.TemporaryDirectory() as temp_dir:
            # First, try to clone the repository
            try:
                logger.info(f"Cloning repository {repo_url} to {temp_dir}")
                subprocess.run(
                    ["git", "clone", "--depth=50", repo_url, temp_dir],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True
                )
            except subprocess.CalledProcessError as e:
                return f"Error cloning repository {repo_url}: {e.stderr.decode('utf-8')}"
            
            # Now scan the local clone
            return self._scan_local_repo(temp_dir)
    
    def _scan_local_repo(self, path: str) -> str:
        """Scan a local git repository for secrets.
        
        Args:
            path: Path to the local repository
            
        Returns:
            Formatted results of the scan
        """
        logger.info(f"Scanning local repository: {path}")
        
        if not os.path.exists(path):
            return f"Error: Path does not exist: {path}"
            
        if not os.path.exists(os.path.join(path, ".git")):
            return f"Error: Not a git repository: {path}"
        
        try:
            # Run TruffleHog against the local repository
            result = subprocess.run(
                [
                    "trufflehog", 
                    "git", 
                    path, 
                    "--json"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False  # Don't raise exception on non-zero exit code
            )
            
            if result.returncode != 0 and result.returncode != 1:  # TruffleHog returns 1 when findings exist
                error_msg = result.stderr.decode('utf-8')
                logger.error(f"TruffleHog scan error: {error_msg}")
                return f"Error scanning repository: {error_msg}"
            
            # Process the output
            return self._process_scan_results(result.stdout.decode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error during TruffleHog scan: {str(e)}")
            return f"Error during repository scan: {str(e)}"
    
    def _scan_file(self, file_path: str) -> str:
        """Scan a specific file for secrets.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Formatted results of the scan
        """
        logger.info(f"Scanning file: {file_path}")
        
        if not os.path.exists(file_path):
            return f"Error: File does not exist: {file_path}"
            
        if not os.path.isfile(file_path):
            return f"Error: Not a file: {file_path}"
        
        try:
            # Run TruffleHog against the specific file
            # Note: TruffleHog doesn't have a built-in file scanner, so we'll create a temporary
            # repo and add the file to it for scanning
            with tempfile.TemporaryDirectory() as temp_dir:
                # Copy the file to the temp directory
                temp_file_path = os.path.join(temp_dir, os.path.basename(file_path))
                with open(file_path, 'rb') as src, open(temp_file_path, 'wb') as dst:
                    dst.write(src.read())
                
                # Initialize a git repo
                subprocess.run(
                    ["git", "init"],
                    cwd=temp_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True
                )
                
                # Configure git user for the commit
                subprocess.run(
                    ["git", "config", "user.email", "scanner@example.com"],
                    cwd=temp_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True
                )
                subprocess.run(
                    ["git", "config", "user.name", "Secret Scanner"],
                    cwd=temp_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True
                )
                
                # Add and commit the file
                subprocess.run(
                    ["git", "add", os.path.basename(file_path)],
                    cwd=temp_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True
                )
                subprocess.run(
                    ["git", "commit", "-m", "Adding file for scan"],
                    cwd=temp_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True
                )
                
                # Now scan the temporary repo
                return self._scan_local_repo(temp_dir)
                
        except Exception as e:
            logger.error(f"Error during file scan: {str(e)}")
            return f"Error during file scan: {str(e)}"
    
    def _process_scan_results(self, output: str) -> str:
        """Process TruffleHog output into a formatted report.
        
        Args:
            output: Raw output from TruffleHog
            
        Returns:
            Formatted scan results
        """
        if not output.strip():
            return "No secrets detected in the scan."
        
        findings = []
        
        # TruffleHog outputs one JSON object per line
        for line in output.strip().split('\n'):
            try:
                if line.strip():
                    finding = json.loads(line)
                    findings.append(finding)
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse TruffleHog output line: {line}")
        
        if not findings:
            return "No valid findings in scan results."
        
        # Create a formatted report
        result = "### TruffleHog Scan Results\n\n"
        result += f"Found {len(findings)} potential secrets or sensitive information.\n\n"
        
        for i, finding in enumerate(findings, 1):
            result += f"**Finding {i}**\n\n"
            
            if "SourceMetadata" in finding and "Data" in finding["SourceMetadata"]:
                meta = finding["SourceMetadata"]["Data"]
                if "Git" in meta:
                    git_data = meta["Git"]
                    result += f"- **Commit**: {git_data.get('commit', 'Unknown')}\n"
                    result += f"- **File**: {git_data.get('file', 'Unknown')}\n"
                    result += f"- **Email**: {git_data.get('email', 'Unknown')}\n"
                    result += f"- **Timestamp**: {git_data.get('timestamp', 'Unknown')}\n"
            
            result += f"- **Detector**: {finding.get('DetectorName', 'Unknown')}\n"
            result += f"- **Confidence**: {self._get_confidence_level(finding)}\n"
            
            # Don't include the actual secret in the report for security reasons
            result += f"- **Verification Status**: Needs verification\n\n"
            
            if "Raw" in finding and finding["Raw"]:
                raw_excerpt = finding["Raw"]
                # Sanitize and truncate the raw excerpt to avoid exposing the actual secret
                sanitized = self._sanitize_raw_data(raw_excerpt)
                result += f"```\n{sanitized}\n```\n\n"
            
        result += "**Note:** This is an automated scan. All findings should be manually verified."
        result += " False positives are possible, and the scan may not detect all secrets."
        
        return result
    
    def _get_confidence_level(self, finding: Dict) -> str:
        """Determine the confidence level of a finding.
        
        Args:
            finding: The finding data from TruffleHog
            
        Returns:
            A string indicating the confidence level
        """
        # TruffleHog doesn't provide a direct confidence score, so we'll infer one
        detector = finding.get("DetectorName", "").lower()
        
        high_confidence_detectors = ["aws", "github", "private_key", "slack"]
        medium_confidence_detectors = ["generic_api_key", "stripe", "twitter"]
        
        if any(hc in detector for hc in high_confidence_detectors):
            return "High"
        elif any(mc in detector for mc in medium_confidence_detectors):
            return "Medium"
        else:
            return "Low"
    
    def _sanitize_raw_data(self, raw_data: str) -> str:
        """Sanitize raw data to avoid exposing actual secrets.
        
        Args:
            raw_data: The raw data snippet from TruffleHog
            
        Returns:
            A sanitized version of the data
        """
        # Truncate if too long
        if len(raw_data) > 200:
            raw_data = raw_data[:200] + "..."
        
        # Redact potential secrets
        secret_patterns = [
            r'([\'"])(?:apikey|api_key|key|token|secret|password|pwd|pw)([\'"])\s*(?::|=>|=)\s*([\'"])(\w+)([\'"])',
            r'([\'"])(?:access_token|access_key|access-token|access-key)([\'"])\s*(?::|=>|=)\s*([\'"])(\w+)([\'"])',
        ]
        
        redacted = raw_data
        for pattern in secret_patterns:
            import re
            redacted = re.sub(pattern, r'\1\2\3[REDACTED]\5', redacted)
        
        return redacted
            
    async def _arun(self, query: str) -> str:
        """Async implementation - for this tool, just calls the sync version."""
        return self._run(query) 