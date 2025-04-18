"""Tool for scanning cloud environments using Prowler for security posture assessment."""

from typing import Any, ClassVar, Dict, List, Optional
import json
import subprocess
import tempfile
from pathlib import Path

from crewai.tools import BaseTool
from pydantic import BaseModel, ConfigDict, Field


class ProwlerScanInput(BaseModel):
    """Input for Prowler cloud security scan."""

    cloud_provider: str = Field(
        ..., 
        description="Cloud provider to scan (aws, azure, gcp)"
    )
    region: Optional[str] = Field(
        None, 
        description="Region to scan (e.g., us-east-1). Leave empty for all regions."
    )
    categories: Optional[List[str]] = Field(
        None, 
        description="Specific categories to scan (e.g., iam, s3, ec2). Leave empty for all."
    )
    compliance_framework: Optional[str] = Field(
        None, 
        description="Compliance framework to check against (e.g., cis, hipaa, gdpr, pci, soc2, iso27001)"
    )


class ProwlerScanTool(BaseTool):
    """Tool for assessing cloud security posture using Prowler."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: ClassVar[str] = "prowler_cloud_security_scan"
    description: str = (
        "Assesses cloud security posture by scanning cloud environments (AWS, Azure, GCP) "
        "using Prowler. Identifies security risks, compliance issues, and provides recommendations."
    )
    input_schema: ClassVar[type] = ProwlerScanInput

    def _run(
        self, 
        cloud_provider: str,
        region: Optional[str] = None,
        categories: Optional[List[str]] = None,
        compliance_framework: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run Prowler scan against the specified cloud provider.
        
        Args:
            cloud_provider: The cloud provider to scan (aws, azure, gcp)
            region: Optional region to scan
            categories: Optional list of specific categories to scan
            compliance_framework: Optional compliance framework to check against
            
        Returns:
            Dictionary containing scan results and findings
        """
        # Validate cloud provider
        if cloud_provider not in ["aws", "azure", "gcp"]:
            return {
                "error": f"Invalid cloud provider: {cloud_provider}. Must be one of: aws, azure, gcp",
                "status": "failed"
            }
        
        # Create temporary file for output
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as temp_file:
            output_file = temp_file.name
        
        # Build prowler command
        command = ["prowler", cloud_provider]
        
        if region:
            command.extend(["--region", region])
        
        if categories:
            for category in categories:
                command.extend(["--category", category])
        
        if compliance_framework:
            command.extend(["--compliance", compliance_framework])
        
        # Add output format
        command.extend(["--output", "json", "--output-file", output_file])
        
        try:
            # Run prowler command
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False
            )
            
            # Check if prowler ran successfully
            if process.returncode != 0:
                return {
                    "error": f"Prowler scan failed: {process.stderr}",
                    "command": " ".join(command),
                    "status": "failed"
                }
            
            # Read results from output file
            output_path = Path(output_file)
            if output_path.exists() and output_path.stat().st_size > 0:
                with open(output_path, 'r') as f:
                    json_data = json.load(f)
                
                # Process results
                findings = self._process_findings(json_data)
                
                return {
                    "status": "success",
                    "cloud_provider": cloud_provider,
                    "command": " ".join(command),
                    "findings_count": len(findings),
                    "findings": findings,
                    "summary": self._generate_summary(findings)
                }
            else:
                return {
                    "status": "success",
                    "cloud_provider": cloud_provider,
                    "command": " ".join(command),
                    "findings_count": 0,
                    "findings": [],
                    "summary": "No findings generated. This could indicate no issues found or scan configuration issue."
                }
                
        except Exception as e:
            return {
                "error": f"Error running Prowler scan: {str(e)}",
                "command": " ".join(command),
                "status": "failed"
            }
        finally:
            # Clean up temp file
            try:
                Path(output_file).unlink(missing_ok=True)
            except:
                pass

    def _process_findings(self, json_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process the raw JSON findings from Prowler.
        
        Args:
            json_data: Raw JSON data from Prowler output
            
        Returns:
            Processed list of findings with relevant information
        """
        processed_findings = []
        
        for finding in json_data:
            processed_finding = {
                "check_id": finding.get("CheckID"),
                "check_title": finding.get("CheckTitle"),
                "status": finding.get("Status"),
                "severity": finding.get("Severity"),
                "resource_id": finding.get("ResourceId"),
                "region": finding.get("Region"),
                "description": finding.get("Description"),
                "risk": finding.get("Risk"),
                "remediation": finding.get("Remediation", {}).get("Recommendation", "No remediation provided"),
                "compliance": finding.get("Compliance", {})
            }
            processed_findings.append(processed_finding)
            
        return processed_findings
    
    def _generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a summary of the findings.
        
        Args:
            findings: Processed findings
            
        Returns:
            Summary of findings by severity and status
        """
        # Count findings by severity
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        status_count = {"FAIL": 0, "PASS": 0, "WARNING": 0, "INFO": 0}
        
        for finding in findings:
            severity = finding.get("severity", "INFO").upper()
            status = finding.get("status", "INFO").upper()
            
            if severity in severity_count:
                severity_count[severity] += 1
                
            if status in status_count:
                status_count[status] += 1
        
        return {
            "total_findings": len(findings),
            "by_severity": severity_count,
            "by_status": status_count
        }

    async def _arun(
        self, 
        cloud_provider: str,
        region: Optional[str] = None,
        categories: Optional[List[str]] = None,
        compliance_framework: Optional[str] = None
    ) -> Dict[str, Any]:
        """Run Prowler scan asynchronously (delegates to sync)."""
        return self._run(cloud_provider, region, categories, compliance_framework) 