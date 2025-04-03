#!/usr/bin/env python3
"""
Example script that demonstrates using the Semgrep Scanner tool to scan
a vulnerable JavaScript application for security issues.

This script:
1. Syncs Semgrep policies for JavaScript/Node.js
2. Runs the Semgrep Scanner on the vulnerable JS application
3. Outputs a security report with findings
"""

import os
import sys
import json
import asyncio
from pathlib import Path
import datetime

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.semgrep_scanner import SemgrepTool
from tools.semgrep_scanner.utils import sync_language_policies

# Configure paths
JS_APP_PATH = Path(__file__).parent / "js_vulnerable_app"
RESULTS_DIR = Path(__file__).parent / "results"
REPORT_FILE = RESULTS_DIR / f"js_app_security_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

# Ensure results directory exists
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def print_header(title):
    """Print a formatted header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


async def sync_js_policies():
    """Synchronize JavaScript and Node.js policies from Semgrep repository."""
    print_header("Synchronizing JavaScript Policies")
    
    print("Synchronizing JavaScript and Node.js policies from Semgrep repository...")
    result = sync_language_policies(["javascript", "typescript"])
    
    if result.get("success", False):
        print(f"Successfully synchronized {result['total_policies']} policies")
        for lang, count in result.get("languages", {}).items():
            print(f"  {lang}: {count} policies")
        return True
    else:
        print(f"Warning: Policy synchronization failed. Using registry rules only.")
        print(f"Error: {result.get('message', 'Unknown error')}")
        return False


async def scan_js_application():
    """Scan the JavaScript application using the Semgrep Scanner tool."""
    print_header("Scanning JavaScript Application")
    
    print(f"Scanning application at: {JS_APP_PATH}")
    
    # Initialize the Semgrep Scanner Tool
    semgrep_tool = SemgrepTool()
    
    # Scan the JavaScript application
    print("Starting security scan...")
    
    # Scan server.js (Node.js/Express)
    server_file = JS_APP_PATH / "server.js"
    print(f"Scanning server-side code: {server_file}")
    server_result = await semgrep_tool.run(
        file_path=str(server_file),
        language="javascript",
        rules=["p/javascript", "p/nodejs", "p/express", "p/security-audit"],
        use_local_policies=True,
        policy_preference="both"
    )
    
    # Scan client.js (Browser JavaScript)
    client_file = JS_APP_PATH / "client.js"
    print(f"Scanning client-side code: {client_file}")
    client_result = await semgrep_tool.run(
        file_path=str(client_file),
        language="javascript",
        rules=["p/javascript", "p/security-audit"],
        use_local_policies=True,
        policy_preference="both"
    )
    
    # Combine results
    combined_findings = []
    if "findings" in server_result:
        combined_findings.extend(server_result["findings"])
    if "findings" in client_result:
        combined_findings.extend(client_result["findings"])
    
    # Create combined summary
    severity_summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    
    for finding in combined_findings:
        severity = finding.get("severity", "info").lower()
        if severity in severity_summary:
            severity_summary[severity] += 1
    
    combined_result = {
        "findings": combined_findings,
        "severity_summary": severity_summary,
        "stats": {
            "total_findings": len(combined_findings),
            "files_scanned": 2,
            "scan_time": server_result.get("stats", {}).get("scan_time", 0) + 
                         client_result.get("stats", {}).get("scan_time", 0)
        },
        "policy_config": {
            "server": server_result.get("policy_config", {}),
            "client": client_result.get("policy_config", {})
        }
    }
    
    return combined_result


def save_report(result):
    """Save the scan results to a JSON file."""
    try:
        with open(REPORT_FILE, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"Security report saved to: {REPORT_FILE}")
    except Exception as e:
        print(f"Error saving report: {str(e)}")


def print_summary(result):
    """Print a summary of the scan results."""
    print_header("Security Scan Summary")
    
    # Check if there was an error
    if "error" in result:
        print(f"Error during scan: {result['error']}")
        return
    
    # Print findings count by severity
    findings = result.get("findings", [])
    severity_counts = result.get("severity_summary", {})
    
    print(f"Total findings: {len(findings)}")
    
    # Print sorted by severity
    severity_order = ["critical", "high", "medium", "low", "info"]
    for severity in severity_order:
        if severity in severity_counts and severity_counts[severity] > 0:
            print(f"  {severity.upper()}: {severity_counts[severity]}")
    
    # Print top findings by severity
    if findings:
        # Sort findings by severity
        sorted_findings = sorted(
            findings,
            key=lambda x: {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "info": 4,
                "unknown": 5
            }.get(x.get("severity", "unknown").lower(), 6)
        )
        
        print("\nTop security findings:")
        # Print top 10 findings or all if less than 10
        for i, finding in enumerate(sorted_findings[:10]):
            severity = finding.get("severity", "unknown").upper()
            rule_id = finding.get("rule_id", "unknown")
            message = finding.get("message", "No description")
            file_path = finding.get("path", "unknown")
            line = finding.get("line", 0)
            
            print(f"{i+1}. [{severity}] {rule_id}")
            print(f"   {message}")
            print(f"   File: {file_path}, Line: {line}")
            if "code" in finding and finding["code"]:
                print(f"   Code: {finding['code'].strip()}")
            print()


async def main():
    """Run the JavaScript application security scan."""
    print_header("JavaScript Application Security Scan")
    print("This example demonstrates how to use the Semgrep Scanner tool to scan")
    print("a vulnerable JavaScript application for security issues.")
    
    # First, sync policies
    policies_synced = await sync_js_policies()
    
    # Scan the JavaScript application
    scan_result = await scan_js_application()
    
    # Save the report
    save_report(scan_result)
    
    # Print summary
    print_summary(scan_result)
    
    print("\nScan completed.")


if __name__ == "__main__":
    asyncio.run(main()) 