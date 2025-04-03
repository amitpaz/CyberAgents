#!/usr/bin/env python3
"""
Example script that demonstrates using the AppSec Engineer Agent to scan
a vulnerable JavaScript application for security issues.

This script:
1. Syncs Semgrep policies for JavaScript/Node.js
2. Runs the AppSec Engineer Agent on the vulnerable JS application
3. Outputs a security report with findings and recommendations
"""

import os
import sys
import json
import asyncio
from pathlib import Path
import datetime

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.appsec_engineer_agent import AppSecEngineerAgent
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
    result = sync_language_policies(["javascript", "typescript", "nodejs"])
    
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
    """Scan the JavaScript application using the AppSec Engineer Agent."""
    print_header("Scanning JavaScript Application")
    
    print(f"Scanning application at: {JS_APP_PATH}")
    
    # Initialize the AppSec Engineer Agent
    appsec_agent = AppSecEngineerAgent()
    
    # Set scan options
    scan_options = {
        "use_local_policies": True,
        "policy_preference": "both",  # Use both registry and local policies
        "severity_threshold": "info",  # Report all issues
        "rules": ["p/javascript", "p/nodejs", "p/express", "p/security-audit", "p/owasp-top-ten"],
    }
    
    # Scan the JavaScript application
    print("Starting security scan...")
    result = await appsec_agent.analyze_repository(
        str(JS_APP_PATH),
        scan_options=scan_options
    )
    
    return result


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
    severity_counts = {}
    
    for finding in findings:
        severity = finding.get("severity", "unknown").lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print(f"Total findings: {len(findings)}")
    
    # Print sorted by severity
    severity_order = ["critical", "high", "medium", "low", "info"]
    for severity in severity_order:
        if severity in severity_counts:
            print(f"  {severity.upper()}: {severity_counts[severity]}")
    
    # Print top 5 most critical findings
    critical_findings = sorted(
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
    
    if critical_findings:
        print("\nTop critical findings:")
        for i, finding in enumerate(critical_findings[:5]):
            severity = finding.get("severity", "unknown").upper()
            rule_id = finding.get("rule_id", "unknown")
            message = finding.get("message", "No description")
            file_path = finding.get("path", "unknown")
            line = finding.get("line", 0)
            
            print(f"{i+1}. [{severity}] {rule_id}")
            print(f"   {message}")
            print(f"   File: {file_path}, Line: {line}")
    
    # Print recommendation summary
    recommendations = result.get("recommendations", [])
    if recommendations:
        print("\nRecommendations:")
        for i, rec in enumerate(recommendations[:5]):
            print(f"{i+1}. {rec}")


async def main():
    """Run the JavaScript application security scan."""
    print_header("JavaScript Application Security Scan")
    print("This example demonstrates how to use the AppSec Engineer Agent to scan")
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