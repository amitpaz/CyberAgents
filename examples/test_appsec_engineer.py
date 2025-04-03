#!/usr/bin/env python3
"""
Test script for the AppSec Engineer Agent.

This script demonstrates how to use the AppSec Engineer Agent to:
1. Analyze code snippets for security vulnerabilities
2. Analyze files for security vulnerabilities
3. Format and display the results
"""

import os
import asyncio
import sys
from pathlib import Path
import json
import datetime

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.appsec_engineer_agent import AppSecEngineerAgent


def print_header(title):
    """Print a formatted header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def print_findings(findings):
    """Print findings in a readable format."""
    if "error" in findings:
        print(f"Error: {findings['error']}")
        return

    # Print scan metadata
    if "scan_metadata" in findings:
        metadata = findings["scan_metadata"]
        print(f"Scan ID: {metadata.get('scan_id')}")
        print(f"Language: {metadata.get('language', 'Multiple/Unknown')}")
        print(f"Scan Time: {metadata.get('scan_time', 0):.2f} seconds")
        print(f"Code Size: {metadata.get('code_size', 0)} bytes")

    # Print severity summary
    if "severity_summary" in findings:
        summary = findings["severity_summary"]
        print("\nSeverity Summary:")
        severity_order = ["critical", "high", "medium", "low", "info"]
        for level in severity_order:
            count = summary.get(level, 0)
            if count > 0:
                print(f"  {level.upper()}: {count}")

    # Print findings
    results = findings.get("findings", [])
    print(f"\nTotal Findings: {len(results)}")

    if results:
        # Sort by severity
        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4
        }
        
        sorted_findings = sorted(
            results, 
            key=lambda x: severity_order.get(x.get("severity", "info").lower(), 999)
        )
        
        # Print findings with details
        for i, finding in enumerate(sorted_findings):
            print(f"\n{i+1}. {finding.get('rule_id')} ({finding.get('severity', 'info').upper()})")
            print(f"   Message: {finding.get('message')}")
            print(f"   File: {finding.get('path')}, Line: {finding.get('line')}")
            if "code" in finding and finding["code"]:
                print(f"   Code: {finding['code'].strip()}")
            if "cwe" in finding and finding["cwe"]:
                print(f"   CWE: {', '.join(finding['cwe'])}")
            if "owasp" in finding and finding["owasp"]:
                print(f"   OWASP: {', '.join(finding['owasp'])}")


async def analyze_code_snippet():
    """Analyze a code snippet for security vulnerabilities."""
    print_header("Analyzing Code Snippet")
    
    # Example vulnerable code
    code = """
    def process_user_data(user_input):
        import os
        # Command injection vulnerability
        os.system("echo " + user_input)
        
        # SQL injection vulnerability
        query = "SELECT * FROM users WHERE username = '" + user_input + "'"
        db.execute(query)
        
        # Path traversal vulnerability
        with open("/var/www/html/" + user_input, "r") as f:
            return f.read()
    """
    
    print("Analyzing the following code snippet:")
    print("-" * 40)
    print(code)
    print("-" * 40)
    
    # Initialize agent and analyze code
    agent = AppSecEngineerAgent()
    findings = await agent.analyze_code(code, language="python", filename="snippet.py")
    
    # Print results
    print_findings(findings)


async def analyze_vulnerability_samples():
    """Analyze the vulnerable code samples."""
    print_header("Analyzing Vulnerable Code Samples")
    
    # Initialize agent
    agent = AppSecEngineerAgent()
    
    # Paths to test files
    test_cases_dir = Path(__file__).parent / "test_cases"
    python_file = test_cases_dir / "vulnerable_python.py"
    js_file = test_cases_dir / "vulnerable_javascript.js"
    
    # Read test files
    with open(python_file, "r") as f:
        python_code = f.read()
    
    with open(js_file, "r") as f:
        js_code = f.read()
    
    # Analyze Python code
    print("\nAnalyzing Python vulnerabilities:")
    python_findings = await agent.analyze_code(
        python_code, 
        language="python",
        filename="vulnerable_python.py"
    )
    print_findings(python_findings)
    
    # Analyze JavaScript code
    print("\nAnalyzing JavaScript vulnerabilities:")
    js_findings = await agent.analyze_code(
        js_code, 
        language="javascript",
        filename="vulnerable_javascript.js"
    )
    print_findings(js_findings)
    
    # Write findings to JSON files for reference
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    output_dir = Path(__file__).parent / "results"
    os.makedirs(output_dir, exist_ok=True)
    
    with open(output_dir / f"python_findings_{timestamp}.json", "w") as f:
        json.dump(python_findings, f, indent=2)
    
    with open(output_dir / f"js_findings_{timestamp}.json", "w") as f:
        json.dump(js_findings, f, indent=2)
    
    print(f"\nFindings saved to {output_dir}")


async def main():
    """Run the AppSec Engineer Agent test script."""
    print_header("AppSec Engineer Agent Test")
    print("This script tests the functionality of the AppSec Engineer Agent")
    print("by scanning various code samples for security vulnerabilities.")
    
    await analyze_code_snippet()
    await analyze_vulnerability_samples()


if __name__ == "__main__":
    asyncio.run(main()) 