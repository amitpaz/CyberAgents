#!/usr/bin/env python3
"""
Example script demonstrating how to use the Semgrep Scanner Tool.

This script shows:
1. How to scan a code snippet for vulnerabilities
2. How to scan a file for vulnerabilities
3. How to process and display the results
"""

import os
import asyncio
import sys
from pathlib import Path
import json

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.semgrep_scanner import SemgrepTool


def print_header(title):
    """Print a formatted header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def print_findings(result):
    """Print scan findings in a structured format."""
    # Print error if any
    if "error" in result:
        print(f"Error: {result['error']}")
        return
    
    # Print stats
    if "stats" in result:
        stats = result["stats"]
        print(f"Files scanned: {stats.get('files_scanned', 0)}")
        print(f"Scan time: {stats.get('scan_time', 0):.2f} seconds")
        print(f"Total findings: {stats.get('total_findings', 0)}")
    
    # Print severity summary
    if "severity_summary" in result:
        summary = result["severity_summary"]
        print("\nSeverity Summary:")
        severity_order = ["critical", "high", "medium", "low", "info"]
        for level in severity_order:
            count = summary.get(level, 0)
            if count > 0:
                print(f"  {level.upper()}: {count}")
    
    # Print findings
    findings = result.get("findings", [])
    if not findings:
        print("\nNo security issues found!")
        return
    
    print("\nSecurity Issues Found:")
    
    # Sort findings by severity
    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4
    }
    
    sorted_findings = sorted(
        findings, 
        key=lambda x: severity_order.get(x.get("severity", "info").lower(), 999)
    )
    
    # Print each finding
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


async def scan_code_snippet():
    """Demonstrate scanning a code snippet for vulnerabilities."""
    print_header("Scanning Code Snippet")
    
    # Example vulnerable code
    code = """
def process_user_data(user_input):
    import os
    import sqlite3
    
    # Command injection vulnerability
    os.system("echo " + user_input)
    
    # SQL injection vulnerability
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    cursor.execute(query)
    
    # Path traversal vulnerability
    with open("/var/www/html/" + user_input, "r") as f:
        return f.read()
"""
    
    print("Analyzing the following code snippet:")
    print("-" * 40)
    print(code)
    print("-" * 40)
    
    # Initialize tool and scan code
    semgrep_tool = SemgrepTool()
    result = await semgrep_tool.run(
        code=code,
        language="python"
    )
    
    # Print results
    print_findings(result)


async def scan_file():
    """Demonstrate scanning a file for vulnerabilities."""
    print_header("Scanning File")
    
    # Get path to the vulnerable Python test file
    test_file = Path(__file__).parent / "test_cases" / "vulnerable_python.py"
    
    if not test_file.exists():
        print(f"Test file not found: {test_file}")
        return
    
    print(f"Scanning file: {test_file}")
    
    # Initialize tool and scan file
    semgrep_tool = SemgrepTool()
    result = await semgrep_tool.run(
        file_path=str(test_file)
    )
    
    # Print results
    print_findings(result)


async def main():
    """Run the Semgrep Scanner Tool example."""
    print_header("Semgrep Scanner Tool Example")
    print("This example demonstrates how to use the Semgrep Scanner Tool to find")
    print("security vulnerabilities in code snippets and files.")
    
    await scan_code_snippet()
    await scan_file()
    
    print("\nExample completed.")


if __name__ == "__main__":
    asyncio.run(main()) 