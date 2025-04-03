#!/usr/bin/env python3
"""
Example script demonstrating how to use the Semgrep Scanner Tool.

This script shows:
1. How to scan a code snippet for vulnerabilities using registry rules
2. How to scan a code snippet using local policies
3. How to scan a file for vulnerabilities using both registry and local policies
4. How to process and display the results
"""

import os
import asyncio
import sys
from pathlib import Path
import json

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.semgrep_scanner import SemgrepTool
from tools.semgrep_scanner.utils import sync_language_policies


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
    
    # Print policy config used
    if "policy_config" in result:
        policy = result["policy_config"]
        print("Policy Configuration:")
        print(f"  Preference: {policy.get('policy_preference', 'both')}")
        print(f"  Registry rules: {', '.join(policy.get('registry_rules', []) or ['None'])}")
        print(f"  Local rules: {len(policy.get('local_rules', []))} rules")
    
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


async def sync_policies():
    """Synchronize required policies for the demo."""
    print_header("Synchronizing Python Policies")
    
    print("Synchronizing Python policies from Semgrep repository...")
    result = sync_language_policies(["python"])
    
    if result.get("success", False):
        print(f"Successfully synchronized {result['total_policies']} policies")
        for lang, count in result.get("languages", {}).items():
            print(f"  {lang}: {count} policies")
    else:
        print(f"Warning: Policy synchronization failed. Will use registry rules only.")
        print(f"Error: {result.get('message', 'Unknown error')}")


async def scan_with_registry_rules():
    """Demonstrate scanning a code snippet with Semgrep registry rules."""
    print_header("Scanning with Registry Rules")
    
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
    
    print("Analyzing code snippet with registry rules:")
    print("-" * 40)
    print(code)
    print("-" * 40)
    
    # Initialize tool and scan code
    semgrep_tool = SemgrepTool()
    result = await semgrep_tool.run(
        code=code,
        language="python",
        rules=["p/security-audit", "p/owasp-top-ten"],
        policy_preference="registry"  # Use only registry rules
    )
    
    # Print results
    print_findings(result)


async def scan_with_local_policies():
    """Demonstrate scanning a code snippet with local policies."""
    print_header("Scanning with Local Policies")
    
    # Example vulnerable code with SQL injection
    code = """
def authenticate_user(username, password):
    import sqlite3
    
    # SQL injection vulnerability in authentication function
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        return True
    return False
"""
    
    print("Analyzing code snippet with local policies:")
    print("-" * 40)
    print(code)
    print("-" * 40)
    
    # Initialize tool and scan code
    semgrep_tool = SemgrepTool()
    result = await semgrep_tool.run(
        code=code,
        language="python",
        use_local_policies=True,
        policy_preference="local"  # Use only local policies
    )
    
    # Print results
    print_findings(result)


async def scan_with_both_policies():
    """Demonstrate scanning a file with both registry and local policies."""
    print_header("Scanning with Both Registry and Local Policies")
    
    # Get path to the vulnerable Python test file
    test_file = Path(__file__).parent / "test_cases" / "vulnerable_python.py"
    
    if not test_file.exists():
        print(f"Test file not found: {test_file}")
        return
    
    print(f"Scanning file with both registry and local policies: {test_file}")
    
    # Initialize tool and scan file
    semgrep_tool = SemgrepTool()
    result = await semgrep_tool.run(
        file_path=str(test_file),
        rules=["p/security-audit"],
        use_local_policies=True,
        policy_preference="both"  # Use both registry and local policies
    )
    
    # Print results
    print_findings(result)


async def main():
    """Run the Semgrep Scanner Tool example."""
    print_header("Semgrep Scanner Tool Example")
    print("This example demonstrates how to use the Semgrep Scanner Tool to find")
    print("security vulnerabilities in code snippets and files using different policy sources.")
    
    # First, sync policies
    await sync_policies()
    
    # Demo different policy configurations
    await scan_with_registry_rules()
    await scan_with_local_policies()
    await scan_with_both_policies()
    
    print("\nExample completed.")


if __name__ == "__main__":
    asyncio.run(main()) 