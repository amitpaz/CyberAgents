#!/usr/bin/env python3
"""
Example script demonstrating how to use the AppSec Engineer Agent.

This script shows how to:
1. Analyze a code snippet for security vulnerabilities
2. Analyze a GitHub repository for security vulnerabilities
"""

import asyncio
import sys
import os
import json
from pathlib import Path

# Add the parent directory to the Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.appsec_engineer_agent import AppSecEngineerAgent


# Example vulnerable code samples
VULNERABLE_PYTHON_CODE = """
def authenticate(username, password):
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    return db.execute(query)

def process_data(user_input):
    # Command injection vulnerability
    os.system("echo " + user_input)
    
    # Path traversal vulnerability
    with open("/tmp/" + user_input, "r") as f:
        return f.read()
"""

VULNERABLE_JS_CODE = """
function displayUser(userId) {
    // XSS vulnerability
    document.getElementById('user').innerHTML = userId;
    
    // Insecure direct object reference
    fetch('/api/users/' + userId)
        .then(response => response.json())
        .then(data => console.log(data));
    
    // Prototype pollution
    const obj = {};
    const prop = userId;
    obj[prop] = userId;
}
"""


async def analyze_code_examples():
    """Analyze example code snippets for vulnerabilities."""
    print("Initializing AppSec Engineer Agent...")
    agent = AppSecEngineerAgent()
    
    print("\n--- Analyzing Python Code ---")
    python_results = await agent.analyze_code(
        VULNERABLE_PYTHON_CODE, 
        language="python",
        filename="example.py"
    )
    print_results(python_results)
    
    print("\n--- Analyzing JavaScript Code ---")
    js_results = await agent.analyze_code(
        VULNERABLE_JS_CODE,
        language="javascript",
        filename="example.js"
    )
    print_results(js_results)


async def analyze_github_repo():
    """Analyze a GitHub repository for vulnerabilities."""
    print("\n--- Analyzing GitHub Repository ---")
    
    # Use a small, public repository for this example
    repo_url = "https://github.com/OWASP/juice-shop"  # Change to a suitable repo
    
    agent = AppSecEngineerAgent()
    results = await agent.analyze_repository(repo_url)
    
    print_results(results)


def print_results(results):
    """Print analysis results in a readable format."""
    if "error" in results:
        print(f"Error: {results['error']}")
        return
    
    # Print scan metadata
    if "scan_metadata" in results:
        metadata = results["scan_metadata"]
        print(f"Scan ID: {metadata.get('scan_id')}")
        print(f"Language: {metadata.get('language', 'Multiple/Unknown')}")
        print(f"Scan Time: {metadata.get('scan_time', 0):.2f} seconds")
    
    # Print severity summary
    if "severity_summary" in results:
        summary = results["severity_summary"]
        print("\nSeverity Summary:")
        for level, count in summary.items():
            if count > 0:
                print(f"  {level.upper()}: {count}")
    
    # Print findings
    findings = results.get("findings", [])
    print(f"\nTotal Findings: {len(findings)}")
    
    if findings:
        print("\nTop Findings:")
        # Sort by severity (critical first)
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
        
        # Print top 5 findings
        for i, finding in enumerate(sorted_findings[:5]):
            print(f"\n{i+1}. {finding.get('rule_id')} ({finding.get('severity', 'info').upper()})")
            print(f"   {finding.get('message')}")
            print(f"   File: {finding.get('path')}, Line: {finding.get('line')}")
            if "code" in finding and finding["code"]:
                print(f"   Code: {finding['code'].strip()}")


async def main():
    """Run the example demonstration."""
    print("===== AppSec Engineer Agent Example =====")
    
    # Analyze code examples
    await analyze_code_examples()
    
    # Uncomment to analyze a GitHub repository (takes longer)
    # await analyze_github_repo()


if __name__ == "__main__":
    asyncio.run(main()) 