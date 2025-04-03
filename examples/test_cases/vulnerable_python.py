#!/usr/bin/env python3
"""
Sample Python code with security vulnerabilities for testing the AppSec Engineer Agent.
This file contains various security issues that should be detected by Semgrep.
"""
import os
import subprocess
import sqlite3


def sql_injection_vulnerability(user_input):
    """Function with SQL injection vulnerability."""
    # SQL injection vulnerability
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    cursor.execute(query)  # Vulnerable to SQL injection
    return cursor.fetchall()


def command_injection_vulnerability(user_input):
    """Function with command injection vulnerability."""
    # Command injection vulnerability
    os.system("echo " + user_input)  # Vulnerable to command injection
    
    # Another command injection vulnerability
    subprocess.call("grep " + user_input + " /var/log/app.log", shell=True)
    
    return "Command executed"


def path_traversal_vulnerability(user_input):
    """Function with path traversal vulnerability."""
    # Path traversal vulnerability
    file_path = "/var/www/uploads/" + user_input
    with open(file_path, "r") as file:
        # Vulnerable to path traversal (e.g., "../../../etc/passwd")
        return file.read()


def insecure_deserialization(serialized_data):
    """Function with insecure deserialization vulnerability."""
    import pickle
    
    # Insecure deserialization vulnerability
    return pickle.loads(serialized_data)  # Vulnerable to arbitrary code execution


def insecure_hash_function():
    """Function using insecure hash function."""
    import hashlib
    
    password = "password123"
    # Insecure hashing algorithm
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed


def hardcoded_credentials():
    """Function with hardcoded credentials."""
    # Hardcoded credentials
    username = "admin"
    password = "admin123"  # Hardcoded password
    api_key = "Abc123XYZ456ApIkEy"  # Hardcoded API key
    
    return {"username": username, "password": password, "api_key": api_key}


def server_side_template_injection(user_input):
    """Function with server-side template injection vulnerability."""
    from flask import render_template_string
    
    # Server-side template injection vulnerability
    template = "<h1>Hello, {}!</h1>".format(user_input)
    return render_template_string(template)  # Vulnerable to SSTI


def main():
    """Main function to simulate application entry point."""
    print("This is a sample application with security vulnerabilities.")
    print("Do not use this code in production!")


if __name__ == "__main__":
    main() 