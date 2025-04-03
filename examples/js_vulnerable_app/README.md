# Vulnerable JavaScript Application

This is a deliberately vulnerable JavaScript application created for security testing and demonstration purposes. 

**⚠️ WARNING: This application contains serious security vulnerabilities. DO NOT deploy in production or expose to the internet.**

## Purpose

This application was created to:

1. Demonstrate common security vulnerabilities in JavaScript/Node.js applications
2. Provide a realistic test case for the AppSec Engineer Agent
3. Test the effectiveness of Semgrep security rules and policies
4. Serve as an educational resource for understanding web application security issues

## Security Vulnerabilities

This application intentionally includes the following vulnerabilities:

### Server-side (Node.js/Express) Vulnerabilities:

- **SQL Injection**: Unsanitized user input directly concatenated into SQL queries
- **Command Injection**: User input passed directly to `exec()` without sanitization
- **Path Traversal**: Unsanitized path components allowing directory traversal
- **Insecure Session Configuration**: Missing secure and httpOnly flags
- **Insecure Direct Object Reference (IDOR)**: Missing access controls on API endpoints
- **Hard-coded Credentials**: Database credentials stored directly in the code
- **Unrestricted File Upload**: Missing validation of file types and content

### Client-side (JavaScript) Vulnerabilities:

- **Cross-Site Scripting (XSS)**: Direct assignment to innerHTML without sanitization
- **DOM-based XSS**: URL fragments used unsafely in DOM manipulation
- **Insecure Use of eval()**: Direct use of eval() on user input
- **Prototype Pollution**: Recursive object merging without proper checks
- **Open Redirect**: Unvalidated URL redirects
- **Insecure Storage**: Sensitive data stored in localStorage
- **Insecure JWT Handling**: Missing JWT signature validation
- **Insecure Cookies**: Missing security flags on cookies
- **Hardcoded Secrets**: API keys and encryption keys in the source code
- **Insecure Random Values**: Using Math.random() for security-related operations
- **Insecure postMessage**: Missing origin validation

## Usage

To run the application:

```bash
cd examples/js_vulnerable_app
npm install
npm start
```

The application will be available at http://localhost:3000.

## Security Testing

To test this application with the AppSec Engineer Agent, run:

```bash
python examples/scan_js_project.py
```

This will:
1. Synchronize JavaScript security policies from the Semgrep repository
2. Run the AppSec Engineer Agent on the application
3. Generate a security report with findings and recommendations

The report will be saved in the `examples/results` directory.

## Educational Use

This application is designed for educational purposes. Each vulnerability includes comments explaining the security issue, making it useful for:

- Security training and awareness
- Testing security scanning tools
- Learning about common web application vulnerabilities
- Understanding secure coding practices (by seeing what not to do)

## License

This code is provided under the MIT license for educational purposes only. 