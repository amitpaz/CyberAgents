/**
 * Example vulnerable Express.js server
 * This file contains several security vulnerabilities for demonstration purposes.
 * DO NOT USE IN PRODUCTION.
 */

const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');
const mysql = require('mysql');

const app = express();
const port = 3000;

// Insecure session configuration (missing secure and httpOnly flags)
app.use(session({
  secret: 'hardcoded-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: {} // Missing secure: true and httpOnly: true
}));

// Parse application/json and application/x-www-form-urlencoded
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Database connection
// Vulnerability: Hardcoded credentials
const dbConnection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password123',
  database: 'userdb'
});

// Serve static files
app.use(express.static('public'));

// User login endpoint
// Vulnerability: SQL Injection
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // SQL Injection vulnerability
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  dbConnection.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (results.length > 0) {
      // Set user session
      req.session.user = {
        id: results[0].id,
        username: results[0].username,
        role: results[0].role
      };
      
      return res.json({ success: true, message: 'Login successful' });
    } else {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  });
});

// User registration endpoint
// Vulnerability: No password hashing
app.post('/api/register', (req, res) => {
  const { username, password, email } = req.body;
  
  // Missing password hashing
  const query = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
  
  dbConnection.query(query, [username, password, email], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    return res.json({ success: true, message: 'Registration successful' });
  });
});

// File download endpoint
// Vulnerability: Path Traversal
app.get('/api/download', (req, res) => {
  const filename = req.query.file;
  
  // Path traversal vulnerability
  const filePath = path.join(__dirname, 'files', filename);
  
  fs.readFile(filePath, (err, data) => {
    if (err) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    res.setHeader('Content-disposition', 'attachment; filename=' + filename);
    res.setHeader('Content-type', 'application/octet-stream');
    res.send(data);
  });
});

// Command execution endpoint
// Vulnerability: Command Injection
app.get('/api/ping', (req, res) => {
  const host = req.query.host;
  
  // Command injection vulnerability
  exec(`ping -c 4 ${host}`, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: 'Ping failed' });
    }
    
    res.json({ result: stdout });
  });
});

// User profile endpoint
// Vulnerability: XSS (Cross-Site Scripting)
app.get('/api/profile/:id', (req, res) => {
  const userId = req.params.id;
  
  dbConnection.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = results[0];
    
    // XSS vulnerability (returning raw user input)
    const htmlResponse = `
      <html>
        <head><title>User Profile</title></head>
        <body>
          <h1>User Profile for ${user.username}</h1>
          <div>Bio: ${user.bio}</div>
          <div>Email: ${user.email}</div>
        </body>
      </html>
    `;
    
    res.send(htmlResponse);
  });
});

// File upload endpoint
// Vulnerability: Unrestricted File Upload
app.post('/api/upload', (req, res) => {
  const { file, filename } = req.body;
  
  // Vulnerability: No validation of file type or content
  const filePath = path.join(__dirname, 'uploads', filename);
  
  // Convert base64 to buffer
  const fileBuffer = Buffer.from(file, 'base64');
  
  fs.writeFile(filePath, fileBuffer, (err) => {
    if (err) {
      return res.status(500).json({ error: 'Upload failed' });
    }
    
    res.json({ success: true, message: 'File uploaded successfully' });
  });
});

// Admin endpoint
// Vulnerability: Insecure Direct Object Reference (IDOR)
app.get('/api/admin/user/:id', (req, res) => {
  const userId = req.params.id;
  
  // Missing authorization check
  // Should check if the current user is an admin
  
  dbConnection.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Sending sensitive user information
    res.json(results[0]);
  });
});

// Start server
app.listen(port, () => {
  console.log(`Vulnerable server running at http://localhost:${port}`);
}); 