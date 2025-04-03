/**
 * Sample JavaScript code with security vulnerabilities for testing the AppSec Engineer Agent.
 * This file contains various security issues that should be detected by Semgrep.
 */

// XSS vulnerability
function displayUserInput(userInput) {
  // Direct DOM manipulation leading to XSS
  document.getElementById('message').innerHTML = userInput;
  
  // Another XSS vulnerability
  const element = document.createElement('div');
  element.innerHTML = '<p>' + userInput + '</p>'; // Vulnerable to XSS
  document.body.appendChild(element);
}

// Prototype pollution vulnerability
function mergeObjects(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object') {
      if (!target[key]) {
        target[key] = {};
      }
      // Vulnerable to prototype pollution
      mergeObjects(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Insecure use of eval
function calculateExpression(expression) {
  // Direct use of eval - vulnerable to code injection
  return eval(expression); // Vulnerable to code injection
}

// SQL injection in Node.js
function getUserData(userId) {
  const mysql = require('mysql');
  const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'users'
  });
  
  // SQL injection vulnerability
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  connection.query(query, (error, results) => {
    if (error) throw error;
    return results;
  });
}

// Insecure Cookie usage
function setCookie(name, value) {
  // Setting cookie without HttpOnly or secure flags
  document.cookie = name + "=" + value; // Insecure cookie usage
}

// Hardcoded credentials
function connectToDatabase() {
  const dbConfig = {
    host: 'localhost',
    user: 'admin',
    password: 'admin123', // Hardcoded password
    database: 'app_data'
  };
  
  // API key hardcoded
  const API_KEY = "AbCdEf123456GhIjKl"; // Hardcoded API key
  
  return dbConfig;
}

// Insecure randomness
function generateToken() {
  // Insecure randomness
  return Math.random().toString(36).substring(2); // Insecure random value
}

// Path traversal vulnerability
function readFile(fileName) {
  const fs = require('fs');
  
  // Path traversal vulnerability
  return fs.readFileSync('/var/www/files/' + fileName, 'utf8');
}

// NoSQL injection vulnerability
function findUser(username) {
  const MongoDB = require('mongodb');
  const db = MongoDB.connect('mongodb://localhost:27017/users');
  
  // NoSQL injection vulnerability
  return db.collection('users').find({
    username: username
  });
}

module.exports = {
  displayUserInput,
  mergeObjects,
  calculateExpression,
  getUserData,
  setCookie,
  connectToDatabase,
  generateToken,
  readFile,
  findUser
}; 