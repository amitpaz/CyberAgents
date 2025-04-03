/**
 * Example vulnerable client-side JavaScript
 * This file contains several security vulnerabilities for demonstration purposes.
 * DO NOT USE IN PRODUCTION.
 */

// Vulnerability: Insecure DOM manipulation (XSS)
function displayUserMessage(message) {
  // XSS vulnerability - direct innerHTML assignment without sanitization
  document.getElementById('messageBox').innerHTML = message;
}

// Vulnerability: Dangerous use of eval
function calculateExpression() {
  const expression = document.getElementById('calculator').value;
  
  // Dangerous use of eval - allows code execution
  const result = eval(expression);
  
  document.getElementById('result').textContent = result;
}

// Vulnerability: Insecure storage of sensitive data
function saveUserCredentials(username, password) {
  // Storing sensitive information in localStorage (unencrypted)
  localStorage.setItem('username', username);
  localStorage.setItem('password', password);
  
  console.log('Credentials saved successfully!');
}

// Vulnerability: Insecure JWT handling
function parseJWT(token) {
  // JWT tokens should be validated before being used
  // This function doesn't verify the signature
  
  const base64Url = token.split('.')[1];
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const jsonPayload = decodeURIComponent(
    atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join('')
  );

  return JSON.parse(jsonPayload);
}

// Vulnerability: DOM-based XSS
function loadContentFromHash() {
  const contentId = window.location.hash.substr(1);
  
  // DOM-based XSS vulnerability
  document.getElementById('dynamicContent').innerHTML = 
    `<div>Loading content for: ${contentId}</div>`;
    
  fetchContent(contentId);
}

// Vulnerability: CSRF vulnerability (missing CSRF token)
function submitFormData(formData) {
  // Missing CSRF token in the request
  fetch('/api/update-profile', {
    method: 'POST',
    body: JSON.stringify(formData),
    headers: {
      'Content-Type': 'application/json'
    }
  })
  .then(response => response.json())
  .then(data => {
    console.log('Success:', data);
  })
  .catch(error => {
    console.error('Error:', error);
  });
}

// Vulnerability: Open redirect
function redirectToPage(url) {
  // Open redirect vulnerability - no validation of the URL
  window.location.href = url;
}

// Vulnerability: Prototype pollution
function mergeObjects(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      // Prototype pollution vulnerability
      if (!target[key]) target[key] = {};
      mergeObjects(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Vulnerability: Insecure random number generation
function generateRandomToken(length) {
  // Insecure random token generation
  let result = '';
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  
  for (let i = 0; i < length; i++) {
    // Math.random() is not cryptographically secure
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  
  return result;
}

// Vulnerability: Insecure postMessage
function setupMessageListener() {
  window.addEventListener('message', function(event) {
    // Missing origin validation
    const data = event.data;
    
    // Process the message without checking its origin
    processMessageData(data);
  });
}

// Vulnerability: Secrets in code
const API_KEY = 'abc123-very-secret-api-key-should-not-be-here';
const ENCRYPTION_KEY = '0x4A2D28BC!a8f901';

// Vulnerability: Insecure cookie usage
function setCookieWithUserData(userData) {
  // Missing httpOnly and secure flags
  // Missing SameSite attribute
  document.cookie = `userData=${JSON.stringify(userData)}; path=/;`;
}

// Attach event listeners when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  // Setup listeners and initialize app
  loadContentFromHash();
  setupMessageListener();
  
  // Listen for hash changes
  window.addEventListener('hashchange', loadContentFromHash);
}); 