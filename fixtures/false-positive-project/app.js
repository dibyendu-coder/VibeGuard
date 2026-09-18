const express = require('express');
const { execSync } = require('child_process');
const fs = require('fs');
const DOMPurify = require('dompurify');

const app = express();

// 1. Parameterized SQL
app.get('/user/:id', (req, res) => {
  db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
});

// 2. Static shell command
app.get('/build', (req, res) => {
  execSync("git status");
});

// 3. Static URL fetch
app.get('/health', async (req, res) => {
  await fetch("https://api.example.com/health");
});

// 4. Server-side role check with trusted session
app.get('/admin', (req, res) => {
  if (req.session && req.session.user && req.session.user.role === 'admin') {
    res.send('Admin Dashboard');
  }
});

// 5. Sanitized HTML
app.get('/render', (req, res) => {
  const safe = DOMPurify.sanitize(req.query.content);
  element.innerHTML = safe;
});

// 6. Safe filesystem path handling
app.get('/read', (req, res) => {
  fs.readFile('safe-content.txt', 'utf-8', () => {});
});
