/**
 * Example Target File for testing VibeGuard
 * Demonstrates common AI/vibe-coding patterns and vulnerabilities
 */

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const child_process = require('child_process');
const axios = require('axios');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

// 1. [SECURITY / CORS]: Insecure wildcard CORS configuration
app.use(cors({ origin: '*' }));

// 2. [SECURITY / SECRETS]: Hardcoded database credentials & mock API key
const DATABASE_URL = 'postgres://dbuser:SuperSecretPassword2026@127.0.0.1:5432/production_db';
const STRIPE_SECRET = 'vbg_test_mock_api_key_51Oz01234567890abcdef';
const pool = new Pool({ connectionString: DATABASE_URL });

// 3. [SECURITY / INJECTION]: SQL Injection via string concatenation
app.get('/api/users', async (req, res) => {
  const userId = req.query.id;
  // Unsanitized input concatenated directly into SQL statement
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  const result = await pool.query(query);
  res.json(result.rows);
});

// 4. [SECURITY & RELIABILITY]: Path Traversal + Synchronous blocking I/O in HTTP handler
app.get('/api/files/download', (req, res) => {
  const fileName = req.query.filename;
  // Vulnerable to ../ path traversal AND blocks Node event loop synchronously
  const data = fs.readFileSync('./uploads/' + fileName, 'utf-8');
  res.send(data);
});

// 5. [SECURITY / RCE]: Dynamic Command Execution vulnerability
app.post('/api/diagnostics/ping', (req, res) => {
  const host = req.body.host;
  // Untrusted input concatenated into shell command
  child_process.exec('ping -c 2 ' + host, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).send(stderr);
    }
    res.send(stdout);
  });
});

// 6. [SECURITY / SSRF]: Server-Side Request Forgery
app.get('/api/proxy/fetch', async (req, res) => {
  const targetUrl = req.query.url;
  // Fetches arbitrary user-supplied URL without allowlist validation
  const response = await axios.get(targetUrl);
  res.json(response.data);
});

// 7. [SECURITY / AUTH]: Missing Resource-Level Authorization on sensitive data
app.delete('/api/accounts/:id', async (req, res) => {
  // Directly deletes account without verifying session identity or role
  await pool.query('DELETE FROM accounts WHERE id = $1', [req.params.id]);
  res.json({ success: true, message: 'Account deleted' });
});

// 8. [SECURITY / LOGGING]: Error disclosure leaking raw stack trace
app.use((err, req, res, next) => {
  console.error('Unhandled server exception:', err);
  res.status(500).json({
    status: 'error',
    message: err.message,
    stack: err.stack, // Leaks internal implementation details and paths
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Example server running on port ${PORT}`);
});

