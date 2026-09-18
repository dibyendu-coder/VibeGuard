const express = require('express');
const cors = require('cors');
const fs = require('fs');
const child_process = require('child_process');

const app = express();

// Insecure wildcard CORS configuration
app.use(cors({ origin: '*' }));

// Hardcoded database connection string
const connectionString = 'postgres://dbadmin:fakePasswordSecret123@localhost:5432/main';

// SQL injection via string concatenation
app.get('/api/users', (req, res) => {
  const query = "SELECT * FROM users WHERE id = '" + req.query.id + "'";
  db.query(query);
  res.json({ ok: true });
});

// Unrestricted file read / path traversal
app.get('/api/view', (req, res) => {
  const content = fs.readFileSync(req.query.file, 'utf-8');
  res.send(content);
});

// Dynamic command execution vulnerability
app.get('/api/ping', (req, res) => {
  child_process.exec('ping -c 1 ' + req.query.host, (err, stdout) => {
    res.send(stdout);
  });
});

// Error handling exposing internal stack trace
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.stack });
});

app.listen(3000);
