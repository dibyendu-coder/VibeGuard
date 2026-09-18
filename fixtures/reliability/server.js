const express = require('express');
const fs = require('fs');
const app = express();

app.get('/data', (req, res) => {
  // Sync file read in HTTP request handler
  const data = fs.readFileSync('/tmp/data.json', 'utf-8');
  res.send(data);
});

try {
  fetch('https://api.external.com/sync');
} catch (err) {}

module.exports = app;
