const express = require('express');
const app = express();

app.get('/render', (req, res) => {
  const content = req.query.input;
  document.getElementById('root').innerHTML = content;
});

app.get('/render-safe', (req, res) => {
  const content = DOMPurify.sanitize(req.query.input);
  document.getElementById('root').innerHTML = content;
});
