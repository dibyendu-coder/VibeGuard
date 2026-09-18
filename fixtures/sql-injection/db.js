const express = require('express');
const app = express();

app.get('/api/users', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(query);
});

app.get('/api/users/safe', (req, res) => {
  db.query("SELECT * FROM users WHERE id = $1", [req.query.id]);
});
