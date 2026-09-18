const express = require('express');
const app = express();

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  console.log('User login password attempt:', password);
  res.json({ user: username, passwordHash: '$2b$10$hashed_secret_value' });
});

module.exports = app;
