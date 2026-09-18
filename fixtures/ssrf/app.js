const express = require('express');
const app = express();

app.get('/fetch-url', async (req, res) => {
  const response = await fetch(req.query.url);
  res.json(await response.json());
});

app.get('/static-fetch', async (req, res) => {
  await fetch("https://api.example.com/status");
});
