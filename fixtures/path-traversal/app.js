const fs = require('fs');
const express = require('express');
const app = express();

app.get('/download', (req, res) => {
  fs.readFile(req.query.file, 'utf-8', (err, data) => {
    res.send(data);
  });
});

app.get('/static', (req, res) => {
  fs.readFile('static.txt', 'utf-8');
});
