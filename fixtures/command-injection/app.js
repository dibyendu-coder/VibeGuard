const { exec, execSync } = require('child_process');
const express = require('express');
const app = express();

app.get('/ping', (req, res) => {
  exec("ping -c 1 " + req.query.host);
});

app.get('/status', (req, res) => {
  execSync("git status");
});
