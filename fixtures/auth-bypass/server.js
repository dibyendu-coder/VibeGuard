const express = require('express');
const app = express();
app.use(express.json());

app.post('/api/auth/login', (req, res) => {
  const { role } = req.body;
  if (role === 'admin') {
    return res.json({ status: 'granted' });
  }
  res.json({ status: 'denied' });
});

app.listen(3000);
