const express = require('express');
const app = express();

app.get('/test', (req, res) => {
  console.log('Test endpoint hit!');
  res.json({ message: 'Test successful!', timestamp: new Date() });
});

app.listen(3002, () => {
  console.log('Test server running on port 3002');
});
