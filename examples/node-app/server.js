// server.js (example)
import express from 'express';
const app = express();
const port = process.env.PORT || 80;

app.use(express.static('.')); // if you want to serve index.html from project root
app.get('/health', (req, res) => res.send('OK'));

app.listen(port, () => console.log(`Listening on port ${port}`));