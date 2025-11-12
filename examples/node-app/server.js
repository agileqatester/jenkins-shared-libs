import express from 'express';

const app = express();
const port = process.env.PORT || 80;

app.get('/health', (req, res) => res.status(200).send('OK'));
app.get('/', (req, res) => res.send('Hello from agileqa node sample!'));

app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
