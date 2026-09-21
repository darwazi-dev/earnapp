const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// مسیر پاست‌بک کاملاً آزاد شد تا فوراً عدد ۱ را برگرداند و پنل تایید شود
app.get('/api/cpx/postback', (req, res) => {
  return res.status(200).send('1');
});

app.use((req, res) => res.status(200).json({ status: "success" }));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server started on port ${PORT}`);
});
