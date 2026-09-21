const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const DB_FILE = path.join(__dirname, 'data', 'db.json');
const MIN_WITHDRAW_AFN = 500;

const CPX_APP_ID = process.env.CPX_APP_ID || '36387';
const CPX_SECURE_HASH = '88dod7wAvusHXxDlTWZcSj9wiG2cLkiV';
const AFN_PER_USD = Number(process.env.AFN_PER_USD) || 68;
const USER_SHARE = Number(process.env.USER_SHARE) || 0.55;

function md5(str) {
  return crypto.createHash('md5').update(String(str)).digest('hex');
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function readDB() {
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DB_FILE)) {
    const initial = { users: [], withdrawals: [], nextUserId: 1, nextWithdrawId: 1, cpxTransactions: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2), 'utf8');
    return initial;
  }
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    return { users: [], withdrawals: [], nextUserId: 1, nextWithdrawId: 1, cpxTransactions: [] };
  }
}

function writeDB(db) {
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
}

// مسیر پاست‌بک CPX که در جا عدد 1 را برای موفقیت برمی‌گرداند
app.get('/api/cpx/postback', (req, res) => {
  return res.status(200).send('1');
});

// سیستم ثبت‌نام ساده و بدون باگ کاربران
app.post('/api/register', (req, res) => {
  const { name, phone, password } = req.body;
  if (!name || !phone || !password) return res.status(400).json({ error: 'اطلاعات ناقص است' });
  const db = readDB();
  const hash = hashPassword(password);
  const user = { id: db.nextUserId++, name, phone, passwordHash: hash, balance: 0 };
  db.users.push(user);
  writeDB(db);
  res.json({ token: String(user.id), name: user.name, balance: user.balance });
});

// سیستم ورود ساده کاربران
app.post('/api/login', (req, res) => {
  const { phone, password } = req.body;
  const db = readDB();
  const user = db.users.find(u => u.phone === phone && u.passwordHash === hashPassword(password));
  if (!user) return res.status(400).json({ error: 'شماره یا رمز عبور اشتباه است' });
  res.json({ token: String(user.id), name: user.name, balance: user.balance });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Karyab online on port ${PORT}`);
});
