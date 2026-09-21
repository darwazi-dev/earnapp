const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const DB_FILE = path.join(__dirname, 'data', 'db.json');
const MIN_WITHDRAW_AFN = 500;

const CPX_APP_ID = (process.env.CPX_APP_ID || '36387').trim();
const CPX_SECURE_HASH = 'MAb1fBtz6Y0TqrfpGkb0UQQ95w5ja4sD';
const AFN_PER_USD = Number(process.env.AFN_PER_USD || 68);
const USER_SHARE = Number(process.env.USER_SHARE || 0.55);

function md5(str) {
  return crypto.createHash('md5').update(String(str)).digest('hex');
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(String(password)).digest('hex');
}

function todayKey() {
  return new Date().toISOString().slice(0, 10);
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function createInitialDB() {
  return { users: [], withdrawals: [], nextUserId: 1, nextWithdrawId: 1, cpxTransactions: [] };
}

function readDB() {
  try {
    const dir = path.dirname(DB_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    if (!fs.existsSync(DB_FILE)) {
      const initial = createInitialDB();
      fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2), 'utf8');
      return initial;
    }
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    if (!raw.trim()) return createInitialDB();
    const db = JSON.parse(raw);
    if (!Array.isArray(db.users)) db.users = [];
    if (!Array.isArray(db.withdrawals)) db.withdrawals = [];
    if (!Array.isArray(db.cpxTransactions)) db.cpxTransactions = [];
    return db;
  } catch (e) {
    return createInitialDB();
  }
}

function writeDB(db) {
  try {
    const dir = path.dirname(DB_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
  } catch (e) {}
}

function findUser(db, userId) {
  return db.users.find(u => Number(u.id) === Number(userId));
}

// ============================================================
// ROUTES
// ============================================================

app.post('/api/register', (req, res) => {
  try {
    const { name, phone, password, question, answer } = req.body;
    if (!name || !phone || !password) return res.status(400).json({ error: 'اطلاعات ناقص است' });
    
    const db = readDB();
    if (db.users.find(u => u.phone === phone)) return res.status(400).json({ error: 'این شماره قبلاً ثبت‌نام کرده است' });
    
    const user = { 
      id: db.nextUserId++, 
      name, 
      phone, 
      passwordHash: hashPassword(password), 
      balance: 0,
      securityQuestion: question || "شهر تولد شما چیست؟",
      securityAnswerHash: answer ? crypto.createHash('sha256').update(String(answer).trim().toLowerCase()).digest('hex') : null,
      completedTasks: {}
    };
    
    db.users.push(user);
    writeDB(db);
    res.json({ token: String(user.id), name: user.name, balance: user.balance });
  } catch (e) {
    res.status(500).json({ error: 'خطای سرور' });
  }
});

app.post('/api/login', (req, res) => {
  try {
    const { phone, password } = req.body;
    const db = readDB();
    const user = db.users.find(u => u.phone === phone && u.passwordHash === hashPassword(password));
    if (!user) return res.status(400).json({ error: 'شماره یا رمز عبور اشتباه است' });
    res.json({ token: String(user.id), name: user.name, balance: user.balance });
  } catch (e) {
    res.status(500).json({ error: 'خطای سرور' });
  }
});

// مسیر بررسی وجود شماره و ارسال سوال امنیتی به برنامه
app.post('/api/forgot-password/check-phone', (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'شماره تلفن را وارد کنید' });
    
    const db = readDB();
    const user = db.users.find(u => String(u.phone) === String(phone).trim());
    if (!user) return res.status(404).json({ error: 'کاربری با این شماره یافت نشد' });
    
    res.json({ question: user.securityQuestion || "شهر تولد شما چیست؟ (تنظیم پیشفرض)" });
  } catch (e) {
    res.status(500).json({ error: 'خطای سرور' });
  }
});

// مسیر تغییر پسورد پس از بررسی پاسخ سوال امنیتی
app.post('/api/forgot-password/reset', (req, res) => {
  try {
    const { phone, answer, newPassword } = req.body;
    if (!phone || !answer || !newPassword) return res.status(400).json({ error: 'فیلدها ناقص است' });
    
    const db = readDB();
    const user = db.users.find(u => String(u.phone) === String(phone).trim());
    if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });

    const inputHash = crypto.createHash('sha256').update(String(answer).trim().toLowerCase()).digest('hex');
    if (user.securityAnswerHash && user.securityAnswerHash !== inputHash) {
      return res.status(400).json({ error: 'پاسخ سوال امنیتی اشتباه است' });
    }

    user.passwordHash = hashPassword(newPassword);
    writeDB(db);
    res.json({ token: String(user.id), name: user.name, balance: user.balance });
  } catch (e) {
    res.status(500).json({ error: 'خطای سرور' });
  }
});

app.get('/api/tasks', (req, res) => {
  const db = readDB();
  res.json({ tasks: [], balance: 0 });
});

app.get('/api/cpx/postback', (req, res) => {
  return res.status(200).send('1');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server started on port ${PORT}`);
});
