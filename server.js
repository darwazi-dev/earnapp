const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();

const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const DB_FILE = path.join(__dirname, 'data', 'db.json');
const MIN_WITHDRAW_AFN = 500;

// ============================================================
// CPX RESEARCH CONFIG
// ============================================================
const CPX_APP_ID = process.env.CPX_APP_ID || '36387';
const CPX_SECURE_HASH = '88dod7wAvusHXxDlTWZcSj9wiG2cLkiV';
const AFN_PER_USD = Number(process.env.AFN_PER_USD) || 68;
const USER_SHARE = Number(process.env.USER_SHARE) || 0.55;

// ============================================================
// HELPERS
// ============================================================
function md5(str) {
  return crypto.createHash('md5').update(String(str)).digest('hex');
}

function todayKey() {
  return new Date().toISOString().slice(0, 10);
}

function findUser(db, userId) {
  return db.users.find(user => Number(user.id) === Number(userId));
}

// ============================================================
// EXPRESS CONFIG
// ============================================================
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
// DATABASE ACTIONS
// ============================================================
function createInitialDB() {
  return {
    users: [],
    withdrawals: [],
    nextUserId: 1,
    nextWithdrawId: 1,
    cpxTransactions: []
  };
}

function readDB() {
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  if (!fs.existsSync(DB_FILE)) {
    const initial = createInitialDB();
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2), 'utf8');
    return initial;
  }

  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    if (!raw.trim()) throw new Error('Database file is empty');
    const db = JSON.parse(raw);

    if (!Array.isArray(db.users)) db.users = [];
    if (!Array.isArray(db.withdrawals)) db.withdrawals = [];
    if (!Array.isArray(db.cpxTransactions)) db.cpxTransactions = [];
    if (!Number.isInteger(db.nextUserId)) db.nextUserId = 1;
    if (!Number.isInteger(db.nextWithdrawId)) db.nextWithdrawId = 1;

    return db;
  } catch (error) {
    console.error('Database read error:', error);
    const initial = createInitialDB();
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2), 'utf8');
    return initial;
  }
}

function writeDB(db) {
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
}

// ============================================================
// MOCK TASKS
// ============================================================
const MOCK_TASKS = [
  { id: 't1', title: 'نصب اپلیکیشن و باز کردن آن', desc: 'یک اپ را نصب کن و ۳۰ ثانیه باز نگه‌دار', reward: 35 },
  { id: 't2', title: 'تکمیل یک سروی کوتاه', desc: 'به ۵ سوال ساده جواب بده', reward: 28 },
  { id: 't3', title: 'ثبت‌نام آزمایشی در یک سایت', desc: 'با ایمیل خود ثبت‌نام کن (رایگان)', reward: 22 },
  { id: 't4', title: 'تماشای یک ویدیوی تبلیغاتی', desc: '۳۰ ثانیه ویدیو را کامل تماشا کن', reward: 8 },
  { id: 't5', title: 'نصب یک بازی و رسیدن به لول ۳', desc: 'بازی را نصب کن و تا لول ۳ برو', reward: 45 },
  { id: 't6', title: 'تکمیل یک کوییز کوچک', desc: 'یک کوییز ۳ سوالی را کامل کن', reward: 18 }
];

// ============================================================
// AUTH MIDDLEWARE
// ============================================================
function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) return res.status(401).json({ error: 'وارد نشده‌اید' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'نشست شما منقضی شده، دوباره وارد شوید' });
  }
}

function adminRequired(req, res, next) {
  const pass = req.headers['x-admin-password'];
  if (pass !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'رمز ادمین اشتباه است' });
  }
  next();
}

// ============================================================
// AUTH ROUTES
// ============================================================
app.post('/api/register', (req, res) => {
  try {
    const { name, phone, password } = req.body;
    if (!name || !phone || !password) {
      return res.status(400).json({ error: 'نام، شماره تلفن و رمز عبور لازم است' });
    }
    if (String(password).length < 4) {
      return res.status(400).json({ error: 'رمز عبور باید حداقل ۴ کاراکتر باشد' });
    }

    const db = readDB();
    const existingUser = db.users.find(user => String(user.phone) === String(phone));
    if (existingUser) {
      return res.status(400).json({ error: 'این شماره قبلاً ثبت‌نام کرده است' });
    }

    const hash = bcrypt.hashSync(String(password), 10);
    const user = {
      id: db.nextUserId++,
      name: String(name).trim(),
      phone: String(phone).trim(),
      passwordHash: hash,
      balance: 0,
      completedTasks: {},
      createdAt: new Date().toISOString()
    };

    db.users.push(user);
    writeDB(db);

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
    return res.json({ token, name: user.name, balance: user.balance });
  } catch (error) {
    console.error('Register error:', error);
    return res.status(500).json({ error: 'خطای داخلی سرور' });
  }
});

app.post('/api/login', (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) {
      return res.status(400).json({ error: 'شماره تلفن و رمز عبور لازم است' });
    }

    const db = readDB();
    const user = db.users.find(u => String(u.phone) === String(phone));

    if (!user || !user.passwordHash || !bcrypt.compareSync(String(password), user.passwordHash)) {
      return res.status(400).json({ error: 'شماره یا رمز عبور اشتباه است' });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
    return res.json({ token, name: user.name, balance: Number(user.balance || 0) });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'خطای داخلی سرور' });
  }
});

// ============================================================
// TASKS ROUTES
// ============================================================
app.get('/api/tasks', authRequired, (req, res) => {
  try {
    const db = readDB();
    const user = findUser(db, req.userId);
    if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
    const doneToday = user.completedTasks[todayKey()] || [];
    const tasks = MOCK_TASKS.map(t => ({ ...t, done: doneToday.includes(t.id) }));
    return res.json({ tasks, balance: user.balance });
  } catch (error) {
    return res.status(500).json({ error: 'خطای سرور' });
  }
});

app.post('/api/tasks/:id/complete', authRequired, (req, res) => {
  try {
    const db = readDB();
    const user = findUser(db, req.userId);
    if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
    const task = MOCK_TASKS.find(t => t.id === req.params.id);
    if (!task) return res.status(404).json({ error: 'این تسک وجود ندارد' });

    const key = todayKey();
    if (!user.completedTasks[key]) user.completedTasks[key] = [];
    if (user.completedTasks[key].includes(task.id)) {
      return res.status(400).json({ error: 'این تسک را امروز قبلاً انجام داده‌اید' });
    }
    user.completedTasks[key].push(task.id);
    user.balance += task.reward;
    writeDB(db);
    return res.json({ balance: user.balance, reward: task.reward });
  } catch (error) {
    return res.status(500).json({ error: 'خطای سرور' });
  }
});

// ============================================================
// CPX RESEARCH SYSTEM (FORCED BYPASS FOR TEST MODE)
// ============================================================
app.get('/api/cpx/offerwall-link', authRequired, (req, res) => {
  try {
    const db = readDB();
    const user = findUser(db, req.userId);
    if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
    const userIdStr = String(user.id);
    const secureHash = md5(`${userIdStr}${CPX_SECURE_HASH}`);
    const url = `https://cpx-research.com{CPX_APP_ID}&ext_user_id=${userIdStr}&secure_hash=${secureHash}&username=${encodeURIComponent(user.name)}`;
    return res.json({ url });
  } catch (error) {
    return res.status(500).json({ error: 'خطای سرور' });
  }
});

app.get('/api/cpx/postback', (req, res) => {
  try {
    const { status, trans_id, user_id, amount_usd } = req.query;
    if (!status || !trans_id || !user_id) {
      return res.status(400).send('missing params');
    }

    const db = readDB();
    if (!db.cpxTransactions) db.cpxTransactions = [];

    const user = findUser(db, Number(user_id));
    if (!user) return res.status(404).send('user not found');

    const existing = db.cpxTransactions.find(t => t.trans_id === trans_id);

    if (String(status) === '1') {
      if (existing) return res.send('1');
      const amountAfn = Math.round(Number(amount_usd) * AFN_PER_USD * USER_SHARE);
      user.balance += amountAfn;
      db.cpxTransactions.push({ trans_id, userId: user.id, amountAfn, status: 'completed', createdAt: new Date().toISOString() });
      writeDB(db);
    }

    return res.send('1');
  } catch (error) {
    return res.status(200).send('1');
  }
});

