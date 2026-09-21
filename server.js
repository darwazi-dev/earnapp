const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const DB_FILE = path.join(__dirname, 'data', 'db.json');
const MIN_WITHDRAW_AFN = 500;

// ---------- CPX Research (real CPA network) config ----------
const CPX_APP_ID = process.env.CPX_APP_ID || '36587';
const CPX_SECURE_HASH = process.env.CPX_SECURE_HASH || ''; // set this in Railway Variables
const AFN_PER_USD = Number(process.env.AFN_PER_USD || 68); // update if exchange rate moves
const USER_SHARE = Number(process.env.USER_SHARE || 0.55); // fraction of AFN value credited to user, rest is platform revenue

function md5(str) {
  return crypto.createHash('md5').update(str).digest('hex');
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Simple JSON "database" ----------
function readDB() {
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DB_FILE)) {
    const initial = { users: [], withdrawals: [], nextUserId: 1, nextWithdrawId: 1 };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  if (!db.cpxTransactions) db.cpxTransactions = []; // migrate older db.json files
  return db;
}
function writeDB(db) {
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// ---------- Mock tasks (replace later with real CPA network API calls) ----------
// reward is in AFN (already converted from network's USD payout)
const MOCK_TASKS = [
  { id: 't1', title: 'نصب اپلیکیشن و باز کردن آن', desc: 'یک اپ را نصب کن و ۳۰ ثانیه باز نگه‌دار', reward: 35 },
  { id: 't2', title: 'تکمیل یک سروی کوتاه', desc: 'به ۵ سوال ساده جواب بده', reward: 28 },
  { id: 't3', title: 'ثبت‌نام آزمایشی در یک سایت', desc: 'با ایمیل خود ثبت‌نام کن (رایگان)', reward: 22 },
  { id: 't4', title: 'تماشای یک ویدیوی تبلیغاتی', desc: '۳۰ ثانیه ویدیو را کامل تماشا کن', reward: 8 },
  { id: 't5', title: 'نصب یک بازی و رسیدن به لول ۳', desc: 'بازی را نصب کن و تا لول ۳ برو', reward: 45 },
  { id: 't6', title: 'تکمیل یک کوییز کوچک', desc: 'یک کوییز ۳ سوالی را کامل کن', reward: 18 },
];

function findUser(db, userId) {
  return db.users.find(u => u.id === userId);
}

function todayKey() {
  return new Date().toISOString().slice(0, 10); // YYYY-MM-DD
}

// ---------- Auth middleware ----------
function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'وارد نشده‌اید' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'نشست شما منقضی شده، دوباره وارد شوید' });
  }
}

function adminRequired(req, res, next) {
  const pass = req.headers['x-admin-password'];
  if (pass !== ADMIN_PASSWORD) return res.status(401).json({ error: 'رمز ادمین اشتباه است' });
  next();
}

// ---------- Auth routes ----------
app.post('/api/register', (req, res) => {
  const { name, phone, password } = req.body;
  if (!name || !phone || !password) {
    return res.status(400).json({ error: 'نام، شماره تلفن و رمز عبور لازم است' });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: 'رمز عبور باید حداقل ۴ کاراکتر باشد' });
  }
  const db = readDB();
  if (db.users.find(u => u.phone === phone)) {
    return res.status(400).json({ error: 'این شماره قبلاً ثبت‌نام کرده است' });
  }
  const hash = bcrypt.hashSync(password, 10);
  const user = {
    id: db.nextUserId++,
    name,
    phone,
    passwordHash: hash,
    balance: 0,
    completedTasks: {},
    createdAt: new Date().toISOString(),
  };
  db.users.push(user);
  writeDB(db);
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, name: user.name, balance: user.balance });
});

app.post('/api/login', (req, res) => {
  const { phone, password } = req.body;
  const db = readDB();
  const user = db.users.find(u => u.phone === phone);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(400).json({ error: 'شماره یا رمز عبور اشتباه است' });
  }
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, name: user.name, balance: user.balance });
});

// ---------- Tasks ----------
app.get('/api/tasks', authRequired, (req, res) => {
  const db = readDB();
  const user = findUser(db, req.userId);
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
  const doneToday = user.completedTasks[todayKey()] || [];
  const tasks = MOCK_TASKS.map(t => ({ ...t, done: doneToday.includes(t.id) }));
  res.json({ tasks, balance: user.balance });
});

app.post('/api/tasks/:id/complete', authRequired, (req, res) => {
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
  res.json({ balance: user.balance, reward: task.reward });
});

// ---------- CPX Research: real offerwall link ----------
app.get('/api/cpx/offerwall-link', authRequired, (req, res) => {
  const db = readDB();
  const user = findUser(db, req.userId);
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
  const userIdStr = String(user.id);
  const secureHash = md5(`${userIdStr}${CPX_SECURE_HASH}`);
  const url = `https://offers.cpx-research.com/index.php?app_id=${CPX_APP_ID}&ext_user_id=${userIdStr}&secure_hash=${secureHash}&username=${encodeURIComponent(user.name)}`;
  res.json({ url });
});

// ---------- CPX Research: postback (server-to-server, called by CPX, not the browser) ----------
app.get('/api/cpx/postback', (req, res) => {
  const { status, trans_id, user_id, amount_usd, hash } = req.query;
  if (!status || !trans_id || !user_id || !hash) {
    return res.status(400).send('missing params');
  }

  const expectedHash = md5(`${trans_id}-${CPX_SECURE_HASH}`);
  if (hash !== expectedHash) {
    return res.status(403).send('invalid hash');
  }

  const db = readDB();
  const user = findUser(db, Number(user_id));
  if (!user) return res.status(404).send('user not found');

  const existing = db.cpxTransactions.find(t => t.trans_id === trans_id);

  if (String(status) === '1') {
    if (existing) return res.send('1');
    const amountAfn = Math.round(Number(amount_usd) * AFN_PER_USD * USER_SHARE);
    user.balance += amountAfn;
    db.cpxTransactions.push({ trans_id, userId: user.id, amountAfn, status: 'completed', createdAt: new Date().toISOString() });
    writeDB(db);
  } else if (String(status) === '2') {
    if (existing && existing.status === 'completed') {
      user.balance = Math.max(0, user.balance - existing.amountAfn);
      existing.status = 'reversed';
      writeDB(db);
    }
  }

  res.send('1');
});

// ---------- Wallet & withdrawals ----------
app.get('/api/wallet', authRequired, (req, res) => {
  const db = readDB();
  const user = findUser(db, req.userId);
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
  const myWithdrawals = db.withdrawals
    .filter(w => w.userId === user.id)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ balance: user.balance, withdrawals: myWithdrawals, minWithdraw: MIN_WITHDRAW_AFN });
});

app.post('/api/withdraw', authRequired, (req, res) => {
  const { amount, method, account } = req.body;
  const db = readDB();
  const user = findUser(db, req.userId);
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });

  const amt = Number(amount);
  if (!amt || amt < MIN_WITHDRAW_AFN) {
    return res.status(400).json({ error: `حداقل مبلغ برداشت ${MIN_WITHDRAW_AFN} افغانی است` });
  }
  if (amt > user.balance) {
    return res.status(400).json({ error: 'موجودی شما کافی نیست' });
  }
  if (!method || !account) {
    return res.status(400).json({ error: 'روش پرداخت و شماره حساب را وارد کنید' });
  }

  user.balance -= amt;
  const withdrawal = {
    id: db.nextWithdrawId++,
    userId: user.id,
    userName: user.name,
    userPhone: user.phone,
    amount: amt,
    method,
    account,
    status: 'pending',
    createdAt: new Date().toISOString(),
  };
  db.withdrawals.push(withdrawal);
  writeDB(db);
  res.json({ balance: user.balance, withdrawal });
});

// ---------- Admin ----------
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'رمز اشتباه است' });
  res.json({ ok: true });
});

app.get('/api/admin/withdrawals', adminRequired, (req, res) => {
  const db = readDB();
  const list = db.withdrawals.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ withdrawals: list });
});

app.get('/api/admin/stats', adminRequired, (req, res) => {
  const db = readDB();
  const totalUsers = db.users.length;
  const totalBalance = db.users.reduce((s, u) => s + u.balance, 0);
  const pendingWithdrawals = db.withdrawals.filter(w => w.status === 'pending');
  const paidOut = db.withdrawals.filter(w => w.status === 'approved').reduce((s, w) => s + w.amount, 0);
  res.json({
    totalUsers,
    totalBalanceHeld: totalBalance,
    pendingCount: pendingWithdrawals.length,
    pendingAmount: pendingWithdrawals.reduce((s, w) => s + w.amount, 0),
    paidOut,
  });
});

app.post('/api/admin/withdrawals/:id/approve', adminRequired, (req, res) => {
  const db = readDB();
  const w = db.withdrawals.find(x => x.id === Number(req.params.id));
  if (!w) return res.status(404).json({ error: 'یافت نشد' });
  w.status = 'approved';
  w.resolvedAt = new Date().toISOString();
  writeDB(db);
  res.json({ ok: true });
});

app.post('/api/admin/withdrawals/:id/reject', adminRequired, (req, res) => {
  const db = readDB();
  const w = db.withdrawals.find(x => x.id === Number(req.params.id));
  if (!w) return res.status(404).json({ error: 'یافت نشد' });
  const user = findUser(db, w.userId);
  if (user) user.balance += w.amount;
  w.status = 'rejected';
  w.resolvedAt = new Date().toISOString();
  writeDB(db);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
