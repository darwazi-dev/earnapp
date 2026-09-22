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

const CPX_APP_ID = (process.env.CPX_APP_ID || '36387').trim();
const CPX_SECURE_HASH = (process.env.CPX_SECURE_HASH || '').trim();
const AFN_PER_USD = Number(process.env.AFN_PER_USD || 68);
const USER_SHARE = Number(process.env.USER_SHARE || 0.55);
// how long a real-money earning stays PENDING before it's safe to withdraw.
// CPX's own fraud window is 15-60 days; this is a shorter MVP default you can raise later.
const EARNING_HOLD_HOURS = Number(process.env.EARNING_HOLD_HOURS || 72);

function md5(str) {
  return crypto.createHash('md5').update(String(str)).digest('hex');
}
function newId() {
  return crypto.randomBytes(12).toString('hex');
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Database ----------
function createInitialDB() {
  return { users: [], withdrawals: [], ledger: [], cpxTransactions: [], nextUserId: 1, nextWithdrawId: 1 };
}
function readDB() {
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DB_FILE)) {
    const initial = createInitialDB();
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  if (!Array.isArray(db.ledger)) db.ledger = [];
  if (!Array.isArray(db.cpxTransactions)) db.cpxTransactions = [];
  // migrate old flat-balance users to the wallet shape
  db.users.forEach(u => {
    if (!u.wallet) {
      u.wallet = {
        available: u.balance || 0,
        pending: 0,
        lifetimeEarnings: u.balance || 0,
        lifetimeWithdrawals: 0,
      };
    }
  });
  return db;
}
function writeDB(db) {
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function findUser(db, userId) { return db.users.find(u => u.id === userId); }
function todayKey() { return new Date().toISOString().slice(0, 10); }

// ---------- Ledger: every wallet change is an immutable, auditable entry ----------
// type: EARNING | WITHDRAWAL | REVERSAL | ADJUSTMENT | TEST
// status: PENDING | APPROVED | REJECTED | REVERSED
function addLedgerEntry(db, { userId, transactionId, type, amount, status, metadata }) {
  const entry = {
    id: newId(),
    userId,
    transactionId: transactionId || newId(),
    type,
    amount,
    currency: 'AFN',
    status,
    createdAt: new Date().toISOString(),
    metadata: metadata || {},
  };
  db.ledger.push(entry);
  return entry;
}

// Moves any EARNING entries whose hold period has passed from pending -> available.
// Called lazily whenever wallet data is read, instead of needing a cron job.
function promotePendingEarnings(db, user) {
  const cutoff = Date.now() - EARNING_HOLD_HOURS * 3600 * 1000;
  let changed = false;
  db.ledger
    .filter(e => e.userId === user.id && e.type === 'EARNING' && e.status === 'PENDING')
    .forEach(e => {
      if (new Date(e.createdAt).getTime() <= cutoff) {
        e.status = 'APPROVED';
        e.resolvedAt = new Date().toISOString();
        user.wallet.pending -= e.amount;
        user.wallet.available += e.amount;
        user.wallet.lifetimeEarnings += e.amount;
        changed = true;
      }
    });
  return changed;
}

// ---------- Mock tasks (test only — instant, non-real money) ----------
const MOCK_TASKS = [
  { id: 't1', title: 'نصب اپلیکیشن و باز کردن آن', desc: 'یک اپ را نصب کن و ۳۰ ثانیه باز نگه‌دار', reward: 35 },
  { id: 't2', title: 'تکمیل یک سروی کوتاه', desc: 'به ۵ سوال ساده جواب بده', reward: 28 },
  { id: 't3', title: 'ثبت‌نام آزمایشی در یک سایت', desc: 'با ایمیل خود ثبت‌نام کن (رایگان)', reward: 22 },
  { id: 't4', title: 'تماشای یک ویدیوی تبلیغاتی', desc: '۳۰ ثانیه ویدیو را کامل تماشا کن', reward: 8 },
  { id: 't5', title: 'نصب یک بازی و رسیدن به لول ۳', desc: 'بازی را نصب کن و تا لول ۳ برو', reward: 45 },
  { id: 't6', title: 'تکمیل یک کوییز کوچک', desc: 'یک کوییز ۳ سوالی را کامل کن', reward: 18 },
];

// ---------- Auth ----------
function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'وارد نشده‌اید' });
  try {
    req.userId = jwt.verify(token, JWT_SECRET).userId;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'نشست شما منقضی شده، دوباره وارد شوید' });
  }
}
function adminRequired(req, res, next) {
  if (req.headers['x-admin-password'] !== ADMIN_PASSWORD) return res.status(401).json({ error: 'رمز ادمین اشتباه است' });
  next();
}

// ---------- Auth routes ----------
app.post('/api/register', (req, res) => {
  const { name, phone, password } = req.body;
  if (!name || !phone || !password) return res.status(400).json({ error: 'نام، شماره تلفن و رمز عبور لازم است' });
  if (password.length < 4) return res.status(400).json({ error: 'رمز عبور باید حداقل ۴ کاراکتر باشد' });
  const db = readDB();
  if (db.users.find(u => u.phone === phone)) return res.status(400).json({ error: 'این شماره قبلاً ثبت‌نام کرده است' });
  const user = {
    id: db.nextUserId++,
    name, phone,
    passwordHash: bcrypt.hashSync(password, 10),
    wallet: { available: 0, pending: 0, lifetimeEarnings: 0, lifetimeWithdrawals: 0 },
    completedTasks: {},
    createdAt: new Date().toISOString(),
  };
  db.users.push(user);
  writeDB(db);
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, name: user.name, balance: user.wallet.available });
});

app.post('/api/login', (req, res) => {
  const { phone, password } = req.body;
  const db = readDB();
  const user = db.users.find(u => u.phone === phone);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) return res.status(400).json({ error: 'شماره یا رمز عبور اشتباه است' });
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, name: user.name, balance: user.wallet.available });
});

// ---------- Mock tasks (test money, credited instantly & approved — clearly separate from real earnings) ----------
app.get('/api/tasks', authRequired, (req, res) => {
  const db = readDB();
  const user = findUser(db, req.userId);
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
  promotePendingEarnings(db, user);
  writeDB(db);
  const doneToday = user.completedTasks[todayKey()] || [];
  res.json({ tasks: MOCK_TASKS.map(t => ({ ...t, done: doneToday.includes(t.id) })), balance: user.wallet.available });
});

app.post('/api/tasks/:id/complete', authRequired, (req, res) => {
  const db = readDB();
  const user = findUser(db, req.userId);
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
  const task = MOCK_TASKS.find(t => t.id === req.params.id);
  if (!task) return res.status(404).json({ error: 'این تسک وجود ندارد' });
  const key = todayKey();
  if (!user.completedTasks[key]) user.completedTasks[key] = [];
  if (user.completedTasks[key].includes(task.id)) return res.status(400).json({ error: 'این تسک را امروز قبلاً انجام داده‌اید' });
  user.completedTasks[key].push(task.id);
  user.wallet.available += task.reward;
  user.wallet.lifetimeEarnings += task.reward;
  addLedgerEntry(db, { userId: user.id, type: 'TEST', amount: task.reward, status: 'APPROVED', metadata: { taskId: task.id } });
  writeDB(db);
  res.json({ balance: user.wallet.available, reward: task.reward });
});

// ---------- CPX Research: real offerwall link ----------
app.get('/api/cpx/offerwall-link', authRequired, (req, res) => {
  const db = readDB();
  const user = findUser(db, req.userId);
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
  const userIdStr = String(user.id);
  const secureHash = md5(`${userIdStr}-${CPX_SECURE_HASH}`);
  const url = `https://offers.cpx-research.com/index.php?app_id=${CPX_APP_ID}&ext_user_id=${userIdStr}&secure_hash=${secureHash}&username=${encodeURIComponent(user.name)}`;
  res.json({ url });
});

// ---------- CPX Research: postback — real money enters PENDING, not available ----------
app.get('/api/cpx/postback', (req, res) => {
  const { status, trans_id, user_id, amount_usd, hash } = req.query;
  if (!status || !trans_id || !user_id || !hash) return res.status(400).send('missing params');

  const expectedHash = md5(`${trans_id}-${CPX_SECURE_HASH}`);
  if (hash !== expectedHash) return res.status(403).send('invalid hash');

  const db = readDB();
  const user = findUser(db, Number(user_id));
  if (!user) return res.status(404).send('user not found');

  const existingTx = db.cpxTransactions.find(t => t.trans_id === trans_id);

  if (String(status) === '1') {
    if (existingTx) return res.send('1'); // already processed, avoid double-credit on retry
    const amountAfn = Math.round(Number(amount_usd) * AFN_PER_USD * USER_SHARE);
    user.wallet.pending += amountAfn; // NOT available yet — sits in fraud-hold
    const entry = addLedgerEntry(db, {
      userId: user.id, transactionId: trans_id, type: 'EARNING', amount: amountAfn, status: 'PENDING',
      metadata: { provider: 'cpx_research', amount_usd },
    });
    db.cpxTransactions.push({ trans_id, userId: user.id, amountAfn, ledgerEntryId: entry.id, createdAt: new Date().toISOString() });
    writeDB(db);
  } else if (String(status) === '2') {
    // CPX detected fraud and is reversing a previously reported completion
    const entry = db.ledger.find(e => e.transactionId === trans_id && e.type === 'EARNING');
    if (entry && entry.status === 'PENDING') {
      entry.status = 'REVERSED';
      entry.resolvedAt = new Date().toISOString();
      user.wallet.pending = Math.max(0, user.wallet.pending - entry.amount);
      writeDB(db);
    } else if (entry && entry.status === 'APPROVED') {
      // rare: already promoted to available before CPX's own reversal window closed — real loss
      entry.status = 'REVERSED';
      entry.resolvedAt = new Date().toISOString();
      user.wallet.available = Math.max(0, user.wallet.available - entry.amount);
      user.wallet.lifetimeEarnings = Math.max(0, user.wallet.lifetimeEarnings - entry.amount);
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
  promotePendingEarnings(db, user);
  writeDB(db);
  const myWithdrawals = db.withdrawals.filter(w => w.userId === user.id).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const myLedger = db.ledger.filter(e => e.userId === user.id).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({
    available: user.wallet.available,
    pending: user.wallet.pending,
    lifetimeEarnings: user.wallet.lifetimeEarnings,
    lifetimeWithdrawals: user.wallet.lifetimeWithdrawals,
    withdrawals: myWithdrawals,
    ledger: myLedger,
    minWithdraw: MIN_WITHDRAW_AFN,
    earningHoldHours: EARNING_HOLD_HOURS,
  });
});

app.post('/api/withdraw', authRequired, (req, res) => {
  const { amount, method, account } = req.body;
  const db = readDB();
  const user = findUser(db, req.userId);
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
  promotePendingEarnings(db, user);
  const amt = Number(amount);
  if (!amt || amt < MIN_WITHDRAW_AFN) return res.status(400).json({ error: `حداقل مبلغ برداشت ${MIN_WITHDRAW_AFN} افغانی است` });
  if (amt > user.wallet.available) return res.status(400).json({ error: 'موجودی قابل‌برداشت شما کافی نیست' });
  if (!method || !account) return res.status(400).json({ error: 'روش پرداخت و شماره حساب را وارد کنید' });

  user.wallet.available -= amt;
  const withdrawId = db.nextWithdrawId++;
  const entry = addLedgerEntry(db, { userId: user.id, type: 'WITHDRAWAL', amount: -amt, status: 'PENDING', metadata: { withdrawId } });
  const withdrawal = {
    id: withdrawId, userId: user.id, userName: user.name, userPhone: user.phone,
    amount: amt, method, account, status: 'pending', ledgerEntryId: entry.id, createdAt: new Date().toISOString(),
  };
  db.withdrawals.push(withdrawal);
  writeDB(db);
  res.json({ balance: user.wallet.available, withdrawal });
});

// ---------- Admin ----------
app.post('/api/admin/login', (req, res) => {
  if (req.body.password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'رمز اشتباه است' });
  res.json({ ok: true });
});
app.get('/api/admin/withdrawals', adminRequired, (req, res) => {
  res.json({ withdrawals: readDB().withdrawals.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)) });
});
app.get('/api/admin/stats', adminRequired, (req, res) => {
  const db = readDB();
  const pending = db.withdrawals.filter(w => w.status === 'pending');
  res.json({
    totalUsers: db.users.length,
    totalAvailable: db.users.reduce((s, u) => s + u.wallet.available, 0),
    totalPending: db.users.reduce((s, u) => s + u.wallet.pending, 0),
    totalLifetimeEarnings: db.users.reduce((s, u) => s + u.wallet.lifetimeEarnings, 0),
    pendingWithdrawCount: pending.length,
    pendingWithdrawAmount: pending.reduce((s, w) => s + w.amount, 0),
    paidOut: db.withdrawals.filter(w => w.status === 'approved').reduce((s, w) => s + w.amount, 0),
  });
});
app.post('/api/admin/withdrawals/:id/approve', adminRequired, (req, res) => {
  const db = readDB();
  const w = db.withdrawals.find(x => x.id === Number(req.params.id));
  if (!w) return res.status(404).json({ error: 'یافت نشد' });
  w.status = 'approved';
  w.resolvedAt = new Date().toISOString();
  const user = findUser(db, w.userId);
  if (user) user.wallet.lifetimeWithdrawals += w.amount;
  const entry = db.ledger.find(e => e.id === w.ledgerEntryId);
  if (entry) entry.status = 'APPROVED';
  writeDB(db);
  res.json({ ok: true });
});
app.post('/api/admin/withdrawals/:id/reject', adminRequired, (req, res) => {
  const db = readDB();
  const w = db.withdrawals.find(x => x.id === Number(req.params.id));
  if (!w) return res.status(404).json({ error: 'یافت نشد' });
  const user = findUser(db, w.userId);
  if (user) user.wallet.available += w.amount; // refund back to available
  const entry = db.ledger.find(e => e.id === w.ledgerEntryId);
  if (entry) entry.status = 'REJECTED';
  w.status = 'rejected';
  w.resolvedAt = new Date().toISOString();
  writeDB(db);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
