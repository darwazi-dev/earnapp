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

function todayKey() {
  return new Date().toISOString().slice(0, 10);
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function createInitialDB() {
  return { users: [], withdrawals: [], nextUserId: 1, nextWithdrawId: 1, cpxTransactions: [] };
}

function readDB() {
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DB_FILE)) {
    const initial = createInitialDB();
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2), 'utf8');
    return initial;
  }
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
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
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
}

function findUser(db, userId) {
  return db.users.find(u => Number(u.id) === Number(userId));
}

const MOCK_TASKS = [
  { id: 't1', title: 'نصب اپلیکیشن و باز کردن آن', desc: 'یک اپ را نصب کن و ۳۰ ثانیه باز نگه‌دار', reward: 35 },
  { id: 't2', title: 'تکمیل یک سروی کوتاه', desc: 'به ۵ سوال ساده جواب بده', reward: 28 },
  { id: 't3', title: 'ثبت‌نام آزمایشی در یک سایت', desc: 'با ایمیل خود ثبت‌نام کن (رایگان)', reward: 22 },
  { id: 't4', title: 'تماشای یک ویدیوی تبلیغاتی', desc: '۳۰ ثانیه ویدیو را کامل تماشا کن', reward: 8 },
  { id: 't5', title: 'نصب یک بازی و رسیدن به لول ۳', desc: 'بازی را نصب کن و تا لول ۳ برو', reward: 45 },
  { id: 't6', title: 'تکمیل یک کوییز کوچک', desc: 'یک کوییز ۳ سوالی را کامل کن', reward: 18 }
];

// سیستم احراز هویت ساده مبتنی بر شناسه عددی (جایگزین JWT سمی و کرش‌کننده)
function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'وارد نشده‌اید' });
  req.userId = Number(token);
  next();
}

function adminMiddleware(req, res, next) {
  if (req.headers['x-admin-password'] !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'رمز ادمین اشتباه است' });
  }
  next();
}

// ثبت‌نام و ورود کاربران
app.post('/api/register', (req, res) => {
  const { name, phone, password } = req.body;
  if (!name || !phone || !password) return res.status(400).json({ error: 'اطلاعات ناقص است' });
  const db = readDB();
  if (db.users.find(u => u.phone === phone)) return res.status(400).json({ error: 'این شماره قبلاً ثبت‌نام کرده است' });
  
  const user = { id: db.nextUserId++, name, phone, passwordHash: hashPassword(password), balance: 0, completedTasks: {} };
  db.users.push(user);
  writeDB(db);
  res.json({ token: String(user.id), name: user.name, balance: user.balance });
});

app.post('/api/login', (req, res) => {
  const { phone, password } = req.body;
  const db = readDB();
  const user = db.users.find(u => u.phone === phone && u.passwordHash === hashPassword(password));
  if (!user) return res.status(400).json({ error: 'شماره یا رمز عبور اشتباه است' });
  res.json({ token: String(user.id), name: user.name, balance: user.balance });
});

// تسک‌ها و لیست فعالیت‌ها
app.get('/api/tasks', authMiddleware, (req, res) => {
  const db = readDB();
  const user = findUser(db, req.userId);
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
  if (!user.completedTasks) user.completedTasks = {};
  const doneToday = user.completedTasks[todayKey()] || [];
  const tasks = MOCK_TASKS.map(t => ({ ...t, done: doneToday.includes(t.id) }));
  res.json({ tasks, balance: user.balance });
});

app.post('/api/tasks/:id/complete', authMiddleware, (req, res) => {
  const db = readDB();
  const user = findUser(db, req.userId);
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
  const task = MOCK_TASKS.find(t => t.id === req.params.id);
  if (!task) return res.status(404).json({ error: 'تسک یافت نشد' });

  if (!user.completedTasks) user.completedTasks = {};
  const key = todayKey();
  if (!user.completedTasks[key]) user.completedTasks[key] = [];
  if (user.completedTasks[key].includes(task.id)) return res.status(400).json({ error: 'امروز انجام شده است' });

  user.completedTasks[key].push(task.id);
  user.balance += task.reward;
  writeDB(db);
  res.json({ balance: user.balance, reward: task.reward });
});

// مسیر پاست‌بک واقعی CPX با ذخیره تراکنش‌ها و افزودن کوین به دیتابیس کاربران زنده
app.get('/api/cpx/postback', (req, res) => {
  try {
    const { status, trans_id, user_id, amount_usd } = req.query;
    if (!status || !trans_id || !user_id) return res.status(200).send('1');

    const db = readDB();
    const user = findUser(db, Number(user_id));
    if (!user) return res.status(200).send('1');

    if (!db.cpxTransactions) db.cpxTransactions = [];
    const existing = db.cpxTransactions.find(t => t.trans_id === trans_id);

    if (String(status) === '1' && !existing) {
      const amountAfn = Math.round(Number(amount_usd || 0) * AFN_PER_USD * USER_SHARE);
      user.balance += amountAfn;
      db.cpxTransactions.push({ trans_id, userId: user.id, amountAfn, status: 'completed', createdAt: new Date().toISOString() });
      writeDB(db);
    }
    return res.status(200).send('1');
  } catch (e) {
    return res.status(200).send('1');
  }
});

// سیستم کیف‌پول و درخواست برداشت وجه افغانی
app.get('/api/wallet', authMiddleware, (req, res) => {
  const db = readDB();
  const user = findUser(db, req.userId);
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
  const myWithdrawals = db.withdrawals.filter(w => Number(w.userId) === Number(user.id));
  res.json({ balance: user.balance, withdrawals: myWithdrawals });
});

app.post('/api/withdraw', authMiddleware, (req, res) => {
  const { amount, paymentMethod, accountDetails } = req.body;
  if (!amount || !paymentMethod || !accountDetails) return res.status(400).json({ error: 'اطلاعات ناقص' });
  
  const withdrawAmount = Number(amount);
  if (withdrawAmount < MIN_WITHDRAW_AFN) return res.status(400).json({ error: `حداقل برداشت ${MIN_WITHDRAW_AFN} افغانی` });

  const db = readDB();
  const user = findUser(db, req.userId);
  if (!user || user.balance < withdrawAmount) return res.status(400).json({ error: 'موجودي ناکافی' });

  user.balance -= withdrawAmount;
  db.withdrawals.push({
    id: db.nextWithdrawId++, userId: user.id, userName: user.name, userPhone: user.phone,
    amount: withdrawAmount, paymentMethod, accountDetails, status: 'pending', createdAt: new Date().toISOString()
  });
  writeDB(db);
  res.json({ balance: user.balance });
});

// پنل مدیریت و تایید پرداخت‌ها
app.get('/api/admin/withdrawals', adminMiddleware, (req, res) => {
  res.json({ withdrawals: readDB().withdrawals });
});

app.post('/api/admin/withdrawals/:id/approve', adminMiddleware, (req, res) => {
  const db = readDB();
  const w = db.withdrawals.find(item => Number(item.id) === Number(req.params.id));
  if (!w) return res.status(404).json({ error: 'یافت نشد' });
  w.status = 'approved';
  writeDB(db);
  res.json({ success: true });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Karyab Enterprise Engine running on port ${PORT}`);
});
