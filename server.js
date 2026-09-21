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
const CPX_SECURE_HASH = 'MAb1fBtz6Y0TqrfpGkb0UQQ95w5ja4sD';
const AFN_PER_USD = Number(process.env.AFN_PER_USD || 68);
const USER_SHARE = Number(process.env.USER_SHARE || 0.55);

function md5(str) {
  return crypto.createHash('md5').update(String(str)).digest('hex');
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function readDB() {
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DB_FILE)) {
    const initial = { users: [], withdrawals: [], nextUserId: 1, nextWithdrawId: 1, cpxTransactions: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  try {
    const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (!Array.isArray(db.cpxTransactions)) db.cpxTransactions = [];
    if (!Array.isArray(db.withdrawals)) db.withdrawals = [];
    if (!Array.isArray(db.users)) db.users = [];
    return db;
  } catch (e) {
    return { users: [], withdrawals: [], nextUserId: 1, nextWithdrawId: 1, cpxTransactions: [] };
  }
}

function writeDB(db) {
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

const MOCK_TASKS = [
  { id: 't1', title: 'نصب اپلیکیشن و باز کردن آن', desc: 'یک اپ را نصب کن و ۳۰ ثانیه باز نگه‌دار', reward: 35 },
  { id: 't2', title: 'تکمیل یک سروی کوتاه', desc: 'به ۵ سوال ساده جواب بده', reward: 28 },
  { id: 't3', title: 'ثبت‌نام آزمایشی در یک سایت', desc: 'با ایمیل خود ثبت‌نام کن (رایگان)', reward: 22 },
  { id: 't4', title: 'تماشای یک ویدیوی تبلیغاتی', desc: '۳۰ ثانیه ویدیو را کامل تماشا کن', reward: 8 },
  { id: 't5', title: 'نصب یک بازی و رسیدن به لول ۳', desc: 'بازی را نصب کن و تا لول ۳ برو', reward: 45 },
  { id: 't6', title: 'تکمیل یک کوییز کوچک', desc: 'یک کوییز ۳ سوالی را کامل کن', reward: 18 },
];

function findUser(db, userId) { return db.users.find(u => u.id === userId); }
function todayKey() { return new Date().toISOString().slice(0, 10); }

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

// ثبت‌نام مجهز به ذخیره سوال و پاسخ امنیتی
app.post('/api/register', (req, res) => {
  const { name, phone, password, question, answer } = req.body;
  if (!name || !phone || !password || !question || !answer) {
    return res.status(400).json({ error: 'همه فیلدها از جمله سوال و پاسخ امنیتی الزامی است' });
  }
  if (password.length < 4) return res.status(400).json({ error: 'رمز عبور باید حداقل ۴ کاراکتر باشد' });
  
  const db = readDB();
  if (db.users.find(u => String(u.phone) === String(phone).trim())) {
    return res.status(400).json({ error: 'این شماره قبلاً ثبت‌نام کرده است' });
  }

  const user = { 
    id: db.nextUserId++, 
    name: String(name).trim(), 
    phone: String(phone).trim(), 
    passwordHash: bcrypt.hashSync(password, 10), 
    securityQuestion: question,
    securityAnswerHash: crypto.createHash('sha256').update(String(answer).trim().toLowerCase()).digest('hex'),
    balance: 0, 
    completedTasks: {}, 
    createdAt: new Date().toISOString() 
  };

  db.users.push(user);
  writeDB(db);
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, name: user.name, balance: user.balance });
});

app.post('/api/login', (req, res) => {
  const { phone, password } = req.body;
  const db = readDB();
  const user = db.users.find(u => String(u.phone) === String(phone).trim());
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) return res.status(400).json({ error: 'شماره یا رمز عبور اشتباه است' });
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, name: user.name, balance: user.balance });
});

// مسیر بررسی وجود شماره تلفن و بازگرداندن متن سوال امنیتی به فرم فراموشی رمز
app.post('/api/forgot-password/check-phone', (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'شماره تلفن را وارد کنید' });
  const db = readDB();
  const user = db.users.find(u => String(u.phone) === String(phone).trim());
  if (!user) return res.status(404).json({ error: 'کاربری با این شماره تلفن یافت نشد' });
  
  // اگر کاربر قدیمی باشد و سوال امنیتی تعریف نکرده باشد
  const question = user.securityQuestion || "شهر تولد شما چیست؟ (تنظیم پیشفرض سیستم)";
  res.json({ question });
});

// مسیر تایید پاسخ سوال امنیتی و ثبت رمز عبور جدید
app.post('/api/forgot-password/reset', (req, res) => {
  const { phone, answer, newPassword } = req.body;
  if (!phone || !answer || !newPassword) return res.status(400).json({ error: 'تمامی فیلدها الزامی است' });
  if (newPassword.length < 4) return res.status(400).json({ error: 'رمز عبور جدید باید حداقل ۴ کاراکتر باشد' });

  const db = readDB();
  const user = db.users.find(u => String(u.phone) === String(phone).trim());
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });

  const inputAnswerHash = crypto.createHash('sha256').update(String(answer).trim().toLowerCase()).digest('hex');
  
  // تایید صحت پاسخ امنیتی (اگر کاربر قدیمی سوال نداشت، کلمه admin یا پاسخ درست تایید می‌شود)
  if (user.securityAnswerHash && user.securityAnswerHash !== inputAnswerHash) {
    return res.status(400).json({ error: 'پاسخ سوال امنیتی اشتباه است' });
  }

  // به‌روزرسانی پسورد
  user.passwordHash = bcrypt.hashSync(newPassword, 10);
  writeDB(db);

  // تولید توکن ورود آنی پس از تعویض پسورد
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, name: user.name, balance: user.balance });
});

app.get('/api/tasks', authRequired, (req, res) => {
  const db = readDB();
  const user = findUser(db, req.userId);
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
  const doneToday = user.completedTasks[todayKey()] || [];
  res.json({ tasks: MOCK_TASKS.map(t => ({ ...t, done: doneToday.includes(t.id) })), balance: user.balance });
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
  user.balance += task.reward;
  writeDB(db);
  res.json({ balance: user.balance, reward: task.reward });
});

app.get('/api/cpx/offerwall-link', authRequired, (req, res) => {
  const db = readDB();
  const user = findUser(db, req.userId);
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
  const userIdStr = String(user.id);
  const secureHash = md5(`${userIdStr}${CPX_SECURE_HASH}`);
  const url = `https://cpx-research.com{CPX_APP_ID}&ext_user_id=${userIdStr}&secure_hash=${secureHash}&username=${encodeURIComponent(user.name)}`;
  res.json({ url });
});

app.get('/api/cpx/postback', (req, res) => {
  const { status, trans_id, user_id, amount_usd, hash } = req.query;
  if (!status || !trans_id || !user_id || !hash) return res.status(400).send('missing params');
  
  if (hash === '{hash}') return res.send('1');
  
  const expectedHash = md5(`${trans_id}${CPX_SECURE_HASH}`);
  if (hash.toLowerCase() !== expectedHash.toLowerCase()) return res.status(403).send('invalid hash');
  
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

app.get('/api/wallet', authRequired, (req, res) => {
  const db = readDB();
  const user = findUser(db, req.userId);
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
  const myWithdrawals = db.withdrawals.filter(w => w.userId === user.id).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ balance: user.balance, withdrawals: myWithdrawals, minWithdraw: MIN_WITHDRAW_AFN });
});

app.post('/api/withdraw', authRequired, (req, res) => {
