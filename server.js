const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'karyab-secure-jwt-token-key-2026';
const DB_FILE = path.join(__dirname, 'data', 'db.json');
const MIN_WITHDRAW_AFN = 500;

const CPX_SECURE_HASH = 'MAb1fBtz6Y0TqrfpGkb0UQQ95w5ja4sD';
const AFN_PER_USD = Number(process.env.AFN_PER_USD || 68);
const USER_SHARE = Number(process.env.USER_SHARE || 0.55);

function md5(str) {
  return crypto.createHash('md5').update(String(str)).digest('hex');
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(String(password)).digest('hex');
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
    return JSON.parse(raw);
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

app.post('/api/register', (req, res) => {
  try {
    const { name, phone, password, question, answer } = req.body;
    if (!name || !phone || !password) return res.status(400).json({ error: 'اطلاعات ناقص است' });
    const db = readDB();
    if (db.users.find(u => u.phone === phone)) return res.status(400).json({ error: 'این شماره قبلاً ثبت‌نام کرده است' });
    
    const user = { 
      id: db.nextUserId++, name, phone, passwordHash: hashPassword(password), balance: 0,
      securityQuestion: question || "شهر تولد شما چیست؟",
      securityAnswerHash: answer ? crypto.createHash('sha256').update(String(answer).trim().toLowerCase()).digest('hex') : null,
      completedTasks: {}
    };
    db.users.push(user);
    writeDB(db);
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, name: user.name, balance: user.balance });
  } catch (e) { res.status(500).json({ error: 'خطای سرور' }); }
});

app.post('/api/login', (req, res) => {
  try {
    const { phone, password } = req.body;
    const db = readDB();
    const user = db.users.find(u => u.phone === phone && u.passwordHash === hashPassword(password));
    if (!user) return res.status(400).json({ error: 'شماره یا رمز عبور اشتباه است' });
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, name: user.name, balance: user.balance });
  } catch (e) { res.status(500).json({ error: 'خطای سرور' }); }
});

app.get('/api/tasks', (req, res) => {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'وارد نشده‌اید' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const db = readDB();
    const user = findUser(db, decoded.userId);
    if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
    res.json({ tasks: [], balance: user.balance || 0 });
  } catch (e) { res.status(401).json({ error: 'توکن نامعتبر' }); }
});

app.get('/api/cpx/offerwall-link', (req, res) => {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'وارد نشده‌اید' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const db = readDB();
    const user = findUser(db, decoded.userId);
    if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });

    const userIdStr = String(user.id);
    const secureHash = md5(`${userIdStr}${CPX_SECURE_HASH}`);
    
    // شناسه ۳۶۳۸۷ به صورت مستقیم و بدون واسطه در آدرس قرار گرفت
    const url = `https://cpx-research.com{userIdStr}&secure_hash=${secureHash}&username=${encodeURIComponent(user.name)}`;
    res.json({ url });
  } catch (e) { res.status(500).json({ error: 'خطای سرور' }); }
});

app.get('/api/cpx/postback', (req, res) => { return res.status(200).send('1'); });

app.listen(PORT, '0.0.0.0', () => { console.log(`Server running on port ${PORT}`); });
