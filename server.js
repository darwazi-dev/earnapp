// ---------- CPX Research: postback (server-to-server, called by CPX, not the browser) ----------
app.get('/api/cpx/postback', (req, res) => {
  const { status, trans_id, user_id, amount_usd, hash } = req.query;
  if (!status || !trans_id || !user_id || !hash) {
    return res.status(400).send('missing params');
  }

  // اصلاح فرمول: حذف خط تیره (-) بر اساس مستندات رسمی پنل CPX
  const expectedHash = md5(`${trans_id}${CPX_SECURE_HASH}`);
  
  // مقایسه هش‌ها با حروف کوچک برای جلوگیری از خطای مچ نشدن کلمات
  if (hash.toLowerCase() !== expectedHash.toLowerCase()) {
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
