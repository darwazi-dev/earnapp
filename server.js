// ---------- Wallet & withdrawals ----------
app.get('/api/wallet', authRequired, (req, res) => {
  const db = readDB();
  const user = findUser(db, req.userId);
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
  const myWithdrawals = db.withdrawals
    .filter(w => w.userId === user.id)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ balance: user.balance, withdrawals: myWithdrawals });
});

app.post('/api/withdraw', authRequired, (req, res) => {
  const { amount, paymentMethod, accountDetails } = req.body;
  if (!amount || !paymentMethod || !accountDetails) {
    return res.status(400).json({ error: 'مبلغ، روش پرداخت و مشخصات حساب الزامی است' });
  }
  const withdrawAmount = Number(amount);
  if (withdrawAmount < MIN_WITHDRAW_AFN) {
    return res.status(400).json({ error: `حداقل مبلغ برداشت ${MIN_WITHDRAW_AFN} افغانی است` });
  }
  const db = readDB();
  const user = findUser(db, req.userId);
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
  if (user.balance < withdrawAmount) {
    return res.status(400).json({ error: 'موجودي کافی نیست' });
  }

  user.balance -= withdrawAmount;
  const withdrawal = {
    id: db.nextWithdrawId++,
    userId: user.id,
    userName: user.name,
    userPhone: user.phone,
    amount: withdrawAmount,
    paymentMethod,
    accountDetails,
    status: 'pending',
    createdAt: new Date().toISOString(),
  };
  db.withdrawals.push(withdrawal);
  writeDB(db);
  res.json({ balance: user.balance, withdrawal });
});

// ---------- Admin panel API ----------
app.get('/api/admin/withdrawals', adminRequired, (req, res) => {
  const db = readDB();
  res.json({ withdrawals: db.withdrawals });
});

app.post('/api/admin/withdrawals/:id/approve', adminRequired, (req, res) => {
  const db = readDB();
  const reqId = Number(req.params.id);
  const w = db.withdrawals.find(item => item.id === reqId);
  if (!w) return res.status(404).json({ error: 'درخواست یافت نشد' });
  w.status = 'approved';
  writeDB(db);
  res.json({ success: true, withdrawal: w });
});

app.post('/api/admin/withdrawals/:id/reject', adminRequired, (req, res) => {
  const db = readDB();
  const reqId = Number(req.params.id);
  const w = db.withdrawals.find(item => item.id === reqId);
  if (!w) return res.status(404).json({ error: 'درخواست یافت نشد' });
  if (w.status === 'pending') {
    const user = findUser(db, w.userId);
    if (user) user.balance += w.amount;
  }
  w.status = 'rejected';
  writeDB(db);
  res.json({ success: true, withdrawal: w });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
