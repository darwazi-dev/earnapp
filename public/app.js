const API = '';
let TOKEN = localStorage.getItem('token') || null;
let USER_NAME = localStorage.getItem('userName') || '';

function showView(name) {
  document.getElementById('view-login').classList.add('hidden');
  document.getElementById('view-register').classList.add('hidden');
  document.getElementById('view-main').classList.add('hidden');
  document.getElementById(`view-${name}`).classList.remove('hidden');
}

function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  setTimeout(() => t.classList.add('hidden'), 2500);
}

function showErr(id, msg) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.classList.remove('hidden');
}
function hideErr(id) {
  document.getElementById(id).classList.add('hidden');
}

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (TOKEN) headers['Authorization'] = 'Bearer ' + TOKEN;
  const res = await fetch(API + path, { ...opts, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || 'خطایی رخ داد');
  return data;
}

async function doLogin() {
  hideErr('login-err');
  const phone = document.getElementById('login-phone').value.trim();
  const password = document.getElementById('login-password').value;
  if (!phone || !password) return showErr('login-err', 'شماره و رمز عبور را وارد کنید');
  try {
    const data = await api('/api/login', { method: 'POST', body: JSON.stringify({ phone, password }) });
    TOKEN = data.token; USER_NAME = data.name;
    localStorage.setItem('token', TOKEN);
    localStorage.setItem('userName', USER_NAME);
    enterApp();
  } catch (e) {
    showErr('login-err', e.message);
  }
}

async function doRegister() {
  hideErr('register-err');
  const name = document.getElementById('reg-name').value.trim();
  const phone = document.getElementById('reg-phone').value.trim();
  const password = document.getElementById('reg-password').value;
  if (!name || !phone || !password) return showErr('register-err', 'همه فیلدها لازم است');
  try {
    const data = await api('/api/register', { method: 'POST', body: JSON.stringify({ name, phone, password }) });
    TOKEN = data.token; USER_NAME = data.name;
    localStorage.setItem('token', TOKEN);
    localStorage.setItem('userName', USER_NAME);
    enterApp();
  } catch (e) {
    showErr('register-err', e.message);
  }
}

function logout() {
  localStorage.removeItem('token');
  localStorage.removeItem('userName');
  TOKEN = null;
  showView('login');
}

async function enterApp() {
  document.getElementById('user-name').textContent = USER_NAME;
  showView('main');
  await loadTasks();
}

async function loadTasks() {
  try {
    const data = await api('/api/tasks');
    document.getElementById('balance').textContent = data.balance;
    const list = document.getElementById('tasks-list');
    list.innerHTML = '';
    data.tasks.forEach(t => {
      const div = document.createElement('div');
      div.className = 'task' + (t.done ? ' done' : '');
      div.innerHTML = `
        <div class="task-icon">🎯</div>
        <div class="task-info">
          <h3>${t.title}</h3>
          <p>${t.desc}</p>
        </div>
        <div class="task-reward">؋${t.reward}<small>پاداش</small></div>
        <button class="task-btn" ${t.done ? 'disabled' : ''} onclick="completeTask('${t.id}')">
          ${t.done ? 'انجام شد' : 'شروع'}
        </button>`;
      list.appendChild(div);
    });
  } catch (e) {
    if (e.message.includes('نشست')) { logout(); }
    toast(e.message);
  }
}

async function openRealOffers() {
  try {
    const data = await api('/api/cpx/offerwall-link');
    window.open(data.url, '_blank');
  } catch (e) {
    toast(e.message);
  }
}

async function completeTask(id) {
  try {
    const data = await api(`/api/tasks/${id}/complete`, { method: 'POST' });
    document.getElementById('balance').textContent = data.balance;
    toast(`آفرین! ${data.reward} افغانی به حساب شما اضافه شد`);
    await loadTasks();
  } catch (e) {
    toast(e.message);
  }
}

function openWithdraw() {
  document.getElementById('withdraw-modal').classList.remove('hidden');
  loadWallet();
}
function closeWithdraw() {
  document.getElementById('withdraw-modal').classList.add('hidden');
  hideErr('wd-err');
}

async function loadWallet() {
  try {
    const data = await api('/api/wallet');
    document.getElementById('pending-sub').textContent =
      data.pending > 0
        ? `؋${data.pending} در حال بررسی (طی ${data.earningHoldHours} ساعت آزاد می‌شود) — حداقل برداشت: ۵۰۰ افغانی`
        : 'حداقل برداشت: ۵۰۰ افغانی';
    const hist = document.getElementById('wd-history');
    if (!data.withdrawals.length) {
      hist.innerHTML = '<div class="hint">هنوز درخواست برداشتی ندارید</div>';
      return;
    }
    const statusLabel = { pending: 'در حال بررسی', approved: 'پرداخت شد', rejected: 'رد شد' };
    hist.innerHTML = '<div class="section-title" style="margin-top:0">تاریخچه درخواست‌ها</div>' +
      data.withdrawals.map(w => `
        <div class="wd-item">
          <span>؋${w.amount} — ${w.method}</span>
          <span class="status-pill status-${w.status}">${statusLabel[w.status]}</span>
        </div>`).join('');
  } catch (e) { toast(e.message); }
}

async function submitWithdraw() {
  hideErr('wd-err');
  const amount = document.getElementById('wd-amount').value;
  const method = document.getElementById('wd-method').value;
  const account = document.getElementById('wd-account').value.trim();
  if (!amount || !account) return showErr('wd-err', 'مبلغ و شماره حساب را وارد کنید');
  try {
    const data = await api('/api/withdraw', { method: 'POST', body: JSON.stringify({ amount, method, account }) });
    document.getElementById('balance').textContent = data.balance;
    toast('درخواست برداشت ثبت شد');
    document.getElementById('wd-amount').value = '';
    document.getElementById('wd-account').value = '';
    await loadWallet();
  } catch (e) {
    showErr('wd-err', e.message);
  }
}

// init
if (TOKEN) { enterApp(); } else { showView('login'); }
