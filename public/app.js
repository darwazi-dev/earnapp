const API = '';
let TOKEN = localStorage.getItem('token') || null;
let USER_NAME = localStorage.getItem('userName') || '';
let FORGOT_PHONE = ''; // ذخیره موقت شماره برای گام دوم بازیابی

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
  const el = document.getElementById(id);
  if (el) el.classList.add('hidden');
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
  const question = document.getElementById('reg-question').value;
  const answer = document.getElementById('reg-answer').value.trim();

  if (!name || !phone || !password || !answer) return showErr('register-err', 'همه فیلدها از جمله پاسخ امنیتی لازم است');
  try {
    const data = await api('/api/register', { method: 'POST', body: JSON.stringify({ name, phone, password, question, answer }) });
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

async function openCpxOfferwall() {
  try {
    const data = await api('/api/cpx/offerwall-link');
    if (data && data.url) {
      window.open(data.url, '_blank');
    } else {
      toast('خطا در دریافت لینک کسب درآمد زنده');
    }
  } catch (e) {
    toast(e.message);
  }
}

async function loadTasks() {
  try {
    const data = await api('/api/tasks');
    document.getElementById('balance').textContent = data.balance;
    const list = document.getElementById('tasks-list');
    list.innerHTML = '';
    
    const cpxDiv = document.createElement('div');
    cpxDiv.className = 'task real-cpx-task';
    cpxDiv.style.background = 'linear-gradient(135deg, #fff3cd 0%, #ffeeba 100%)';
    cpxDiv.style.border = '1px solid #ffeeba';
    cpxDiv.innerHTML = `
      <div class="task-icon">💰</div>
      <div class="task-info">
        <h3 style="color:#856404">دیوار درآمد واقعی (نظرسنجی زنده)</h3>
        <p style="color:#856404">تکمیل هر نظرسنجی = واریز آنی پول نقد به حساب افغانی شما</p>
      </div>
      <div class="task-reward" style="color:#856404">؋ عالی<small>نامحدود</small></div>
      <button class="task-btn" style="background:#056839; color:#fff; font-weight:bold" onclick="openCpxOfferwall()">
        کسب درآمد
      </button>`;
    list.appendChild(cpxDiv);

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

// کدهای مربوط به مدیریت مودال فراموشی رمز عبور
function openForgotModal() {
  hideErr('forgot-err');
  document.getElementById('forgot-modal').classList.remove('hidden');
  document.getElementById('forgot-step1').classList.remove('hidden');
  document.getElementById('forgot-step2').classList.add('hidden');
  document.getElementById('forgot-phone').value = '';
  document.getElementById('forgot-answer').value = '';
  document.getElementById('forgot-new-password').value = '';
}

function closeForgotModal() {
  document.getElementById('forgot-modal').classList.add('hidden');
}

async function checkForgotPhone() {
  hideErr('forgot-err');
  const phone = document.getElementById('forgot-phone').value.trim();
  if (!phone) return showErr('forgot-err', 'شماره تلفن را وارد کنید');
  try {
    const data = await api('/api/forgot-password/check-phone', { method: 'POST', body: JSON.stringify({ phone }) });
    FORGOT_PHONE = phone;
    document.getElementById('forgot-question-text').textContent = data.question;
    document.getElementById('forgot-step1').classList.add('hidden');
    document.getElementById('forgot-step2').classList.remove('hidden');
  } catch (e) {
    showErr('forgot-err', e.message);
  }
}

async function submitResetPassword() {
  hideErr('forgot-err');
  const answer = document.getElementById('forgot-answer').value.trim();
  const newPassword = document.getElementById('forgot-new-password').value;
  if (!answer || !newPassword) return showErr('forgot-err', 'پاسخ سوال امنیتی و رمز جدید را وارد کنید');
  if (newPassword.length < 4) return showErr('forgot-err', 'رمز جدید باید حداقل ۴ کاراکتر باشد');
  try {
    const data = await api('/api/forgot-password/reset', { method: 'POST', body: JSON.stringify({ phone: FORGOT_PHONE, answer, newPassword }) });
    closeForgotModal();
    toast('رمز عبور با موفقیت تغییر کرد');
    TOKEN = data.token; USER_NAME = data.name;
    localStorage.setItem('token', TOKEN);
    localStorage.setItem('userName', USER_NAME);
    enterApp();
  } catch (e) {
    showErr('forgot-err', e.message);
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
