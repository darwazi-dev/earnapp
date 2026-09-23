const API = '';

let TOKEN = localStorage.getItem('token') || null;
let USER_NAME = localStorage.getItem('userName') || '';
let PROFILE_DATA = null;

function el(id) {
  return document.getElementById(id);
}

function showView(name) {
  ['login', 'register', 'main'].forEach(view => {
    const node = el(`view-${view}`);
    if (node) node.classList.add('hidden');
  });

  const target = el(`view-${name}`);
  if (target) target.classList.remove('hidden');
}

function toast(msg) {
  const t = el('toast');

  if (!t) {
    alert(msg);
    return;
  }

  t.textContent = msg;
  t.classList.remove('hidden');

  setTimeout(() => {
    t.classList.add('hidden');
  }, 3000);
}

function showErr(id, msg) {
  const node = el(id);
  if (!node) return;

  node.textContent = msg;
  node.classList.remove('hidden');
}

function hideErr(id) {
  const node = el(id);
  if (node) node.classList.add('hidden');
}

function formatMoney(value) {
  const n = Number(value || 0);

  return new Intl.NumberFormat('fa-AF', {
    maximumFractionDigits: 2
  }).format(n);
}

async function api(path, opts = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(opts.headers || {})
  };

  if (TOKEN) {
    headers.Authorization = `Bearer ${TOKEN}`;
  }

  let res;

  try {
    res = await fetch(API + path, {
      ...opts,
      headers
    });
  } catch (error) {
    throw new Error('ارتباط با سرور برقرار نشد');
  }

  const contentType = res.headers.get('content-type') || '';

  let data = {};

  if (contentType.includes('application/json')) {
    data = await res.json().catch(() => ({}));
  } else {
    const text = await res.text().catch(() => '');
    data = { error: text };
  }

  if (res.status === 401 && TOKEN && !path.startsWith('/api/admin/')) {
    logout(false);
    throw new Error('نشست شما منقضی شده، دوباره وارد شوید');
  }

  if (!res.ok) {
    throw new Error(
      data.error ||
      `خطای سرور (${res.status})`
    );
  }

  return data;
}

// ---------- Login ----------
async function doLogin() {
  hideErr('login-err');

  const phone = el('login-phone')?.value.trim() || '';
  const password = el('login-password')?.value || '';

  if (!phone || !password) {
    return showErr(
      'login-err',
      'شماره و رمز عبور را وارد کنید'
    );
  }

  try {
    const data = await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({
        phone,
        password
      })
    });

    TOKEN = data.token;
    USER_NAME = data.name || '';

    localStorage.setItem('token', TOKEN);
    localStorage.setItem('userName', USER_NAME);

    await enterApp();
  } catch (error) {
    showErr('login-err', error.message);
  }
}

// ---------- Register ----------
async function doRegister() {
  hideErr('register-err');

  const name = el('reg-name')?.value.trim() || '';
  const phone = el('reg-phone')?.value.trim() || '';
  const password = el('reg-password')?.value || '';

  if (!name || !phone || !password) {
    return showErr(
      'register-err',
      'همه فیلدها لازم است'
    );
  }

  if (password.length < 8) {
    return showErr(
      'register-err',
      'رمز عبور باید حداقل ۸ کاراکتر باشد'
    );
  }

  try {
    const data = await api('/api/register', {
      method: 'POST',
      body: JSON.stringify({
        name,
        phone,
        password
      })
    });

    TOKEN = data.token;
    USER_NAME = data.name || name;

    localStorage.setItem('token', TOKEN);
    localStorage.setItem('userName', USER_NAME);

    await enterApp();
  } catch (error) {
    showErr('register-err', error.message);
  }
}

// ---------- Logout ----------
function logout(showMessage = true) {
  localStorage.removeItem('token');
  localStorage.removeItem('userName');

  TOKEN = null;
  USER_NAME = '';

  showView('login');

  if (showMessage) {
    toast('از حساب خارج شدید');
  }
}

// ---------- Main ----------
async function enterApp() {
  const userName = el('user-name');

  if (userName) {
    userName.textContent = USER_NAME;
  }

  showView('main');

  await Promise.allSettled([
    loadTasks(),
    loadWalletSummary(),
    loadProfile()
  ]);
}

// ---------- Profile photo ----------
function chooseProfilePhoto() {
  el('profile-photo-input')?.click();
}

function renderProfilePhoto(photo) {
  const avatar = el('profile-avatar');
  if (!avatar) return;
  if (photo) {
    avatar.innerHTML = '<img src="' + photo + '" alt="عکس پروفایل">';
  } else {
    avatar.textContent = (USER_NAME || 'ک').trim().charAt(0) || 'ک';
  }
}

async function loadProfile() {
  try {
    const data = await api('/api/profile');
    PROFILE_DATA = data;
    USER_NAME = data.name || USER_NAME;
    localStorage.setItem('userName', USER_NAME);
    const userName = el('user-name');
    if (userName) userName.textContent = USER_NAME;
    renderProfilePhoto(data.profile_photo || '');
    renderAccount(data);
  } catch (error) {
    console.error('Profile:', error);
  }
}

function renderAccount(data) {
  if (!data) return;
  const name = el('account-name');
  const phone = el('account-phone');
  const language = el('account-language');
  const notifications = el('account-notifications');
  const status = el('account-phone-status');
  const photo = el('account-photo');
  if (name) name.value = data.name || '';
  if (phone) phone.textContent = data.phone || '';
  if (language) language.value = data.language || 'fa-AF';
  if (notifications) notifications.checked = data.notifications_enabled !== false;
  if (status) status.textContent = data.phone_verified ? 'تأیید شده' : 'هنوز تأیید نشده';
  if (photo) {
    photo.innerHTML = data.profile_photo
      ? '<img src="' + data.profile_photo + '" alt="عکس پروفایل">'
      : escapeHtml((data.name || 'ک').trim().charAt(0) || 'ک');
  }
}

async function openAccount() {
  const sheet = el('account-sheet');
  if (sheet) sheet.classList.remove('hidden');
  if (!PROFILE_DATA) await loadProfile();
  else renderAccount(PROFILE_DATA);
}

function closeAccount() {
  el('account-sheet')?.classList.add('hidden');
}

async function saveAccountSettings() {
  const name = el('account-name')?.value.trim() || '';
  const language = el('account-language')?.value || 'fa-AF';
  const notificationsEnabled = Boolean(el('account-notifications')?.checked);
  if (name.length < 2) return toast('نام معتبر وارد کنید');
  try {
    const data = await api('/api/profile/settings', {
      method: 'POST',
      body: JSON.stringify({ name, language, notificationsEnabled })
    });
    USER_NAME = data.name;
    localStorage.setItem('userName', USER_NAME);
    await loadProfile();
    toast('تنظیمات حساب ذخیره شد');
  } catch (error) {
    toast(error.message);
  }
}

async function uploadProfilePhoto(file) {
  if (!file) return;
  if (!['image/jpeg','image/png','image/webp'].includes(file.type)) {
    toast('فقط تصویر JPG، PNG یا WebP انتخاب کنید');
    return;
  }
  if (file.size > 8 * 1024 * 1024) {
    toast('حجم تصویر باید کمتر از ۸ مگابایت باشد');
    return;
  }

  try {
    const bitmap = await createImageBitmap(file);
    const max = 320;
    const scale = Math.min(1, max / Math.max(bitmap.width, bitmap.height));
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(bitmap.width * scale));
    canvas.height = Math.max(1, Math.round(bitmap.height * scale));
    const ctx = canvas.getContext('2d');
    ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    bitmap.close?.();

    const photo = canvas.toDataURL('image/jpeg', 0.78);
    const data = await api('/api/profile/photo', {
      method: 'POST',
      body: JSON.stringify({ photo })
    });
    renderProfilePhoto(data.photo);
    if (PROFILE_DATA) {
      PROFILE_DATA.profile_photo = data.photo;
      renderAccount(PROFILE_DATA);
    }
    toast('عکس پروفایل ذخیره شد');
  } catch (error) {
    toast(error.message || 'آپلود عکس انجام نشد');
  } finally {
    const input = el('profile-photo-input');
    if (input) input.value = '';
  }
}

// ---------- Opportunities ----------
async function loadTasks() {
  try {
    const data = await api('/api/tasks');

    const balance = el('balance');

    if (balance) {
      balance.textContent = formatMoney(data.balance);
    }

    const list = el('tasks-list');

    if (!list) return;

    list.innerHTML = '';

    if (data.realOffersAvailable) {
      const card = document.createElement('div');

      card.className = 'task';

      card.innerHTML = `
        <div class="task-icon">📋</div>

        <div class="task-info">
          <h3>فرصت‌های درآمد</h3>
          <p>
            سروی‌ها و فرصت‌های موجود را مشاهده کنید.
            پاداش فقط پس از تایید ارائه‌دهنده ثبت می‌شود.
          </p>
        </div>

        <button
          class="task-btn"
          type="button"
          onclick="openRealOffers()"
        >
          مشاهده
        </button>
      `;

      list.appendChild(card);
    }

    if (Array.isArray(data.tasks) && data.tasks.length) {
      data.tasks.forEach(task => {
        const div = document.createElement('div');

        div.className =
          'task' + (task.done ? ' done' : '');

        div.innerHTML = `
          <div class="task-icon">🎯</div>

          <div class="task-info">
            <h3>${escapeHtml(task.title)}</h3>
            <p>${escapeHtml(task.desc || '')}</p>
          </div>

          <div class="task-reward">
            ؋${formatMoney(task.reward)}
            <small>پاداش</small>
          </div>

          <button
            class="task-btn"
            ${task.done ? 'disabled' : ''}
            onclick="completeTask('${escapeAttribute(task.id)}')"
          >
            ${task.done ? 'انجام شد' : 'شروع'}
          </button>
        `;

        list.appendChild(div);
      });
    }

    if (
      !data.realOffersAvailable &&
      (!Array.isArray(data.tasks) || !data.tasks.length)
    ) {
      list.innerHTML = `
        <div class="hint">
          در حال حاضر فرصت درآمد فعالی موجود نیست.
        </div>
      `;
    }
  } catch (error) {
    toast(error.message);
  }
}

async function openRealOffers() {
  try {
    const data = await api('/api/cpx/offerwall-link');

    if (!data.url) {
      throw new Error('لینک فرصت‌ها دریافت نشد');
    }

    const win = window.open(
      data.url,
      '_blank',
      'noopener,noreferrer'
    );

    if (!win) {
      toast('اجازه باز شدن صفحه جدید را در مرورگر فعال کنید');
    }
  } catch (error) {
    toast(error.message);
  }
}

// Kept only for compatibility.
// Production backend does not credit fake tasks.
async function completeTask(id) {
  try {
    await api(
      `/api/tasks/${encodeURIComponent(id)}/complete`,
      { method: 'POST' }
    );

    await Promise.allSettled([
      loadTasks(),
      loadWalletSummary()
    ]);
  } catch (error) {
    toast(error.message);
  }
}

// ---------- Wallet summary ----------
async function loadWalletSummary() {
  try {
    const data = await api('/api/wallet');

    const balance = el('balance');

    if (balance) {
      balance.textContent =
        formatMoney(data.available);
    }

    renderPendingInfo(data);
    renderHomeWalletSummary(data);
  } catch (error) {
    console.error('Wallet summary:', error);
    const recent = el('recent-activity-list');
    if (recent) recent.innerHTML = '<div class="activity-empty">دریافت فعالیت‌های اخیر ناموفق بود</div>';
  }
}

function renderHomeWalletSummary(data) {
  const available = el('home-available');
  const pending = el('home-pending');
  const lifetime = el('home-lifetime');
  if (available) available.textContent = formatMoney(data.available || 0);
  if (pending) pending.textContent = formatMoney(data.pending || 0);
  if (lifetime) lifetime.textContent = formatMoney(data.lifetimeEarnings || 0);

  const recent = el('recent-activity-list');
  if (!recent) return;
  const ledger = Array.isArray(data.ledger) ? data.ledger.slice(0, 5) : [];
  if (!ledger.length) {
    recent.innerHTML = '<div class="activity-empty">هنوز فعالیت مالی ثبت نشده است</div>';
    return;
  }

  const labels = {
    EARNING: 'درآمد',
    EARNING_APPROVED: 'تأیید درآمد',
    WITHDRAWAL_RESERVED: 'درخواست برداشت',
    WITHDRAWAL_PAID: 'پرداخت برداشت',
    REVERSAL: 'اصلاح درآمد',
    ADJUSTMENT: 'اصلاح حساب'
  };

  recent.innerHTML = ledger.map(item => {
    const amount = Number(item.amount || 0);
    const sign = amount > 0 ? '+' : '';
    const label = labels[item.type] || 'تراکنش کیف پول';
    const status = escapeHtml(String(item.status || ''));
    return '<div class="activity-item"><div><strong>' +
      escapeHtml(label) + '</strong><div class="activity-meta">' + status +
      '</div></div><strong>' + sign + formatMoney(amount) + ' ؋</strong></div>';
  }).join('');
}

function renderPendingInfo(data) {
  const pendingSub = el('pending-sub');

  if (!pendingSub) return;

  const minWithdraw =
    formatMoney(data.minWithdraw || 500);

  if (Number(data.pending || 0) > 0) {
    pendingSub.textContent =
      `؋${formatMoney(data.pending)} در حال بررسی — ` +
      `حداقل برداشت: ${minWithdraw} افغانی`;
  } else {
    pendingSub.textContent =
      `حداقل برداشت: ${minWithdraw} افغانی`;
  }
}

// ---------- Withdrawal modal ----------
async function openWithdraw() {
  const modal = el('withdraw-modal');

  if (modal) {
    modal.classList.remove('hidden');
  }

  await Promise.all([
    loadWallet(),
    loadWithdrawalMethods()
  ]);
}

async function loadWithdrawalMethods() {
  const select = el('wd-method');
  if (!select) return;

  select.innerHTML = '<option value="">در حال دریافت...</option>';

  try {
    const data = await api('/api/withdrawal-methods');
    const methods = Array.isArray(data.methods) ? data.methods : [];

    if (!methods.length) {
      select.innerHTML = '<option value="">روش برداشت فعالی وجود ندارد</option>';
      select.disabled = true;
      return;
    }

    select.disabled = false;
    select.innerHTML =
      '<option value="">روش پرداخت را انتخاب کنید</option>' +
      methods.map(method =>
        '<option value="' + escapeAttribute(method.code) + '">' +
        escapeHtml(method.name) +
        '</option>'
      ).join('');
  } catch (error) {
    select.innerHTML = '<option value="">دریافت روش‌ها ناموفق بود</option>';
    select.disabled = true;
    showErr('wd-err', error.message);
  }
}

function closeWithdraw() {
  const modal = el('withdraw-modal');

  if (modal) {
    modal.classList.add('hidden');
  }

  hideErr('wd-err');
}

async function loadWallet() {
  try {
    const data = await api('/api/wallet');

    const balance = el('balance');

    if (balance) {
      balance.textContent =
        formatMoney(data.available);
    }

    renderPendingInfo(data);

    const hist = el('wd-history');

    if (!hist) return;

    if (
      !Array.isArray(data.withdrawals) ||
      !data.withdrawals.length
    ) {
      hist.innerHTML = `
        <div class="hint">
          هنوز درخواست برداشتی ندارید
        </div>
      `;

      return;
    }

    const statusLabel = {
      pending: 'در حال بررسی',
      approved: 'تایید شده',
      rejected: 'رد شده'
    };

    hist.innerHTML = `
      <div
        class="section-title"
        style="margin-top:0"
      >
        تاریخچه درخواست‌ها
      </div>

      ${data.withdrawals.map(w => `
        <div class="wd-item">
          <span>
            ؋${formatMoney(w.amount)}
            —
            ${escapeHtml(w.method || 'نامشخص')}
          </span>

          <span
            class="status-pill status-${escapeAttribute(w.status)}"
          >
            ${statusLabel[w.status] || escapeHtml(w.rawStatus || w.status)}
          </span>
        </div>
      `).join('')}
    `;
  } catch (error) {
    toast(error.message);
  }
}

async function submitWithdraw() {
  hideErr('wd-err');

  const amount = el('wd-amount')?.value || '';
  const method = el('wd-method')?.value || '';
  const account = el('wd-account')?.value.trim() || '';

  if (!amount || !method || !account) {
    return showErr(
      'wd-err',
      'مبلغ، روش پرداخت و شماره حساب را وارد کنید'
    );
  }

  try {
    const data = await api('/api/withdraw', {
      method: 'POST',
      body: JSON.stringify({
        amount,
        method,
        account
      })
    });

    const balance = el('balance');

    if (balance) {
      balance.textContent =
        formatMoney(data.balance);
    }

    toast('درخواست برداشت با موفقیت ثبت شد');

    if (el('wd-amount')) {
      el('wd-amount').value = '';
    }

    if (el('wd-account')) {
      el('wd-account').value = '';
    }

    await loadWallet();
  } catch (error) {
    showErr('wd-err', error.message);
  }
}


// ---------- Support ----------
function openSupport() {
  hideErr('support-err');
  el('support-modal')?.classList.remove('hidden');
  loadSupportTickets();
}

function closeSupport() {
  el('support-modal')?.classList.add('hidden');
  hideErr('support-err');
}

async function submitSupportTicket() {
  hideErr('support-err');
  const category = el('support-category')?.value || '';
  const subject = el('support-subject')?.value.trim() || '';
  const message = el('support-message')?.value.trim() || '';

  if (message.length < 5) {
    return showErr('support-err', 'لطفاً توضیحات کامل‌تری بنویسید');
  }

  try {
    const data = await api('/api/support/tickets', {
      method: 'POST',
      body: JSON.stringify({ category, subject, message })
    });

    if (el('support-subject')) el('support-subject').value = '';
    if (el('support-message')) el('support-message').value = '';

    toast('درخواست پشتیبانی ثبت شد: ' + (data.ticket?.ticket_id || ''));
    await loadSupportTickets();
  } catch (error) {
    showErr('support-err', error.message);
  }
}

async function loadSupportTickets() {
  const box = el('support-history');
  if (!box) return;

  box.innerHTML = '<div class="hint">در حال دریافت درخواست‌ها...</div>';

  try {
    const data = await api('/api/support/tickets');
    const tickets = Array.isArray(data.tickets) ? data.tickets : [];

    if (!tickets.length) {
      box.innerHTML = '<div class="hint">هنوز درخواست پشتیبانی ندارید.</div>';
      return;
    }

    box.innerHTML = `
      <div style="font-weight:bold;margin-bottom:10px;">درخواست‌های من</div>
      ${tickets.map(t => `
        <div class="wd-item" style="display:block;">
          <div style="display:flex;justify-content:space-between;gap:8px;">
            <strong>${escapeHtml(t.ticket_id)}</strong>
            <span class="status-pill status-pending">${escapeHtml(t.status)}</span>
          </div>
          <div style="margin-top:6px;">${escapeHtml(t.subject || t.category)}</div>
        </div>
      `).join('')}
    `;
  } catch (error) {
    box.innerHTML = '<div class="err">' + escapeHtml(error.message) + '</div>';
  }
}

// ---------- Safe HTML helpers ----------
function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function escapeAttribute(value) {
  return escapeHtml(value)
    .replaceAll('`', '&#096;');
}

// ---------- Forgot password ----------
// UI compatibility only.
// Password reset is intentionally not faked.
// A verified OTP/recovery backend must be added before launch.
async function openForgotModal() {
  const phone = prompt('شماره موبایل حساب خود را وارد کنید:');
  if (phone === null) return;

  const cleanPhone = phone.trim();
  if (!cleanPhone) {
    toast('شماره موبایل را وارد کنید');
    return;
  }

  try {
    const data = await api('/api/auth/password-recovery/request', {
      method: 'POST',
      body: JSON.stringify({ phone: cleanPhone })
    });

    toast(data.message || 'درخواست بازیابی ثبت شد');
  } catch (error) {
    toast(error.message);
  }
}

function closeForgotModal() {
  const modal = el('forgot-modal');

  if (modal) {
    modal.classList.add('hidden');
  }
}

function checkForgotPhone() {
  toast('بازیابی امن رمز عبور هنوز فعال نشده است');
}

function submitResetPassword() {
  toast('بازیابی امن رمز عبور هنوز فعال نشده است');
}

// ---------- Init ----------
document.addEventListener('DOMContentLoaded', () => {
  if (TOKEN) {
    enterApp();
  } else {
    showView('login');
  }
});
