document.addEventListener('DOMContentLoaded',()=>applyLanguage(localStorage.getItem('kariyabLanguage') || 'fa-AF'));

const API = '';

let TOKEN = localStorage.getItem('token') || null;
let USER_NAME = localStorage.getItem('userName') || '';
let PROFILE_DATA = null;

function getDeviceKey() {
  let key = localStorage.getItem('kariyabDeviceKey');
  if (!key) {
    const bytes = new Uint8Array(24);
    crypto.getRandomValues(bytes);
    key = Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
    localStorage.setItem('kariyabDeviceKey', key);
  }
  return key;
}

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

  const authMode = name === 'login' || name === 'register';
  document.body.classList.toggle('auth-mode', authMode);
}

let toastTimer = null;

function toast(msg) {
  const t = el('toast');

  if (!t) {
    alert(msg);
    return;
  }

  if (toastTimer) clearTimeout(toastTimer);

  t.textContent = msg;
  t.classList.remove('hidden');

  const duration = String(msg || '').length > 70 ? 6500 : 4500;
  toastTimer = setTimeout(() => {
    t.classList.add('hidden');
    toastTimer = null;
  }, duration);
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
    'X-Kariyab-Device': getDeviceKey(),
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
    avatar.replaceChildren();
    const img = document.createElement('img');
    img.src = photo;
    img.alt = 'عکس پروفایل';
    avatar.appendChild(img);
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

const UI_I18N = {
  'fa-AF': {
    accountTitle:'حساب من', languageNote:'زبان انتخابی پس از ذخیره روی رابط برنامه اعمال می‌شود.',
    home:'خانه', opportunities:'فرصت‌ها', withdraw:'برداشت', support:'پشتیبانی', account:'حساب من',
    save:'ذخیره تنظیمات', changePhoto:'تغییر عکس', logout:'خروج از حساب',
    incomeTitle:'فرصت‌های درآمد', withdrawMoney:'برداشت پول', supportTitle:'پشتیبانی',
    recent:'فعالیت اخیر', saved:'تنظیمات حساب ذخیره شد'
  },
  'ps-AF': {
    accountTitle:'زما حساب', languageNote:'ټاکل شوې ژبه له خوندي کولو وروسته د اپ پر مخ تطبیقېږي.',
    home:'کور', opportunities:'فرصتونه', withdraw:'ایستل', support:'ملاتړ', account:'زما حساب',
    save:'تنظیمات خوندي کړئ', changePhoto:'انځور بدل کړئ', logout:'له حسابه وتل',
    incomeTitle:'د عاید فرصتونه', withdrawMoney:'پیسې وباسئ', supportTitle:'ملاتړ',
    recent:'وروستی فعالیت', saved:'د حساب تنظیمات خوندي شول'
  },
  'en': {
    accountTitle:'My account', languageNote:'The selected language is applied to the app after saving.',
    home:'Home', opportunities:'Opportunities', withdraw:'Withdraw', support:'Support', account:'My account',
    save:'Save settings', changePhoto:'Change photo', logout:'Log out',
    incomeTitle:'Earning opportunities', withdrawMoney:'Withdraw money', supportTitle:'Support',
    recent:'Recent activity', saved:'Account settings saved'
  }
};

function applyLanguage(language) {
  const lang = UI_I18N[language] ? language : 'fa-AF';
  const t = UI_I18N[lang];
  document.documentElement.lang = lang === 'en' ? 'en' : (lang === 'ps-AF' ? 'ps' : 'fa');
  document.documentElement.dir = lang === 'en' ? 'ltr' : 'rtl';

  const setText=(selector,text)=>{
    const node=document.querySelector(selector);
    if(node) node.textContent=text;
  };
  setText('#account-title',t.accountTitle);
  setText('#language-note',t.languageNote);

  const modalText = {
    'fa-AF': {
      notifications:'اعلان‌ها', readAll:'خواندن همه',
      supportTitle:'پشتیبانی کاریاب', supportTopic:'موضوع درخواست', supportSubject:'عنوان (اختیاری)', supportMessage:'توضیحات', submitSupport:'ثبت درخواست', close:'بستن',
      withdrawTitle:'درخواست برداشت وجه', amount:'مبلغ (افغانی)', method:'روش پرداخت', accountField:'نمبر حساب / شماره تماس', submitWithdraw:'ثبت درخواست', closePage:'بستن صفحه',
      supportOptions:['درآمد ثبت نشده','فعالیت تایید نشده','برداشت پرداخت نشده','مشکل حساب','سؤال دیگر']
    },
    'ps-AF': {
      notifications:'خبرتیاوې', readAll:'ټول لوستل',
      supportTitle:'د کاریاب ملاتړ', supportTopic:'د غوښتنې موضوع', supportSubject:'سرلیک (اختیاري)', supportMessage:'تفصیل', submitSupport:'غوښتنه ثبت کړئ', close:'بندول',
      withdrawTitle:'د پیسو ایستلو غوښتنه', amount:'مبلغ (افغانۍ)', method:'د تادیې طریقه', accountField:'د حساب شمېره / د اړیکې شمېره', submitWithdraw:'غوښتنه ثبت کړئ', closePage:'پاڼه بنده کړئ',
      supportOptions:['عاید نه دی ثبت شوی','فعالیت نه دی تایید شوی','ایستل نه دي تادیه شوي','د حساب ستونزه','بله پوښتنه']
    },
    en: {
      notifications:'Notifications', readAll:'Read all',
      supportTitle:'Kariyab Support', supportTopic:'Request topic', supportSubject:'Subject (optional)', supportMessage:'Details', submitSupport:'Submit request', close:'Close',
      withdrawTitle:'Withdrawal request', amount:'Amount (AFN)', method:'Payment method', accountField:'Account / phone number', submitWithdraw:'Submit request', closePage:'Close',
      supportOptions:['Earning not recorded','Task not approved','Withdrawal not paid','Account issue','Other']
    }
  };
  const m = modalText[lang] || modalText['fa-AF'];
  setText('#notifications-title',m.notifications);
  setText('#notifications-sheet .account-head button:first-of-type',m.readAll);
  setText('#support-modal h3',m.supportTitle);
  setText('#support-modal .input-group:nth-of-type(1) label',m.supportTopic);
  setText('#support-modal .input-group:nth-of-type(2) label',m.supportSubject);
  setText('#support-modal .input-group:nth-of-type(3) label',m.supportMessage);
  setText('#support-modal .modal-content > button:nth-of-type(1)',m.submitSupport);
  setText('#support-modal .modal-content > button:nth-of-type(2)',m.close);
  document.querySelectorAll('#support-category option').forEach((o,i)=>{ if(m.supportOptions[i]) o.textContent=m.supportOptions[i]; });
  setText('#withdraw-modal h3',m.withdrawTitle);
  setText('#withdraw-modal .input-group:nth-of-type(1) label',m.amount);
  setText('#withdraw-modal .input-group:nth-of-type(2) label',m.method);
  setText('#withdraw-modal .input-group:nth-of-type(3) label',m.accountField);
  setText('#withdraw-modal .modal-content > button:nth-of-type(1)',m.submitWithdraw);
  setText('#withdraw-modal .modal-content > button:nth-of-type(2)',m.closePage);
  const navLabels=[t.home,t.opportunities,t.withdraw,t.support,t.account];
  document.querySelectorAll('.mobile-bottom-nav button').forEach((button,index)=>{
    const icon=button.querySelector('.nav-icon');
    const label=navLabels[index];
    if(!label) return;
    Array.from(button.childNodes).forEach(node=>{
      if(node.nodeType===Node.TEXT_NODE) node.remove();
    });
    button.appendChild(document.createTextNode(label));
    if(icon) button.insertBefore(icon,button.firstChild);
  });
  setText('.account-actions button:nth-child(1)',t.save);
  setText('.account-actions button:nth-child(2)',t.changePhoto);
  setText('#account-sheet .account-panel > button:last-child',t.logout);

  document.querySelectorAll('#view-main h3').forEach(node=>{
    if(node.textContent.includes('فرصت') || node.textContent.includes('عاید') || node.textContent.includes('Earning')) node.textContent=t.incomeTitle;
    if(node.textContent.includes('فعالیت اخیر') || node.textContent.includes('وروستی فعالیت') || node.textContent.includes('Recent activity')) node.textContent=t.recent;
  });

  document.querySelectorAll('#view-main button').forEach(node=>{
    const value=node.textContent.trim();
    if(value.includes('برداشت پول') || value.includes('پیسې وباسئ') || value==='Withdraw money') node.textContent=t.withdrawMoney;
    if(value==='پشتیبانی' || value==='ملاتړ' || value==='Support') node.textContent=t.supportTitle;
  });
  localStorage.setItem('kariyabLanguage',lang);
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
  applyLanguage(data.language || localStorage.getItem('kariyabLanguage') || 'fa-AF');
  if (notifications) notifications.checked = data.notifications_enabled !== false;
  if (status) status.textContent = data.phone_verified ? 'تأیید شده ✓' : 'هنوز تأیید نشده';
  const verifyBtn = el('phone-verify-btn');
  const verifyBox = el('phone-verify-box');
  if (verifyBtn) verifyBtn.style.display = data.phone_verified ? 'none' : 'inline-block';
  if (data.phone_verified && verifyBox) verifyBox.classList.add('hidden');
  if (photo) {
    if (data.profile_photo) {
      photo.replaceChildren();
      const img = document.createElement('img');
      img.src = data.profile_photo;
      img.alt = 'عکس پروفایل';
      photo.appendChild(img);
    } else {
      photo.textContent = (data.name || 'ک').trim().charAt(0) || 'ک';
    }
  }
}

async function sendPhoneVerification() {
  const btn = el('phone-verify-btn');
  const box = el('phone-verify-box');
  const note = el('phone-verify-note');
  if (btn) btn.disabled = true;
  try {
    const data = await api('/api/auth/phone-verification/send', { method: 'POST' });
    if (data.alreadyVerified) {
      await loadProfile();
      return;
    }
    if (box) box.classList.remove('hidden');
    if (note) note.textContent = 'کد تأیید ارسال شد و تا ۱۰ دقیقه معتبر است.';
    el('phone-verify-code')?.focus();
  } catch (error) {
    toast(error.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function submitPhoneVerification() {
  const code = el('phone-verify-code')?.value.trim() || '';
  if (!/^\d{6}$/.test(code)) return toast('کد ۶ رقمی را وارد کنید');
  const btn = el('phone-verify-submit');
  if (btn) btn.disabled = true;
  try {
    await api('/api/auth/phone-verification/verify', {
      method: 'POST',
      body: JSON.stringify({ code })
    });
    toast('شماره تلفن تأیید شد ✓');
    await loadProfile();
  } catch (error) {
    toast(error.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function openAccount() {
  const sheet = el('account-sheet');
  if (sheet) sheet.classList.remove('hidden');
  if (!PROFILE_DATA) await loadProfile();
  else renderAccount(PROFILE_DATA);
  await loadIdentityVerificationStatus();
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
    await loadNotifications();
    applyLanguage(data.language || language);
    toast(UI_I18N[data.language || language]?.saved || UI_I18N['fa-AF'].saved);
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

async function deleteAccount() {
  const password = prompt('برای حذف حساب، رمز عبور فعلی خود را وارد کنید:');
  if (password === null) return;
  if (!password) return toast('رمز عبور لازم است');

  const confirmed = confirm(
    'حساب شما غیرفعال و اطلاعات شخصی آن حذف می‌شود. سوابق مالی لازم برای حسابرسی نگهداری می‌شود. آیا ادامه می‌دهید؟'
  );
  if (!confirmed) return;

  try {
    await api('/api/account/delete', {
      method: 'POST',
      body: JSON.stringify({ password, confirmation: 'DELETE' })
    });

    localStorage.removeItem('token');
    localStorage.removeItem('userName');
    TOKEN = null;
    USER_NAME = '';
    PROFILE_DATA = null;
    closeAccount();
    showView('register');
    toast('حساب حذف شد. اکنون می‌توانید یک حساب تازه بسازید.');
  } catch (error) {
    toast(error.message);
  }
}

const deleteAccountBtn = el('delete-account-btn');
if (deleteAccountBtn) {
  deleteAccountBtn.addEventListener('click', deleteAccount);
}

// ---------- Identity verification ----------
async function imageFileToDataUrl(file) {
  if (!file || !['image/jpeg','image/png','image/webp'].includes(file.type)) {
    throw new Error('فقط تصویر JPG، PNG یا WebP انتخاب کنید');
  }
  if (file.size > 8 * 1024 * 1024) throw new Error('حجم هر تصویر باید کمتر از ۸ مگابایت باشد');

  const bitmap = await createImageBitmap(file);
  const max = 1000;
  const scale = Math.min(1, max / Math.max(bitmap.width, bitmap.height));
  const canvas = document.createElement('canvas');
  canvas.width = Math.max(1, Math.round(bitmap.width * scale));
  canvas.height = Math.max(1, Math.round(bitmap.height * scale));
  const ctx = canvas.getContext('2d');
  ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  bitmap.close?.();

  let quality = 0.78;
  let data = canvas.toDataURL('image/jpeg', quality);
  while (data.length > 650000 && quality > 0.42) {
    quality -= 0.08;
    data = canvas.toDataURL('image/jpeg', quality);
  }
  if (data.length > 700000) throw new Error('تصویر پس از فشرده‌سازی هنوز بزرگ است؛ تصویر دیگری انتخاب کنید');
  return data;
}

function identityStatusLabel(status) {
  return ({
    UNVERIFIED: 'تأیید نشده',
    UNDER_REVIEW: 'در حال بررسی',
    VERIFIED: 'تأیید شده',
    REJECTED: 'رد شده',
    CANCELLED: 'لغو شده'
  })[String(status || '').toUpperCase()] || 'تأیید نشده';
}

async function loadIdentityVerificationStatus() {
  try {
    const data = await api('/api/identity-verification');
    const status = String(data.status || 'UNVERIFIED').toUpperCase();
    const accountStatus = el('identity-status');
    const modalStatus = el('identity-current-status');
    const submit = el('identity-submit-btn');
    if (accountStatus) accountStatus.textContent = identityStatusLabel(status);
    if (modalStatus) {
      modalStatus.textContent = status === 'REJECTED' && data.verification?.rejection_reason
        ? 'وضعیت: رد شده — ' + data.verification.rejection_reason
        : 'وضعیت: ' + identityStatusLabel(status);
    }
    if (submit) {
      submit.disabled = status === 'UNDER_REVIEW' || status === 'VERIFIED';
      submit.textContent = status === 'VERIFIED' ? 'هویت تأیید شده' :
        status === 'UNDER_REVIEW' ? 'در حال بررسی' : 'ارسال برای بررسی';
    }
    return data;
  } catch (error) {
    const status = el('identity-status');
    if (status) status.textContent = 'دریافت وضعیت ناموفق بود';
    return null;
  }
}

async function openIdentityVerification() {
  hideErr('identity-err');
  el('identity-modal')?.classList.remove('hidden');
  await loadIdentityVerificationStatus();
}

function closeIdentityVerification() {
  el('identity-modal')?.classList.add('hidden');
  hideErr('identity-err');
}

async function submitIdentityVerification() {
  hideErr('identity-err');
  const documentType = el('identity-document-type')?.value || '';
  const documentNumber = el('identity-document-number')?.value.trim() || '';
  const documentFile = el('identity-document-image')?.files?.[0];
  const selfieFile = el('identity-selfie-image')?.files?.[0];

  if (documentNumber.length < 4 || !documentFile || !selfieFile) {
    return showErr('identity-err', 'شماره مدرک، تصویر مدرک و سلفی را کامل وارد کنید');
  }

  const submit = el('identity-submit-btn');
  try {
    if (submit) { submit.disabled = true; submit.textContent = 'در حال ارسال...'; }
    const [documentImage, selfieImage] = await Promise.all([
      imageFileToDataUrl(documentFile),
      imageFileToDataUrl(selfieFile)
    ]);
    await api('/api/identity-verification', {
      method: 'POST',
      body: JSON.stringify({ documentType, documentNumber, documentImage, selfieImage })
    });
    toast('درخواست احراز هویت برای بررسی ارسال شد');
    await loadIdentityVerificationStatus();
  } catch (error) {
    showErr('identity-err', error.message);
    if (submit) submit.disabled = false;
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
          data-action="open-real-offers"
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
            data-action="complete-task" data-task-id="${escapeAttribute(task.id)}"
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

  const lang = localStorage.getItem('kariyabLanguage') || 'fa-AF';
  const activityLabels = {
    'fa-AF': {
      EARNING:'درآمد', EARNING_APPROVED:'تأیید درآمد', WITHDRAWAL_RESERVED:'درخواست برداشت',
      WITHDRAWAL_PAID:'پرداخت برداشت', WITHDRAWAL_REFUND:'برگشت برداشت', REVERSAL:'اصلاح درآمد',
      ADJUSTMENT:'اصلاح حساب', LEGACY_RECONCILIATION_BASELINE:'تطبیق حساب', fallback:'تراکنش کیف پول'
    },
    'ps-AF': {
      EARNING:'عاید', EARNING_APPROVED:'عاید تایید شو', WITHDRAWAL_RESERVED:'د ایستلو غوښتنه',
      WITHDRAWAL_PAID:'ایستل تادیه شول', WITHDRAWAL_REFUND:'د ایستلو بېرته ستنول', REVERSAL:'د عاید سمون',
      ADJUSTMENT:'د حساب سمون', LEGACY_RECONCILIATION_BASELINE:'د حساب تطبیق', fallback:'د بټوې معامله'
    },
    en: {
      EARNING:'Earning', EARNING_APPROVED:'Earning approved', WITHDRAWAL_RESERVED:'Withdrawal request',
      WITHDRAWAL_PAID:'Withdrawal paid', WITHDRAWAL_REFUND:'Withdrawal refund', REVERSAL:'Earning reversal',
      ADJUSTMENT:'Account adjustment', LEGACY_RECONCILIATION_BASELINE:'Account reconciliation', fallback:'Wallet transaction'
    }
  };
  const statusLabels = {
    'fa-AF': {PENDING:'در حال بررسی', APPROVED:'تأیید شده', REQUESTED:'درخواست شده', UNDER_REVIEW:'در حال بررسی', PROCESSING:'در حال پردازش', PAID:'پرداخت شده', REJECTED:'رد شده', FAILED:'ناموفق', CANCELLED:'لغو شده'},
    'ps-AF': {PENDING:'د ارزونې لاندې', APPROVED:'تایید شوی', REQUESTED:'غوښتنه شوې', UNDER_REVIEW:'د ارزونې لاندې', PROCESSING:'د پروسس لاندې', PAID:'تادیه شوی', REJECTED:'رد شوی', FAILED:'ناکام', CANCELLED:'لغوه شوی'},
    en: {PENDING:'Pending', APPROVED:'Approved', REQUESTED:'Requested', UNDER_REVIEW:'Under review', PROCESSING:'Processing', PAID:'Paid', REJECTED:'Rejected', FAILED:'Failed', CANCELLED:'Cancelled'}
  };
  const labels = activityLabels[lang] || activityLabels['fa-AF'];
  const statuses = statusLabels[lang] || statusLabels['fa-AF'];

  recent.innerHTML = ledger.map(item => {
    const amount = Number(item.amount || 0);
    const sign = amount > 0 ? '+' : '';
    const label = labels[item.type] || labels.fallback;
    const rawStatus = String(item.status || '').toUpperCase();
    const status = escapeHtml(statuses[rawStatus] || rawStatus);
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
      `؋${formatMoney(data.pending)} در انتظار تأیید تسویه — ` +
      `حداقل برداشت: ${minWithdraw} افغانی`;
  } else {
    pendingSub.textContent =
      `حداقل برداشت: ${minWithdraw} افغانی`;
  }
}

// ---------- Notifications ----------
async function loadNotifications() {
  if (!TOKEN) return;
  try {
    const data = await api('/api/notifications');
    const badge = el('notification-badge');
    const unread = Number(data.unread || 0);
    if (badge) {
      badge.textContent = unread > 99 ? '99+' : String(unread);
      badge.classList.toggle('hidden', unread < 1);
    }
    const list = el('notifications-list');
    if (!list) return;
    const items = Array.isArray(data.notifications) ? data.notifications : [];
    if (!items.length) {
      list.innerHTML = '<div class="activity-empty">هنوز اعلانی ندارید</div>';
      return;
    }
    list.innerHTML = items.map(item =>
      '<div class="notification-item ' + (item.read ? '' : 'unread') +
      '" data-action="notification-read" data-notification-id="' + safeNumericId(item.id) + '">' +
      '<div>' + escapeHtml(item.title) + '</div>' +
      '<small>' + escapeHtml(item.body) + '</small>' +
      '<small>' + escapeHtml(new Date(item.createdAt).toLocaleString('fa-AF')) + '</small>' +
      '</div>'
    ).join('');
  } catch (error) {
    console.error('Notifications:', error);
  }
}

async function openNotifications() {
  el('notifications-sheet')?.classList.remove('hidden');
  await loadNotifications();
}

function closeNotifications() {
  el('notifications-sheet')?.classList.add('hidden');
}

async function markNotificationRead(id) {
  try {
    await api('/api/notifications/' + encodeURIComponent(id) + '/read', { method: 'POST' });
    await loadNotifications();
  } catch (error) {
    toast(error.message);
  }
}

async function markAllNotificationsRead() {
  try {
    await api('/api/notifications/read-all', { method: 'POST' });
    await loadNotifications();
  } catch (error) {
    toast(error.message);
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
    select.replaceChildren();

    const placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.textContent = 'روش پرداخت را انتخاب کنید';
    select.appendChild(placeholder);

    methods.forEach(method => {
      const option = document.createElement('option');
      option.value = String(method.code || '');
      option.textContent = String(method.name || '');
      option.dataset.accountLabel = String(method.accountLabel || '');
      option.dataset.accountPlaceholder = String(method.accountPlaceholder || '');
      option.dataset.accountType = String(method.accountType || 'text');
      select.appendChild(option);
    });

    const syncAccountField = () => {
      const selected = select.options[select.selectedIndex];
      const input = el('wd-account');
      const label = el('wd-account-label');
      if (!input || !label) return;

      label.textContent =
        selected?.dataset.accountLabel || 'نمبر حساب / شماره تماس';
      input.placeholder =
        selected?.dataset.accountPlaceholder || 'شماره حساب یا شماره تماس';
      input.inputMode =
        selected?.dataset.accountType === 'phone' ? 'tel' : 'text';
    };

    select.addEventListener('change', syncAccountField);
    syncAccountField();
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
      requested: 'درخواست شده',
      under_review: 'در حال بررسی',
      approved: 'تایید شده',
      processing: 'در حال پردازش',
      paid: 'پرداخت شده',
      rejected: 'رد شده',
      failed: 'ناموفق',
      cancelled: 'لغو شده'
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
            class="status-pill ${withdrawalStatusClass(w.status)}"
          >
            ${w.isTest ? 'آزمایشی · ' : ''}${statusLabel[w.status] || escapeHtml(w.rawStatus || w.status)}
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

    if (el('wd-method')) {
      el('wd-method').value = '';
      el('wd-method').dispatchEvent(new Event('change'));
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

function safeNumericId(value) {
  const id = Number(value);
  return Number.isSafeInteger(id) && id > 0 ? String(id) : '0';
}

function withdrawalStatusClass(value) {
  const status = String(value || '').toLowerCase();
  return ['pending', 'approved', 'rejected', 'processing', 'paid', 'failed', 'cancelled'].includes(status)
    ? 'status-' + status
    : 'status-pending';
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
document.addEventListener('click', (event) => {
  const actionEl = event.target.closest('[data-action]');
  if (!actionEl) return;
  const action = actionEl.dataset.action;
  if (action === 'open-real-offers') return openRealOffers();
  if (action === 'complete-task') return completeTask(actionEl.dataset.taskId);
  if (action === 'notification-read') return markNotificationRead(Number(actionEl.dataset.notificationId));
});

document.addEventListener('DOMContentLoaded', () => {
  document.addEventListener('click', (event) => {
    const target = event.target.closest('button');
    if (!target) return;
    if (target.id === 'identity-open-btn') {
      event.preventDefault();
      openIdentityVerification();
    } else if (target.id === 'identity-submit-btn') {
      event.preventDefault();
      submitIdentityVerification();
    } else if (target.id === 'identity-close-btn') {
      event.preventDefault();
      closeIdentityVerification();
    }
  });

  if (TOKEN) {
    enterApp().then(() => {
      const params = new URLSearchParams(window.location.search);
      if (params.get('withdraw') === '1') {
        openWithdraw();
        history.replaceState({}, '', '/');
      }
    });
  } else {
    showView('login');
  }
});


el('phone-verify-btn')?.addEventListener('click', sendPhoneVerification);
el('phone-verify-submit')?.addEventListener('click', submitPhoneVerification);
