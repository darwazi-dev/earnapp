let ADMIN_TOKEN =
  sessionStorage.getItem('kariyabAdminToken') || '';


function escapeHtml(value){
  return String(value ?? '')
    .replaceAll('&','&amp;')
    .replaceAll('<','&lt;')
    .replaceAll('>','&gt;')
    .replaceAll('"','&quot;')
    .replaceAll("'","&#039;");
}


function showNotice(message,type='ok'){

  const el =
    document.getElementById('notice');

  el.textContent = message;

  el.className =
    'notice ' +
    (type === 'error'
      ? 'notice-error'
      : 'notice-ok');

  el.classList.remove('hidden');
}


async function adminApi(path,options={}){

  const headers = {
    'Content-Type':'application/json',
    'Authorization':'Bearer ' + ADMIN_TOKEN,
    ...(options.headers || {})
  };

  const response =
    await fetch(path,{
      ...options,
      headers
    });

  const data =
    await response
      .json()
      .catch(()=>({}));

  if(response.status === 401){

    sessionStorage.removeItem(
      'kariyabAdminToken'
    );

    ADMIN_TOKEN = '';

    throw new Error(
      'دسترسی ادمین معتبر نیست'
    );
  }

  if(!response.ok){

    throw new Error(
      data.error || 'خطای سرور'
    );
  }

  return data;
}


async function adminLogin(){

  const input =
    document.getElementById('adminPass');

  const error =
    document.getElementById('loginError');

  const password =
    input.value.trim();

  error.classList.add('hidden');

  if(!password){

    error.textContent =
      'رمز ادمین را وارد کنید';

    error.classList.remove('hidden');

    return;
  }

  try{

    const response =
      await fetch('/api/admin/login',{
        method:'POST',
        headers:{
          'Content-Type':'application/json'
        },
        body:JSON.stringify({
          password
        })
      });

    const data =
      await response
        .json()
        .catch(()=>({}));

    if(!response.ok){

      throw new Error(
        data.error ||
        'رمز ادمین اشتباه است'
      );
    }

    if(!data.token){
      throw new Error('نشست امن ادمین ایجاد نشد');
    }

    ADMIN_TOKEN = data.token;

    sessionStorage.setItem(
      'kariyabAdminToken',
      data.token
    );

    document
      .getElementById('loginBox')
      .classList.add('hidden');

    document
      .getElementById('dashboard')
      .classList.remove('hidden');

    await loadDashboard();

  }catch(e){

    error.textContent = e.message;

    error.classList.remove('hidden');
  }
}


function logoutAdmin(){

  ADMIN_TOKEN = '';

  sessionStorage.removeItem(
    'kariyabAdminToken'
  );

  location.reload();
}


function statusLabel(status){

  const map = {
    REQUESTED:'درخواست شده',
    UNDER_REVIEW:'در حال بررسی',
    APPROVED:'تأیید شده',
    PROCESSING:'در حال پردازش',
    PAID:'پرداخت شده',
    REJECTED:'رد شده',
    CANCELLED:'لغو شده',
    FAILED:'ناموفق'
  };

  return map[status] || status;
}


function statusClass(status){

  if(
    status === 'REQUESTED' ||
    status === 'UNDER_REVIEW'
  ){
    return 's-requested';
  }

  if(status === 'APPROVED'){
    return 's-approved';
  }

  if(status === 'PROCESSING'){
    return 's-processing';
  }

  if(status === 'PAID'){
    return 's-paid';
  }

  if(status === 'REJECTED'){
    return 's-rejected';
  }

  return 's-other';
}


function renderActions(w){
  const id=Number(w.id);
  const status=String(w.rawStatus || '');

  if(status === 'REQUESTED' || status === 'UNDER_REVIEW'){
    return '<div class="actions">'+
      '<button class="btn-approve withdrawal-action" data-action="approve" data-id="'+id+'">تأیید</button>'+
      '<button class="btn-reject withdrawal-action" data-action="reject" data-id="'+id+'">رد</button>'+
      '</div>';
  }

  if(status === 'APPROVED'){
    return '<div class="actions">'+
      '<button class="btn-processing withdrawal-action" data-action="processing" data-id="'+id+'">شروع پردازش</button>'+
      '<button class="btn-paid withdrawal-action" data-action="paid" data-id="'+id+'">ثبت پرداخت</button>'+
      '<button class="btn-reject withdrawal-action" data-action="reject" data-id="'+id+'">رد</button>'+
      '</div>';
  }

  if(status === 'PROCESSING'){
    return '<div class="actions">'+
      '<button class="btn-paid withdrawal-action" data-action="paid" data-id="'+id+'">ثبت پرداخت</button>'+
      '</div>';
  }

  return '—';
}

async function loadDashboard(){

  try{

    const [
      stats,
      data
    ] = await Promise.all([
      adminApi('/api/admin/stats'),
      adminApi('/api/admin/withdrawals')
    ]);

    loadSupportTickets();
    loadFraudFlags();
    loadIdentityVerifications();


    document.getElementById(
      'stats'
    ).innerHTML = `

      <div class="stat">
        <div class="num">
          ${escapeHtml(stats.totalUsers)}
        </div>
        <div class="label">
          کل کاربران
        </div>
      </div>

      <div class="stat">
        <div class="num">
          ${escapeHtml(stats.totalBalanceHeld)} ؋
        </div>
        <div class="label">
          موجودی نزد کاربران
        </div>
      </div>

      <div class="stat">
        <div class="num">
          ${escapeHtml(stats.pendingCount)}
        </div>
        <div class="label">
          درخواست در انتظار
        </div>
      </div>

      <div class="stat">
        <div class="num">
          ${escapeHtml(stats.pendingAmount)} ؋
        </div>
        <div class="label">
          مبلغ در انتظار
        </div>
      </div>

      <div class="stat">
        <div class="num">
          ${escapeHtml(stats.paidOut)} ؋
        </div>
        <div class="label">
          پرداخت‌شده
        </div>
      </div>
    `;


    const tbody =
      document.getElementById(
        'withdrawalTable'
      );


    if(
      !data.withdrawals ||
      !data.withdrawals.length
    ){

      tbody.innerHTML = `
        <tr>
          <td colspan="8" class="empty">
            هیچ درخواست برداشتی وجود ندارد
          </td>
        </tr>
      `;

      return;
    }


    tbody.innerHTML =
      data.withdrawals
        .map(w=>{

          const status =
            String(w.rawStatus || '');

          return `
            <tr>

              <td>
                ${escapeHtml(w.userName)}
              </td>

              <td>
                ${escapeHtml(w.userPhone)}
              </td>

              <td>
                <strong>
                  ${escapeHtml(w.amount)} ؋
                </strong>
              </td>

              <td>
                ${escapeHtml(w.method || '—')}
              </td>

              <td class="account-cell">
                ${escapeHtml(w.account || '—')}
              </td>

              <td>
                <span class="pill ${statusClass(status)}">
                  ${escapeHtml(statusLabel(status))}
                </span>
              </td>

              <td>
                ${
                  w.paymentReference
                  ? `<span class="ref">${escapeHtml(w.paymentReference)}</span>`
                  : '—'
                }
              </td>

              <td>
                ${renderActions(w)}
              </td>

            </tr>
          `;

        })
        .join('');


  }catch(e){

    showNotice(
      e.message,
      'error'
    );

    if(!ADMIN_TOKEN){

      document
        .getElementById('dashboard')
        .classList.add('hidden');

      document
        .getElementById('loginBox')
        .classList.remove('hidden');
    }
  }
}


async function approveWithdrawal(id){

  if(
    !confirm(
      'این درخواست برداشت تأیید شود؟'
    )
  ){
    return;
  }

  try{

    await adminApi(
      `/api/admin/withdrawals/${id}/approve`,
      {
        method:'POST',
        body:JSON.stringify({})
      }
    );

    showNotice(
      'درخواست برداشت تأیید شد.'
    );

    await loadDashboard();

  }catch(e){

    showNotice(
      e.message,
      'error'
    );
  }
}


async function markProcessing(id){

  if(
    !confirm(
      'پردازش این پرداخت شروع شود؟'
    )
  ){
    return;
  }

  try{

    await adminApi(
      `/api/admin/withdrawals/${id}/processing`,
      {
        method:'POST',
        body:JSON.stringify({})
      }
    );

    showNotice(
      'وضعیت به «در حال پردازش» تغییر کرد.'
    );

    await loadDashboard();

  }catch(e){

    showNotice(
      e.message,
      'error'
    );
  }
}


async function markPaid(id){

  const paymentReference =
    prompt(
      'Payment Reference / شماره مرجع پرداخت را وارد کنید:'
    );

  if(paymentReference === null){
    return;
  }

  const ref =
    paymentReference.trim();

  if(!ref){

    showNotice(
      'شماره مرجع پرداخت الزامی است.',
      'error'
    );

    return;
  }


  if(
    !confirm(
      'آیا مطمئن هستید که پول واقعاً پرداخت شده است؟'
    )
  ){
    return;
  }


  try{

    await adminApi(
      `/api/admin/withdrawals/${id}/paid`,
      {
        method:'POST',
        body:JSON.stringify({
          paymentReference:ref
        })
      }
    );

    showNotice(
      'پرداخت با موفقیت ثبت شد.'
    );

    await loadDashboard();

  }catch(e){

    showNotice(
      e.message,
      'error'
    );
  }
}


async function rejectWithdrawal(id){

  const reason =
    prompt(
      'دلیل رد درخواست را وارد کنید:'
    );

  if(reason === null){
    return;
  }

  const cleanReason =
    reason.trim();

  if(!cleanReason){

    showNotice(
      'دلیل رد درخواست را وارد کنید.',
      'error'
    );

    return;
  }


  if(
    !confirm(
      'درخواست رد شود و مبلغ به موجودی کاربر برگردد؟'
    )
  ){
    return;
  }


  try{

    await adminApi(
      `/api/admin/withdrawals/${id}/reject`,
      {
        method:'POST',
        body:JSON.stringify({
          reason:cleanReason
        })
      }
    );

    showNotice(
      'درخواست رد شد و مبلغ به کیف پول کاربر برگشت.'
    );

    await loadDashboard();

  }catch(e){

    showNotice(
      e.message,
      'error'
    );
  }
}


document.getElementById('adminLoginBtn')?.addEventListener('click', adminLogin);
document.getElementById('adminLogoutBtn')?.addEventListener('click', logoutAdmin);
document.getElementById('reconcileBtn')?.addEventListener('click', reconcileWallets);
document.getElementById('refreshDashboardBtn')?.addEventListener('click', loadDashboard);
document.getElementById('refreshFraudBtn')?.addEventListener('click', loadFraudFlags);
document.getElementById('refreshSupportBtn')?.addEventListener('click', loadSupportTickets);
document.getElementById('refreshIdentityBtn')?.addEventListener('click', loadIdentityVerifications);

document.getElementById('identityTable')?.addEventListener('click', async (event)=>{
  const imageButton=event.target.closest('.identity-image');
  if(imageButton){
    const id=Number(imageButton.dataset.id);
    const kind=imageButton.dataset.kind || '';
    if(!Number.isFinite(id) || !['document','selfie'].includes(kind)) return;
    try{
      const data=await adminApi('/api/admin/identity-verifications/'+id+'/evidence/'+kind);
      const win=window.open('','_blank');
      if(!win) return showNotice('مرورگر نمایش تصویر را مسدود کرد.','error');
      win.document.write('<!doctype html><meta charset="utf-8"><title>Identity image</title><style>body{margin:0;background:#111;display:flex;min-height:100vh;align-items:center;justify-content:center}img{max-width:96vw;max-height:96vh;object-fit:contain}</style><img alt="Identity review">');
      win.document.querySelector('img').src=data.image;
      win.document.close();
    }catch(e){ showNotice(e.message,'error'); }
    return;
  }
  const button=event.target.closest('.identity-action');
  if(!button) return;
  const id=Number(button.dataset.id);
  if(!Number.isFinite(id)) return;
  return reviewIdentity(id,button.dataset.action==='verify'?'VERIFIED':'REJECTED');
});

document.getElementById('withdrawalTable')?.addEventListener('click', async (event)=>{
  const button=event.target.closest('.withdrawal-action');
  if(!button) return;
  const id=Number(button.dataset.id);
  const action=button.dataset.action;
  if(!Number.isFinite(id)) return;
  if(action==='approve') return approveWithdrawal(id);
  if(action==='reject') return rejectWithdrawal(id);
  if(action==='processing') return markProcessing(id);
  if(action==='paid') return markPaid(id);
});

document
  .getElementById('adminPass')
  .addEventListener(
    'keydown',
    e=>{
      if(e.key === 'Enter'){
        adminLogin();
      }
    }
  );


if(ADMIN_TOKEN){

  document
    .getElementById('loginBox')
    .classList.add('hidden');

  document
    .getElementById('dashboard')
    .classList.remove('hidden');

  loadDashboard();
}


function supportStatusLabel(status){
  const map={
    OPEN:'باز',
    IN_PROGRESS:'در حال رسیدگی',
    RESOLVED:'حل شده',
    CLOSED:'بسته شده'
  };
  return map[status] || status;
}

async function loadSupportTickets(){
  const tbody=document.getElementById('supportTable');
  if(!tbody) return;

  try{
    const data=await adminApi('/api/admin/support/tickets');
    const tickets=Array.isArray(data.tickets) ? data.tickets : [];

    if(!tickets.length){
      tbody.innerHTML='<tr><td colspan="7" class="empty">هیچ درخواست پشتیبانی وجود ندارد</td></tr>';
      return;
    }

    tbody.innerHTML=tickets.map(t=>`
      <tr>
        <td><strong>${escapeHtml(t.ticket_id)}</strong></td>
        <td>${escapeHtml(t.user_name)}</td>
        <td>${escapeHtml(t.user_phone)}</td>
        <td>${escapeHtml(t.subject || t.category)}</td>
        <td style="max-width:260px">${escapeHtml(t.message)}</td>
        <td><span class="pill s-other">${escapeHtml(supportStatusLabel(t.status))}</span></td>
        <td>
          <select class="support-status-select" data-ticket-id="${Number(t.id)}" style="padding:8px;border-radius:8px">
            <option value="">تغییر وضعیت</option>
            <option value="OPEN">باز</option>
            <option value="IN_PROGRESS">در حال رسیدگی</option>
            <option value="RESOLVED">حل شده</option>
            <option value="CLOSED">بسته شده</option>
          </select>
        </td>
      </tr>
    `).join('');
  }catch(e){
    tbody.innerHTML='<tr><td colspan="7" class="empty">'+escapeHtml(e.message)+'</td></tr>';
  }
}

async function changeSupportStatus(id,status){
  if(!status) return;
  try{
    await adminApi(`/api/admin/support/tickets/${id}/status`,{
      method:'POST',
      body:JSON.stringify({status})
    });
    showNotice('وضعیت درخواست پشتیبانی تغییر کرد.');
    await loadSupportTickets();
  }catch(e){
    showNotice(e.message,'error');
    await loadSupportTickets();
  }
}


async function reconcileWallets(){
  const box=document.getElementById('reconcileResult');
  box.textContent='در حال بررسی...';

  try{
    const data=await adminApi('/api/admin/wallet-reconciliation');
    if(data.ok){
      box.textContent='سالم ✓ — '+String(data.checkedUsers)+' کاربر بررسی شد و اختلافی پیدا نشد.';
      box.style.color='var(--ok)';
      box.style.fontWeight='700';
    }else{
      box.textContent='اختلاف مالی پیدا شد — '+String(data.mismatches)+' مورد از '+String(data.checkedUsers)+' کاربر. تا بررسی کامل، پرداخت جدید انجام ندهید.';
      box.style.color='var(--danger)';
      box.style.fontWeight='700';

      const details=document.createElement('div');
      details.style.marginTop='10px';
      details.style.fontWeight='400';

      (data.mismatchUsers || []).forEach(u=>{
        const row=document.createElement('div');
        row.style.marginTop='8px';
        row.style.direction='rtl';
        row.appendChild(document.createTextNode(
          'کاربر #'+String(u.userId)+
          ' | موجودی فعلی: '+String(u.available)+' ؋'+
          ' | موجودی مورد انتظار: '+String(u.expectedAvailable)+' ؋'+
          ' | اختلاف Available: '+String(u.availableDifference)+' ؋'+
          ' | Pending فعلی: '+String(u.pending)+' ؋'+
          ' | Pending مورد انتظار: '+String(u.expectedPending)+' ؋'+
          ' | اختلاف Pending: '+String(u.pendingDifference)+' ؋ '
        ));
        const btn=document.createElement('button');
        btn.className='btn-primary';
        btn.style.marginRight='8px';
        btn.style.padding='5px 9px';
        btn.textContent='جزئیات';
        btn.addEventListener('click',()=>showFinancialDiagnostics(Number(u.userId)));
        row.appendChild(btn);

        const baselineBtn=document.createElement('button');
        baselineBtn.className='btn-primary';
        baselineBtn.style.marginRight='8px';
        baselineBtn.style.padding='5px 9px';
        baselineBtn.textContent='ثبت baseline آزمایشی';
        baselineBtn.addEventListener('click',()=>createLegacyBaseline(Number(u.userId)));
        row.appendChild(baselineBtn);

        details.appendChild(row);
      });
      box.appendChild(details);
    }
  }catch(e){
    box.textContent=e.message;
    box.style.color='var(--danger)';
    box.style.fontWeight='700';
  }
}


async function createLegacyBaseline(userId){
  if(!confirm('این کار فقط اختلاف داده‌های آزمایشی قدیمی را با یک Ledger entry حسابرسی‌شده baseline می‌کند و موجودی کیف پول را تغییر نمی‌دهد. ادامه می‌دهید؟')) return;
  try{
    const data=await adminApi('/api/admin/wallet-reconciliation/'+encodeURIComponent(userId)+'/baseline',{
      method:'POST',
      body:JSON.stringify({})
    });
    showNotice(data.adjusted ? 'Baseline آزمایشی با Audit Log ثبت شد.' : 'نیازی به baseline نبود.');
    await reconcileWallets();
  }catch(e){
    showNotice(e.message,'error');
  }
}

async function showFinancialDiagnostics(userId){
  try{
    const data=await adminApi('/api/admin/financial-diagnostics/'+encodeURIComponent(userId));
    const lines=[
      'Wallet: '+JSON.stringify(data.wallet),
      'Transactions: '+JSON.stringify(data.transactions),
      'Ledger: '+JSON.stringify(data.ledger),
      'Withdrawals: '+JSON.stringify(data.withdrawals)
    ];
    const win=window.open('','_blank');
    if(!win){
      showNotice('مرورگر پنجره جزئیات را مسدود کرد.','error');
      return;
    }
    win.document.write('<!doctype html><meta charset="utf-8"><title>Financial Diagnostics</title><pre style="white-space:pre-wrap;word-break:break-word;font-family:monospace;padding:20px">'+escapeHtml(lines.join('\n\n'))+'</pre>');
    win.document.close();
  }catch(e){
    showNotice(e.message,'error');
  }
}


function identityAdminStatusLabel(status){
  return ({UNDER_REVIEW:'در حال بررسی',VERIFIED:'تأیید شده',REJECTED:'رد شده',CANCELLED:'لغو شده'})[status] || status;
}

async function loadIdentityVerifications(){
  const tbody=document.getElementById('identityTable');
  if(!tbody) return;
  try{
    const data=await adminApi('/api/admin/identity-verifications');
    const rows=Array.isArray(data.verifications)?data.verifications:[];
    if(!rows.length){
      tbody.innerHTML='<tr><td colspan="6" class="empty">درخواست احراز هویتی وجود ندارد</td></tr>';
      return;
    }
    tbody.innerHTML=rows.map(v=>{
      const actions=v.status==='UNDER_REVIEW'
        ? '<div class="actions"><button class="btn-approve identity-action" data-action="verify" data-id="'+Number(v.id)+'">تأیید</button><button class="btn-reject identity-action" data-action="reject" data-id="'+Number(v.id)+'">رد</button></div>'
        : '—';
      return '<tr>'+
        '<td>'+escapeHtml(v.user_name)+'</td>'+
        '<td>'+escapeHtml(v.document_type)+'<div class="ref">••••'+escapeHtml(v.document_number_last4 || '')+'</div></td>'+
        '<td>'+(v.has_document_image?'<button class="btn-primary identity-image" data-kind="document" data-id="'+Number(v.id)+'">مشاهده مدرک</button>':'حذف شده')+'</td>'+
        '<td>'+(v.has_selfie_image?'<button class="btn-primary identity-image" data-kind="selfie" data-id="'+Number(v.id)+'">مشاهده سلفی</button>':'حذف شده')+'</td>'+
        '<td><span class="pill '+statusClass(v.status)+'">'+escapeHtml(identityAdminStatusLabel(v.status))+'</span></td>'+
        '<td>'+actions+'</td></tr>';
    }).join('');
  }catch(e){
    tbody.innerHTML='<tr><td colspan="6" class="empty">'+escapeHtml(e.message)+'</td></tr>';
  }
}

async function reviewIdentity(id,decision){
  let reason='';
  if(decision==='REJECTED'){
    const entered=prompt('دلیل رد احراز هویت را وارد کنید:');
    if(entered===null) return;
    reason=entered.trim();
    if(reason.length<3) return showNotice('دلیل رد را واضح بنویسید.','error');
  }else if(!confirm('مدرک و سلفی را بررسی کرده‌اید و هویت این کاربر تأیید شود؟')){
    return;
  }
  try{
    await adminApi('/api/admin/identity-verifications/'+id+'/review',{
      method:'POST',
      body:JSON.stringify({decision,reason})
    });
    showNotice(decision==='VERIFIED'?'هویت کاربر تأیید شد.':'درخواست احراز هویت رد شد.');
    await loadIdentityVerifications();
  }catch(e){ showNotice(e.message,'error'); }
}

async function loadFraudFlags(){
  const tbody=document.getElementById('fraudTable');
  if(!tbody) return;
  try{
    const data=await adminApi('/api/admin/fraud-flags');
    const flags=Array.isArray(data.flags)?data.flags:[];
    if(!flags.length){
      tbody.innerHTML='<tr><td colspan="6" class="empty">هشدار امنیتی بازی وجود ندارد</td></tr>';
      return;
    }
    tbody.innerHTML=flags.map(f=>`
      <tr>
        <td>${escapeHtml(f.user_name || ('#'+f.user_id))}</td>
        <td>${escapeHtml(f.flag_type)}</td>
        <td>${escapeHtml(f.severity || '—')}</td>
        <td style="max-width:280px">${escapeHtml(typeof f.details==='string'?f.details:JSON.stringify(f.details || {}))}</td>
        <td>${escapeHtml(f.status)}</td>
        <td>
          <select class="fraud-status-select" data-flag-id="${Number(f.id)}" style="padding:8px;border-radius:8px">
            <option value="">تغییر وضعیت</option>
            <option value="OPEN">باز</option>
            <option value="UNDER_REVIEW">در حال بررسی</option>
            <option value="RESOLVED">حل شده</option>
            <option value="DISMISSED">رد هشدار</option>
          </select>
        </td>
      </tr>
    `).join('');
  }catch(e){
    tbody.innerHTML='<tr><td colspan="6" class="empty">'+escapeHtml(e.message)+'</td></tr>';
  }
}

async function changeFraudStatus(id,status){
  if(!status) return;
  try{
    await adminApi('/api/admin/fraud-flags/'+id+'/status',{
      method:'POST',
      body:JSON.stringify({status})
    });
    showNotice('وضعیت هشدار امنیتی ثبت شد.');
    await loadFraudFlags();
  }catch(e){
    showNotice(e.message,'error');
  }
}

// CSP-safe delegated handlers for generated admin controls.
document.addEventListener('change', (event) => {
  const supportSelect = event.target.closest('.support-status-select');
  if (supportSelect) {
    const id = Number(supportSelect.dataset.ticketId);
    if (id && supportSelect.value) changeSupportStatus(id, supportSelect.value);
    return;
  }
  const fraudSelect = event.target.closest('.fraud-status-select');
  if (fraudSelect) {
    const id = Number(fraudSelect.dataset.flagId);
    if (id && fraudSelect.value) changeFraudStatus(id, fraudSelect.value);
  }
});

async function recoverUserPassword(){
  const phoneEl=document.getElementById('recoveryPhone');
  const passEl=document.getElementById('recoveryPassword');
  const resultEl=document.getElementById('recoveryResult');
  const phone=phoneEl.value.trim();
  const newPassword=passEl.value;

  resultEl.className='err hidden';
  resultEl.textContent='';

  if(!phone || newPassword.length < 12){
    resultEl.textContent='شماره حساب و رمز جدید حداقل ۱۲ کاراکتری را وارد کنید';
    resultEl.classList.remove('hidden');
    return;
  }

  if(!confirm('رمز همین حساب تغییر کند؟ اطلاعات کیف پول و سوابق مالی تغییر نمی‌کند.')) return;

  try{
    await adminApi('/api/admin/users/recover-password',{
      method:'POST',
      body:JSON.stringify({phone,newPassword})
    });
    passEl.value='';
    resultEl.textContent='رمز حساب با موفقیت تغییر کرد. اکنون با رمز جدید وارد حساب کاربر شوید.';
    resultEl.className='notice notice-ok';
  }catch(e){
    resultEl.textContent=e.message;
    resultEl.className='notice notice-error';
  }
}

document.getElementById('recoverUserBtn')?.addEventListener('click',recoverUserPassword);
