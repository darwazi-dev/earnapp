const token=localStorage.getItem('token');
const $=id=>document.getElementById(id);
const money=v=>new Intl.NumberFormat('fa-AF',{maximumFractionDigits:2}).format(Number(v||0));
const esc=v=>String(v??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'","&#039;");
const typeLabels={EARNING:'درآمد',EARNING_APPROVED:'تأیید درآمد',WITHDRAWAL_RESERVED:'رزرو برداشت',WITHDRAWAL_PAID:'پرداخت برداشت',WITHDRAWAL_REFUND:'برگشت برداشت',REVERSAL:'برگشت/اصلاح درآمد',ADJUSTMENT:'اصلاح حساب',LEGACY_RECONCILIATION_BASELINE:'تطبیق حساب'};
const statusLabels={PENDING:'🟡 در انتظار',APPROVED:'🟢 تأیید شده',REQUESTED:'🟡 درخواست شده',UNDER_REVIEW:'🟡 در حال بررسی',PROCESSING:'🟡 در حال پردازش',PAID:'🟢 پرداخت شده',REJECTED:'🔴 رد شده',REVERSED:'🔴 برگشت داده شده',FAILED:'🔴 ناموفق',CANCELLED:'لغو شده'};
function date(v){try{return new Date(v).toLocaleString('fa-AF')}catch{return ''}}
async function load(){
 if(!token){location.replace('/');return}
 try{
  const res=await fetch('/api/wallet',{headers:{Authorization:'Bearer '+token}});
  if(res.status===401){localStorage.removeItem('token');location.replace('/');return}
  const data=await res.json();
  if(!res.ok) throw new Error(data.error||'دریافت کیف پول انجام نشد');
  const available=Number(data.available||0), pending=Number(data.pending||0);
  $('total-balance').textContent=money(available+pending);
  $('available').textContent=money(available); $('pending').textContent=money(pending);
  $('lifetime-earnings').textContent=money(data.lifetimeEarnings); $('lifetime-withdrawals').textContent=money(data.lifetimeWithdrawals);
  $('minimum').textContent=money(data.minWithdraw); $('minimum-card').textContent=money(data.minWithdraw);
  const ledger=Array.isArray(data.ledger)?data.ledger:[];
  $('ledger').innerHTML=ledger.length?ledger.map(x=>{
    const amount=Number(x.amount||0), sign=amount>0?'+':'';
    return '<div class="row"><div class="row-main"><strong>'+esc(typeLabels[x.type]||'تراکنش کیف پول')+'</strong><div class="meta">'+esc(statusLabels[String(x.status||'').toUpperCase()]||x.status||'')+' · '+esc(date(x.createdAt))+'</div></div><div class="amount">'+sign+money(amount)+' ؋</div></div>';
  }).join(''):'<div class="empty">هنوز تراکنش مالی ثبت نشده است.</div>';
  const withdrawals=Array.isArray(data.withdrawals)?data.withdrawals:[];
  $('withdrawals').innerHTML=withdrawals.length?withdrawals.map(w=>
    '<div class="row"><div class="row-main"><strong>'+esc(w.method||'روش نامشخص')+'</strong><div class="meta">'+esc(statusLabels[String(w.rawStatus||'').toUpperCase()]||w.rawStatus||'')+' · '+esc(date(w.createdAt))+'</div></div><div class="amount">'+money(w.amount)+' ؋</div></div>'
  ).join(''):'<div class="empty">هنوز درخواست برداشتی ثبت نشده است.</div>';
 }catch(e){$('ledger').innerHTML='<div class="error">'+esc(e.message)+'</div>'}
}
$('refresh').addEventListener('click',load); load();