function toggleKariyabMenu(open){
      const menu=document.getElementById('kariyab-menu');
      const backdrop=document.getElementById('menu-backdrop');
      const toggle=document.querySelector('.menu-toggle');
      if(!menu||!backdrop) return;
      menu.classList.toggle('open',open);
      backdrop.classList.toggle('open',open);
      if(toggle) toggle.setAttribute('aria-expanded',open?'true':'false');
    }
    function syncProfileAvatar(){
      const name=(document.getElementById('user-name')?.textContent||'کاریاب').trim();
      const avatar=document.getElementById('profile-avatar');
      if(avatar && !avatar.querySelector('img')) avatar.textContent=name.charAt(0)||'ک';
    }
    const nameNode=document.getElementById('user-name');
    if(nameNode) new MutationObserver(syncProfileAvatar).observe(nameNode,{childList:true,subtree:true,characterData:true});
    syncProfileAvatar();
    document.addEventListener('keydown',e=>{if(e.key==='Escape')toggleKariyabMenu(false)});

const UI_ACTIONS=new Map([
['click-1',()=>openAccount()],
['change-2',e=>uploadProfilePhoto(e.currentTarget.files?.[0])],
['click-3',()=>toggleKariyabMenu(true)],
['click-4',()=>toggleKariyabMenu(false)],
['click-5',()=>toggleKariyabMenu(false)],
['click-6',()=>{toggleKariyabMenu(false);openSupport()}],
['click-7',()=>doLogin()],
['click-8',()=>showView('register')],
['click-9',()=>openForgotModal()],
['click-10',()=>doRegister()],
['click-11',()=>showView('login')],
['click-12',()=>openNotifications()],
['click-13',()=>logout()],
['click-14',()=>openWithdraw()],
['click-15',()=>openSupport()],
['click-16',e=>{if(e.target===e.currentTarget)closeNotifications()}],
['click-17',()=>markAllNotificationsRead()],
['click-18',()=>closeNotifications()],
['click-19',e=>{if(e.target===e.currentTarget)closeAccount()}],
['click-20',()=>closeAccount()],
['click-21',()=>saveAccountSettings()],
['click-22',()=>chooseProfilePhoto()],
['click-23',()=>logout()],
['click-24',()=>submitSupportTicket()],
['click-25',()=>closeSupport()],
['click-26',()=>submitWithdraw()],
['click-27',()=>closeWithdraw()],
['click-28',()=>window.scrollTo({top:0,behavior:'smooth'})],
['click-29',()=>document.getElementById('tasks-list')?.scrollIntoView({behavior:'smooth'})],
['click-30',()=>openWithdraw()],
['click-31',()=>openSupport()],
['click-32',()=>openAccount()]
]);
document.addEventListener('click',e=>{const el=e.target.closest('[data-ui^="click-"]');if(!el)return;const fn=UI_ACTIONS.get(el.dataset.ui);if(fn)fn({target:e.target,currentTarget:el});});
document.addEventListener('change',e=>{const el=e.target.closest('[data-ui^="change-"]');if(!el)return;const fn=UI_ACTIONS.get(el.dataset.ui);if(fn)fn({target:e.target,currentTarget:el});});
