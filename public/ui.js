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
function runUiHandler(el,attr,event){
  const raw=el.getAttribute(attr);
  if(!raw)return;
  const code=decodeURIComponent(raw);
  const fn=new Function('event',code);
  fn.call(el,event);
}
document.addEventListener('click',event=>{
  const el=event.target.closest('[data-onclick]');
  if(el) runUiHandler(el,'data-onclick',event);
});
document.addEventListener('change',event=>{
  const el=event.target.closest('[data-onchange]');
  if(el) runUiHandler(el,'data-onchange',event);
});