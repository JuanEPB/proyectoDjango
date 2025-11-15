// static/js/auth.js
const BASE_URL = 'http://18.191.169.4:3000';  // Definido en el template por settings.API_URL
const BRIDGE = { store:'/bridge/store-token/', clear:'/bridge/clear-token/' };
const TOKEN_KEY = 'pc_access_token_v1';
let ACCESS_TOKEN=null, REFRESH_TIMER=null;

const saveAccessToken=(t)=>{ACCESS_TOKEN=t||null;t?sessionStorage.setItem(TOKEN_KEY,t):sessionStorage.removeItem(TOKEN_KEY);scheduleRefresh(t); if(t) fetch(BRIDGE.store,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({accessToken:t})}).catch(()=>{});};
const loadAccessToken=()=>{const t=sessionStorage.getItem(TOKEN_KEY);ACCESS_TOKEN=t||null;scheduleRefresh(t);return t;};
const decodeJwt=(tok)=>{try{const[,p]=tok.split('.');return JSON.parse(atob(p.replace(/-/g,'+').replace(/_/g,'/')));}catch{return null;}};
const scheduleRefresh=(t)=>{if(REFRESH_TIMER)clearTimeout(REFRESH_TIMER); if(!t)return; const exp=decodeJwt(t)?.exp; if(!exp)return; const ms=exp*1000-Date.now()-30000; REFRESH_TIMER=setTimeout(()=>refreshAccess().catch(()=>{}),Math.max(ms,2000));};

async function loginFront(email, pass){
  const r = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify({ email, contraseña: pass }) // 👈 ahora igual que en la DB
  });

  if (!r.ok) throw new Error('Credenciales incorrectas');
  const data = await r.json();
  if (!data?.accessToken) throw new Error('Sin accessToken');
  saveAccessToken(data.accessToken);
  return data.user || null;
}


async function refreshAccess(){
  const r = await fetch(`${BASE_URL}/api/auth/refresh`, { method:'POST', credentials:'include', headers:{'Accept':'application/json'} });
  if(!r.ok) throw new Error('refresh fail');
  const { accessToken } = await r.json();
  if(!accessToken) throw new Error('no token');
  saveAccessToken(accessToken);
}

async function logoutFront(){ try{ await fetch(`${BASE_URL}/api/auth/logout`, {method:'POST',credentials:'include'}); }catch{} saveAccessToken(null); fetch(BRIDGE.clear,{method:'POST'}).catch(()=>{}); }

function bindLoginPage(){
  const btn=document.getElementById('btn-login'); if(!btn) return;
  const emailEl=document.getElementById('login-email'); const passEl=document.getElementById('login-pass'); const msg=document.getElementById('login-msg');
  const go=async()=>{ try{ msg&&(msg.style.display='none'); await loginFront((emailEl.value||'').trim(), (passEl.value||'').trim()); location.href='/medicamentos/'; }catch(e){ if(msg){ msg.textContent=e.message||'Error de login'; msg.style.display=''; } } };
  btn.addEventListener('click',go); [emailEl,passEl].forEach(i=>i?.addEventListener('keydown',e=>{ if(e.key==='Enter') go(); }));
}

document.addEventListener('DOMContentLoaded',()=>{ loadAccessToken(); bindLoginPage(); });
