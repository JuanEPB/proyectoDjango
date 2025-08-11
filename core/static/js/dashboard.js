// ====== CONFIG ======
const BASE_URL = 'http://127.0.0.1:3000'; // Nest
const API = {
  login:   `${BASE_URL}/api/auth/login`,
  refresh: `${BASE_URL}/api/auth/refresh`,
  logout:  `${BASE_URL}/api/auth/logout`,
};

// endpoints puente en Django
const BRIDGE = {
  store: '/bridge/store-token/', // POST { accessToken }
  clear: '/bridge/clear-token/', // POST
};

// ====== TOKEN en sessionStorage ======
const TOKEN_KEY = 'pc_access_token_v1';
const STORE = sessionStorage; // clave: sesión del navegador
let ACCESS_TOKEN = null;
let REFRESH_TIMER = null;


const saveAccessToken = (t) => {
  ACCESS_TOKEN = t || null;
  if (t) STORE.setItem(TOKEN_KEY, t);
  else   STORE.removeItem(TOKEN_KEY);
  scheduleRefreshFromToken(t);
  // Mantén sincronizada la sesión de Django
  if (t) {
    fetch(BRIDGE.store, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ accessToken: t })
    }).catch(()=>{});
  }
};

const loadAccessToken = () => {
  const t = STORE.getItem(TOKEN_KEY);
  ACCESS_TOKEN = t || null;
  scheduleRefreshFromToken(t);
  return t;
};

const decodeJwt = (tok) => {
  try {
    const [, p] = tok.split('.');
    const json = atob(p.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(decodeURIComponent(escape(json)));
  } catch { return null; }
};

const scheduleRefreshFromToken = (t) => {
  if (REFRESH_TIMER) { clearTimeout(REFRESH_TIMER); REFRESH_TIMER = null; }
  if (!t) return;
  const exp = decodeJwt(t)?.exp; if (!exp) return;
  const ms = exp * 1000 - Date.now() - 30000; // refrescar 30s antes
  REFRESH_TIMER = setTimeout(() => refreshAccess().catch(()=>{}), Math.max(ms, 2000));
};

async function refreshAccess() {
  const r = await fetch(API.refresh, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Accept': 'application/json' }
  });
  if (!r.ok) throw new Error('refresh fail');
  const { accessToken } = await r.json();
  if (!accessToken) throw new Error('no token');
  saveAccessToken(accessToken);
}

async function loginFront(email, pass) {
  const r = await fetch(API.login, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ email, contraseña: pass })
  });
  if (!r.ok) throw new Error('Credenciales incorrectas');
  const data = await r.json();
  if (!data?.accessToken) throw new Error('Sin accessToken en respuesta');
  saveAccessToken(data.accessToken);
  return data.user || null;
}

async function logoutFront() {
  // 1) limpiar inmediatamente token en cliente (para evitar “sesión pegada”)
  ACCESS_TOKEN = null;
  sessionStorage.removeItem(TOKEN_KEY);

  // 2) notificar servidor y bridge (sin bloquear UX)
  try { await fetch(API.logout, { method: 'POST', credentials: 'include' }); } catch {}
  try { await fetch(BRIDGE.clear, { method: 'POST' }); } catch {}

  // 3) redirigir
  window.location.href = '/login/';
}

// ====== Vincular form del sidebar "Cerrar sesión" ======
function bindSidebarLogout() {
  const form = document.querySelector('form[action$="/logout/"], form[action$="/logout"]');
  if (!form) return;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();          // evitamos el POST del form
    await logoutFront();         // hace limpieza + redirige
  });
}

// ====== UI login (si usas /login)
function bindLoginPage() {
  const btn = document.getElementById('btn-login');
  if (!btn) return;
  const emailEl = document.getElementById('login-email');
  const passEl  = document.getElementById('login-pass');
  const msg     = document.getElementById('login-msg');

  btn.addEventListener('click', async () => {
    try {
      msg && (msg.style.display='none');
      await loginFront((emailEl.value||'').trim(), (passEl.value||'').trim());
      window.location.href = '/medicamentos/';
    } catch(e) {
      if (msg) { msg.textContent = e.message || 'Error de login'; msg.style.display=''; }
    }
  });
  [emailEl, passEl].forEach(i => i?.addEventListener('keydown', e => { if (e.key === 'Enter') btn.click(); }));
}

// ====== Chart.js: pinta usando datos que Django deja en window.__DATA__
function initChartsFromServerData() {
  if (!window.__DATA__) return;
  const { resumen, stockTop, categorias, rotacion, vencimientos } = window.__DATA__;
  const chartBaseOpts = { responsive:true, maintainAspectRatio:false, plugins:{ legend:{position:'bottom'} } };

  // Resumen
  if (document.getElementById('graficaResumen')) {
    new Chart(document.getElementById('graficaResumen'), {
      type:'doughnut',
      data:{ labels:['Disponibles','Stock Crítico (<10)','Caducados'],
        datasets:[{ data:[resumen.disponibles, resumen.criticos, resumen.caducados],
          backgroundColor:['rgba(54,162,235,.6)','rgba(255,206,86,.6)','rgba(239,68,68,.6)'],
          borderColor:['rgba(54,162,235,1)','rgba(255,206,86,1)','rgba(239,68,68,1)'], borderWidth:1 }] },
      options: chartBaseOpts
    });
  }
  // Stock top
  if (document.getElementById('graficaStock')) {
    new Chart(document.getElementById('graficaStock'), {
      type:'bar',
      data:{ labels: stockTop.labels, datasets:[{ label:'Stock', data: stockTop.values, backgroundColor:'rgba(21,112,239,.35)', borderColor:'rgba(21,112,239,1)', borderWidth:1 }] },
      options:{ ...chartBaseOpts, scales:{ y:{ beginAtZero:true } } }
    });
  }
  // Categorías
  if (document.getElementById('graficaCategorias')) {
    const colors = categorias.labels.map(()=> `rgba(${Math.floor(Math.random()*200)},${Math.floor(Math.random()*200)},${Math.floor(Math.random()*200)},.6)`);
    new Chart(document.getElementById('graficaCategorias'), {
      type:'pie',
      data:{ labels: categorias.labels, datasets:[{ data: categorias.values, backgroundColor: colors, borderColor: colors, borderWidth:1 }] },
      options: chartBaseOpts
    });
  }
  // Rotación (dummy)
  if (document.getElementById('graficaRotacion')) {
    new Chart(document.getElementById('graficaRotacion'), {
      type:'bar',
      data:{ labels: rotacion.labels, datasets:[{ label:'Unid/periodo', data: rotacion.values, backgroundColor:'rgba(34,197,94,.35)', borderColor:'rgba(34,197,94,1)' }] },
      options:{ ...chartBaseOpts, indexAxis:'y', scales:{ x:{ beginAtZero:true } } }
    });
  }
  // Vencimientos
  if (document.getElementById('graficaVencimientos')) {
    new Chart(document.getElementById('graficaVencimientos'), {
      type:'bar',
      data:{ labels:['30 días','60 días','90 días'], datasets:[{ label:'Por vencer', data:[vencimientos.d30, vencimientos.d60, vencimientos.d90],
        backgroundColor:['rgba(245,158,11,.35)','rgba(245,158,11,.5)','rgba(239,68,68,.5)'],
        borderColor:['rgba(245,158,11,1)','rgba(245,158,11,1)','rgba(239,68,68,1)'] }] },
      options:{ ...chartBaseOpts, scales:{ y:{ beginAtZero:true } } }
    });
  }
}

function renderKPIsFromData() {
  if (!window.__DATA__?.resumen) return;
  const { disponibles = 0, criticos = 0, caducados = 0 } = window.__DATA__.resumen;
  const el = (id) => document.getElementById(id);
  if (el('kpi-total'))     el('kpi-total').textContent = (disponibles + criticos + caducados);
  if (el('kpi-criticos'))  el('kpi-criticos').textContent = criticos;
  if (el('kpi-caducados')) el('kpi-caducados').textContent = caducados;
  if (el('kpi-ordenes'))   el('kpi-ordenes').textContent = 0;
}

function renderTablaFromMeds() {
  const tb = document.getElementById('tabla-meds');
  if (!tb) return;
  const meds = Array.isArray(window.__MEDS__) ? window.__MEDS__ : [];
  const fmt = (n) => new Intl.NumberFormat('es-MX', { style:'currency', currency:'MXN' }).format(Number(n||0));
  const safe = (v) => (v ?? '');
  tb.innerHTML = meds.map(m => `
    <tr>
      <td>${safe(m.id)}</td>
      <td>${safe(m.nombre)}</td>
      <td>${safe(m.lote)}</td>
      <td>${safe(m.caducidad)}</td>
      <td><span class="badge-soft">${(m.proveedor?.nombre)||m.proveedor||''}</span></td>
      <td>${Number(m.stock||0)}</td>
      <td>${m.precio!=null ? fmt(m.precio) : ''}</td>
      <td>${(m.categoria?.nombre)||m.categoria||''}</td>
    </tr>
  `).join('');
}

/* ====== Arranque ====== */
document.addEventListener('DOMContentLoaded', () => {
  loadAccessToken();
  bindLoginPage();        // solo hace algo en /login
  bindSidebarLogout();    // ← importante para cerrar sesión bien
  renderKPIsFromData();
  renderTablaFromMeds();
  initChartsFromServerData();
});
