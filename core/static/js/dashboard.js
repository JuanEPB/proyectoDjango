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

// ---------- fetchWithAuth centralizado ----------
window.fetchWithAuth = async function(input, init = {}) {
  // Normaliza URL: permite pasar '/api/...' o 'http://...'
  const toUrl = (u) => {
    if (/^https?:\/\//i.test(u)) return u;
    const path = u.startsWith('/') ? u.slice(1) : u;
    return `${BASE_URL}/${path}`;
  };

  let token = TOKEN_KEY || sessionStorage.getItem(TOKEN_KEY) || null;

  const headers = new Headers(init.headers || {});
  headers.set('Accept', 'application/json');
  if (!headers.has('Content-Type') && init.method && init.method !== 'GET') {
    headers.set('Content-Type', 'application/json');
  }
  if (token) headers.set('Authorization', `Bearer ${token}`);

  let res = await fetch(toUrl(input), { ...init, headers, credentials: 'include' });

  // Si expira → refresca una vez y reintenta
  if (res.status === 401) {
    try {
      await refreshAccess(); // esto ya actualiza ACCESS_TOKEN
      token = TOKEN_KEY || sessionStorage.getItem(TOKEN_KEY);
      if (token) headers.set('Authorization', `Bearer ${token}`);
      res = await fetch(toUrl(input), { ...init, headers, credentials: 'include' });
    } catch (e) {
      saveAccessToken(null);
      throw new Error('Sesión expirada. Vuelve a iniciar sesión.');
    }
  }

  if (!res.ok) {
    const msg = await res.text().catch(() => '');
    throw new Error(msg || `HTTP ${res.status}`);
  }
  const ct = res.headers.get('content-type') || '';
  return ct.includes('application/json') ? res.json() : res;
};

// ====== TOKEN en sessionStorage ======
const TOKEN_KEY = "{{ TOKEN_KEY}}";
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
      options:{ ...chartBaseOpts, scales:{ y:{  } } }
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

// ====== AUTOCOMPLETE + BUSCADOR ======
(function(){
  const input = document.getElementById('buscador');
  const list  = document.getElementById('buscador-sugerencias');
  if (!input || !list) return;

  const meds = Array.isArray(window.__MEDS__) ? window.__MEDS__ : [];
  const norm = s => (s||'').toString().toLowerCase().trim();

  let hideTimer = null;
  const showList = () => { list.style.display = 'block'; };
  const hideList = () => { list.style.display = 'none'; };
  const clearList = () => { list.innerHTML = ''; };

  const renderItems = (items) => {
    clearList();
    if (!items.length) { hideList(); return; }
    list.innerHTML = items.map(m => `
      <div class="autocomplete-item" data-id="${m.id}">
        <span>${m.nombre || '(sin nombre)'}</span>
        ${m.categoria?.nombre ? `<span class="pill">${m.categoria.nombre}</span>` : ''}
        ${m.stock!=null ? `<span class="pill">Stock: ${m.stock}</span>` : ''}
      </div>
    `).join('');
    showList();
  };

  // Debounce
  let lastHandle = 0;
  const debounce = (fn, ms=180) => (...args) => {
    clearTimeout(lastHandle);
    lastHandle = setTimeout(() => fn(...args), ms);
  };

  // Buscar por nombre o categoría
  const buscar = debounce(() => {
    const q = norm(input.value);
    if (!q) { clearList(); hideList(); return; }
    const results = meds.filter(m => {
      const n = norm(m.nombre);
      const c = norm(m.categoria?.nombre);
      return n.includes(q) || c.includes(q);
    }).slice(0, 12);
    renderItems(results);
  });

  // Click en sugerencia: intenta ir al detalle si estás en inventario,
  // o resalta en la tabla si estás en dashboard
  list.addEventListener('click', (e) => {
    const item = e.target.closest('.autocomplete-item');
    if (!item) return;
    const id = item.getAttribute('data-id');

    // Si existe una URL de detalle con patrón /inventario/detalle/<id>/, navega:
    if (window.location.pathname.includes('/inventory') || window.location.pathname.includes('/inventario')) {
      window.location.href = `/inventario/detalle/${id}/`;
      return;
    }

    // En Dashboard: intentar hacer scroll a la fila en la tabla si existe
    const row = document.querySelector(`#tabla-meds tr td:first-child`);
    // (opcional) podrías marcar la fila si usas data-id en cada <tr>
    hideList();
    input.blur();
  });

  input.addEventListener('input', buscar);
  input.addEventListener('focus', () => { if (list.innerHTML) showList(); });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { hideList(); input.blur(); }
  });

  document.addEventListener('click', (e) => {
    if (e.target === input || list.contains(e.target)) return;
    hideTimer && clearTimeout(hideTimer);
    hideTimer = setTimeout(hideList, 60);
  });
})();

// ====== FILTRO EN TABLA (Inventario) ======
(function(){
  const input = document.getElementById('inv-search');
  const table = document.getElementById('tabla-inv');
  if (!input || !table) return;

  const norm = s => (s||'').toString().toLowerCase().trim();
  input.addEventListener('input', () => {
    const q = norm(input.value);
    [...table.querySelectorAll('tbody tr')].forEach(tr => {
      const text = norm(tr.innerText);
      tr.style.display = text.includes(q) ? '' : 'none';
    });
  });
})();


/* ====== Arranque ====== */
document.addEventListener('DOMContentLoaded', () => {
  loadAccessToken();
  bindLoginPage();        // solo hace algo en /login
  bindSidebarLogout();    // ← importante para cerrar sesión bien
  renderKPIsFromData();
  renderTablaFromMeds();
  initChartsFromServerData();
});

// =======================
// REPORTES (vista /reports)
// =======================
(function(){
  // Si no estamos en /reports, salir
  const isReports = document.getElementById('btn-refrescar');
  if (!isReports) return;

  // ------- Endpoints -------
  const ENDPOINTS = {
    docsByTipo: (tipo) => `/api/documentos/tipo/${encodeURIComponent(tipo)}`,
    docById:    (id)   => `/api/documentos/${id}`,
  };

  const $ = (id) => document.getElementById(id);
  const byDateDesc = (a,b)=> new Date(b.createdAt||0) - new Date(a.createdAt||0);

  // ------- Descarga: PDF directo o JSON->PDF -------
  async function descargarVentaPDF(docId) {
  const endpoint = `/api/documentos/${encodeURIComponent(docId)}`;

  // 1) Intento directo: ¿es PDF?
  try {
    const r = await fetch(endpoint, { headers: { 'X-Requested-With': 'XMLHttpRequest' } });
    if (!r.ok) throw new Error('HTTP ' + r.status);

    const ct = (r.headers.get('content-type') || '').toLowerCase();
    // Si es un PDF, lo entregamos como Blob
    if (ct.includes('application/pdf')) {
      const blob = await r.blob();
      const fname = filenameFromDisposition(r.headers.get('content-disposition')) || `venta_${docId}.pdf`;
      downloadBlob(blob, fname);
      return;
    }

    // Si no es PDF, asumimos JSON con el detalle de la venta
    const data = await r.json();
    if (Array.isArray(data) || typeof data === 'object') {
      await generarVentaPDFdesdeJSON(data, docId);
      return;
    }

    throw new Error('Respuesta no reconocida');
  } catch (err) {
    console.warn('Fallo intento directo, probando detalle de venta:', err);
  }

  // 2) Fallback: pedimos el detalle de venta por su ID y generamos PDF
  try {
    const r2 = await fetch(`/api/ventas/${encodeURIComponent(docId)}`, { headers: { 'X-Requested-With':'XMLHttpRequest' }});
    if (!r2.ok) throw new Error('HTTP ' + r2.status);
    const venta = await r2.json();
    await generarVentaPDFdesdeJSON(venta, docId);
  } catch (e) {
    console.error('No se pudo generar el PDF de la venta', e);
    alert('No se pudo descargar el PDF de la venta.');
  }

  // Utils
  function filenameFromDisposition(cd) {
    if (!cd) return null;
    const m = /filename\*?=(?:UTF-8'')?["']?([^"';]+)["']?/i.exec(cd);
    return m ? decodeURIComponent(m[1]) : null;
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename || 'documento.pdf';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(()=> URL.revokeObjectURL(url), 1000);
  }
}

/** Genera un PDF simple y limpio con jsPDF a partir del JSON de venta */
async function generarVentaPDFdesdeJSON(venta, docId) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });

  // --- Normaliza datos ---
  const folio = venta.folio || venta.id || docId || '-';
  const fecha = (venta.fecha || '').toString().slice(0, 19).replace('T', ' ') || '';
  const cliente = venta.cliente || venta.paciente || 'Cliente general';
  const total = Number(venta.total || 0);

  const detalles = Array.isArray(venta.detalles) ? venta.detalles : (venta.items || []);
  const rows = detalles.map((d, i) => {
    const nombre = d.nombre || (d.medicamento && d.medicamento.nombre) || `Item ${i+1}`;
    const cant = Number(d.cantidad || d.qty || 1);
    const precio = Number(d.precioUnitario || d.precio || 0);
    const subtotal = cant * precio;
    return { nombre, cant, precio, subtotal };
  });

  // --- Estilos base ---
  let y = 60, left = 56, right = 540, lh = 18;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.text('PharmaControl - Comprobante de Venta', left, y); y += 26;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(11);
  doc.text(`Folio: ${folio}`, left, y); y += lh;
  if (fecha) { doc.text(`Fecha: ${fecha}`, left, y); y += lh; }
  doc.text(`Cliente: ${cliente}`, left, y); y += lh + 8;

  // Cabecera tabla
  doc.setFont('helvetica', 'bold');
  doc.text('Producto', left, y);
  doc.text('Cant.', left + 300, y, { align: 'left' });
  doc.text('P. Unit.', left + 360, y, { align: 'left' });
  doc.text('Subtotal', right, y, { align: 'right' });
  y += 8; doc.line(left, y, right, y); y += 14;

  // Filas
  doc.setFont('helvetica', 'normal');
  const money = n => '$' + Number(n||0).toFixed(2);
  rows.forEach(r => {
    const wrap = doc.splitTextToSize(r.nombre, 280);
    // Producto
    doc.text(wrap, left, y);
    // Cant / Precio / Subtotal (alineados)
    doc.text(String(r.cant),     left + 300, y);
    doc.text(money(r.precio),    left + 360, y);
    doc.text(money(r.subtotal),  right,      y, { align: 'right' });
    // siguiente línea considerando el alto del wrap
    y += Math.max(lh, wrap.length * 14);
    if (y > 760) { doc.addPage(); y = 60; }
  });

  y += 10; doc.line(left, y, right, y); y += lh;

  // Totales
  const subtotal = rows.reduce((acc,r)=> acc + r.subtotal, 0);
  const iva = total > 0 ? (total - subtotal) : 0;
  doc.setFont('helvetica', 'bold');
  doc.text('Subtotal:', left + 360, y);     doc.text(money(subtotal), right, y, { align: 'right' }); y += lh;
  doc.text('IVA:',      left + 360, y);     doc.text(money(iva),      right, y, { align: 'right' }); y += lh;
  doc.text('TOTAL:',    left + 360, y);     doc.text(money(total||subtotal), right, y, { align: 'right' });

  // Pie
  y += lh * 2;
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.text('Gracias por su compra. Sistema PharmaControl.', left, y);

  // Descarga
  doc.save(`venta_${folio}.pdf`);
}

  // ------- Card 2: SOLO "Tickets" (conteo) -------
  async function cargarTicketsVentas(){
    const sk  = $('ventas-loading');
    const box = $('ventas-content');
    if (!sk || !box) return;
    sk.style.display = 'block'; box.style.display = 'none';

    try{
      const diasSel = $('rep-periodo');
      const dias = Number(diasSel?.value || 30);
      const limite = Date.now() - dias*86400000;

      const arr = await fetchWithAuth(ENDPOINTS.docsByTipo('venta'));
      const ventas = (Array.isArray(arr)?arr:[]).filter(v => {
        const t = v.createdAt ? new Date(v.createdAt).getTime() : 0;
        return t >= limite;
      });

      // Muestra SOLO tickets y oculta los demás KPIs + gráfica
      $('ven-tickets') && ( $('ven-tickets').textContent = ventas.length );
      $('ven-total')   && ( $('ven-total').closest('.kpi').style.display   = 'none' );
      $('ven-prom')    && ( $('ven-prom').closest('.kpi').style.display    = 'none' );
      $('ven-items')   && ( $('ven-items').closest('.kpi').style.display   = 'none' );
      document.getElementById('venChart')?.closest('.chart-wrap')?.remove();
    }catch(e){
      console.error(e);
    }finally{
      sk.style.display='none'; box.style.display='block';
    }
  }

  // ------- Card 3: Últimos reportes por tipo "venta" -------
  async function cargarUltimaVenta(){
    const cont = $('ult-venta');
    if (!cont) return;
    cont.textContent = 'Cargando…';
    try{
      const arr = await fetchWithAuth(ENDPOINTS.docsByTipo('venta'));
      const docs = (Array.isArray(arr)?arr:[]).sort(byDateDesc).slice(0, 10);

      const html = docs.map(d=>{
        const fecha = d.createdAt ? new Date(d.createdAt).toLocaleString() : 'Sin fecha';
        const nombre = d.filename || 'venta.json';
        const id = d._id || d.id;
        return `
          <div class="ia-item">
            <div><strong>${nombre}</strong></div>
            <div class="text-muted-2">${fecha}</div>
            <button class="btn-ghost" data-dlid="${id}"><i class="bi bi-download"></i> Descargar</button>
          </div>
          <div class="divider"></div>
        `;
      }).join('') || 'No hay reportes de venta.';

      cont.innerHTML = html;
      // Bind descarga
      cont.querySelectorAll('[data-ticket-id]').forEach(btn=>{
        btn.addEventListener('click', ()=>{
          const id = btn.getAttribute('data-dlid');
         descargarTicketVenta(id);
        });
      });
    }catch(e){
      console.error(e);
      cont.textContent = 'No disponible.';
    }
  }

  // ------- Card 4: Últimos reportes IA (PDF o JSON→PDF) -------
  async function cargarUltimosReportesIA(){
    const cont = $('ultimos-ia');
    if (!cont) return;
    cont.textContent = 'Cargando…';
    try{
      const arr = await fetchWithAuth(ENDPOINTS.docsByTipo('IA'));
      const docs = (Array.isArray(arr)?arr:[]).sort(byDateDesc).slice(0, 10);

      cont.innerHTML = docs.map(d=>{
        const fecha = d.createdAt ? new Date(d.createdAt).toLocaleString() : 'Sin fecha';
        const nombre = d.filename || 'reporte_IA';
        const id = d._id || d.id;
        return `
          <div class="ia-item">
            <div><strong>${nombre}</strong></div>
            <div class="text-muted-2">${fecha}</div>
            <button class="btn-ghost" data-dlid="${id}">
              <i class="bi bi-download"></i> Descargar PDF
            </button>
          </div>
          <div class="divider"></div>
        `;
      }).join('') || 'No hay reportes IA.';

      cont.querySelectorAll('[data-dlid]').forEach(btn=>{
        btn.addEventListener('click', ()=>{
          const id = btn.getAttribute('data-dlid');
          const doc = docs.find(x => (x._id||x.id) == id);
          if (doc) descargarDoc(doc);
        });
      });
    }catch(e){
      console.error(e);
      cont.textContent = 'Error al cargar los reportes IA.';
    }
  }

  // ------- INIT + eventos -------
  window.initReportsPage = function(){
    // botón refrescar
    const refresh = $('btn-refrescar');
    refresh && refresh.addEventListener('click', ()=>{
      cargarTicketsVentas();
      cargarUltimaVenta();
      cargarUltimosReportesIA();
    });

    // cambio de periodo → recalcula SOLO tickets
    const periodo = $('rep-periodo');
    periodo && periodo.addEventListener('change', cargarTicketsVentas);

    // primer render
    cargarTicketsVentas();
    cargarUltimaVenta();
    cargarUltimosReportesIA();
  };
})();


/* ======================================================
   Preferencias de tema (modo claro / oscuro persistente)
   ====================================================== */

const THEME_KEY = 'pc_theme'; // Clave en localStorage

// -------------------------
// Función: aplicar tema
// -------------------------
// Aplica el tema claro u oscuro a la etiqueta <html>.
// Usamos data-theme="dark" para activar los estilos CSS.
function applyTheme(theme) {
  if (theme === 'dark') {
    document.documentElement.setAttribute('data-theme', 'dark');
  } else {
    document.documentElement.removeAttribute('data-theme');
  }
}

// -------------------------
// Función: guardar tema
// -------------------------
// Guarda la preferencia del usuario en localStorage.
function saveTheme(theme) {
  localStorage.setItem(THEME_KEY, theme);
}

// -------------------------
// Bloque inmediato (IIFE)
// -------------------------
// Se ejecuta antes de que se pinte la página, evitando
// el parpadeo blanco al recargar.
(function () {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved === 'dark') {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
})();

// -------------------------
// Evento principal
// -------------------------
// Espera a que el DOM esté cargado para vincular
// los botones "Claro" y "Oscuro".
document.addEventListener('DOMContentLoaded', () => {
  const btnLight = document.getElementById('theme-light');
  const btnDark  = document.getElementById('theme-dark');

  // Aplica el tema guardado
  const current = localStorage.getItem(THEME_KEY) || 'light';
  applyTheme(current);

  // Botón "Claro"
  if (btnLight) {
    btnLight.addEventListener('click', () => {
      applyTheme('light');
      saveTheme('light');
    });
  }

  // Botón "Oscuro"
  if (btnDark) {
    btnDark.addEventListener('click', () => {
      applyTheme('dark');
      saveTheme('dark');
    });
  }
});





// Reportes

// ----- TICKET 80mm (recibo) -----
// Descarga tipo ticket 80mm con jsPDF a partir del JSON que da tu endpoint
async function descargarTicketVenta(id) {
  const data = await fetch('/api/documentos/descargar/' + encodeURIComponent(id), {
    headers: { 'X-Requested-With':'XMLHttpRequest' }
  }).then(r => r.json());

  await generarTicket80mm(data); // <- la función de jsPDF que ya te pasé
}


/**
 * Genera un ticket estilo recibo (80mm) a partir del JSON:
 * {
 *   id, usuario{ farmacia{nombre, direccion, telefono, lema, logo_url, empresa{...}} },
 *   fecha, total, detalles[{ medicamento{nombre}, cantidad, precioUnitario }]
 * }
 */
async function generarTicket80mm(data) {
  const { jsPDF } = window.jspdf;

  // 80mm ≈ 226.77 pt; alto dinámico
  const W = 226.77;
  let y = 12;
  const lh = 12;
  const padX = 10;

  // Calcula alto estimado
  const detalles = Array.isArray(data.detalles) ? data.detalles : [];
  const lineasItems = detalles.reduce((acc, d) => acc + 1 + Math.ceil((d?.medicamento?.nombre || '').length / 26), 0);
  const H = Math.max(240 + lineasItems * (lh + 2), 380);

  const doc = new jsPDF({ unit: 'pt', format: [W, H] });

  const farmacia = data.usuario?.farmacia || {};
  const empresa  = farmacia.empresa || {};
  const nombreFarm = farmacia.nombre || empresa.nombre || 'Farmacia';
  const lema = farmacia.lema || '';
  const dir  = farmacia.direccion || empresa.direccion || '';
  const tel  = farmacia.telefono || empresa.telefono_contacto || '';

  const folio = data.id || data.folio || '';
  const fecha = (data.fecha || '').toString().slice(0,19).replace('T',' ') || '';

  const money = (n)=>'$'+Number(n||0).toFixed(2);

  // Encabezado
  doc.setFont('helvetica','bold'); doc.setFontSize(11);
  doc.text(nombreFarm, W/2, y+=14, { align:'center' });

  if (lema) { doc.setFont('helvetica','normal'); doc.setFontSize(9); doc.text(lema, W/2, y+=12, { align:'center' }); }
  if (dir)  { doc.setFontSize(8); doc.text(doc.splitTextToSize(dir, W-20), W/2, y+=12, { align:'center' }); }
  if (tel)  { doc.text(`Tel: ${tel}`, W/2, y+=10, { align:'center' }); }

  y+=6; doc.setLineWidth(0.7); doc.line(padX, y, W-padX, y); y+=8;

  // Datos del ticket
  doc.setFont('helvetica','bold'); doc.setFontSize(9);
  doc.text(`Ticket: ${folio}`, padX, y);
  doc.setFont('helvetica','normal');
  doc.text(`Fecha: ${fecha}`, padX, y+=lh);

  y+=4; doc.setLineWidth(0.5); doc.line(padX, y, W-padX, y); y+=10;

  // Cabecera de items
  doc.setFont('helvetica','bold');
  doc.text('Producto', padX, y);
  doc.text('Cant',    W-86, y);
  doc.text('P.Unit',  W-56, y);
  doc.text('Imp.',    W-14, y, { align:'right' });

  y+=6; doc.setLineWidth(0.3); doc.line(padX, y, W-padX, y); y+=10;

  // Items
  doc.setFont('helvetica','normal');
  detalles.forEach((d) => {
    const nombre = d?.medicamento?.nombre || d?.nombre || '';
    const cant   = Number(d?.cantidad || 1);
    const pu     = Number(d?.precioUnitario || d?.precio || 0);
    const imp    = cant * pu;

    // Nombre envuelto
    const wrap = doc.splitTextToSize(nombre, W - 100);
    doc.text(wrap, padX, y);
    // columnas derechas en primera línea únicamente
    doc.text(String(cant), W-86, y);
    doc.text(money(pu),    W-56, y);
    doc.text(money(imp),   W-14, y, { align:'right' });

    y += Math.max(lh, wrap.length * (lh-2));
  });

  y+=6; doc.line(padX, y, W-padX, y); y+=10;

  // Totales
  const subtotal = detalles.reduce((s,d)=> s + (Number(d.cantidad||1) * Number(d.precioUnitario||d.precio||0)), 0);
  const total = Number(data.total || subtotal);
  const iva   = Math.max(0, total - subtotal);

  doc.setFont('helvetica','bold');
  doc.text('SUBTOTAL', W-56, y); doc.text(money(subtotal), W-14, y, { align:'right' }); y+=lh;
  doc.text('IVA',      W-56, y); doc.text(money(iva),      W-14, y, { align:'right' }); y+=lh+2;

  doc.setFontSize(11);
  doc.text('TOTAL', W-56, y); doc.text(money(total), W-14, y, { align:'right' });

  // Pie
  y += lh*2;
  doc.setFont('helvetica','normal'); doc.setFontSize(8);
  doc.text('¡Gracias por su compra!', W/2, y, { align:'center' });

  doc.save(`ticket_${folio || 'venta'}.pdf`);
}
