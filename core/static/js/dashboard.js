// ====== CONFIG GENERAL (auth & roles) ======

// Permite sobreescribir la URL base desde window.APP_CONFIG.API_URL
const RAW_BASE_URL = (window.APP_CONFIG && window.APP_CONFIG.API_URL)
  ? String(window.APP_CONFIG.API_URL)
  : 'https://api.pharmacontrol.site';

// Normaliza URL base (sin slash final)
const BASE_URL = RAW_BASE_URL.replace(/\/+$/, '');

const API = {
  login:   `${BASE_URL}/api/auth/login`,
  refresh: `${BASE_URL}/api/auth/refresh`,
  logout:  `${BASE_URL}/api/auth/logout`,
};

// Puente con Django (mismo dominio que la app web)
const BRIDGE = {
  store: '/bridge/store-token/',
  clear: '/bridge/clear-token/',
};

// Clave del token en storage (usa la que define base.html si existe)
const TOKEN_KEY = window.TOKEN_KEY || 'pc_access_token_v1';

// Usaremos sessionStorage por seguridad; si no existe, cae a localStorage
const STORE = (typeof window !== 'undefined' && window.sessionStorage)
  ? window.sessionStorage
  : (typeof window !== 'undefined' ? window.localStorage : null);

let ACCESS_TOKEN = null;

// =========================
// Utilidades básicas
// =========================

function safeJSON(res) {
  return res.json().catch(() => ({}));
}

function loadAccessToken() {
  if (!STORE) return null;
  const t = STORE.getItem(TOKEN_KEY);
  ACCESS_TOKEN = t || null;
  return ACCESS_TOKEN;
}

async function saveAccessToken(token) {
  ACCESS_TOKEN = token || null;
  if (STORE) {
    if (token) STORE.setItem(TOKEN_KEY, token);
    else STORE.removeItem(TOKEN_KEY);
  }

  // Sincroniza con la sesión de Django
  try {
    if (token) {
      await fetch(BRIDGE.store, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ accessToken: token }),
        credentials: 'include',
      });
    } else {
      await fetch(BRIDGE.clear, {
        method: 'POST',
        credentials: 'include',
      });
    }
  } catch (e) {
    console.warn('[auth] Error sincronizando token con Django:', e);
  }

  syncCurrentUser();
}

// Decodifica el payload del JWT sin validar firma (solo para UI)
function parseJwt(token) {
  try {
    const [, payload] = token.split('.');
    if (!payload) return null;
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    const json = atob(padded);
    return JSON.parse(json);
  } catch (e) {
    console.warn('[auth] No se pudo decodificar el JWT:', e);
    return null;
  }
}

function syncCurrentUser() {
  const t = ACCESS_TOKEN || loadAccessToken();
  if (!t) {
    window.CURRENT_USER = null;
    return;
  }
  window.CURRENT_USER = parseJwt(t) || null;
}

// =========================
// Llamadas auth API
// =========================

async function loginRequest(email, contraseña) {
  const res = await fetch(API.login, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, contraseña }),
  });

  if (!res.ok) {
    const detail = await safeJSON(res);
    const msg = detail?.message || detail?.error || 'Credenciales inválidas.';
    throw new Error(msg);
  }

  const data = await safeJSON(res);
  if (!data || !data.accessToken) {
    throw new Error('La API no devolvió accessToken.');
  }

  await saveAccessToken(data.accessToken);
  return data;
}

async function refreshTokenIfNeeded() {
  const token = ACCESS_TOKEN || loadAccessToken();
  if (!token) return null;

  try {
    const res = await fetch(API.refresh, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
    });
    if (!res.ok) return null;
    const data = await safeJSON(res);
    if (data && data.accessToken) {
      await saveAccessToken(data.accessToken);
      return data.accessToken;
    }
  } catch (e) {
    console.warn('[auth] Error refrescando token:', e);
  }
  return null;
}

// Logout completo: NestJS + Django + storage
async function logoutFront() {
  const token = ACCESS_TOKEN || loadAccessToken();

  try {
    if (token) {
      await fetch(API.logout, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
      });
    }
  } catch (e) {
    console.warn('[auth] Error llamando logout API:', e);
  }

  try {
    await saveAccessToken(null);
  } catch (e) {
    console.warn('[auth] Error limpiando sesión:', e);
  }

  // Redirección a login
  window.location.href = '/login/';
}

// expone por si algo externo lo quiere usar
window.logoutFront = logoutFront;

// =========================
// fetchWithAuth helper
// =========================

window.fetchWithAuth = async function (input, init = {}) {
  const url = (u) => {
    if (/^https?:\/\//i.test(u)) return u;
    const path = u.startsWith('/') ? u.slice(1) : u;
    return `${BASE_URL}/${path}`;
  };

  const finalInit = { ...init, headers: { ...(init.headers || {}) } };

  let token = ACCESS_TOKEN || loadAccessToken();
  if (!token) {
    // Intentar refrescar por si hay sesión de Django con token.
    await refreshTokenIfNeeded();
    token = ACCESS_TOKEN || loadAccessToken();
  }

  if (token) {
    finalInit.headers['Authorization'] = `Bearer ${token}`;
  }
  finalInit.credentials = finalInit.credentials || 'include';

  const target = typeof input === 'string' ? input : input.url;
  const response = await fetch(url(target), finalInit);

  // Si regresó 401, intentamos 1 vez refrescar y repetir
  if (response.status === 401) {
    const refreshed = await refreshTokenIfNeeded();
    if (refreshed) {
      finalInit.headers['Authorization'] = `Bearer ${refreshed}`;
      return fetch(url(target), finalInit);
    }
  }

  return response;
};

// =========================
// Roles (solo UI)
// =========================

function applyRoleVisibility() {
  const u = window.CURRENT_USER;
  if (!u) return;

  const rawRole = (u.role || u.rol || u.Role || '').toString().toLowerCase();
  if (!rawRole) return;

  const isAdmin = rawRole === 'admin';

  // Oculta navegación avanzada a no-admins
  if (!isAdmin) {
    // Usuarios
    document.querySelectorAll('.side-bar a[href$="/users/"]').forEach((a) => {
      a.closest('.content')?.classList.add('d-none');
    });
    // Configuración
    document.querySelectorAll('.side-bar a[href$="/settings/"]').forEach((a) => {
      a.closest('.content')?.classList.add('d-none');
    });
  }
}

// =========================
// Inicialización por página
// =========================

document.addEventListener('DOMContentLoaded', () => {
  console.log('═══════════════════════════════════');
  console.log('Pharmacontrol · dashboard.js listo');
  console.log('BASE_URL:', BASE_URL);

  const body = document.body;
  const isLogin = body.classList.contains('auth-body');

  // Sincroniza usuario decodificando el JWT que haya guardado
  syncCurrentUser();
  applyRoleVisibility();

  // ---- Página de LOGIN ----
  if (isLogin) {
    const emailInput = document.getElementById('login-email');
    const passInput  = document.getElementById('login-pass');
    const btnLogin   = document.getElementById('btn-login');
    const msgBox     = document.getElementById('login-msg');

    if (btnLogin && emailInput && passInput) {
      btnLogin.addEventListener('click', async () => {
        if (!emailInput.value || !passInput.value) {
          msgBox.textContent = 'Completa correo y contraseña.';
          msgBox.style.display = 'block';
          return;
        }

        btnLogin.disabled = true;
        btnLogin.classList.add('is-loading');
        msgBox.style.display = 'none';

        try {
          await loginRequest(emailInput.value.trim(), passInput.value);
          // Éxito: redirigimos al dashboard principal
          window.location.href = '/medicamentos/';
        } catch (e) {
          console.error(e);
          msgBox.textContent = e.message || 'No se pudo iniciar sesión.';
          msgBox.style.display = 'block';
        } finally {
          btnLogin.disabled = false;
          btnLogin.classList.remove('is-loading');
        }
      });

      // Enter para enviar
      [emailInput, passInput].forEach((inp) => {
        inp.addEventListener('keyup', (ev) => {
          if (ev.key === 'Enter') {
            btnLogin.click();
          }
        });
      });
    }

    console.log('Página de login inicializada.');
  }

  // ---- Páginas internas (con base.html, sidebar, etc.) ----
  document.addEventListener('click', (e) => {
    const logoutButton = e.target.closest('[data-action="logout"]');
    if (logoutButton) {
      e.preventDefault();
      logoutFront();
    }
  });

  console.log('✓ Inicialización completada');
  console.log('═══════════════════════════════════');
});
