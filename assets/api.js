/* ============================================================
   ВайбВиспр Web — клиент API.
   - Access-токен хранится в localStorage (короткий, 15 мин).
   - Refresh-токен лежит в HttpOnly cookie — JS его не видит и не может
     украсть через XSS. Браузер сам шлёт его на /api/auth/* endpoints.
   - Автоматически рефрешит access при 401.
   ============================================================ */

// Авто-детект окружения:
//   - localhost / 127.0.0.1 → локальный бэкенд для разработки
//   - всё остальное (прод-домен) → backend на том же домене под /api/
// При необходимости можно переопределить window.VF_API_BASE = '...'
// в инлайн-скрипте перед подключением api.js.
const API_BASE = window.VF_API_BASE || (
  ['localhost', '127.0.0.1'].includes(window.location.hostname)
    ? 'http://localhost:3000'
    : window.location.origin + '/api'
);
const STORAGE = {
  access:  'vf_access_token',
  user:    'vf_user',
  // Legacy: до перевода на HttpOnly cookie веб хранил refresh в localStorage.
  // Если он там остался — НЕ удаляем сразу, иначе залогиненные юзеры
  // отвалятся через 15 мин (cookie у них ещё нет). Используем legacy refresh
  // один раз в refreshAccess() — сервер вернёт Set-Cookie, и тогда удалим.
  legacyRefresh: 'vf_refresh_token',
};

const auth = {
  get accessToken()  { return localStorage.getItem(STORAGE.access);  },
  get user()         {
    try { return JSON.parse(localStorage.getItem(STORAGE.user) || 'null'); }
    catch { return null; }
  },
  isAuthenticated()  { return !!this.accessToken; },
  save(accessToken, user) {
    if (accessToken)  localStorage.setItem(STORAGE.access, accessToken);
    if (user)         localStorage.setItem(STORAGE.user,   JSON.stringify(user));
  },
  clear() {
    localStorage.removeItem(STORAGE.access);
    localStorage.removeItem(STORAGE.user);
    localStorage.removeItem(STORAGE.legacyRefresh);
  },
};

function showToast(message, variant = 'info', ttl = 3500) {
  const t = document.createElement('div');
  t.className = 'toast' + (variant === 'danger' ? ' danger' : '');
  t.textContent = message;
  document.body.appendChild(t);
  setTimeout(() => {
    t.style.transition = 'opacity .2s ease';
    t.style.opacity = '0';
    setTimeout(() => t.remove(), 220);
  }, ttl);
}

async function refreshAccess() {
  // Refresh-токен сидит в HttpOnly cookie — браузер сам его шлёт.
  // Для уже залогиненных юзеров (до перехода на cookie) — fallback на legacy
  // refresh из localStorage один раз: сервер вернёт Set-Cookie и мы сотрём
  // legacy. После этого все последующие refresh идут только через cookie.
  let legacy = null;
  try { legacy = localStorage.getItem(STORAGE.legacyRefresh); } catch {}
  const body = legacy ? JSON.stringify({ refreshToken: legacy }) : undefined;

  const resp = await fetch(`${API_BASE}/auth/refresh`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body,
  });
  if (!resp.ok) {
    auth.clear();
    try { localStorage.removeItem(STORAGE.legacyRefresh); } catch {}
    throw new Error('refresh_failed');
  }
  // Успех — cookie встал. Можно безопасно стереть legacy.
  try { localStorage.removeItem(STORAGE.legacyRefresh); } catch {}
  const { accessToken } = await resp.json();
  localStorage.setItem(STORAGE.access, accessToken);
  return accessToken;
}

/**
 * Универсальный fetch к нашему API с Bearer-токеном.
 * При 401 пробует один раз обновить access и повторить запрос.
 * credentials:'include' нужен чтобы refresh-cookie ходила.
 */
async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }
  const token = auth.accessToken;
  if (token) headers.set('Authorization', `Bearer ${token}`);

  let resp = await fetch(`${API_BASE}${path}`, {
    ...options,
    credentials: 'include',
    headers,
  });

  // Token expired? Попробуем рефрешнуть и повторить. Cookie ходит сама —
  // нет нужды проверять есть ли refresh локально.
  if (resp.status === 401) {
    try {
      const newAccess = await refreshAccess();
      headers.set('Authorization', `Bearer ${newAccess}`);
      resp = await fetch(`${API_BASE}${path}`, {
        ...options,
        credentials: 'include',
        headers,
      });
    } catch {
      // refresh не сработал — попадаем в ветку «не авторизован» ниже.
    }
  }

  return resp;
}

async function register(email, password, name) {
  const body = { email, password };
  if (name) body.name = name;
  const resp = await fetch(`${API_BASE}/auth/register`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const msg =
      data?.error === 'email_taken'      ? 'Этот email уже зарегистрирован' :
      data?.error === 'validation_error' ? friendlyValidationMessage(data.issues) :
      data?.message || 'Не удалось зарегистрироваться';
    throw new Error(msg);
  }
  // Backend теперь возвращает { needsVerification: true, email }
  // вместо токенов. Юзер должен пойти на verify.html и ввести код из письма.
  return data;
}

async function verifyEmail(email, code) {
  const resp = await fetch(`${API_BASE}/auth/verify-email`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, code }),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const msg = data?.message || 'Не удалось подтвердить код';
    const err = new Error(msg);
    err.code = data?.error;
    err.remainingAttempts = data?.remainingAttempts;
    throw err;
  }
  auth.save(data.accessToken, data.user);
  return data;
}

async function resendVerificationCode(email) {
  const resp = await fetch(`${API_BASE}/auth/resend-code`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(data?.message || 'Не удалось отправить код');
  }
  return data;
}

async function login(email, password) {
  const resp = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    // Если backend сказал needsVerification — это не ошибка а сигнал
    // что аккаунт есть, но email не подтверждён. Кидаем особую ошибку
    // которую UI может обработать редиректом на verify.html.
    if (data?.needsVerification && data?.email) {
      const err = new Error('Email не подтверждён');
      err.code = 'email_not_verified';
      err.needsVerification = true;
      err.email = data.email;
      throw err;
    }
    const msg = data?.message || 'Неверный email или пароль';
    throw new Error(msg);
  }
  auth.save(data.accessToken, data.user);
  return data;
}

async function logout() {
  // Best-effort: даже если запрос упал, локально access стираем.
  // Сервер очистит cookie сам через Set-Cookie с истёкшим Max-Age.
  try {
    await fetch(`${API_BASE}/auth/logout`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
    });
  } catch {}
  auth.clear();
}

async function me() {
  const resp = await apiFetch('/me');
  if (!resp.ok) throw new Error('not_authenticated');
  return resp.json();
}

async function plans() {
  const resp = await fetch(`${API_BASE}/billing/plans`);
  if (!resp.ok) throw new Error('plans_failed');
  return resp.json();
}

async function startCheckout(planId) {
  const resp = await apiFetch('/billing/checkout', {
    method: 'POST',
    body: JSON.stringify({ planId }),
  });
  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}));
    throw new Error(data?.message || 'Не удалось создать платёж');
  }
  return resp.json();
}

async function updateProfile(name) {
  const resp = await apiFetch('/auth/profile', {
    method: 'POST',
    body: JSON.stringify({ name }),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.message || data.error || 'Не удалось сохранить');
  return data;
}

async function forgotPassword(email) {
  const resp = await fetch(`${API_BASE}/auth/forgot-password`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.message || data.error || 'Не удалось отправить письмо');
  return data;
}

async function resetPassword(token, newPassword) {
  const resp = await fetch(`${API_BASE}/auth/reset-password`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, newPassword }),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.message || data.error || 'Не удалось сбросить пароль');
  return data;
}

async function changePassword(oldPassword, newPassword) {
  const resp = await apiFetch('/auth/change-password', {
    method: 'POST',
    body: JSON.stringify({ oldPassword, newPassword }),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.message || data.error || 'Не удалось сменить пароль');
  return data;
}

async function deleteAccount() {
  const resp = await apiFetch('/auth/delete-account', {
    method: 'POST',
    body: JSON.stringify({ confirm: 'УДАЛИТЬ' }),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.message || data.error || 'Не удалось удалить аккаунт');
  // Локальные токены тоже чистим
  auth.clear();
  return data;
}

async function cancelSubscription() {
  const resp = await apiFetch('/billing/cancel', { method: 'POST' });
  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}));
    throw new Error(data?.message || 'Не удалось отменить подписку');
  }
  return resp.json();
}

function friendlyValidationMessage(issues) {
  if (!Array.isArray(issues) || !issues.length) return 'Проверьте поля формы';
  const first = issues[0];
  const field = Array.isArray(first.path) ? first.path.join('.') : '';
  const fieldRu = ({
    email:    'Email',
    password: 'Пароль',
  })[field] || field;
  return fieldRu ? `${fieldRu}: ${first.message}` : first.message;
}

// Экспорт для inline-скриптов на страницах.
/**
 * Универсальная JSON-обёртка над apiFetch — для админ-страниц.
 * @param {string} path — путь без /api префикса, например "/admin/users".
 * @param {{method?: string, body?: any}=} opts — body будет JSON.stringify-нут.
 * @returns {Promise<any>} распарсенный JSON ответа.
 * @throws Error если status >= 400.
 */
async function apiJSON(path, opts = {}) {
  const init = { method: opts.method || 'GET' };
  if (opts.body !== undefined) {
    init.body = JSON.stringify(opts.body);
  }
  const resp = await apiFetch(path, init);
  const text = await resp.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!resp.ok) {
    const msg = (data && (data.message || data.error)) || `HTTP ${resp.status}`;
    throw new Error(msg);
  }
  return data;
}

window.VF = {
  auth,
  showToast,
  apiFetch,
  apiJSON,
  register,
  verifyEmail,
  resendVerificationCode,
  login,
  logout,
  me,
  plans,
  startCheckout,
  cancelSubscription,
  changePassword,
  deleteAccount,
  forgotPassword,
  resetPassword,
  updateProfile,
};
