// client/src/api/request.js
const ABSOLUTE_URL = /^https?:\/\//i;
const TOKEN_STORAGE_KEY = 'secure-messenger.accessToken';

let accessToken = null;

function isBrowser() {
  return typeof window !== 'undefined' && typeof window.document !== 'undefined';
}

function readTokenFromStorage() {
  if (!isBrowser()) {
    return null;
  }
  try {
    return window.localStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    return null;
  }
}

function writeTokenToStorage(token) {
  if (!isBrowser()) {
    return;
  }
  try {
    if (token) {
      window.localStorage.setItem(TOKEN_STORAGE_KEY, token);
    } else {
      window.localStorage.removeItem(TOKEN_STORAGE_KEY);
    }
  } catch {
    /* ignore storage failures */
  }
}

function syncGlobalToken(token) {
  if (typeof globalThis === 'undefined') {
    return;
  }

  if (token) {
    globalThis.__ACCESS_TOKEN__ = token;
  } else if (typeof globalThis.__ACCESS_TOKEN__ !== 'undefined') {
    try {
      delete globalThis.__ACCESS_TOKEN__;
    } catch {
      globalThis.__ACCESS_TOKEN__ = undefined;
    }
  }
}

export function setAccessToken(token) {
  accessToken = token || null;
  writeTokenToStorage(accessToken);
  syncGlobalToken(accessToken);
}

export function clearAccessToken() {
  accessToken = null;
  writeTokenToStorage(null);
  syncGlobalToken(null);
}

export function getAccessToken() {
  if (accessToken) {
    return accessToken;
  }

  const stored = readTokenFromStorage();
  if (stored) {
    accessToken = stored;
    syncGlobalToken(accessToken);
    return accessToken;
  }

  if (typeof globalThis !== 'undefined' && typeof globalThis.__ACCESS_TOKEN__ === 'string') {
    return globalThis.__ACCESS_TOKEN__;
  }

  return null;
}

function resolveUrl(path) {
  if (ABSOLUTE_URL.test(path)) {
    return path;
  }
  if (typeof window !== 'undefined' && typeof window.document !== 'undefined') {
    return path;
  }
  const base = process.env.API_BASE_URL || globalThis.__API_BASE_URL;
  if (!base) {
    throw new Error('API base URL is required when running outside the browser');
  }
  return new URL(path, base).toString();
}

export async function request(url, method = 'GET', body) {
  const resolvedUrl = resolveUrl(url);
  const opts = { method, headers: {} };
  if (body !== undefined && body !== null) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }

  const token = getAccessToken();
  if (token) {
    opts.headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(resolvedUrl, opts);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.status === 204 ? null : res.json();
}
