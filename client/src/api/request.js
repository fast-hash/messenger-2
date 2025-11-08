// client/src/api/request.js
const ABSOLUTE_URL = /^https?:\/\//i;
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
  const opts = { method, headers: {}, credentials: 'include' };
  if (body !== undefined && body !== null) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }

  const res = await fetch(resolvedUrl, opts);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.status === 204 ? null : res.json();
}
