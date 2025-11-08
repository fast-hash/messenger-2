import jwt from 'jsonwebtoken';

const COOKIE_NAME = 'access_token';

function isSecureEnv() {
  const env = (process.env.NODE_ENV || '').toLowerCase();
  return env === 'production' || env === 'staging';
}

export function parseCookies(header) {
  const map = new Map();
  if (typeof header !== 'string' || header.length === 0) {
    return map;
  }

  const pairs = header.split(';');
  for (const pair of pairs) {
    const index = pair.indexOf('=');
    if (index === -1) {
      continue;
    }
    const name = pair.slice(0, index).trim();
    if (!name) {
      continue;
    }
    const rawValue = pair.slice(index + 1).trim();
    if (!rawValue) {
      map.set(name, '');
      continue;
    }
    try {
      map.set(name, decodeURIComponent(rawValue));
    } catch {
      map.set(name, rawValue);
    }
  }

  return map;
}

export function extractAccessToken(req) {
  const header = req?.headers?.authorization || '';
  if (typeof header === 'string' && header.startsWith('Bearer ')) {
    return header.slice(7);
  }

  const cookieHeader = req?.headers?.cookie;
  const cookies = parseCookies(cookieHeader);
  return cookies.get(COOKIE_NAME) || null;
}

function resolveExpiry(token) {
  const decoded = jwt.decode(token);
  if (!decoded || typeof decoded !== 'object' || !decoded.exp) {
    return null;
  }
  const expMs = decoded.exp * 1000;
  const msUntilExpiry = Math.max(0, expMs - Date.now());
  return { expires: new Date(expMs), maxAge: msUntilExpiry || undefined };
}

export function setAccessTokenCookie(res, token) {
  if (!token) {
    throw new Error('ACCESS_TOKEN_REQUIRED');
  }
  const expiry = resolveExpiry(token);
  const options = {
    httpOnly: true,
    sameSite: 'strict',
    secure: isSecureEnv(),
    path: '/',
    ...(expiry ?? {}),
  };
  res.cookie(COOKIE_NAME, token, options);
}

export function clearAccessTokenCookie(res) {
  const options = {
    httpOnly: true,
    sameSite: 'strict',
    secure: isSecureEnv(),
    path: '/',
  };
  res.clearCookie(COOKIE_NAME, options);
}

export { COOKIE_NAME };
