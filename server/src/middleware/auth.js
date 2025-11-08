// JWT verification with clock skew tolerance and HTTP middleware
import jwt from 'jsonwebtoken';

import config from '../config.js';
import User from '../models/User.js';

const JWT_ALG = Object.freeze({
  RS256: 'RS256',
  HS256: 'HS256',
});
const SUPPORTED_ALGS = new Set(Object.values(JWT_ALG));
const CLOCK_TOLERANCE_SEC = parseInt(process.env.JWT_CLOCK_TOLERANCE_SEC || '120', 10);

function buildUser(payload) {
  if (!payload || typeof payload !== 'object') {
    throw new Error('NO_PAYLOAD');
  }
  const subject = payload.sub ?? payload.userId ?? payload.id;
  if (!subject) {
    throw new Error('NO_SUBJECT');
  }
  const id = subject.toString();
  return { ...payload, id };
}

let cachedPubKey = null;
let cachedSharedSecret = null;
let cachedAudience = undefined;
let cachedIssuer = undefined;

const tokenVersionCache = new Map();
const TOKEN_VERSION_TTL_MS = 30_000;

export function getPublicKey() {
  if (cachedPubKey) return cachedPubKey;
  const k = process.env.JWT_PUBLIC_KEY;
  if (!k) throw new Error('JWT_PUBLIC_KEY not set');
  // поддержка PEM в переменных окружения с \n
  cachedPubKey = k.replace(/\\n/g, '\n');
  return cachedPubKey;
}

export function getSharedSecret() {
  if (cachedSharedSecret) return cachedSharedSecret;

  // Предпочитаем явный JWT_SHARED_SECRET, но поддерживаем историческое имя JWT_SECRET для совместимости.
  const envCandidates = [process.env.JWT_SHARED_SECRET, process.env.JWT_SECRET];
  const fromEnv = envCandidates.find((value) => typeof value === 'string' && value.length > 0);
  if (fromEnv) {
    cachedSharedSecret = fromEnv;
    return cachedSharedSecret;
  }

  try {
    const secret = config.get('jwt.secret');
    if (typeof secret !== 'string' || secret.length === 0) {
      throw new Error('JWT_SECRET_INVALID');
    }
    cachedSharedSecret = secret;
    return cachedSharedSecret;
  } catch (err) {
    throw new Error('JWT_SECRET_NOT_SET', { cause: err });
  }
}

export function getJwtAudience() {
  if (cachedAudience !== undefined) {
    return cachedAudience;
  }

  const envValue = process.env.JWT_AUDIENCE;
  if (envValue) {
    cachedAudience = envValue;
    return cachedAudience;
  }

  if (config.has('jwt.audience')) {
    cachedAudience = config.get('jwt.audience');
    return cachedAudience;
  }

  cachedAudience = null;
  return cachedAudience;
}

export function getJwtIssuer() {
  if (cachedIssuer !== undefined) {
    return cachedIssuer;
  }

  const envValue = process.env.JWT_ISSUER;
  if (envValue) {
    cachedIssuer = envValue;
    return cachedIssuer;
  }

  if (config.has('jwt.issuer')) {
    cachedIssuer = config.get('jwt.issuer');
    return cachedIssuer;
  }

  cachedIssuer = null;
  return cachedIssuer;
}

function resolveVerification(token) {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || typeof decoded !== 'object' || !decoded.header) {
    throw new Error('TOKEN_DECODE_FAILED');
  }

  const { alg } = decoded.header;
  if (!SUPPORTED_ALGS.has(alg)) {
    throw new Error('UNSUPPORTED_ALG');
  }

  if (alg === JWT_ALG.RS256) {
    return { key: getPublicKey(), algorithms: [JWT_ALG.RS256] };
  }

  if (alg === JWT_ALG.HS256) {
    return { key: getSharedSecret(), algorithms: [JWT_ALG.HS256] };
  }

  throw new Error('UNSUPPORTED_ALG');
}

export function verifyAccess(token) {
  if (!token) throw new Error('NO_TOKEN');
  const { key, algorithms } = resolveVerification(token);
  const verifyOptions = {
    algorithms,
    clockTolerance: CLOCK_TOLERANCE_SEC,
  };
  const audience = getJwtAudience();
  if (audience) {
    verifyOptions.audience = audience;
  }
  const issuer = getJwtIssuer();
  if (issuer) {
    verifyOptions.issuer = issuer;
  }
  const payload = jwt.verify(token, key, {
    ...verifyOptions,
  });
  return buildUser(payload);
}

async function fetchTokenVersion(userId) {
  const cacheKey = userId.toString();
  const now = Date.now();
  const cached = tokenVersionCache.get(cacheKey);
  if (cached && cached.expiresAt > now) {
    return cached.version;
  }

  const doc = await User.findById(userId).select('tokenVersion').lean();
  if (!doc) {
    throw new Error('USER_NOT_FOUND');
  }

  const version = typeof doc.tokenVersion === 'number' ? doc.tokenVersion : 0;
  tokenVersionCache.set(cacheKey, { version, expiresAt: now + TOKEN_VERSION_TTL_MS });
  return version;
}

export async function ensureActiveUserSession(user) {
  if (!user || !user.id) {
    throw new Error('NO_USER');
  }
  const claimed = typeof user.tokenVersion === 'number' ? user.tokenVersion : 0;
  const actual = await fetchTokenVersion(user.id);
  if (claimed !== actual) {
    throw new Error('TOKEN_REVOKED');
  }
}

export async function authRequired(req, res, next) {
  try {
    const hdr = req.headers.authorization || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : '';
    const user = verifyAccess(token);
    await ensureActiveUserSession(user);
    req.user = user;
    return next();
  } catch {
    res.status(401).json({ error: 'unauthorized' });
  }
}

export default authRequired;

export function __resetAuthCache() {
  cachedPubKey = null;
  cachedSharedSecret = null;
  cachedAudience = undefined;
  cachedIssuer = undefined;
  tokenVersionCache.clear();
}
