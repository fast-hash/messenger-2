// JWT verification with clock skew tolerance and HTTP middleware
import jwt from 'jsonwebtoken';

import config from '../config.js';

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
  const candidates = [process.env.JWT_SHARED_SECRET, process.env.JWT_SECRET];
  for (const candidate of candidates) {
    if (candidate && typeof candidate === 'string' && candidate.length > 0) {
      cachedSharedSecret = candidate;
      return cachedSharedSecret;
    }
  }

  try {
    const secret = config.get('jwt.secret');
    if (typeof secret !== 'string' || secret.length === 0) {
      throw new Error('JWT_SECRET_INVALID');
    }
    if (
      secret === 'dev-only-secret-please-change' &&
      (process.env.NODE_ENV || '').toLowerCase() === 'production'
    ) {
      throw new Error('JWT_SECRET_DEFAULT_IN_PROD');
    }
    cachedSharedSecret = secret;
    return cachedSharedSecret;
  } catch (err) {
    throw new Error('JWT_SECRET_NOT_SET', { cause: err });
  }
}

export function resolveVerification(token) {
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

export function verifyJwt(token, options = {}) {
  if (!token) throw new Error('NO_TOKEN');
  const { key, algorithms } = resolveVerification(token);
  const verifyOptions = {
    algorithms,
    clockTolerance: CLOCK_TOLERANCE_SEC,
    ...options,
  };
  return jwt.verify(token, key, verifyOptions);
}

export function verifyAccess(token) {
  const payload = verifyJwt(token);
  return buildUser(payload);
}

export function authRequired(req, res, next) {
  try {
    const hdr = req.headers.authorization || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : '';
    req.user = verifyAccess(token);
    return next();
  } catch {
    res.status(401).json({ error: 'unauthorized' });
  }
}

export default authRequired;

export function __resetAuthCache() {
  cachedPubKey = null;
  cachedSharedSecret = null;
}
