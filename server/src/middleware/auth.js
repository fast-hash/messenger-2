// JWT verification with clock skew tolerance and HTTP middleware
import jwt from 'jsonwebtoken';

const JWT_ALG = ['RS256'];
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

export function getPublicKey() {
  if (cachedPubKey) return cachedPubKey;
  const k = process.env.JWT_PUBLIC_KEY;
  if (!k) throw new Error('JWT_PUBLIC_KEY not set');
  // поддержка PEM в переменных окружения с \n
  cachedPubKey = k.replace(/\\n/g, '\n');
  return cachedPubKey;
}

export function verifyAccess(token) {
  if (!token) throw new Error('NO_TOKEN');
  const payload = jwt.verify(token, getPublicKey(), {
    algorithms: JWT_ALG,
    clockTolerance: CLOCK_TOLERANCE_SEC,
  });
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
