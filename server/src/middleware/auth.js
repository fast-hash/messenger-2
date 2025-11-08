// JWT verification with clock skew tolerance and HTTP middleware
import { verifyAccess as verifyAccessBase } from '../lib/jwt.js';

export const verifyAccess = verifyAccessBase;

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
