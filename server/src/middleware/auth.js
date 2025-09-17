import jwt from 'jsonwebtoken';

import config from '../config.js';

export default function auth(req, res, next) {
  const header = req.header('Authorization');
  const token = header?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'missing_token' });
  }

  try {
    const secret = config.get('jwt.secret');
    const payload = jwt.verify(token, secret);
    const userId = payload.userId || payload.id || payload.sub;
    if (!userId) {
      return res.status(401).json({ error: 'invalid_token' });
    }
    req.user = { id: typeof userId === 'string' ? userId : userId?.toString() };
    if (!req.user.id) {
      return res.status(401).json({ error: 'invalid_token' });
    }
    next();
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
}
