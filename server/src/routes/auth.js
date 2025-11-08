import bcrypt from 'bcryptjs';
import { Router } from 'express';

import config from '../config.js';
import { signAccessToken } from '../lib/jwt.js';
import User from '../models/User.js';

const router = Router();
const jwtAudience =
  process.env.JWT_AUDIENCE ||
  (config.has?.('jwt.audience') ? config.get('jwt.audience') : undefined);
const jwtIssuer =
  process.env.JWT_ISSUER || (config.has?.('jwt.issuer') ? config.get('jwt.issuer') : undefined);

router.post('/register', async (req, res) => {
  const { username, email, password, publicKey } = req.body || {};
  if (!username || !email || !password || !publicKey) {
    return res.status(400).json({ error: 'missing_fields' });
  }

  try {
    const existing = await User.findOne({ email }).lean();
    if (existing) {
      return res.status(400).json({ error: 'user_exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    const user = await User.create({ username, email, password: hash, publicKey });

    const payload = { sub: user.id, userId: user.id };
    if (jwtAudience) payload.aud = jwtAudience;
    if (jwtIssuer) payload.iss = jwtIssuer;
    const token = signAccessToken(payload);
    return res.status(201).json({ token, userId: user.id });
  } catch (err) {
    req.app?.locals?.logger?.error?.('auth.register_failed', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'missing_credentials' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'invalid_credentials' });
    }

    const passwordOk = await bcrypt.compare(password, user.password);
    if (!passwordOk) {
      return res.status(400).json({ error: 'invalid_credentials' });
    }

    const payload = { sub: user.id, userId: user.id };
    if (jwtAudience) payload.aud = jwtAudience;
    if (jwtIssuer) payload.iss = jwtIssuer;
    const token = signAccessToken(payload);
    return res.json({ token, userId: user.id });
  } catch (err) {
    req.app?.locals?.logger?.error?.('auth.login_failed', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

export default router;
