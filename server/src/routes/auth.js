import bcrypt from 'bcryptjs';
import { Router } from 'express';
import jwt from 'jsonwebtoken';

import config from '../config.js';
import User from '../models/User.js';
import { getSharedSecret, getJwtAudience, getJwtIssuer } from '../middleware/auth.js';

const router = Router();
const jwtExpires = config.get('jwt.expiresIn');

function buildTokenOptions() {
  const options = { expiresIn: jwtExpires, algorithm: 'HS256' };
  const audience = getJwtAudience();
  if (audience) {
    options.audience = audience;
  }
  const issuer = getJwtIssuer();
  if (issuer) {
    options.issuer = issuer;
  }
  return options;
}

function signSessionToken(user) {
  const secret = getSharedSecret();
  const payload = { sub: user.id, userId: user.id, tokenVersion: user.tokenVersion ?? 0 };
  return jwt.sign(payload, secret, buildTokenOptions());
}

router.post('/register', async (req, res) => {
  const { username, email, password, publicKey } = req.body || {};
  if (!username || !email || !password || !publicKey) {
    return res.status(400).json({ error: 'missing_fields' });
  }

  try {
    const existing = await User.findOne({
      $or: [{ email }, { username }],
    }).lean();
    if (existing) {
      return res.status(400).json({ error: 'user_exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    const user = await User.create({ username, email, password: hash, publicKey });

    const token = signSessionToken(user);
    return res.status(201).json({ token, userId: user.id, tokenVersion: user.tokenVersion });
  } catch (err) {
    if (err?.code === 11000 && err?.name === 'MongoServerError') {
      return res.status(400).json({ error: 'user_exists' });
    }
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

    const token = signSessionToken(user);
    return res.json({ token, userId: user.id, tokenVersion: user.tokenVersion });
  } catch (err) {
    req.app?.locals?.logger?.error?.('auth.login_failed', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

export default router;
