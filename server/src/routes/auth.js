import bcrypt from 'bcryptjs';
import { Router } from 'express';
import jwt from 'jsonwebtoken';

import config from '../config.js';
import User from '../models/User.js';
import sanitizeBase64 from '../util/sanitizeBase64.js';
import {
  clearAccessTokenCookie,
  extractAccessToken,
  setAccessTokenCookie,
} from '../util/accessTokenCookie.js';
import { verifyAccess } from '../middleware/auth.js';

const USERNAME_REGEX = /^[a-zA-Z0-9._-]+$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_USERNAME_LENGTH = 32;
const MIN_USERNAME_LENGTH = 3;
const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128;
const MAX_PUBLIC_KEY_BYTES = 256;

function sanitizeUsername(value) {
  if (typeof value !== 'string') {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed.length < MIN_USERNAME_LENGTH || trimmed.length > MAX_USERNAME_LENGTH) {
    return null;
  }
  if (!USERNAME_REGEX.test(trimmed)) {
    return null;
  }
  return trimmed;
}

function sanitizeEmail(value) {
  if (typeof value !== 'string') {
    return null;
  }
  const normalised = value.trim().toLowerCase();
  if (normalised.length === 0 || normalised.length > 254) {
    return null;
  }
  if (!EMAIL_REGEX.test(normalised)) {
    return null;
  }
  return normalised;
}

function sanitizePassword(value) {
  if (typeof value !== 'string') {
    return null;
  }
  if (value.length < MIN_PASSWORD_LENGTH || value.length > MAX_PASSWORD_LENGTH) {
    return null;
  }
  return value;
}

const router = Router();
const jwtSecret = config.get('jwt.secret');
const jwtExpires = config.get('jwt.expiresIn');

router.post('/register', async (req, res) => {
  const { username, email, password, publicKey } = req.body || {};
  if (!username || !email || !password || !publicKey) {
    return res.status(400).json({ error: 'missing_fields' });
  }

  const sanitizedUsername = sanitizeUsername(username);
  const sanitizedEmail = sanitizeEmail(email);
  const sanitizedPassword = sanitizePassword(password);
  const sanitizedPublicKey = sanitizeBase64(publicKey, { maxBytes: MAX_PUBLIC_KEY_BYTES });

  if (!sanitizedUsername || !sanitizedEmail || !sanitizedPassword || !sanitizedPublicKey) {
    return res.status(400).json({ error: 'invalid_fields' });
  }

  try {
    const existing = await User.findOne({
      $or: [{ email: sanitizedEmail }, { username: sanitizedUsername }],
    }).lean();
    if (existing) {
      return res.status(400).json({ error: 'user_exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(sanitizedPassword, salt);
    const user = await User.create({
      username: sanitizedUsername,
      email: sanitizedEmail,
      password: hash,
      publicKey: sanitizedPublicKey,
    });

    const payload = { sub: user.id, userId: user.id };
    const token = jwt.sign(payload, jwtSecret, { expiresIn: jwtExpires, algorithm: 'HS256' });
    setAccessTokenCookie(res, token);
    return res.status(201).json({ userId: user.id });
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

  const normalisedEmail = sanitizeEmail(email);
  if (!normalisedEmail) {
    return res.status(400).json({ error: 'invalid_credentials' });
  }

  try {
    const user = await User.findOne({ email: normalisedEmail });
    if (!user) {
      return res.status(400).json({ error: 'invalid_credentials' });
    }

    const passwordOk = await bcrypt.compare(password, user.password);
    if (!passwordOk) {
      return res.status(400).json({ error: 'invalid_credentials' });
    }

    const payload = { sub: user.id, userId: user.id };
    const token = jwt.sign(payload, jwtSecret, { expiresIn: jwtExpires, algorithm: 'HS256' });
    setAccessTokenCookie(res, token);
    return res.json({ userId: user.id });
  } catch (err) {
    req.app?.locals?.logger?.error?.('auth.login_failed', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

router.post('/logout', (req, res) => {
  clearAccessTokenCookie(res);
  res.status(204).send();
});

router.get('/session', (req, res) => {
  try {
    const token = extractAccessToken(req);
    if (!token) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    const user = verifyAccess(token);
    return res.json({ userId: user.id });
  } catch (err) {
    req.app?.locals?.logger?.warn?.('auth.session_failed', err);
    return res.status(401).json({ error: 'unauthorized' });
  }
});

export default router;
