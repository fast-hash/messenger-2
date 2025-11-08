import assert from 'node:assert/strict';
import test from 'node:test';

import express from 'express';
import jwt from 'jsonwebtoken';
import supertest from 'supertest';

import { signAccessToken } from '../src/lib/jwt.js';
import authMiddleware, { verifyAccess } from '../src/middleware/auth.js';

const prevAlgorithm = process.env.JWT_ALGORITHM;
const prevSecret = process.env.JWT_SECRET;
process.env.JWT_ALGORITHM = 'HS256';
process.env.JWT_SECRET = 'test-hs256-secret';

test('HS256 token issued by signAccessToken verifies successfully', () => {
  const token = signAccessToken({ sub: 'user-123', role: 'tester' });
  const payload = verifyAccess(token);
  assert.equal(payload.sub, 'user-123');
  assert.equal(payload.role, 'tester');
});

test('token with unexpected key id is rejected', () => {
  process.env.JWT_KID = 'kid-main';
  const good = signAccessToken({ sub: 'user-456' });
  const payload = verifyAccess(good);
  assert.equal(payload.sub, 'user-456');

  const tampered = jwt.sign({ sub: 'user-456' }, process.env.JWT_SECRET, {
    algorithm: 'HS256',
    keyid: 'other-kid',
  });
  assert.throws(() => verifyAccess(tampered));
  delete process.env.JWT_KID;
});

test('auth middleware allows a signed HS256 token', async () => {
  const app = express();
  app.get('/secure', authMiddleware, (req, res) => {
    res.json({ ok: true, user: req.user.sub || req.user.userId });
  });

  const token = signAccessToken({ sub: 'user-http' });
  const request = supertest(app);
  const res = await request.get('/secure').set('Authorization', `Bearer ${token}`);
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.body, { ok: true, user: 'user-http' });
});

test('teardown env cleanup', () => {
  if (prevAlgorithm === undefined) {
    delete process.env.JWT_ALGORITHM;
  } else {
    process.env.JWT_ALGORITHM = prevAlgorithm;
  }
  if (prevSecret === undefined) {
    delete process.env.JWT_SECRET;
  } else {
    process.env.JWT_SECRET = prevSecret;
  }
});
