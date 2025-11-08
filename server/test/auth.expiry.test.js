import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { test } from 'node:test';

import jwt from 'jsonwebtoken';

import { verifyAccess } from '../src/middleware/auth.js';

const CLOCK_TOL = 120;

// локальная пара ключей для этого файла тестов
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const PRIV = privateKey.export({ type: 'pkcs1', format: 'pem' });
const PUB = publicKey.export({ type: 'pkcs1', format: 'pem' });

process.env.JWT_PUBLIC_KEY = PUB;
process.env.JWT_CLOCK_TOLERANCE_SEC = String(CLOCK_TOL);
process.env.JWT_AUDIENCE = 'rs-test';
process.env.JWT_ISSUER = 'rs-issuer';

test('expired long ago -> 401', () => {
  const now = Math.floor(Date.now() / 1000);
  const token = jwt.sign({ sub: 'u1', tokenVersion: 0, iat: now - 400, exp: now - 300 }, PRIV, {
    algorithm: 'RS256',
    audience: 'rs-test',
    issuer: 'rs-issuer',
  });
  assert.throws(() => verifyAccess(token));
});

test('exp just in the past (within skew) -> accepted', () => {
  const now = Math.floor(Date.now() / 1000);
  const token = jwt.sign({ sub: 'u2', tokenVersion: 0, iat: now - 30, exp: now - 30 }, PRIV, {
    algorithm: 'RS256',
    audience: 'rs-test',
    issuer: 'rs-issuer',
  });
  const payload = verifyAccess(token);
  assert.equal(payload.id, 'u2');
  assert.equal(payload.sub, 'u2');
});

test('nbf slightly in the future (within skew) -> accepted', () => {
  const now = Math.floor(Date.now() / 1000);
  const token = jwt.sign({ sub: 'u3', tokenVersion: 0, nbf: now + 30, exp: now + 3600 }, PRIV, {
    algorithm: 'RS256',
    audience: 'rs-test',
    issuer: 'rs-issuer',
  });
  const payload = verifyAccess(token);
  assert.equal(payload.id, 'u3');
  assert.equal(payload.sub, 'u3');
});

test('nbf far in the future -> 401', () => {
  const now = Math.floor(Date.now() / 1000);
  const token = jwt.sign({ sub: 'u4', tokenVersion: 0, nbf: now + 600, exp: now + 3600 }, PRIV, {
    algorithm: 'RS256',
    audience: 'rs-test',
    issuer: 'rs-issuer',
  });
  assert.throws(() => verifyAccess(token));
});
