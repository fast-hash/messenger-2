import assert from 'node:assert/strict';
import { test } from 'node:test';

import jwt from 'jsonwebtoken';

import { verifyAccess, __resetAuthCache } from '../src/middleware/auth.js';

function withEnv(overrides, fn) {
  const previousValues = new Map();
  const keys = Object.keys(overrides);

  keys.forEach((key) => {
    previousValues.set(key, process.env[key]);
    const value = overrides[key];
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  });

  __resetAuthCache();

  try {
    fn();
  } finally {
    keys.forEach((key) => {
      const previous = previousValues.get(key);
      if (previous === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = previous;
      }
    });
    __resetAuthCache();
  }
}

function withSharedSecret(secret, fn) {
  withEnv(
    {
      JWT_SHARED_SECRET: secret,
      JWT_SECRET: undefined,
      JWT_PUBLIC_KEY: undefined,
    },
    fn
  );
}

function withLegacySecret(secret, fn) {
  withEnv(
    {
      JWT_SHARED_SECRET: undefined,
      JWT_SECRET: secret,
      JWT_PUBLIC_KEY: undefined,
    },
    fn
  );
}

test('HS256 tokens are accepted when shared secret configured', () => {
  withSharedSecret('unit-test-secret', () => {
    const token = jwt.sign({ sub: 'hs-user', userId: 'hs-user' }, 'unit-test-secret', {
      algorithm: 'HS256',
      expiresIn: '5m',
    });
    const payload = verifyAccess(token);
    assert.equal(payload.id, 'hs-user');
    assert.equal(payload.sub, 'hs-user');
    assert.equal(payload.userId, 'hs-user');
  });
});

test('HS256 tokens use JWT_SECRET env for backwards compatibility', () => {
  withLegacySecret('legacy-secret', () => {
    const token = jwt.sign({ sub: 'legacy-user', userId: 'legacy-user' }, 'legacy-secret', {
      algorithm: 'HS256',
      expiresIn: '5m',
    });
    const payload = verifyAccess(token);
    assert.equal(payload.id, 'legacy-user');
    assert.equal(payload.sub, 'legacy-user');
  });
});

test('tokens signed with unsupported algorithm are rejected', () => {
  withSharedSecret('unit-test-secret', () => {
    const token = jwt.sign({ sub: 'bad-alg' }, 'unit-test-secret', {
      algorithm: 'HS384',
      expiresIn: '5m',
    });
    assert.throws(() => verifyAccess(token));
  });
});
