import assert from 'node:assert/strict';
import { test } from 'node:test';

import User from '../src/models/User.js';
import { ensureActiveUserSession, __resetAuthCache } from '../src/middleware/auth.js';

function mockFindById(result) {
  const original = User.findById;
  User.findById = () => ({
    select() {
      return {
        lean: async () => result,
      };
    },
  });
  return () => {
    User.findById = original;
  };
}

test('ensureActiveUserSession allows token with matching version', async () => {
  __resetAuthCache();
  const restore = mockFindById({ tokenVersion: 2 });
  try {
    await assert.doesNotReject(() => ensureActiveUserSession({ id: 'user-1', tokenVersion: 2 }));
  } finally {
    restore();
    __resetAuthCache();
  }
});

test('ensureActiveUserSession rejects revoked token', async () => {
  __resetAuthCache();
  const restore = mockFindById({ tokenVersion: 3 });
  try {
    await assert.rejects(() => ensureActiveUserSession({ id: 'user-1', tokenVersion: 2 }), /TOKEN_REVOKED/);
  } finally {
    restore();
    __resetAuthCache();
  }
});

test('ensureActiveUserSession rejects when user missing', async () => {
  __resetAuthCache();
  const restore = mockFindById(null);
  try {
    await assert.rejects(() => ensureActiveUserSession({ id: 'user-missing', tokenVersion: 0 }), /USER_NOT_FOUND/);
  } finally {
    restore();
    __resetAuthCache();
  }
});
