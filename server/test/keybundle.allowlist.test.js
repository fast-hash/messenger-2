import assert from 'node:assert/strict';
import { test } from 'node:test';

import jwt from 'jsonwebtoken';
import { MongoMemoryServer } from 'mongodb-memory-server';
import mongoose from 'mongoose';
import supertest from 'supertest';

import { createApp } from '../src/app.js';
import KeyBundle from '../src/models/KeyBundle.js';
import User from '../src/models/User.js';
import { closeRedis, setRedisClient } from '../src/services/replayGuard.js';

class NoopRedis {
  async set() {
    return 'OK';
  }
}

let mongod;
let request;
const redis = new NoopRedis();
const audience = 'secure-messenger-app';
const issuer = 'secure-messenger-auth';
const sharedSecret = 'allowlist-secret';

async function signToken(user) {
  return jwt.sign({ sub: user.id, userId: user.id, tokenVersion: user.tokenVersion }, sharedSecret, {
    algorithm: 'HS256',
    expiresIn: '15m',
    audience,
    issuer,
  });
}

test('setup', async () => {
  process.env.JWT_SHARED_SECRET = sharedSecret;
  process.env.KEYBUNDLE_REQUIRE_ALLOWLIST = 'true';
  process.env.JWT_AUDIENCE = audience;
  process.env.JWT_ISSUER = issuer;

  mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri());

  const app = createApp();
  request = supertest(app);
  setRedisClient(redis);
});

test('allowlist enforced for key retrieval', async () => {
  await Promise.all([User.deleteMany({}), KeyBundle.deleteMany({})]);

  const owner = await User.create({
    username: 'owner',
    email: 'owner@example.com',
    password: 'hash',
    publicKey: 'owner-key',
  });
  const requester = await User.create({
    username: 'requester',
    email: 'requester@example.com',
    password: 'hash',
    publicKey: 'requester-key',
  });

  await KeyBundle.create({
    userId: owner._id,
    identityKey: 'identity-key',
    signedPreKey: { keyId: 1, publicKey: 'signed-key', signature: 'sig' },
    oneTimePreKeys: [{ keyId: 1, publicKey: 'otp-key', used: false }],
    allowAnyRequester: false,
    allowedRequesters: [],
  });

  const requesterToken = await signToken(requester);

  const forbidden = await request
    .get(`/api/keybundle/${owner.id}`)
    .set('Authorization', `Bearer ${requesterToken}`);
  assert.equal(forbidden.status, 403);
  assert.equal(forbidden.body.error, 'forbidden');

  await KeyBundle.updateOne({ userId: owner._id }, { $set: { allowedRequesters: [requester._id] } });

  const allowed = await request
    .get(`/api/keybundle/${owner.id}`)
    .set('Authorization', `Bearer ${requesterToken}`);
  assert.equal(allowed.status, 200);
  assert.equal(allowed.body.oneTimePreKey.keyId, 1);

  const bundleAfter = await KeyBundle.findOne({ userId: owner._id }).lean();
  assert.ok(bundleAfter.oneTimePreKeys[0].used, 'pre-key marked as used');

  const noKeys = await request
    .get(`/api/keybundle/${owner.id}`)
    .set('Authorization', `Bearer ${requesterToken}`);
  assert.equal(noKeys.status, 410);
});

test('teardown', async () => {
  await mongoose.disconnect();
  if (mongod) {
    await mongod.stop();
  }
  await closeRedis();
  setRedisClient(undefined);
});
