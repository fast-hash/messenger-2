import assert from 'node:assert/strict';
import test from 'node:test';

import { MongoMemoryServer } from 'mongodb-memory-server';
import mongoose from 'mongoose';
import supertest from 'supertest';

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

const { createApp } = await import('../src/app.js');

let mongod;
let app;
let request;
const userId = new mongoose.Types.ObjectId().toString();

function authStub(req, _res, next) {
  req.user = { id: userId };
  next();
}

const basePayload = {
  identityKey: 'QUJDRA==',
  signedPreKey: {
    keyId: 1,
    publicKey: 'QUJDRA==',
    signature: 'QUJDRA==',
  },
};

test('setup', async () => {
  mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri());
  app = createApp({ authMiddleware: authStub });
  request = supertest(app);
});

test('rejects invalid one-time pre-key payloads', async () => {
  const cases = [
    [{ keyId: '1', publicKey: 'QUJDRA==' }],
    [{ keyId: 1 }],
    [{ keyId: 1, publicKey: '' }],
    [{ keyId: 1, publicKey: 'not-base64!!' }],
    [{ keyId: -1, publicKey: 'QUJDRA==' }],
  ];

  for (const invalid of cases) {
    const res = await request.post('/api/keybundle').send({
      ...basePayload,
      oneTimePreKeys: invalid,
    });

    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error, 'invalid_payload');
  }
});

test('teardown', async () => {
  await mongoose.disconnect();
  if (mongod) {
    await mongod.stop();
  }
});
