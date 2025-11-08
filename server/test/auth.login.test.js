import assert from 'node:assert/strict';
import test from 'node:test';

import { MongoMemoryServer } from 'mongodb-memory-server';
import mongoose from 'mongoose';
import supertest from 'supertest';

import { createApp } from '../src/app.js';

let mongod;
let request;

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

test('setup login fixtures', async () => {
  mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri('auth-login'));

  const app = createApp();
  request = supertest(app);

  const registerPayload = {
    username: 'login-user',
    email: 'login@example.com',
    password: 'LoginPass123',
    publicKey: Buffer.from('login-public-key').toString('base64'),
  };

  const res = await request.post('/api/auth/register').send(registerPayload);
  assert.equal(res.statusCode, 201);
});

test('login accepts uppercase email', async () => {
  const res = await request.post('/api/auth/login').send({
    email: 'LOGIN@EXAMPLE.COM',
    password: 'LoginPass123',
  });

  assert.equal(res.statusCode, 200);
  assert.ok(res.body?.token);
  assert.ok(res.body?.userId);
});

test('login rejects malformed email', async () => {
  const res = await request.post('/api/auth/login').send({
    email: 'not-an-email',
    password: 'LoginPass123',
  });

  assert.equal(res.statusCode, 400);
  assert.equal(res.body?.error, 'invalid_credentials');
});

test('teardown login fixtures', async () => {
  await mongoose.disconnect();
  if (mongod) {
    await mongod.stop();
  }
});
