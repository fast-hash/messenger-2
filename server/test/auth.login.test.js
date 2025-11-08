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

test('login accepts uppercase email and sets session cookie', async () => {
  const res = await request.post('/api/auth/login').send({
    email: 'LOGIN@EXAMPLE.COM',
    password: 'LoginPass123',
  });

  assert.equal(res.statusCode, 200);
  assert.ok(res.body?.userId);
  const cookies = res.headers['set-cookie'] || [];
  assert.ok(
    cookies.some((cookie) => /^access_token=/i.test(cookie)),
    'access_token cookie must be present'
  );
  const cookieHeader = cookies.find((cookie) => /^access_token=/i.test(cookie));
  assert.ok(cookieHeader, 'cookie header missing');

  const session = await request.get('/api/auth/session').set('Cookie', cookieHeader);
  assert.equal(session.statusCode, 200);
  assert.equal(session.body?.userId, res.body.userId);

  const logout = await request.post('/api/auth/logout').set('Cookie', cookieHeader);
  assert.equal(logout.statusCode, 204);
  const clearedCookies = logout.headers['set-cookie'] || [];
  assert.ok(
    clearedCookies.some((cookie) => /^access_token=;/i.test(cookie) || /Max-Age=0/i.test(cookie)),
    'logout must clear cookie'
  );

  const afterLogout = await request.get('/api/auth/session');
  assert.equal(afterLogout.statusCode, 401);
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
