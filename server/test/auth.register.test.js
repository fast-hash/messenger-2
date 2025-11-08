import assert from 'node:assert/strict';
import test from 'node:test';

import { MongoMemoryServer } from 'mongodb-memory-server';
import mongoose from 'mongoose';
import supertest from 'supertest';

import { createApp } from '../src/app.js';

let mongod;
let request;

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

test('setup register fixtures', async () => {
  mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri('auth-register'));

  const app = createApp();
  request = supertest(app);
});

test('register rejects duplicate usernames', async () => {
  const basePayload = {
    username: 'duplicate-user',
    email: 'first@example.com',
    password: 'StrongPass123',
    publicKey: Buffer.from('first-public-key').toString('base64'),
  };

  const first = await request.post('/api/auth/register').send(basePayload);
  assert.equal(first.statusCode, 201);
  const cookies = first.headers['set-cookie'] || [];
  assert.ok(
    cookies.some((cookie) => /^access_token=/i.test(cookie)),
    'access_token cookie must be issued on registration'
  );

  const second = await request.post('/api/auth/register').send({
    ...basePayload,
    email: 'second@example.com',
    publicKey: Buffer.from('second-public-key').toString('base64'),
  });

  assert.equal(second.statusCode, 400);
  assert.equal(second.body?.error, 'user_exists');
});

test('register rejects invalid email and public key', async () => {
  const payload = {
    username: 'bad-user',
    email: 'not-an-email',
    password: 'StrongPass123',
    publicKey: 'not-base64',
  };

  const res = await request.post('/api/auth/register').send(payload);
  assert.equal(res.statusCode, 400);
  assert.equal(res.body?.error, 'invalid_fields');
});

test('register rejects too-short username', async () => {
  const payload = {
    username: 'xy',
    email: 'short@example.com',
    password: 'StrongPass123',
    publicKey: Buffer.from('short-user').toString('base64'),
  };

  const res = await request.post('/api/auth/register').send(payload);
  assert.equal(res.statusCode, 400);
  assert.equal(res.body?.error, 'invalid_fields');
});

test('teardown register fixtures', async () => {
  await mongoose.disconnect();
  if (mongod) {
    await mongod.stop();
  }
});
