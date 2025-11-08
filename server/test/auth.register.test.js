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
    publicKey: 'first-public-key',
  };

  const first = await request.post('/api/auth/register').send(basePayload);
  assert.equal(first.statusCode, 201);

  const second = await request.post('/api/auth/register').send({
    ...basePayload,
    email: 'second@example.com',
    publicKey: 'second-public-key',
  });

  assert.equal(second.statusCode, 400);
  assert.equal(second.body?.error, 'user_exists');
});

test('teardown register fixtures', async () => {
  await mongoose.disconnect();
  if (mongod) {
    await mongod.stop();
  }
});
