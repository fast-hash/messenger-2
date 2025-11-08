import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { createServer } from 'node:http';
import { after, before, test } from 'node:test';

import jwt from 'jsonwebtoken';
import { Server } from 'socket.io';
import ioClient from 'socket.io-client';
import User from '../src/models/User.js';
import { __resetAuthCache } from '../src/middleware/auth.js';
import { socketAuth } from '../src/ws/auth-middleware.js';

let httpServer;
let io;
let baseURL;
let PRIV;
let PUB;
let restoreFindById;

function mockUser(version = 0) {
  if (typeof restoreFindById === 'function') {
    restoreFindById();
  }
  const original = User.findById;
  User.findById = () => ({
    select() {
      return {
        lean: async () => ({ tokenVersion: version }),
      };
    },
  });
  restoreFindById = () => {
    User.findById = original;
  };
}

before(async () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  PRIV = privateKey.export({ type: 'pkcs1', format: 'pem' });
  PUB = publicKey.export({ type: 'pkcs1', format: 'pem' });
  process.env.JWT_PUBLIC_KEY = PUB;
  process.env.JWT_CLOCK_TOLERANCE_SEC = '120';
  process.env.JWT_AUDIENCE = 'socket-test';
  process.env.JWT_ISSUER = 'socket-suite';

  httpServer = createServer();
  io = new Server(httpServer, { cors: { origin: '*' } });
  socketAuth(io);

  await new Promise((r) => httpServer.listen(0, r));
  const port = httpServer.address().port;
  baseURL = `http://127.0.0.1:${port}`;
});

after(async () => {
  restoreFindById?.();
  __resetAuthCache();
  await new Promise((r) => io.close(r));
  await new Promise((r) => httpServer.close(r));
});

test('expired token -> connect_error + no connection', async () => {
  const now = Math.floor(Date.now() / 1000);
  mockUser(0);
  const expired = jwt.sign({ sub: 'u1', tokenVersion: 0, iat: now - 400, exp: now - 300 }, PRIV, {
    algorithm: 'RS256',
    audience: 'socket-test',
    issuer: 'socket-suite',
  });

  await new Promise((resolve) => {
    const c = ioClient(baseURL, { auth: { token: expired }, reconnection: false, timeout: 1000 });
    c.on('connect', () => {
      c.disconnect();
      assert.fail('should not connect with expired token');
    });
    c.on('connect_error', (err) => {
      assert.match(String(err?.message || err), /AUTH_FAILED|Unauthorized|401/i);
      resolve();
    });
  });
});

test('valid token -> connect ok', async () => {
  const now = Math.floor(Date.now() / 1000);
  mockUser(0);
  const good = jwt.sign({ sub: 'u2', tokenVersion: 0, iat: now - 1, exp: now + 3600 }, PRIV, {
    algorithm: 'RS256',
    audience: 'socket-test',
    issuer: 'socket-suite',
  });

  await new Promise((resolve, reject) => {
    const c = ioClient(baseURL, { auth: { token: good }, reconnection: false, timeout: 2000 });
    c.on('connect', () => {
      c.disconnect();
      resolve();
    });
    c.on('connect_error', (e) => reject(e));
  });
});
