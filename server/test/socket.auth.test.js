import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import test from 'node:test';

import jwt from 'jsonwebtoken';
import { MongoMemoryServer } from 'mongodb-memory-server';
import mongoose from 'mongoose';
import { io as Client } from 'socket.io-client';

import { attachSockets } from '../src/app.js';
import Chat from '../src/models/Chat.js';

process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-socket-secret';
process.env.JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'aud';
process.env.JWT_ISSUER = process.env.JWT_ISSUER || 'iss';

let mongod;
let httpServer;
let io;
let port;

test('setup', async () => {
  mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri());
  httpServer = createServer((_, res) => {
    res.statusCode = 200;
    res.end('ok');
  });
  io = attachSockets(httpServer);
  await new Promise((resolve) => httpServer.listen(0, resolve));
  const address = httpServer.address();
  port = typeof address === 'object' ? address.port : address;
});

test('rejects without JWT; allows with JWT and join works', async () => {
  await assert.rejects(async () => {
    await new Promise((resolve, reject) => {
      const client = Client(`http://127.0.0.1:${port}`, {
        autoConnect: true,
        transports: ['websocket'],
      });
      client.on('connect', () => {
        client.close();
        resolve();
      });
      client.on('connect_error', (err) => {
        client.close();
        reject(err);
      });
    });
  });

  const userId = new mongoose.Types.ObjectId().toString();
  const chatId = new mongoose.Types.ObjectId().toString();
  await Chat.deleteMany({});
  await Chat.create({
    _id: new mongoose.Types.ObjectId(chatId),
    participants: [new mongoose.Types.ObjectId(userId)],
  });
  const token = jwt.sign({ sub: userId }, process.env.JWT_SECRET, {
    algorithm: 'HS256',
    audience: process.env.JWT_AUDIENCE,
    issuer: process.env.JWT_ISSUER,
  });

  await new Promise((resolve, reject) => {
    const client = Client(`http://127.0.0.1:${port}`, {
      autoConnect: true,
      transports: ['websocket'],
      extraHeaders: { Authorization: `Bearer ${token}` },
    });
    client.on('connect_error', (err) => {
      client.close();
      reject(err);
    });
    client.on('connect', () => {
      client.emit('join', { chatId }, (ack) => {
        try {
          assert.equal(ack?.ok, true);
          client.close();
          resolve();
        } catch (err) {
          client.close();
          reject(err);
        }
      });
    });
  });
});

test('teardown', async () => {
  if (io) {
    io.close();
  }
  if (httpServer) {
    await new Promise((resolve) => httpServer.close(resolve));
  }
  await mongoose.disconnect();
  if (mongod) {
    await mongod.stop();
  }
});
