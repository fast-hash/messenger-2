import crypto from 'node:crypto';

import { createClient } from 'redis';

import config from '../config.js';

let redisClient;
let connectPromise;

export function sha256Base64Str(b64) {
  return crypto.createHash('sha256').update(b64, 'utf8').digest('hex');
}

export function setRedisClient(client) {
  redisClient = client || undefined;
  connectPromise = undefined;
}

export async function closeRedis() {
  const client = await resolveClient(false);
  if (client && typeof client.quit === 'function') {
    await client.quit();
  } else if (client && typeof client.disconnect === 'function') {
    await client.disconnect();
  }
  redisClient = undefined;
  connectPromise = undefined;
}

async function resolveClient(connectIfNeeded = true) {
  if (redisClient) {
    return redisClient;
  }
  if (!connectIfNeeded) {
    return undefined;
  }
  if (!connectPromise) {
    const defaultUrl = config.has('redis.uri') ? config.get('redis.uri') : 'redis://127.0.0.1:6379';
    const url = process.env.REDIS_URL || defaultUrl;
    const client = createClient({ url });
    client.on('error', (err) => {
      console.error('[redis]', err.message);
    });
    connectPromise = client
      .connect()
      .then(() => {
        redisClient = client;
        return redisClient;
      })
      .catch((err) => {
        connectPromise = undefined;
        throw err;
      });
  }
  return connectPromise;
}

export async function ensureNotReplayed(chatId, encryptedPayload, ttlSeconds = 600) {
  const client = await resolveClient();
  if (!client) {
    return { ok: true, key: null };
  }
  const digest = sha256Base64Str(encryptedPayload);
  const key = `replay:${chatId}:${digest}`;
  const result = await client.set(key, '1', { NX: true, EX: ttlSeconds });
  const ok = result === 'OK';
  return { ok, key };
}

export async function getRedisClient() {
  return resolveClient();
}
