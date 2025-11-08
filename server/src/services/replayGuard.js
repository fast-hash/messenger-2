import crypto from 'node:crypto';

import { createClient } from 'redis';

import config from '../config.js';

let redisClient;
let connectPromise;
const fallbackReplayStore = new Map();
const FALLBACK_MAX_ENTRIES = Math.max(Number.parseInt(process.env.REPLAY_FALLBACK_CAP || '2000', 10) || 2000, 100);

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

export function __resetReplayFallback() {
  fallbackReplayStore.clear();
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
  let client;
  try {
    client = await resolveClient();
  } catch (err) {
    console.error('[replayGuard]', 'redis connection failed, falling back to memory store');
    client = undefined;
  }
  const digest = sha256Base64Str(encryptedPayload);
  const key = `replay:${chatId}:${digest}`;
  if (client) {
    try {
      const result = await client.set(key, '1', { NX: true, EX: ttlSeconds });
      const ok = result === 'OK';
      return { ok, key };
    } catch (err) {
      console.error('[replayGuard]', 'redis set failed, falling back to memory store', err?.message);
    }
  }

  const now = Date.now();
  const expiresAt = now + ttlSeconds * 1000;
  const existing = fallbackReplayStore.get(key);
  if (existing && existing > now) {
    return { ok: false, key };
  }
  fallbackReplayStore.set(key, expiresAt);
  if (fallbackReplayStore.size > FALLBACK_MAX_ENTRIES) {
    for (const [entryKey, expiry] of fallbackReplayStore) {
      if (expiry <= now) {
        fallbackReplayStore.delete(entryKey);
      }
    }
  }
  return { ok: true, key };
}

export async function getRedisClient() {
  return resolveClient();
}
