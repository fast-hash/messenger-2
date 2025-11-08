import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  ensureNotReplayed,
  setRedisClient,
  __resetReplayFallback,
} from '../src/services/replayGuard.js';

test('fallback store rejects duplicate payloads when redis set fails', async () => {
  __resetReplayFallback();
  setRedisClient({
    async set() {
      throw new Error('redis down');
    },
  });

  try {
    const first = await ensureNotReplayed('chat1', 'payload-1', 1);
    assert.equal(first.ok, true);

    const second = await ensureNotReplayed('chat1', 'payload-1', 1);
    assert.equal(second.ok, false);
  } finally {
    setRedisClient(undefined);
    __resetReplayFallback();
  }
});

test('fallback store expires entries after ttl', async () => {
  __resetReplayFallback();
  setRedisClient({
    async set() {
      throw new Error('redis down');
    },
  });

  try {
    const ttlSeconds = 0.001; // roughly one millisecond
    const first = await ensureNotReplayed('chat2', 'payload-2', ttlSeconds);
    assert.equal(first.ok, true);

    await new Promise((resolve) => setTimeout(resolve, 5));

    const second = await ensureNotReplayed('chat2', 'payload-2', ttlSeconds);
    assert.equal(second.ok, true);
  } finally {
    setRedisClient(undefined);
    __resetReplayFallback();
  }
});
