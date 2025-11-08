'use strict';

module.exports = { seedIfNeeded, genCipher };

const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function randomB64(length = 256) {
  let result = '';
  for (let i = 0; i < length; i += 1) {
    const index = Math.floor(Math.random() * chars.length);
    result += chars[index];
  }
  return result;
}

async function seedIfNeeded(ctx, events, done) {
  if (process.env.VERIFY_MODE === '1') {
    try {
      await fetch('http://127.0.0.1:3000/__test__/bootstrap');
    } catch (err) {
      console.warn('failed to prime bootstrap endpoint', err);
    }
  }
  ctx.vars.chatId = process.env.ART_CHAT_ID || 'chat-1';
  return done();
}

function genCipher(ctx, events, done) {
  ctx.vars.b64 = randomB64(512);
  return done();
}
