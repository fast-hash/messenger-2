import { test, expect } from '@playwright/test';

const B64_RE = /^[A-Za-z0-9+/=]+$/;

test('A → B: сеть только base64; в UI у B — расшифрованный текст', async ({ browser }) => {
  const baseUrl = process.env.E2E_BASE_URL || 'http://localhost:3000';
  const apiUrl = process.env.E2E_API_URL || 'http://localhost:8080';
  const response = await fetch(`${apiUrl}/__test__/bootstrap`, { method: 'POST' });
  if (!response.ok) {
    throw new Error(`bootstrap failed: ${response.status}`);
  }
  const { chatId, tokenA, tokenB } = await response.json();

  const seenRequests: Array<Record<string, unknown>> = [];
  const wsFrames: string[] = [];

  const ctxA = await browser.newContext();
  const pageA = await ctxA.newPage();
  await pageA.addInitScript(
    ([token]) => {
      localStorage.setItem('authToken', token);
      localStorage.setItem('token', token);
    },
    [tokenA]
  );

  const ctxB = await browser.newContext();
  const pageB = await ctxB.newPage();
  await pageB.addInitScript(
    ([token]) => {
      localStorage.setItem('authToken', token);
      localStorage.setItem('token', token);
    },
    [tokenB]
  );

  for (const page of [pageA, pageB]) {
    page.on('request', (req) => {
      if (req.method() !== 'POST') return;
      const url = new URL(req.url());
      if (url.pathname !== '/api/messages') return;
      try {
        const parsed = req.postDataJSON();
        seenRequests.push(parsed);
      } catch {
        const raw = req.postData();
        if (raw) {
          seenRequests.push({ raw });
        }
      }
    });

    page.on('websocket', (ws) => {
      ws.on('framereceived', (data) => {
        if (typeof data === 'string') {
          wsFrames.push(data);
        }
      });
    });
  }

  await pageA.goto(`${baseUrl}/chat/${chatId}`);
  await pageB.goto(`${baseUrl}/chat/${chatId}`);

  const composerA = pageA.getByTestId('composer');
  await composerA.click();
  await composerA.fill('Привет');
  await composerA.press('Enter');

  const messagesB = pageB.getByTestId('messages');
  await expect(messagesB).toContainText('Привет');

  await expect.poll(() => seenRequests.length, { timeout: 5000 }).toBeGreaterThan(0);
  for (const body of seenRequests) {
    const keys = Object.keys(body).sort();
    expect(keys).toEqual(['chatId', 'encryptedPayload']);

    const chatField = body.chatId as unknown;
    expect(typeof chatField).toBe('string');
    expect(chatField).toBe(chatId);

    const encrypted = body.encryptedPayload as unknown;
    expect(typeof encrypted).toBe('string');
    expect(B64_RE.test(encrypted as string)).toBeTruthy();
  }

  expect(wsFrames.every((frame) => !frame.includes('Привет'))).toBeTruthy();

  await ctxA.close();
  await ctxB.close();
});
