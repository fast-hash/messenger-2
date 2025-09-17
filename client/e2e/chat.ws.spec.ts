import { expect, test } from '@playwright/test';

const B64_RE = /^[A-Za-z0-9+/=]+$/;

function parseSocketIoFrame(frame: unknown): [string, unknown] | null {
  if (typeof frame !== 'string') {
    return null;
  }
  if (!frame.startsWith('42')) {
    return null;
  }
  const payload = frame.slice(2);
  try {
    const decoded = JSON.parse(payload);
    if (Array.isArray(decoded) && decoded.length >= 1) {
      const [event, data] = decoded as [string, unknown];
      return [event, data];
    }
  } catch {
    return null;
  }
  return null;
}

test('Socket.IO frames contain ciphertext payloads only', async ({ browser }) => {
  const baseUrl = process.env.E2E_BASE_URL || 'http://localhost:3000';
  const apiUrl = process.env.E2E_API_URL || 'http://localhost:8080';

  const response = await fetch(`${apiUrl}/__test__/bootstrap`, { method: 'POST' });
  if (!response.ok) {
    throw new Error(`bootstrap failed: ${response.status}`);
  }
  const { chatId, tokenA, tokenB } = await response.json();

  const messageEvents: Array<Record<string, unknown>> = [];

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

  const pages = [pageA, pageB];

  for (const page of pages) {
    page.on('websocket', (ws) => {
      ws.on('framereceived', (frame) => {
        const parsed = parseSocketIoFrame(frame);
        if (!parsed) {
          return;
        }
        const [event, data] = parsed;
        if (event !== 'message' || typeof data !== 'object' || data === null) {
          return;
        }
        messageEvents.push(data as Record<string, unknown>);
      });
    });
  }

  await pageA.goto(`${baseUrl}/chat/${chatId}`);
  await pageB.goto(`${baseUrl}/chat/${chatId}`);

  const composer = pageA.getByTestId('composer');
  await composer.click();
  await composer.fill('Привет');
  await composer.press('Enter');

  await expect.poll(() => messageEvents.length, { timeout: 5000 }).toBeGreaterThan(0);

  for (const payload of messageEvents) {
    expect(Object.keys(payload).sort()).toEqual(
      ['chatId', 'createdAt', 'encryptedPayload', 'senderId'].sort()
    );

    const chatField = payload.chatId as unknown;
    expect(typeof chatField).toBe('string');
    expect(chatField).toBe(chatId);

    const senderField = payload.senderId as unknown;
    expect(typeof senderField).toBe('string');

    const createdField = payload.createdAt as unknown;
    expect(typeof createdField === 'string' || createdField instanceof Date).toBeTruthy();

    const encrypted = payload.encryptedPayload as unknown;
    expect(typeof encrypted).toBe('string');
    expect(B64_RE.test(encrypted as string)).toBeTruthy();
    expect((encrypted as string).includes('Привет')).toBeFalsy();
  }

  await ctxA.close();
  await ctxB.close();
});
