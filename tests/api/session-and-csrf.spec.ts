/**
 * Authentication, session management and CSRF protection.
 */
import { test, expect, accounts, PASSWORD } from '../../fixtures/test';

const sidFrom = (setCookie: string | undefined) => setCookie?.match(/sid=([^;]+)/)?.[1];

test.describe('Authentication', () => {
  test('failed logins give the same answer for unknown users and wrong passwords', async ({ anonymous }) => {
    const unknownUser = await anonymous.post('/api/login', { username: 'no-such-user', password: PASSWORD });
    const wrongPassword = await anonymous.post('/api/login', { username: accounts.otherMember, password: 'wrong' });

    expect(unknownUser.status()).toBe(401);
    expect(wrongPassword.status()).toBe(401);
    expect(await unknownUser.json()).toEqual(await wrongPassword.json());
  });

  test('an account is locked after 5 failed attempts, even with the right password', async ({ anonymous }) => {
    for (let attempt = 1; attempt <= 5; attempt++) {
      const response = await anonymous.post('/api/login', { username: accounts.lockoutTarget, password: `guess-${attempt}` });
      expect(response.status()).toBe(401);
    }
    const correct = await anonymous.post('/api/login', { username: accounts.lockoutTarget, password: PASSWORD });
    expect(correct.status()).toBe(429);
  });

  test('malformed credentials are rejected cleanly', async ({ anonymous }) => {
    for (const body of [{}, { username: ['alice'], password: PASSWORD }, { username: 'alice', password: { $ne: '' } }]) {
      expect((await anonymous.post('/api/login', body)).status(), JSON.stringify(body)).toBe(400);
    }
  });
});

test.describe('Session cookie', () => {
  test('is HttpOnly and SameSite=Strict', async ({ anonymous }) => {
    const response = await anonymous.post('/api/login', { username: accounts.member, password: PASSWORD });
    const cookie = response.headers()['set-cookie'] ?? '';
    expect(cookie).toMatch(/sid=/);
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=Strict/i);
  });

  test('is rotated on login (session fixation)', async ({ anonymous }) => {
    const first = await anonymous.post('/api/login', { username: accounts.member, password: PASSWORD });
    const firstSid = sidFrom(first.headers()['set-cookie']);

    // Log in again from the same client, which still holds the first cookie.
    const second = await anonymous.post('/api/login', { username: accounts.otherMember, password: PASSWORD });
    const secondSid = sidFrom(second.headers()['set-cookie']);

    expect(firstSid).toBeTruthy();
    expect(secondSid).toBeTruthy();
    expect(secondSid).not.toBe(firstSid);
  });

  test('is invalidated on the server at logout, not just deleted in the browser', async ({ loginAs, playwright, baseURL }) => {
    const session = await loginAs(accounts.member);
    const { cookies } = await session.request.storageState();
    const stolenSid = cookies.find((c) => c.name === 'sid')!.value;

    expect((await session.post('/api/logout')).status()).toBe(204);

    // Replay the old cookie from a different client, as an attacker who captured it would.
    const attacker = await playwright.request.newContext({ baseURL, extraHTTPHeaders: { Cookie: `sid=${stolenSid}` } });
    expect((await attacker.get('/api/me')).status()).toBe(401);
    await attacker.dispose();
  });
});

test.describe('CSRF protection', () => {
  test('state-changing requests without a CSRF token are rejected', async ({ loginAs }) => {
    const session = await loginAs(accounts.member);
    const response = await session.request.post('/api/notes', { data: { title: 'CSRF attempt' } });
    expect(response.status()).toBe(403);
  });

  test("a CSRF token from another user's session is rejected", async ({ loginAs }) => {
    const victim = await loginAs(accounts.member);
    const attacker = await loginAs(accounts.otherMember);
    const response = await victim.request.post('/api/notes', {
      data: { title: 'CSRF attempt' },
      headers: { 'X-CSRF-Token': attacker.csrfToken! },
    });
    expect(response.status()).toBe(403);
  });

  test('the same request with the right token succeeds (control)', async ({ loginAs }) => {
    const session = await loginAs(accounts.member);
    expect((await session.post('/api/notes', { title: 'Legit' })).status()).toBe(201);
  });
});
