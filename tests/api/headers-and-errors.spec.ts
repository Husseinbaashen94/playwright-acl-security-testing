/**
 * Security headers and error handling (OWASP Secure Headers / information disclosure).
 */
import { test, expect, accounts } from '../../fixtures/test';

const requiredHeaders: Record<string, RegExp> = {
  'content-security-policy': /default-src 'self'.*script-src 'self'.*frame-ancestors 'none'/,
  'x-frame-options': /^DENY$/i,
  'x-content-type-options': /^nosniff$/i,
  'referrer-policy': /^no-referrer$/i,
  'cross-origin-opener-policy': /^same-origin$/i,
};

test.describe('Security headers', () => {
  for (const path of ['/login', '/api/notes']) {
    test(`${path} sends the required security headers`, async ({ anonymous }) => {
      const headers = (await anonymous.get(path)).headers();
      for (const [name, pattern] of Object.entries(requiredHeaders)) {
        expect(headers[name], name).toMatch(pattern);
      }
    });
  }

  test('the server does not advertise its framework', async ({ anonymous }) => {
    const headers = (await anonymous.get('/login')).headers();
    expect(headers['x-powered-by']).toBeUndefined();
  });

  test('CSP does not allow inline scripts or eval', async ({ anonymous }) => {
    const csp = (await anonymous.get('/login')).headers()['content-security-policy'] ?? '';
    expect(csp, 'CSP header present').toContain('script-src');
    expect(csp).not.toContain("'unsafe-inline'");
    expect(csp).not.toContain("'unsafe-eval'");
  });

  test('authenticated responses are not cached', async ({ loginAs }) => {
    const session = await loginAs(accounts.member);
    expect((await session.get('/api/notes')).headers()['cache-control']).toBe('no-store');
  });
});

test.describe('Error handling', () => {
  test('malformed JSON returns a generic error with no stack trace', async ({ loginAs }) => {
    const session = await loginAs(accounts.member);
    const response = await session.request.post('/api/notes', {
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrfToken! },
      data: '{"title": "unterminated',
    });
    const body = await response.text();
    expect(response.status()).toBe(400);
    expect(body).not.toMatch(/at .+\(.+:\d+:\d+\)|node_modules|SyntaxError/);
  });

  test('oversized payloads are refused', async ({ loginAs }) => {
    const session = await loginAs(accounts.member);
    const response = await session.post('/api/notes', { title: 'x', body: 'A'.repeat(50_000) });
    expect(response.status()).toBe(413);
  });

  test('unknown routes return a plain 404', async ({ anonymous }) => {
    const response = await anonymous.get('/api/../../etc/passwd');
    expect(response.status()).toBe(404);
    expect(await response.text()).not.toContain('root:');
  });
});
