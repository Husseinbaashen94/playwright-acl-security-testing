/**
 * Stored cross-site scripting: a payload saved by one user must render as inert text for another.
 * Each payload tries to set a flag on window; if any script runs, the flag (or a dialog) gives it away.
 */
import { test, expect, accounts } from '../../fixtures/test';

const payloads = [
  '<script>window.__xss = "script-tag"</script>',
  '<img src=x onerror="window.__xss=\'img-onerror\'">',
  '<svg onload="window.__xss=\'svg-onload\'"></svg>',
  '"><iframe src="javascript:window.top.__xss=\'iframe\'"></iframe>',
  '<a href="javascript:window.__xss=\'link\'">click</a>',
];

test.describe('Stored XSS', () => {
  for (const payload of payloads) {
    test(`renders as text: ${payload.slice(0, 40)}`, async ({ page, loginPage, loginAs }) => {
      const attacker = await loginAs(accounts.otherMember);
      const marker = `xss-${Date.now()}`;
      await attacker.createNote({ title: `${marker} ${payload}`, body: payload });

      const dialogs: string[] = [];
      page.on('dialog', async (dialog) => {
        dialogs.push(dialog.message());
        await dialog.dismiss();
      });

      await loginPage(page, accounts.member);
      await page.goto('/notes');

      const note = page.getByTestId('note').filter({ hasText: marker });
      await expect(note).toHaveCount(1);

      // The payload is shown literally...
      await expect(note.getByTestId('note-title')).toHaveText(`${marker} ${payload}`);
      await expect(note.getByTestId('note-body')).toHaveText(payload);
      // ...and no element it tried to inject exists in the DOM.
      await expect(note.locator('script, img, svg, iframe, a[href^="javascript"]')).toHaveCount(0);

      // Give any event-handler payload (onerror/onload) a moment to fire, then check nothing executed.
      await page.waitForTimeout(250);
      expect(await page.evaluate(() => (window as unknown as { __xss?: string }).__xss)).toBeUndefined();
      expect(dialogs).toEqual([]);
    });
  }

  test('CSP blocks inline script even if markup were injected', async ({ page, loginPage }) => {
    const violations: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error' && /Content Security Policy/i.test(msg.text())) violations.push(msg.text());
    });

    await loginPage(page, accounts.member);
    await page.goto('/notes');

    // Simulate a successful injection by adding an inline script to the live DOM.
    await page.evaluate(() => {
      const script = document.createElement('script');
      script.textContent = 'window.__xss = "inline"';
      document.body.appendChild(script);
    });

    expect(await page.evaluate(() => (window as unknown as { __xss?: string }).__xss)).toBeUndefined();
    expect(violations.length).toBeGreaterThan(0);
  });
});
