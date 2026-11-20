/**
 * The UI must match the access rules: hide what a role can't use,
 * and still block it when someone types the URL directly.
 */
import { test, expect, accounts } from '../../fixtures/test';

const navByRole = [
  { role: 'member', username: accounts.member, team: false, admin: false },
  { role: 'manager', username: accounts.manager, team: true, admin: false },
  { role: 'admin', username: accounts.admin, team: true, admin: true },
] as const;

test.describe('Role-based navigation', () => {
  for (const { role, username, team, admin } of navByRole) {
    test(`${role} sees only the menu items they may use`, async ({ page, loginPage }) => {
      await loginPage(page, username);
      await page.goto('/notes');

      await expect(page.getByTestId('current-user')).toContainText(`(${role})`);
      await expect(page.getByTestId('nav-notes')).toBeVisible();
      await expect(page.getByTestId('nav-team')).toHaveCount(team ? 1 : 0);
      await expect(page.getByTestId('nav-admin')).toHaveCount(admin ? 1 : 0);
    });
  }

  const forcedBrowsing = [
    { role: 'member', username: accounts.member, path: '/admin' },
    { role: 'member', username: accounts.member, path: '/team' },
    { role: 'manager', username: accounts.manager, path: '/admin' },
  ] as const;

  for (const { role, username, path } of forcedBrowsing) {
    test(`${role} typing ${path} directly gets 403`, async ({ page, loginPage }) => {
      await loginPage(page, username);
      const response = await page.goto(path);
      expect(response?.status()).toBe(403);
      await expect(page.getByTestId('forbidden')).toBeVisible();
      await expect(page.getByTestId('admin-heading')).toHaveCount(0);
    });
  }

  test('anonymous visitors are sent to the login page', async ({ page }) => {
    for (const path of ['/notes', '/team', '/admin']) {
      await page.goto(path);
      await expect(page, path).toHaveURL(/\/login$/);
    }
  });

  test('login form shows a generic error and logs in on valid credentials', async ({ page }) => {
    await page.goto('/login');
    await page.getByLabel('Username').fill(accounts.otherMember);
    await page.getByLabel('Password').fill('wrong');
    await page.getByRole('button', { name: 'Log in' }).click();
    await expect(page.getByTestId('login-error')).toHaveText('Invalid username or password');

    await page.getByLabel('Password').fill('Passw0rd!');
    await page.getByRole('button', { name: 'Log in' }).click();
    await expect(page).toHaveURL(/\/notes$/);
  });

  test('logging out ends the session for every page', async ({ page, loginPage }) => {
    await loginPage(page, accounts.member);
    await page.goto('/notes');
    await page.getByTestId('logout').click();
    await expect(page).toHaveURL(/\/login$/);

    await page.goto('/notes');
    await expect(page).toHaveURL(/\/login$/);
  });

  test('a member sees no private notes owned by others in the UI', async ({ page, loginPage, loginAs }) => {
    const owner = await loginAs(accounts.otherMember);
    const secretTitle = `Dave secret ${Date.now()}`;
    await owner.createNote({ title: secretTitle, private: true });

    await loginPage(page, accounts.member);
    await page.goto('/notes');
    await expect(page.getByTestId('note-title').first()).toBeVisible();
    await expect(page.getByText(secretTitle)).toHaveCount(0);
  });
});
