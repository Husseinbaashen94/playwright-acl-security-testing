/**
 * Vertical access control: users must not be able to raise their own privileges,
 * directly or through side doors such as mass assignment.
 */
import { test, expect, accounts, userIds } from '../../fixtures/test';

test.describe('Privilege escalation', () => {
  test('mass assignment: a member cannot make themselves admin via profile update', async ({ loginAs }) => {
    const member = await loginAs(accounts.member);

    await member.patch('/api/me', { displayName: 'Carol Member', role: 'admin', orgId: 'globex' });

    const { user } = await (await member.get('/api/me')).json();
    expect(user.role).toBe('member');
    expect(user.orgId).toBe('acme');
    expect((await member.get('/api/admin/audit-log')).status()).toBe(403);
  });

  test('a manager cannot promote themselves or anyone else', async ({ loginAs }) => {
    const manager = await loginAs(accounts.manager);
    expect((await manager.patch(`/api/users/${userIds.bob}/role`, { role: 'admin' })).status()).toBe(403);
    expect((await manager.patch(`/api/users/${userIds.frank}/role`, { role: 'manager' })).status()).toBe(403);
  });

  test('an admin cannot change their own role (prevents accidental lock-out of the last admin)', async ({ loginAs }) => {
    const admin = await loginAs(accounts.admin);
    expect((await admin.patch(`/api/users/${userIds.alice}/role`, { role: 'member' })).status()).toBe(400);
  });

  test("an admin cannot change roles in another tenant", async ({ loginAs }) => {
    const foreignAdmin = await loginAs(accounts.foreignAdmin);
    expect((await foreignAdmin.patch(`/api/users/${userIds.frank}/role`, { role: 'admin' })).status()).toBe(404);
  });

  test('role values are validated', async ({ loginAs }) => {
    const admin = await loginAs(accounts.admin);
    for (const role of ['superadmin', 'ADMIN', '', null, ['admin']]) {
      const response = await admin.patch(`/api/users/${userIds.frank}/role`, { role });
      expect(response.status(), `role=${JSON.stringify(role)}`).toBe(400);
    }
  });

  test('a role change takes effect immediately on the next request', async ({ loginAs }) => {
    const admin = await loginAs(accounts.admin);
    const frank = await loginAs(accounts.roleTarget);
    expect((await frank.get('/api/users')).status()).toBe(403);

    await admin.patch(`/api/users/${userIds.frank}/role`, { role: 'manager' });
    try {
      // Same session, no re-login: permissions must be evaluated per request, not cached in the session.
      expect((await frank.get('/api/users')).status()).toBe(200);
    } finally {
      await admin.patch(`/api/users/${userIds.frank}/role`, { role: 'member' });
    }
    expect((await frank.get('/api/users')).status()).toBe(403);
  });
});
