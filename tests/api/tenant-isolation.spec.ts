/**
 * Horizontal access control: one tenant (organisation) must never see or touch another's data,
 * even with the highest role, and must not be able to tell whether another tenant's ids exist.
 */
import { test, expect, accounts } from '../../fixtures/test';

test.describe('Tenant isolation', () => {
  test("note lists never include another tenant's notes", async ({ loginAs }) => {
    const acmeMember = await loginAs(accounts.member);
    const globexAdmin = await loginAs(accounts.foreignAdmin);

    const acmeNotes: { orgId: string }[] = (await (await acmeMember.get('/api/notes')).json()).notes;
    const globexNotes: { orgId: string }[] = (await (await globexAdmin.get('/api/notes')).json()).notes;

    expect(acmeNotes.length).toBeGreaterThan(0);
    expect(acmeNotes.every((n) => n.orgId === 'acme')).toBe(true);
    expect(globexNotes.every((n) => n.orgId === 'globex')).toBe(true);
  });

  test('user directory only lists your own organisation', async ({ loginAs }) => {
    const acmeAdmin = await loginAs(accounts.admin);
    const users: { orgId: string }[] = (await (await acmeAdmin.get('/api/users')).json()).users;
    expect(users.length).toBeGreaterThan(1);
    expect(new Set(users.map((u) => u.orgId))).toEqual(new Set(['acme']));
  });

  test("another tenant's note is indistinguishable from a missing one (no existence oracle)", async ({ loginAs }) => {
    const acme = await loginAs(accounts.member);
    const globexAdmin = await loginAs(accounts.foreignAdmin);
    const acmeNoteId = await acme.createNote({ title: 'Acme secret' });

    const crossTenant = await globexAdmin.get(`/api/notes/${acmeNoteId}`);
    const missing = await globexAdmin.get('/api/notes/987654321');

    expect(crossTenant.status()).toBe(404);
    expect(crossTenant.status()).toBe(missing.status());
    expect(await crossTenant.json()).toEqual(await missing.json());
  });

  test("audit log only shows your own tenant's activity", async ({ loginAs }) => {
    const acme = await loginAs(accounts.member);
    await acme.createNote({ title: 'Audit me' });

    const globexAdmin = await loginAs(accounts.foreignAdmin);
    const entries: { orgId: string }[] = (await (await globexAdmin.get('/api/admin/audit-log')).json()).entries;
    expect(entries.every((e) => e.orgId === 'globex')).toBe(true);
  });

  test('IDOR sweep: a member cannot read any private note they do not own', async ({ loginAs }) => {
    const owner = await loginAs(accounts.otherMember);
    const attacker = await loginAs(accounts.member);
    const privateIds = [
      await owner.createNote({ private: true }),
      await owner.createNote({ private: true }),
      await owner.createNote({ private: true }),
    ];

    // Walk the id space around the real ids, the way an attacker enumerating ids would.
    const minId = Math.min(...privateIds) - 3;
    const maxId = Math.max(...privateIds) + 3;
    const leaked: number[] = [];
    for (let id = minId; id <= maxId; id++) {
      const response = await attacker.get(`/api/notes/${id}`);
      if (response.status() === 200) {
        const { note } = await response.json();
        if (note.private && note.ownerId !== 3) leaked.push(id);
      }
    }
    expect(leaked, 'private notes readable by a non-owner').toEqual([]);

    // And the list endpoint mustn't leak them either.
    const listed: { id: number }[] = (await (await attacker.get('/api/notes')).json()).notes;
    const listedIds = new Set(listed.map((n) => n.id));
    expect(privateIds.filter((id) => listedIds.has(id)), 'private notes in list').toEqual([]);
  });
});
