/**
 * Role-based access control matrix.
 *
 * Every row is one capability, every column a role, every cell the exact HTTP status expected.
 * The matrix is the specification: reviewing access rules means reviewing this table.
 * A test is generated for every cell, so a single missing check shows up as a single named failure.
 */
import { test, expect, accounts, userIds, type Session } from '../../fixtures/test';

type Role = 'anonymous' | 'member' | 'manager' | 'admin' | 'foreignAdmin';

interface Capability {
  name: string;
  /** Prepares data (as the note owner) and returns the request to make as the role under test. */
  run: (actor: Session, owner: Session) => Promise<number>;
  expected: Partial<Record<Role, number>>;
}

const capabilities: Capability[] = [
  {
    name: 'list notes',
    run: async (actor) => (await actor.get('/api/notes')).status(),
    expected: { anonymous: 401, member: 200, manager: 200, admin: 200 },
  },
  {
    name: "read another user's team note",
    run: async (actor, owner) => {
      const id = await owner.createNote({ private: false });
      return (await actor.get(`/api/notes/${id}`)).status();
    },
    expected: { anonymous: 401, member: 200, manager: 200, admin: 200, foreignAdmin: 404 },
  },
  {
    name: "read another user's private note",
    run: async (actor, owner) => {
      const id = await owner.createNote({ private: true });
      return (await actor.get(`/api/notes/${id}`)).status();
    },
    expected: { anonymous: 401, member: 403, manager: 200, admin: 200, foreignAdmin: 404 },
  },
  {
    name: 'create a note',
    run: async (actor) => (await actor.post('/api/notes', { title: 'ACL check' })).status(),
    expected: { anonymous: 401, member: 201, manager: 201, admin: 201 },
  },
  {
    name: "edit another user's note",
    run: async (actor, owner) => {
      const id = await owner.createNote();
      return (await actor.patch(`/api/notes/${id}`, { title: 'Edited' })).status();
    },
    expected: { anonymous: 401, member: 403, manager: 200, admin: 200, foreignAdmin: 404 },
  },
  {
    name: "delete another user's note",
    run: async (actor, owner) => {
      const id = await owner.createNote();
      return (await actor.delete(`/api/notes/${id}`)).status();
    },
    expected: { anonymous: 401, member: 403, manager: 403, admin: 204, foreignAdmin: 404 },
  },
  {
    name: 'list team members',
    run: async (actor) => (await actor.get('/api/users')).status(),
    expected: { anonymous: 401, member: 403, manager: 200, admin: 200 },
  },
  {
    name: "change a user's role",
    // Sets frank to the role he already has, so a successful call changes nothing.
    run: async (actor) => (await actor.patch(`/api/users/${userIds.frank}/role`, { role: 'member' })).status(),
    expected: { anonymous: 401, member: 403, manager: 403, admin: 200, foreignAdmin: 404 },
  },
  {
    name: 'read the audit log',
    run: async (actor) => (await actor.get('/api/admin/audit-log')).status(),
    expected: { anonymous: 401, member: 403, manager: 403, admin: 200 },
  },
];

const roleUser: Record<Exclude<Role, 'anonymous'>, string> = {
  member: accounts.member,
  manager: accounts.manager,
  admin: accounts.admin,
  foreignAdmin: accounts.foreignAdmin,
};

test.describe('Access-control matrix', () => {
  for (const capability of capabilities) {
    test.describe(capability.name, () => {
      for (const [role, status] of Object.entries(capability.expected) as [Role, number][]) {
        test(`${role} → ${status}`, async ({ loginAs, anonymous }) => {
          const owner = await loginAs(accounts.otherMember);
          const actor = role === 'anonymous' ? anonymous : await loginAs(roleUser[role]);
          expect(await capability.run(actor, owner)).toBe(status);
        });
      }
    });
  }
});
