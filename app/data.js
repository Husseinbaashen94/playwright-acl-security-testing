/**
 * In-memory seed data for TeamNotes, the system under test.
 * Two tenants (organisations), four roles, public and private notes.
 * Demo-only passwords: this app exists purely as a test target.
 */
const PASSWORD = 'Passw0rd!';

const orgs = [
  { id: 'acme', name: 'Acme Corp' },
  { id: 'globex', name: 'Globex Inc' },
];

const users = [
  { id: 1, username: 'alice', displayName: 'Alice Admin', role: 'admin', orgId: 'acme' },
  { id: 2, username: 'bob', displayName: 'Bob Manager', role: 'manager', orgId: 'acme' },
  { id: 3, username: 'carol', displayName: 'Carol Member', role: 'member', orgId: 'acme' },
  { id: 4, username: 'dave', displayName: 'Dave Member', role: 'member', orgId: 'acme' },
  { id: 5, username: 'erin', displayName: 'Erin Admin', role: 'admin', orgId: 'globex' },
  { id: 6, username: 'frank', displayName: 'Frank Member', role: 'member', orgId: 'acme' },
  { id: 7, username: 'lockme', displayName: 'Lockout Target', role: 'member', orgId: 'acme' },
].map((u) => ({ ...u, password: PASSWORD }));

let nextNoteId = 100;
const notes = [
  { id: 1, orgId: 'acme', ownerId: 3, title: 'Carol team note', body: 'Visible to Acme', private: false },
  { id: 2, orgId: 'acme', ownerId: 3, title: 'Carol private note', body: 'Only Carol and managers', private: true },
  { id: 3, orgId: 'acme', ownerId: 4, title: 'Dave team note', body: 'Visible to Acme', private: false },
  { id: 4, orgId: 'globex', ownerId: 5, title: 'Globex roadmap', body: 'Confidential to Globex', private: false },
];

const auditLog = [];

module.exports = {
  PASSWORD,
  orgs,
  users,
  notes,
  auditLog,
  newNoteId: () => nextNoteId++,
};
