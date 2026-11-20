/**
 * Mutation-style check of the test suite itself.
 *
 * Runs the suite against TeamNotes in VULNERABLE mode and asserts that every planted
 * vulnerability is caught by at least one failing test. If a vulnerability slips through,
 * the suite has a blind spot and this script exits non-zero.
 *
 *   npm run verify:detection
 */
import { spawnSync } from 'node:child_process';

const planted = [
  { vulnerability: 'IDOR: member reads a private note', mustFail: /read another user's private note › member → 403/ },
  { vulnerability: 'Cross-tenant read', mustFail: /read another user's team note › foreignAdmin → 404/ },
  { vulnerability: 'Missing role check on user directory', mustFail: /list team members › member → 403/ },
  { vulnerability: 'Missing role check on role changes', mustFail: /change a user's role › manager → 403/ },
  { vulnerability: 'Manager can delete others\' notes', mustFail: /delete another user's note › manager → 403/ },
  { vulnerability: 'Tenant data leak in lists', mustFail: /never include another tenant's notes/ },
  { vulnerability: 'Existence oracle for other tenants', mustFail: /indistinguishable from a missing one/ },
  { vulnerability: 'Mass assignment of role', mustFail: /mass assignment/ },
  { vulnerability: 'No brute-force lockout', mustFail: /locked after 5 failed attempts/ },
  { vulnerability: 'Session cookie readable by JS', mustFail: /HttpOnly and SameSite=Strict/ },
  { vulnerability: 'Session fixation', mustFail: /rotated on login/ },
  { vulnerability: 'Session survives logout', mustFail: /invalidated on the server at logout/ },
  { vulnerability: 'Missing CSRF protection', mustFail: /without a CSRF token are rejected/ },
  { vulnerability: 'Missing security headers', mustFail: /sends the required security headers/ },
  { vulnerability: 'Framework disclosure', mustFail: /does not advertise its framework/ },
  { vulnerability: 'Stack trace disclosure', mustFail: /no stack trace/ },
  { vulnerability: 'Stored XSS', mustFail: /Stored XSS › renders as text/ },
  { vulnerability: 'Forced browsing to admin page', mustFail: /typing \/admin directly gets 403/ },
];

const run = spawnSync('npx', ['playwright', 'test', '--reporter=json'], {
  env: { ...process.env, VULNERABLE: '1' },
  encoding: 'utf8',
  maxBuffer: 64 * 1024 * 1024,
});

const report = JSON.parse(run.stdout);
const failedTitles = [];
(function walk(suite, path) {
  for (const spec of suite.specs ?? []) {
    const status = spec.tests.at(-1)?.results.at(-1)?.status;
    if (status && status !== 'passed' && status !== 'skipped') failedTitles.push(`${path} › ${spec.title}`);
  }
  for (const child of suite.suites ?? []) walk(child, `${path} › ${child.title}`);
})({ suites: report.suites }, '');

let missed = 0;
console.log(`\nVulnerable-mode run: ${failedTitles.length} failing tests\n`);
for (const { vulnerability, mustFail } of planted) {
  const caught = failedTitles.filter((t) => mustFail.test(t));
  console.log(`${caught.length ? '✔ caught ' : '✘ MISSED '} ${vulnerability}${caught.length ? ` (${caught.length} test${caught.length > 1 ? 's' : ''})` : ''}`);
  if (!caught.length) missed++;
}

if (missed) {
  console.error(`\n${missed} planted vulnerabilit${missed > 1 ? 'ies were' : 'y was'} not detected.`);
  process.exit(1);
}
console.log(`\nAll ${planted.length} planted vulnerabilities were detected.`);
