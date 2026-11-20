# ACL & Security Testing with Playwright

![ACL & Security Tests](https://github.com/Husseinbaashen94/playwright-acl-security-testing/actions/workflows/ci.yml/badge.svg)
![Playwright](https://img.shields.io/badge/Playwright-TypeScript-2EAD33?logo=playwright)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010%20focused-000000?logo=owasp)

Access-control and application-security test suite written with **Playwright + TypeScript**. It runs against **TeamNotes**, a small multi-tenant notes app that ships with this repo, so every test runs on a system I'm authorised to attack.

**85 tests** cover role-based access control, tenant isolation, IDOR, privilege escalation, session management, CSRF, security headers, information disclosure and stored XSS, through both the **API** and the **browser**.

## Proving the tests work

A security suite that always passes proves nothing. TeamNotes has a `VULNERABLE=1` mode that switches on **18 real flaws**, and CI runs the suite against it to confirm **every one is caught**:

```
$ npm run verify:detection

Vulnerable-mode run: 50 failing tests

✔ caught  IDOR: member reads a private note (1 test)
✔ caught  Cross-tenant read (1 test)
✔ caught  Mass assignment of role (1 test)
✔ caught  Session fixation (1 test)
✔ caught  Missing CSRF protection (1 test)
✔ caught  Stored XSS (5 tests)
✔ caught  Forced browsing to admin page (2 tests)
  … 18 of 18
All 18 planted vulnerabilities were detected.
```

CI has two jobs: **the suite passes against the secure app**, and **the suite fails against the vulnerable app in all 18 expected places**.

> 🐞 **A real bug found along the way.** While writing this suite, the role-validation test found a genuine privilege escalation in the app: sending `{"role": ["admin"]}` (an array) passed `Object.hasOwn()` through string coercion and made the user an admin. It was fixed with a type check, and the test stays as a regression guard.

## The system under test

| User | Role | Tenant |
|------|------|--------|
| alice | admin | Acme |
| bob | manager | Acme |
| carol, dave, frank | member | Acme |
| erin | admin | Globex |

Notes can be **team** (visible to the tenant) or **private** (owner + managers/admins). Managers can edit others' notes but only admins can delete them.

## What's covered

### Access-control matrix: `tests/api/acl-matrix.spec.ts`
The access rules are written as a table: **9 capabilities × 5 roles**. A test is generated for every cell, so a missing check fails as one clearly named test, e.g. `delete another user's note › manager → 403`.

| Capability | anonymous | member | manager | admin | other-tenant admin |
|---|---|---|---|---|---|
| read another user's private note | 401 | **403** | 200 | 200 | **404** |
| edit another user's note | 401 | **403** | 200 | 200 | **404** |
| delete another user's note | 401 | **403** | **403** | 204 | **404** |
| change a user's role | 401 | **403** | **403** | 200 | **404** |
| read the audit log | 401 | **403** | **403** | 200 | – |
| *…and 4 more* | | | | | |

### Horizontal access & IDOR: `tenant-isolation.spec.ts`
- Lists, directories and audit logs never cross tenants
- Another tenant's resource returns the **same 404 as a missing one** (no existence oracle)
- **IDOR sweep:** walks the id space the way an attacker would and fails if any private note leaks

### Vertical access: `privilege-escalation.spec.ts`
- **Mass assignment:** `PATCH /api/me {"role":"admin"}` is ignored
- Managers can't promote anyone, admins can't change their own role or another tenant's users
- Role values are type-checked (the bug above)
- Permission changes apply on the **next request**, not the next login

### Sessions, auth & CSRF: `session-and-csrf.spec.ts`
- Same error for unknown user vs wrong password (no **user enumeration**)
- **Lockout** after 5 failures, even when the 6th attempt uses the right password
- NoSQL-style payloads (`{"$ne": ""}`) are rejected
- Cookie is `HttpOnly` + `SameSite=Strict` and **rotated on login** (session fixation)
- Logout **invalidates the session server-side**, so a replayed stolen cookie gets `401`
- Writes without a CSRF token, or with **another user's token**, get `403`

### Headers & disclosure: `headers-and-errors.spec.ts`
CSP (no `unsafe-inline` / `unsafe-eval`), `X-Frame-Options`, `nosniff`, `Referrer-Policy`, COOP, `no-store` on authenticated data, no `X-Powered-By`, no stack traces, payload size limits.

### Browser tests: `tests/ui/`
- **RBAC navigation:** each role sees only its menu items, and **forced browsing** to `/admin` or `/team` gets a 403 page
- **Stored XSS:** 5 payloads (script tag, `onerror`, `onload`, `javascript:` iframe/link) saved by one user and viewed by another. The test checks the text renders literally, no injected element exists, no script ran and no dialog fired
- **CSP enforcement:** an inline script injected into the live DOM is blocked, and the CSP violation is observed

## Design decisions

- **Specification as data.** The ACL matrix is the single source of truth for who can do what.
- **Session fixture.** `loginAs('carol')` returns a client that carries the cookie and sends the CSRF header automatically, while `anonymous` has neither.
- **Each test sets up its own data.** Notes are created per test by the owner, so tests don't depend on each other.
- **Dedicated accounts for destructive checks.** Lockout and role-change tests use their own users, so they can't break other tests.
- **Tests of the tests.** `verify-detection.mjs` maps each planted flaw to the tests that must catch it.

## Getting started

### 1. Prerequisites

| Tool | Version | Check | Install |
|------|---------|-------|---------|
| Node.js | 20.12 or newer (22 LTS recommended) | `node -v` | [nodejs.org](https://nodejs.org/) |
| Git | any recent | `git --version` | [git-scm.com](https://git-scm.com/downloads) |

Nothing else is needed: the app under test (TeamNotes) ships in this repo and starts automatically.

### 2. Clone and install

```bash
git clone https://github.com/Husseinbaashen94/playwright-acl-security-testing.git
cd playwright-acl-security-testing
npm install
npx playwright install --with-deps chromium
```

### 3. Configure (optional)

Everything works out of the box. To change a setting, copy the template and fill in only what you need:

```bash
cp .env.example .env
```

| Variable | Purpose and default |
|----------|---------------------|
| `PORT` | Port for the bundled TeamNotes app. Default `3210` |
| `VULNERABLE` | `1` starts the app with its 18 planted vulnerabilities. Default: empty, which means secure |

Empty values use the default. `.env` is git-ignored, so nothing you put in it is ever committed.

### 4. Run the tests

```bash
npm test                    # starts TeamNotes, runs all 85 tests, stops it
npm run verify:detection    # runs against the vulnerable build and checks all 18 flaws are caught
npx playwright test --project=api   # API tests only
npx playwright test --project=ui    # browser tests only
npm run typecheck
```

To explore the app by hand, run `npm start` and open http://localhost:3210. Log in as `alice` (admin), `bob` (manager) or `carol` (member) with password `Passw0rd!`. Use `npm run start:vulnerable` for the flawed build.

### 5. View the report

Run `npm run report` to open the HTML report. Failed tests keep a full trace.

### Troubleshooting

| Problem | Fix |
|---------|-----|
| `Port 3210 is already in use` | Stop the other process, or set `PORT` in `.env` |
| `Executable doesn't exist` | Run `npx playwright install --with-deps chromium` |
| Many tests fail unexpectedly | Check `.env` doesn't set `VULNERABLE=1` |

## Project structure

```
app/                          # TeamNotes, the system under test (Express)
├── server.js                 # routes, access control, VULNERABLE switches
├── data.js                   # seeded tenants, users, notes
└── public/                   # client JS/CSS (external files, so CSP can forbid inline)
fixtures/test.ts              # loginAs / anonymous / loginPage fixtures
tests/api/                    # acl-matrix, tenant-isolation, privilege-escalation, session-and-csrf, headers-and-errors
tests/ui/                     # rbac-navigation, xss
scripts/verify-detection.mjs  # runs the suite in vulnerable mode and checks every flaw is caught
```

> ⚠️ Only run security tests against systems you own or are authorised to test. This suite targets its own bundled app for exactly that reason.
