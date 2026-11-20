/**
 * TeamNotes: a deliberately small multi-tenant app used as the system under test.
 *
 * Set VULNERABLE=1 to switch on real flaws (IDOR, missing role checks, mass assignment,
 * missing CSRF and headers, XSS, session fixation). CI runs the suite in that mode and
 * expects it to FAIL, which proves the tests detect the vulnerabilities they claim to.
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const db = require('./data');

// Optional local settings (PORT, VULNERABLE): copy .env.example to .env. Already-set variables win.
const envFile = path.join(__dirname, '..', '.env');
if (fs.existsSync(envFile)) process.loadEnvFile(envFile);

const VULNERABLE = process.env.VULNERABLE === '1';
const PORT = Number(process.env.PORT || 3210);
const MAX_FAILED_LOGINS = 5;

const app = express();
if (!VULNERABLE) app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));

// ---------- Security headers ----------
app.use((req, res, next) => {
  if (!VULNERABLE) {
    res.set({
      'Content-Security-Policy':
        "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      'Cache-Control': 'no-store',
    });
  }
  next();
});

app.use('/static', express.static(path.join(__dirname, 'public')));

// ---------- Sessions ----------
const sessions = new Map(); // sid -> { userId, csrfToken }
const failedLogins = new Map(); // username -> count

const newId = () => crypto.randomBytes(24).toString('hex');

function parseCookies(header = '') {
  return Object.fromEntries(
    header
      .split(';')
      .map((part) => part.trim().split('='))
      .filter(([k, v]) => k && v)
      .map(([k, v]) => [k, decodeURIComponent(v)]),
  );
}

app.use((req, res, next) => {
  const sid = parseCookies(req.headers.cookie).sid;
  const session = sid && sessions.get(sid);
  req.sid = session ? sid : undefined;
  req.session = session;
  req.user = session ? db.users.find((u) => u.id === session.userId) : undefined;
  next();
});

function setSessionCookie(res, sid) {
  res.cookie('sid', sid, { httpOnly: !VULNERABLE, sameSite: VULNERABLE ? 'lax' : 'strict', path: '/' });
}

// ---------- Access-control helpers ----------
const ROLE_RANK = { member: 1, manager: 2, admin: 3 };
const atLeast = (user, role) => !!user && ROLE_RANK[user.role] >= ROLE_RANK[role];

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Authentication required' });
  next();
}

const requireRole = (role) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'Authentication required' });
  if (!VULNERABLE && !atLeast(req.user, role)) return res.status(403).json({ error: 'Forbidden' });
  next();
};

/** State-changing requests must echo the session's CSRF token in a header. */
function requireCsrf(req, res, next) {
  if (VULNERABLE) return next();
  if (!req.session || req.get('X-CSRF-Token') !== req.session.csrfToken) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  next();
}

const publicUser = (u) => ({ id: u.id, username: u.username, displayName: u.displayName, role: u.role, orgId: u.orgId });

function canReadNote(user, note) {
  if (VULNERABLE) return true; // IDOR: any logged-in user can read any note
  if (note.orgId !== user.orgId) return false;
  return !note.private || note.ownerId === user.id || atLeast(user, 'manager');
}

function audit(req, action, detail) {
  db.auditLog.push({ at: new Date().toISOString(), by: req.user?.username, orgId: req.user?.orgId, action, detail });
}

// ---------- Auth API ----------
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'username and password are required' });
  }
  if (!VULNERABLE && (failedLogins.get(username) || 0) >= MAX_FAILED_LOGINS) {
    return res.status(429).json({ error: 'Account temporarily locked' });
  }
  const user = db.users.find((u) => u.username === username && u.password === password);
  if (!user) {
    failedLogins.set(username, (failedLogins.get(username) || 0) + 1);
    // Same message for unknown user and wrong password: no username enumeration.
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  failedLogins.delete(username);

  // Rotate the session id on login (prevents session fixation). Vulnerable mode reuses it.
  if (req.sid) sessions.delete(req.sid);
  const sid = VULNERABLE && req.sid ? req.sid : newId();
  const csrfToken = newId();
  sessions.set(sid, { userId: user.id, csrfToken });
  setSessionCookie(res, sid);
  res.json({ user: publicUser(user), csrfToken });
});

app.post('/api/logout', requireAuth, requireCsrf, (req, res) => {
  if (!VULNERABLE) sessions.delete(req.sid);
  res.clearCookie('sid', { path: '/' });
  res.status(204).end();
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user), csrfToken: req.session.csrfToken });
});

app.patch('/api/me', requireAuth, requireCsrf, (req, res) => {
  const { displayName } = req.body || {};
  if (VULNERABLE) {
    Object.assign(req.user, req.body); // mass assignment: lets a user set their own role
  } else if (typeof displayName === 'string' && displayName.trim()) {
    req.user.displayName = displayName.trim().slice(0, 60);
  } else {
    return res.status(400).json({ error: 'displayName is required' });
  }
  res.json({ user: publicUser(req.user) });
});

// ---------- Notes API ----------
app.get('/api/notes', requireAuth, (req, res) => {
  res.json({ notes: db.notes.filter((n) => canReadNote(req.user, n)) });
});

app.get('/api/notes/:id', requireAuth, (req, res) => {
  const note = db.notes.find((n) => n.id === Number(req.params.id));
  // Another tenant's note looks exactly like a missing one: don't confirm it exists.
  if (!note || (!VULNERABLE && note.orgId !== req.user.orgId)) return res.status(404).json({ error: 'Not found' });
  if (!canReadNote(req.user, note)) return res.status(403).json({ error: 'Forbidden' });
  res.json({ note });
});

app.post('/api/notes', requireRole('member'), requireCsrf, (req, res) => {
  const { title, body = '', private: isPrivate = false } = req.body || {};
  if (typeof title !== 'string' || !title.trim() || title.length > 200) {
    return res.status(400).json({ error: 'title is required (max 200 chars)' });
  }
  const note = {
    id: db.newNoteId(),
    orgId: req.user.orgId,
    ownerId: req.user.id,
    title: title.trim(),
    body: String(body).slice(0, 5000),
    private: Boolean(isPrivate),
  };
  db.notes.push(note);
  audit(req, 'note.create', note.id);
  res.status(201).json({ note });
});

app.patch('/api/notes/:id', requireAuth, requireCsrf, (req, res) => {
  const note = db.notes.find((n) => n.id === Number(req.params.id));
  if (!note || (!VULNERABLE && note.orgId !== req.user.orgId)) return res.status(404).json({ error: 'Not found' });
  const allowed = VULNERABLE || note.ownerId === req.user.id || atLeast(req.user, 'manager');
  if (!allowed) return res.status(403).json({ error: 'Forbidden' });
  const { title, body } = req.body || {};
  if (typeof title === 'string' && title.trim()) note.title = title.trim().slice(0, 200);
  if (typeof body === 'string') note.body = body.slice(0, 5000);
  audit(req, 'note.update', note.id);
  res.json({ note });
});

app.delete('/api/notes/:id', requireAuth, requireCsrf, (req, res) => {
  const index = db.notes.findIndex((n) => n.id === Number(req.params.id));
  const note = db.notes[index];
  if (!note || (!VULNERABLE && note.orgId !== req.user.orgId)) return res.status(404).json({ error: 'Not found' });
  // Owners and admins may delete; managers may edit others' notes but not delete them.
  const allowed = VULNERABLE || note.ownerId === req.user.id || req.user.role === 'admin';
  if (!allowed) return res.status(403).json({ error: 'Forbidden' });
  db.notes.splice(index, 1);
  audit(req, 'note.delete', note.id);
  res.status(204).end();
});

// ---------- User management API ----------
app.get('/api/users', requireRole('manager'), (req, res) => {
  const scope = VULNERABLE ? db.users : db.users.filter((u) => u.orgId === req.user.orgId);
  res.json({ users: scope.map(publicUser) });
});

app.patch('/api/users/:id/role', requireRole('admin'), requireCsrf, (req, res) => {
  const target = db.users.find((u) => u.id === Number(req.params.id));
  if (!target || (!VULNERABLE && target.orgId !== req.user.orgId)) return res.status(404).json({ error: 'Not found' });
  const { role } = req.body || {};
  // typeof check matters: ["admin"] would otherwise pass Object.hasOwn via string coercion (found by the test suite).
  if (typeof role !== 'string' || !Object.hasOwn(ROLE_RANK, role)) {
    return res.status(400).json({ error: 'role must be member, manager or admin' });
  }
  if (!VULNERABLE && target.id === req.user.id) return res.status(400).json({ error: 'Admins cannot change their own role' });
  target.role = role;
  audit(req, 'user.role', `${target.username} -> ${role}`);
  res.json({ user: publicUser(target) });
});

app.get('/api/admin/audit-log', requireRole('admin'), (req, res) => {
  res.json({ entries: db.auditLog.filter((e) => VULNERABLE || e.orgId === req.user.orgId) });
});

// ---------- HTML pages ----------
const escapeHtml = (value) =>
  VULNERABLE
    ? String(value)
    : String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function page(req, title, content) {
  const nav = req.user
    ? `<nav>
         <a href="/notes" data-testid="nav-notes">Notes</a>
         ${atLeast(req.user, 'manager') ? '<a href="/team" data-testid="nav-team">Team</a>' : ''}
         ${req.user.role === 'admin' ? '<a href="/admin" data-testid="nav-admin">Admin</a>' : ''}
         <span data-testid="current-user">${escapeHtml(req.user.displayName)} (${req.user.role})</span>
         <button type="button" id="logout" data-testid="logout">Log out</button>
       </nav>`
    : '';
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  ${req.session ? `<meta name="csrf-token" content="${req.session.csrfToken}">` : ''}
  <title>${escapeHtml(title)} · TeamNotes</title>
  <link rel="stylesheet" href="/static/app.css">
</head>
<body>
  <header><strong>TeamNotes</strong>${nav}</header>
  <main>${content}</main>
  <script src="/static/app.js"></script>
</body>
</html>`;
}

const forbiddenPage = (req) =>
  page(req, 'Forbidden', '<h1 data-testid="forbidden">403 · You do not have access to this page</h1>');

function requirePageRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.redirect('/login');
    if (!VULNERABLE && !atLeast(req.user, role)) return res.status(403).send(forbiddenPage(req));
    next();
  };
}

app.get('/', (req, res) => res.redirect(req.user ? '/notes' : '/login'));

app.get('/login', (req, res) => {
  res.send(
    page(
      req,
      'Log in',
      `<h1>Log in</h1>
       <form id="login-form">
         <label>Username <input name="username" autocomplete="username" required></label>
         <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
         <button type="submit">Log in</button>
         <p role="alert" data-testid="login-error"></p>
       </form>`,
    ),
  );
});

app.get('/notes', requirePageRole('member'), (req, res) => {
  const items = db.notes
    .filter((n) => canReadNote(req.user, n))
    .map(
      (n) => `<li data-testid="note" data-note-id="${n.id}">
                <h2 data-testid="note-title">${escapeHtml(n.title)}</h2>
                <p data-testid="note-body">${escapeHtml(n.body)}</p>
                ${n.private ? '<small>Private</small>' : ''}
              </li>`,
    )
    .join('');
  res.send(
    page(
      req,
      'Notes',
      `<h1>Notes</h1>
       <form id="note-form">
         <label>Title <input name="title" required maxlength="200"></label>
         <label>Body <textarea name="body"></textarea></label>
         <label><input type="checkbox" name="private"> Private</label>
         <button type="submit">Add note</button>
       </form>
       <ul data-testid="notes">${items}</ul>`,
    ),
  );
});

app.get('/team', requirePageRole('manager'), (req, res) => {
  const rows = db.users
    .filter((u) => VULNERABLE || u.orgId === req.user.orgId)
    .map((u) => `<tr data-testid="team-row"><td>${escapeHtml(u.displayName)}</td><td>${u.role}</td></tr>`)
    .join('');
  res.send(page(req, 'Team', `<h1>Team</h1><table><tbody>${rows}</tbody></table>`));
});

app.get('/admin', requirePageRole('admin'), (req, res) => {
  res.send(page(req, 'Admin', '<h1 data-testid="admin-heading">Administration</h1><p>Audit log and role management.</p>'));
});

// ---------- Errors ----------
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (VULNERABLE) return res.status(500).send(`<pre>${err.stack}</pre>`); // leaks internals
  const status = err.status || err.statusCode || 500;
  res.status(status).json({ error: status === 500 ? 'Internal server error' : 'Bad request' });
});

app.listen(PORT, () => {
  console.log(`TeamNotes listening on http://localhost:${PORT}${VULNERABLE ? '  ⚠  VULNERABLE MODE' : ''}`);
});
