const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const LIMIT_BYTES = 104857600; // 100 MB of free storage per person
const CHUNK_BYTES = 1024 * 1024; // file bytes are split into 1 MB rows
const IS_STAGING = process.env.USERNODE_ENV === 'staging';

// The platform signs user-identity tokens with an RSA private key it never
// shares. Containers get only the PUBLIC half, so this app can verify who a
// user is but cannot mint an identity — and neither can any other app.
const JWT_PUBLIC_KEY = (process.env.USERNODE_JWT_PUBLIC_KEY || '')
  .replace(/\\n/g, '\n');

// Tokens are minted for one app: the audience is this app's numeric id, so a
// token issued for a different app is rejected below rather than accepted as
// a valid user.
const APP_AUDIENCE = process.env.USERNODE_APP_ID
  ? 'usernode:app:' + process.env.USERNODE_APP_ID
  : null;

// Visitors with no Homeroom account ("guests") may look around this app at
// its own address, read-only (every public app). The platform marks
// them with a token of their own: ES256, signed by a key of its own (its
// public half is USERNODE_GUEST_JWT_PUBLIC_KEY), this audience, `pur:
// 'guest'`, `guest: true`, and no id or username. Such a visitor is
// `req.guest`, never `req.user`, and every write they try is answered 401
// `account_required`, which the bridge turns into "Make an account to
// continue".
const GUEST_AUDIENCE = APP_AUDIENCE ? APP_AUDIENCE + ':guest' : null;
const GUEST_PUBLIC_KEY = (process.env.USERNODE_GUEST_JWT_PUBLIC_KEY || '')
  .replace(/\\n/g, '\n');

// Paths that stay open without authentication. Add a path here (and add it
// with `app.get`/`app.post` below) if you deliberately want it public.
// Everything else requires a valid platform-issued JWT.
const PUBLIC_API_PATHS = new Set(['/health']);

app.use(express.json());

// The platform's three centrally hosted files — the bridge, the native UI
// kit and the Tailwind runtime — are reachable at these paths on this app's
// OWN origin, so index.html can load them with a RELATIVE path and never
// name the platform's hostname. A hostname baked into an app is what breaks
// every app at once when the platform's domain moves.
//
// In production and on a staging preview the platform's edge answers these
// before the request ever reaches this process. This handler is what makes
// the same relative paths work under a plain `node server.js`.
// Registered BEFORE the auth middleware because these three files are
// public.
const PLATFORM_ORIGIN = (process.env.USERNODE_PLATFORM_ORIGIN || '')
  .replace(/\/+$/, '');

app.get(/^\/usernode-(?:bridge|native|tailwind)\//, async (req, res) => {
  try {
    if (!PLATFORM_ORIGIN) return res.sendStatus(503);
    const upstream = await fetch(PLATFORM_ORIGIN + req.path);
    if (!upstream.ok) return res.sendStatus(upstream.status);
    const type = upstream.headers.get('content-type');
    if (type) res.type(type);
    // max-age=0 with revalidation, never a long TTL: the whole point of
    // central hosting is that a platform-side fix lands on the next load.
    res.set('Cache-Control', 'public, max-age=0, must-revalidate');
    return res.send(Buffer.from(await upstream.arrayBuffer()));
  } catch (err) {
    console.warn('hosted asset fetch failed: ' + err.message);
    return res.sendStatus(502);
  }
});

// "Now" for this request, as a Date: `req.now`. Only a staging container
// reads `?un-now=` / `x-usernode-now`. See "Time-dependent features" in the
// platform conventions.
const PREVIEW_NOW = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:\d{2})$/;
function requestNow(req) {
  const raw = IS_STAGING ? (req.headers['x-usernode-now'] || req.query['un-now']) : null;
  return typeof raw === 'string' && PREVIEW_NOW.test(raw) ? new Date(raw) : new Date();
}

// Verify platform-issued JWT if one was passed, then enforce auth on
// anything not explicitly marked public. The iframe adds `?token=…`
// on load; the frontend script forwards the token via `x-usernode-token`
// on subsequent fetches.
app.use((req, res, next) => {
  req.now = requestNow(req);
  const token = req.query.token || req.headers['x-usernode-token'];
  if (token && JWT_PUBLIC_KEY && APP_AUDIENCE) {
    try {
      // Pin the algorithm, issuer and audience. Without `algorithms` a
      // caller could hand us an HS256 token signed with the public PEM
      // (which every app knows) and forge any user.
      const claims = jwt.verify(token, JWT_PUBLIC_KEY, {
        algorithms: ['RS256'],
        issuer: 'usernode',
        audience: APP_AUDIENCE,
      });
      // `pur` names what the token is for. Only user-identity tokens
      // authenticate a person here.
      if (claims && claims.pur === 'iframe') req.user = claims;
    } catch {}
  }
  if (!req.user && token && GUEST_PUBLIC_KEY && GUEST_AUDIENCE) {
    try {
      const guest = jwt.verify(token, GUEST_PUBLIC_KEY, {
        algorithms: ['ES256'],
        issuer: 'usernode',
        audience: GUEST_AUDIENCE,
      });
      if (guest && guest.pur === 'guest' && guest.guest === true) req.guest = true;
    } catch {}
  }

  // Static assets (CSS/JS/images) are always served; the API and the HTML
  // shell are gated so direct hits to the staging/prod subdomain don't
  // leak app data to the public internet. A guest may READ: every GET,
  // `/api/*` included, so read routes must not assume req.user (use
  // `req.user ? req.user.id : null`). Every write needs an account.
  if (req.method !== 'GET' || req.path.startsWith('/api/')) {
    if (PUBLIC_API_PATHS.has(req.path)) return next();
    if (!req.user && req.guest) {
      if (req.method === 'GET' || req.method === 'HEAD') return next();
      return res.status(401).json({ error: 'account_required' });
    }
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
});

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// The template ships no favicon file; index.html carries an inline SVG
// icon instead. Answer 204 here so anything that still probes
// /favicon.ico (older browsers, direct visits) doesn't fall through to
// the auth-gated catch-all and surface a 401 in the console on every
// fresh load.
app.get('/favicon.ico', (_req, res) => res.status(204).end());

/* ── HomeVault ────────────────────────────────────────────────────────────
 * Uploaded file bytes are kept in Postgres (`file_chunks`, 1 MB rows):
 * the platform's file storage takes only images of up to 5 MB, and a vault
 * holds any file up to a person's 100 MB. The tables are `staging:private`
 * so file bytes never reach staging clones.
 */
const SCHEMA = `
CREATE TABLE IF NOT EXISTS files (
  id bigserial PRIMARY KEY,
  owner_id text NOT NULL,
  owner_username text NOT NULL,
  name text NOT NULL,
  content_type text NOT NULL,
  size_bytes bigint NOT NULL,
  visibility text NOT NULL DEFAULT 'only_me'
    CHECK (visibility IN ('only_me', 'members', 'public')),
  public_token text UNIQUE,
  is_demo boolean NOT NULL DEFAULT false,
  demo_viewer_id text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS file_chunks (
  file_id bigint NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  seq int NOT NULL,
  data bytea NOT NULL,
  PRIMARY KEY (file_id, seq)
);
CREATE TABLE IF NOT EXISTS reports (
  id bigserial PRIMARY KEY,
  file_id bigint NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  reporter_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS demo_seeds (
  viewer_id text PRIMARY KEY,
  seeded_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE files IS 'staging:private';
COMMENT ON TABLE file_chunks IS 'staging:private';
COMMENT ON TABLE reports IS 'staging:private';
COMMENT ON TABLE demo_seeds IS 'staging:private';
`;

async function ensureSchema() {
  if (!process.env.DATABASE_URL) {
    console.warn('No DATABASE_URL: running without the vault (API routes will fail)');
    return;
  }
  await pool.query(SCHEMA);
}

// Membership comes from the platform, keyed per person, cached for 60 s
// (rate limit: 120/min per app and user).
const membersCache = new Map(); // user id -> { at, isMember }
async function isMember(user, userToken) {
  const base = process.env.USERNODE_PLATFORM_API_V1_URL;
  if (!base || !user) return false;
  const cached = membersCache.get(user.id);
  if (cached && Date.now() - cached.at < 60000) return cached.isMember;
  let isMember = false;
  try {
    const headers = { 'x-usernode-user-token': userToken };
    if (process.env.USERNODE_LLM_PROXY_TOKEN) {
      headers['x-usernode-app-token'] = process.env.USERNODE_LLM_PROXY_TOKEN;
    }
    const resp = await fetch(base.replace(/\/+$/, '') + '/members', { headers });
    // 200 → a member; 403 `not_a_member` → not one; anything else, treat
    // as not a member rather than failing the page.
    isMember = resp.ok;
  } catch {}
  membersCache.set(user.id, { at: Date.now(), isMember });
  return isMember;
}

/* ── Staging demo (IS_STAGING && ?demo=1 only) ───────────────────────────
 * The first /api/vault request with demo=1 writes the viewer's eight demo
 * files once, marked is_demo, plus two rows owned by made-up members. A
 * demo_seeds marker keeps it a once-per-viewer write: what the viewer then
 * does to the demo files (share, delete) stays. Every query without
 * demo=1 filters out is_demo rows, including the quota sum, so the plain
 * route sees production's answer.
 */
const DEMO_CONTENT = Buffer.from('HomeVault demo placeholder file content');
const DEMO_FILES = [
  // Display order (newest first); inserted in reverse so id DESC matches.
  { name: 'Band poster.jpg', type: 'image/jpeg', size: 16304742, visibility: 'public' },
  { name: 'Moving checklist.pdf', type: 'application/pdf', size: 98304, visibility: 'members' },
  { name: 'Reading list.txt', type: 'text/plain', size: 12288, visibility: 'only_me' },
  { name: 'Family recipes.docx', type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', size: 8173771, visibility: 'public' },
  { name: 'Garden plan.png', type: 'image/png', size: 3253723, visibility: 'members' },
  { name: 'Budget March.xlsx', type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', size: 655360, visibility: 'only_me' },
  { name: 'Lake weekend.jpg', type: 'image/jpeg', size: 12582912, visibility: 'public' },
  { name: 'Lease agreement 2025.pdf', type: 'application/pdf', size: 2516582, visibility: 'members' },
];
const DEMO_SHARED = [
  { ownerId: 'demo-maya', username: 'Maya', name: 'Trip itinerary.pdf', size: 1258291, visibility: 'members' },
  { ownerId: 'demo-daniel', username: 'Daniel', name: 'Birthday photos.zip', size: 35651584, visibility: 'public' },
];

async function insertFile(client, { ownerId, username, name, type, size, visibility, isDemo, demoViewerId }) {
  const row = await client.query(
    `INSERT INTO files (owner_id, owner_username, name, content_type, size_bytes, visibility, is_demo, demo_viewer_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
    [ownerId, username, name, type, size, visibility, isDemo, demoViewerId]
  );
  const id = row.rows[0].id;
  // Demo files carry a few placeholder bytes so downloads work; real
  // uploads get their bytes from the request body.
  const data = isDemo ? DEMO_CONTENT : null;
  if (data) {
    for (let seq = 0; seq * CHUNK_BYTES < data.length; seq++) {
      await client.query('INSERT INTO file_chunks (file_id, seq, data) VALUES ($1, $2, $3)',
        [id, seq, data.subarray(seq * CHUNK_BYTES, (seq + 1) * CHUNK_BYTES)]);
    }
  }
  return id;
}

async function ensureDemo(client, viewerId, username) {
  await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', ['demo:' + viewerId]);
  const marker = await client.query('SELECT 1 FROM demo_seeds WHERE viewer_id = $1', [viewerId]);
  if (marker.rowCount) return;
  for (const f of [...DEMO_FILES].reverse()) {
    await insertFile(client, {
      ownerId: viewerId, username, name: f.name, type: f.type,
      size: f.size, visibility: f.visibility, isDemo: true, demoViewerId: viewerId,
    });
  }
  for (const s of DEMO_SHARED) {
    await insertFile(client, {
      ownerId: s.ownerId, username: s.username, name: s.name, type: 'application/octet-stream',
      size: s.size, visibility: s.visibility, isDemo: true, demoViewerId: viewerId,
    });
  }
  await client.query('INSERT INTO demo_seeds (viewer_id) VALUES ($1) ON CONFLICT DO NOTHING', [viewerId]);
}

// Own demo rows and the fake shared rows only exist on staging, behind
// demo=1; every route's queries follow the same demo clause.
function demoClause(demo) {
  return demo ? '' : ' AND is_demo = false';
}

function fileJson(row) {
  return {
    id: Number(row.id),
    name: row.name,
    sizeBytes: Number(row.size_bytes),
    visibility: row.visibility,
    publicToken: row.public_token || null,
  };
}

app.get('/api/vault', async (req, res) => {
  // A guest has no vault: an empty one, read-only.
  if (!req.user) {
    return res.json({ username: null, usedBytes: 0, limitBytes: LIMIT_BYTES, files: [], shared: [] });
  }
  const viewer = req.user.id;
  const demo = IS_STAGING && req.query.demo === '1';
  try {
    if (demo) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await ensureDemo(client, viewer, req.user.username);
        await client.query('COMMIT');
      } finally {
        client.release();
      }
    }
    const own = await pool.query(
      `SELECT id, name, visibility, public_token, size_bytes FROM files
       WHERE owner_id = $1${demoClause(demo)} ORDER BY created_at DESC, id DESC`,
      [viewer]
    );
    // Only the viewer's own demo rows and the fake shared rows are added
    // with demo=1; other people's demo uploads never appear.
    const demoSharedClause = demo
      ? ' AND (is_demo = false OR (is_demo = true AND demo_viewer_id = $1))'
      : ' AND is_demo = false';
    // Demo shared rows (Maya, Daniel) are fake staging data, shown with
    // demo=1 even when the viewer is not a project member; real shared
    // rows need membership.
    const [member, shared] = await Promise.all([
      isMember(req.user, req.headers['x-usernode-token'] || req.query.token),
      pool.query(
        `SELECT id, name, visibility, size_bytes, owner_username, is_demo FROM files
         WHERE owner_id <> $1 AND visibility IN ('members', 'public')${demoSharedClause}
         ORDER BY created_at DESC, id DESC LIMIT 200`,
        [viewer]
      ),
    ]);
    const used = await pool.query(
      `SELECT COALESCE(SUM(size_bytes), 0) AS used FROM files WHERE owner_id = $1${demoClause(demo)}`,
      [viewer]
    );
    return res.json({
      username: req.user.username,
      usedBytes: Number(used.rows[0].used),
      limitBytes: LIMIT_BYTES,
      demo: demo ? true : undefined,
      files: own.rows.map(fileJson),
      shared: shared.rows.filter((row) => row.is_demo || member).map((row) => ({
        id: Number(row.id),
        name: row.name,
        sizeBytes: Number(row.size_bytes),
        visibility: row.visibility,
        ownerUsername: row.owner_username,
      })),
    });
  } catch (err) {
    console.error('GET /api/vault failed: ' + err.message);
    return res.status(500).json({ error: 'vault_unavailable' });
  }
});

// Raw file upload. `express.raw` because the bytes arrive as the body; a
// 100 MB cap matches the per-person limit.
app.post('/api/files', express.raw({ limit: LIMIT_BYTES, type: '*/*' }), async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'account_required' });
  const name = typeof req.query.name === 'string' && req.query.name.trim()
    ? req.query.name.trim().slice(0, 255) : 'Untitled file';
  const type = typeof req.query.type === 'string' && req.query.type
    ? req.query.type.slice(0, 255) : 'application/octet-stream';
  const body = Buffer.isBuffer(req.body) ? req.body
    : (req.body ? Buffer.from(JSON.stringify(req.body)) : Buffer.alloc(0));
  const demo = IS_STAGING && req.query.demo === '1';
  const viewer = req.user.id;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // One lock per owner: two simultaneous uploads can't both pass the
    // quota check.
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', ['quota:' + viewer]);
    const used = await client.query(
      `SELECT COALESCE(SUM(size_bytes), 0) AS used FROM files WHERE owner_id = $1${demoClause(demo)}`,
      [viewer]
    );
    const usedBytes = Number(used.rows[0].used);
    if (usedBytes + body.length > LIMIT_BYTES) {
      await client.query('ROLLBACK');
      return res.status(413).json({
        error: 'vault_full',
        usedBytes,
        freeBytes: Math.max(LIMIT_BYTES - usedBytes, 0),
      });
    }
    const id = await insertFile(client, {
      ownerId: viewer, username: req.user.username, name, type,
      size: body.length, visibility: 'only_me', isDemo: demo, demoViewerId: viewer,
    });
    for (let seq = 0; seq * CHUNK_BYTES < body.length; seq++) {
      await client.query('INSERT INTO file_chunks (file_id, seq, data) VALUES ($1, $2, $3)',
        [id, seq, body.subarray(seq * CHUNK_BYTES, (seq + 1) * CHUNK_BYTES)]);
    }
    await client.query('COMMIT');
    return res.status(201).json({
      id: Number(id), name, sizeBytes: body.length, visibility: 'only_me', publicToken: null,
    });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch {}
    console.error('POST /api/files failed: ' + err.message);
    return res.status(500).json({ error: 'upload_failed' });
  } finally {
    client.release();
  }
});

async function loadFile(idOrToken, column) {
  const result = await pool.query(
    `SELECT id, owner_id, owner_username, name, content_type, size_bytes, visibility, public_token, is_demo
     FROM files WHERE ${column} = $1`, [idOrToken]);
  return result.rows[0] || null;
}

// Sends the file's bytes as a DOWNLOAD, never as something the browser
// could render: application/octet-stream, attachment, nosniff — an
// uploaded HTML file can never run on the app's origin.
async function sendFile(res, file) {
  const chunks = await pool.query('SELECT data FROM file_chunks WHERE file_id = $1 ORDER BY seq', [file.id]);
  const name = file.name || 'file';
  res.status(200);
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', 'attachment; filename*=UTF-8\'\'' + encodeURIComponent(name));
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Length', String(Number(file.size_bytes)));
  for (const chunk of chunks.rows) {
    if (!res.write(chunk.data)) {
      await new Promise((resolve) => res.once('drain', resolve));
    }
  }
  res.end();
}

// Who can open a file: its owner; a project member when it is `members`;
// anyone when it is `public`. Demo rows are staging make-believe and open
// to the demo viewer.
function canSee(file, user, member) {
  if (!user) return false;
  if (file.is_demo) return true;
  if (String(file.owner_id) === String(user.id)) return true;
  if (!member) return false;
  return file.visibility === 'members' || file.visibility === 'public';
}

app.get('/api/files/:id/download', async (req, res) => {
  if (!req.user) return res.status(403).json({ error: 'not_allowed' });
  if (!/^\d+$/.test(req.params.id)) return res.sendStatus(404);
  let file;
  try {
    file = await loadFile(req.params.id, 'id');
  } catch (err) {
    console.error('download failed: ' + err.message);
    return res.status(500).json({ error: 'download_failed' });
  }
  if (!file) return res.sendStatus(404);
  const member = await isMember(req.user, req.headers['x-usernode-token'] || req.query.token);
  if (!canSee(file, req.user, member)) return res.status(403).json({ error: 'not_allowed' });
  try {
    return await sendFile(res, file);
  } catch (err) {
    console.error('download failed: ' + err.message);
    return res.status(500).json({ error: 'download_failed' });
  }
});

// Who can open it: only the owner. `public` mints a fresh link token; any
// other choice clears it, so the old link stops working.
app.patch('/api/files/:id', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'account_required' });
  if (!/^\d+$/.test(req.params.id)) return res.sendStatus(404);
  const visibility = req.body && req.body.visibility;
  if (!['only_me', 'members', 'public'].includes(visibility)) {
    return res.status(400).json({ error: 'bad_visibility' });
  }
  let file;
  try {
    file = await loadFile(req.params.id, 'id');
  } catch (err) {
    console.error('share change failed: ' + err.message);
    return res.status(500).json({ error: 'share_change_failed' });
  }
  if (!file) return res.sendStatus(404);
  if (String(file.owner_id) !== String(req.user.id)) return res.status(403).json({ error: 'not_allowed' });
  const token = visibility === 'public'
    ? crypto.randomBytes(16).toString('hex') : null;
  try {
    const updated = await pool.query(
      'UPDATE files SET visibility = $1, public_token = $2 WHERE id = $3 RETURNING id, name, visibility, public_token, size_bytes',
      [visibility, token, req.params.id]);
    const row = updated.rows[0];
    return res.json(fileJson(row));
  } catch (err) {
    console.error('share change failed: ' + err.message);
    return res.status(500).json({ error: 'share_change_failed' });
  }
});

// Only the owner can delete. Chunks and reports cascade; the space frees
// at once.
app.delete('/api/files/:id', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'account_required' });
  if (!/^\d+$/.test(req.params.id)) return res.sendStatus(404);
  let file;
  try {
    file = await loadFile(req.params.id, 'id');
  } catch (err) {
    console.error('delete failed: ' + err.message);
    return res.status(500).json({ error: 'delete_failed' });
  }
  if (!file) return res.sendStatus(404);
  if (String(file.owner_id) !== String(req.user.id)) return res.status(403).json({ error: 'not_allowed' });
  try {
    await pool.query('DELETE FROM files WHERE id = $1', [req.params.id]);
    return res.json({ ok: true });
  } catch (err) {
    console.error('delete failed: ' + err.message);
    return res.status(500).json({ error: 'delete_failed' });
  }
});

// A report from someone who can see the file. It records one row and
// nothing else; it does not hide anything.
app.post('/api/files/:id/report', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'account_required' });
  if (!/^\d+$/.test(req.params.id)) return res.sendStatus(404);
  let file;
  try {
    file = await loadFile(req.params.id, 'id');
  } catch (err) {
    console.error('report failed: ' + err.message);
    return res.status(500).json({ error: 'report_failed' });
  }
  if (!file) return res.sendStatus(404);
  const member = await isMember(req.user, req.headers['x-usernode-token'] || req.query.token);
  if (!canSee(file, req.user, member)) return res.status(403).json({ error: 'not_allowed' });
  try {
    await pool.query('INSERT INTO reports (file_id, reporter_id) VALUES ($1, $2)',
      [req.params.id, req.user.id]);
    return res.status(201).json({ ok: true });
  } catch (err) {
    console.error('report failed: ' + err.message);
    return res.status(500).json({ error: 'report_failed' });
  }
});

// The public link: open to anyone who has it, signed in or not. Registered
// before the `*` catch-all; a non-/api GET already passes the auth
// middleware.
app.get('/s/:token', async (req, res) => {
  try {
    const file = await loadFile(req.params.token, 'public_token');
    if (!file || file.visibility !== 'public' || !file.public_token) return res.sendStatus(404);
    return await sendFile(res, file);
  } catch (err) {
    console.error('public link failed: ' + err.message);
    return res.status(500).send('Download failed');
  }
});

// Body errors (an upload over the 100 MB cap never reaches the route's own
// quota check) and anything else thrown by a route, as JSON.
app.use((err, _req, res, _next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'vault_full' });
  }
  console.error('request failed: ' + (err && err.message));
  return res.status(500).json({ error: 'internal_error' });
});

app.use(express.static(path.join(__dirname, 'public')));

// HTML shell: serve the app if authenticated. Unauthenticated top-level
// visits (share links pasted into a browser — Sec-Fetch-Dest: document)
// are sent to the platform's chromeless view of this app, where the shell
// embeds it with a real token so the link just works.
app.get('*', (req, res) => {
  if (!req.user && !req.guest) {
    const deepPath = /^\/[A-Za-z0-9\-._~!$&()*+,;=:@\/%?]*$/.test(req.originalUrl)
      ? '?path=' + encodeURIComponent(req.originalUrl) : '';
    if (PLATFORM_ORIGIN && req.get('sec-fetch-dest') === 'document') {
      return res.redirect(302, PLATFORM_ORIGIN + '/app/homevault-9012d2/full' + deepPath);
    }
    return res.status(401).send(`<!doctype html><meta charset=utf-8><title>Open in Homeroom</title>
<body style="font-family:system-ui;background:#09090b;color:#e4e4e7;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
  <div style="max-width:24rem;padding:2rem;text-align:center">
    <h1 style="font-size:1.25rem;margin:0 0 0.5rem">Open this app inside Homeroom</h1>
    <p style="color:#a1a1aa;font-size:0.9rem;margin:0 0 1.25rem">This page is served via the platform; direct visits aren't authenticated.</p>
    <a href="${PLATFORM_ORIGIN}/app/homevault-9012d2/full${deepPath}" style="display:inline-block;padding:0.5rem 1rem;background:#0f766e;color:white;border-radius:0.5rem;text-decoration:none;font-size:0.9rem">Open in Homeroom</a>
  </div>
</body>`);
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

async function start() {
  await ensureSchema();
  const server = app.listen(port, () => console.log(`Listening on :${port}`));
  // Let Envoy retire idle upstream connections at 60s, with a 15s margin.
  server.keepAliveTimeout = 75_000;
  // Stop accepting connections, drain for ~3 s, close the pool, exit.
  let stopped = false;
  function shutdown(signal) {
    if (stopped) return;
    stopped = true;
    console.log(`${signal}: shutting down`);
    server.close(() => finish());
    setTimeout(finish, 3000).unref();
  }
  function finish() {
    if (!process.env.DATABASE_URL) return process.exit(0);
    pool.end().then(() => process.exit(0), () => process.exit(0));
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

start().catch(err => { console.error(err); process.exit(1); });