// Velo Kinetix Systems back end (runs on Render).
// What it does:
//   1. Client accounts: sign up, sign in, and "who am I" for the login page.
//   2. Site agents: every client can register sites; an agent checks each one on a timer.
//   3. Alerts: when a site goes down or comes back, it posts to your Make webhook,
//      so your existing Make error emails reach you.
// Settings come from Render "Environment" variables (never put secrets in this file):
//   DATABASE_URL        Render PostgreSQL "Internal Database URL"          (required)
//   SESSION_SECRET      long random text used to sign login tokens          (required)
//   ALLOWED_ORIGINS     sites allowed to call this API, comma separated     (optional)
//   MAKE_ALERT_WEBHOOK  Make webhook that should receive site alerts        (optional)
//   MAKE_SIGNUP_WEBHOOK Make webhook that should hear about new sign-ups    (optional)
//   CHECK_EVERY_MINUTES how often agents check sites, default 5             (optional)
'use strict';
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { Pool } = require('pg');

const PORT = process.env.PORT || 10000;
const SECRET = process.env.SESSION_SECRET;
if (!process.env.DATABASE_URL || !SECRET) {
  console.error('Missing DATABASE_URL or SESSION_SECRET. Add them under Environment on Render.');
  process.exit(1);
}
const ORIGINS = (process.env.ALLOWED_ORIGINS ||
  'https://velokinetixsystems.com,https://www.velokinetixsystems.com')
  .split(',').map(s => s.trim()).filter(Boolean);
const CHECK_MINUTES = Math.max(1, Number(process.env.CHECK_EVERY_MINUTES) || 5);
const TOKEN_DAYS = 14;

// Render's Internal Database URL (host like dpg-xxxx-a) needs no SSL; outside addresses do.
const dbHost = (() => { try { return new URL(process.env.DATABASE_URL).hostname; } catch { return ''; } })();
const useSSL = process.env.PGSSL === 'require' ||
  (process.env.PGSSL !== 'off' && dbHost.includes('.') && dbHost !== '127.0.0.1');
const db = new Pool({ connectionString: process.env.DATABASE_URL, ssl: useSSL ? { rejectUnauthorized: false } : false });

// ---------- database tables (created automatically on first start) ----------
async function setupDatabase() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      company TEXT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS sites (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      label TEXT NOT NULL,
      url TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'unknown',
      last_checked TIMESTAMPTZ,
      last_ms INTEGER,
      last_error TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS agent_events (
      id SERIAL PRIMARY KEY,
      site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
      kind TEXT NOT NULL,
      detail TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );`);
}

// ---------- passwords and login tokens ----------
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(pw, salt, 64);
  return 'scrypt$' + salt.toString('hex') + '$' + key.toString('hex');
}
function checkPassword(pw, stored) {
  const [, saltHex, keyHex] = String(stored).split('$');
  if (!saltHex || !keyHex) return false;
  const key = crypto.scryptSync(pw, Buffer.from(saltHex, 'hex'), 64);
  return crypto.timingSafeEqual(key, Buffer.from(keyHex, 'hex'));
}
const b64 = s => Buffer.from(s).toString('base64url');
function makeToken(userId) {
  const body = b64(JSON.stringify({ uid: userId, exp: Date.now() + TOKEN_DAYS * 864e5 }));
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}
function readToken(token) {
  const [body, sig] = String(token || '').split('.');
  if (!body || !sig) return null;
  const good = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  try { const p = JSON.parse(Buffer.from(body, 'base64url').toString()); return p.exp > Date.now() ? p : null; }
  catch { return null; }
}

// ---------- small helpers ----------
const clean = (v, max = 200) => String(v == null ? '' : v).trim().slice(0, max);
const emailOk = e => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e);
const publicUser = u => ({ id: u.id, name: u.name, company: u.company, email: u.email, created_at: u.created_at });
async function postToMake(url, payload) {
  if (!url) return;
  try {
    await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload), signal: AbortSignal.timeout(10000) });
  } catch (e) { console.error('Make webhook failed:', e.message); }
}
// Simple brake on repeated sign-in attempts: 10 per 15 minutes per address.
const attempts = new Map();
function tooMany(key) {
  const now = Date.now(), list = (attempts.get(key) || []).filter(t => now - t < 15 * 60e3);
  list.push(now); attempts.set(key, list); return list.length > 10;
}

// ---------- web server ----------
const app = express();
app.set('trust proxy', 1);
app.use(cors({ origin: (o, cb) => cb(null, !o || ORIGINS.includes(o)), methods: ['GET', 'POST', 'DELETE'] }));
app.use(express.json({ limit: '20kb' }));

function requireLogin(req, res, next) {
  const t = (req.get('authorization') || '').replace(/^Bearer\s+/i, '');
  const p = readToken(t);
  if (!p) return res.status(401).json({ ok: false, message: 'Please sign in again.' });
  req.userId = p.uid; next();
}

app.get('/', (req, res) => res.json({ ok: true, service: 'Velo Kinetix Systems API' }));
app.get('/health', async (req, res) => {
  try { await db.query('SELECT 1'); res.json({ ok: true, database: 'connected' }); }
  catch { res.status(503).json({ ok: false, database: 'unreachable' }); }
});

// Field names match the website forms: name, company, email, password.
app.post('/api/signup', async (req, res) => {
  const name = clean(req.body.name, 120), company = clean(req.body.company, 160);
  const email = clean(req.body.email, 200).toLowerCase(), password = String(req.body.password || '');
  if (!name || !emailOk(email)) return res.status(400).json({ ok: false, message: 'Enter your name and a valid email address.' });
  if (password.length < 8) return res.status(400).json({ ok: false, message: 'Your password needs at least 8 characters.' });
  try {
    const r = await db.query(
      'INSERT INTO users (name, company, email, password_hash) VALUES ($1,$2,$3,$4) RETURNING *',
      [name, company || null, email, hashPassword(password)]);
    const user = r.rows[0];
    postToMake(process.env.MAKE_SIGNUP_WEBHOOK, { event: 'signup', name, company, email, created_at: user.created_at });
    res.status(201).json({ ok: true, message: 'Account created.', token: makeToken(user.id), user: publicUser(user) });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ ok: false, message: 'An account with that email already exists. Try signing in.' });
    console.error(e); res.status(500).json({ ok: false, message: 'Something went wrong. Please try again.' });
  }
});

app.post('/api/signin', async (req, res) => {
  const email = clean(req.body.email, 200).toLowerCase(), password = String(req.body.password || '');
  if (tooMany(email + '|' + req.ip)) return res.status(429).json({ ok: false, message: 'Too many attempts. Wait 15 minutes and try again.' });
  const r = await db.query('SELECT * FROM users WHERE email=$1', [email]).catch(() => null);
  const user = r && r.rows[0];
  if (!user || !checkPassword(password, user.password_hash))
    return res.status(401).json({ ok: false, message: 'That email and password do not match.' });
  res.json({ ok: true, message: 'Signed in.', token: makeToken(user.id), user: publicUser(user) });
});

app.get('/api/me', requireLogin, async (req, res) => {
  const r = await db.query('SELECT * FROM users WHERE id=$1', [req.userId]);
  if (!r.rows[0]) return res.status(401).json({ ok: false, message: 'Please sign in again.' });
  res.json({ ok: true, user: publicUser(r.rows[0]) });
});

// ---------- sites and their agents ----------
app.get('/api/sites', requireLogin, async (req, res) => {
  const r = await db.query('SELECT id,label,url,status,last_checked,last_ms,last_error FROM sites WHERE user_id=$1 ORDER BY id', [req.userId]);
  res.json({ ok: true, sites: r.rows });
});
app.post('/api/sites', requireLogin, async (req, res) => {
  let url = clean(req.body.url, 300); const label = clean(req.body.label, 80) || url;
  if (url && !/^https?:\/\//i.test(url)) url = 'https://' + url;
  try { const u = new URL(url); if (!/^https?:$/.test(u.protocol)) throw 0; } catch { return res.status(400).json({ ok: false, message: 'Enter a full web address, like https://example.com' }); }
  const count = await db.query('SELECT count(*)::int AS n FROM sites WHERE user_id=$1', [req.userId]);
  if (count.rows[0].n >= 25) return res.status(400).json({ ok: false, message: 'You have reached 25 sites. Contact us to add more.' });
  const r = await db.query('INSERT INTO sites (user_id,label,url) VALUES ($1,$2,$3) RETURNING id,label,url,status', [req.userId, label, url]);
  checkSite(r.rows[0]).catch(() => {});
  res.status(201).json({ ok: true, site: r.rows[0] });
});
app.delete('/api/sites/:id', requireLogin, async (req, res) => {
  await db.query('DELETE FROM sites WHERE id=$1 AND user_id=$2', [Number(req.params.id) || 0, req.userId]);
  res.json({ ok: true });
});

// The agent: load the site, time it, record the result, and alert Make when the state changes.
const SLOW_MS = 8000;
async function checkSite(site) {
  const started = Date.now(); let status = 'up', error = null;
  try {
    const r = await fetch(site.url, { redirect: 'follow', signal: AbortSignal.timeout(15000), headers: { 'User-Agent': 'VeloKinetixAgent/1.0' } });
    if (r.status >= 500) { status = 'down'; error = 'Server error ' + r.status; }
    else if (r.status >= 400) { status = 'down'; error = 'Page error ' + r.status; }
  } catch (e) { status = 'down'; error = e.name === 'TimeoutError' ? 'No response in 15 seconds' : 'Could not connect'; }
  const ms = Date.now() - started;
  if (status === 'up' && ms > SLOW_MS) { status = 'slow'; error = 'Took ' + (ms / 1000).toFixed(1) + ' seconds'; }
  const prev = await db.query('SELECT s.status, u.name, u.email, u.company FROM sites s JOIN users u ON u.id=s.user_id WHERE s.id=$1', [site.id]);
  if (!prev.rows[0]) return;
  await db.query('UPDATE sites SET status=$1,last_checked=now(),last_ms=$2,last_error=$3 WHERE id=$4', [status, ms, error, site.id]);
  const was = prev.rows[0].status;
  if (was !== status && !(was === 'unknown' && status === 'up')) {
    await db.query('INSERT INTO agent_events (site_id,kind,detail) VALUES ($1,$2,$3)', [site.id, status, error]);
    const c = prev.rows[0];
    postToMake(process.env.MAKE_ALERT_WEBHOOK, {
      event: status === 'up' ? 'site_recovered' : 'site_' + status,
      site: site.label, url: site.url, status, previous_status: was, detail: error, response_ms: ms,
      client_name: c.name, client_company: c.company, client_email: c.email, checked_at: new Date().toISOString()
    });
  }
}
let running = false;
async function patrol() {
  if (running) return; running = true;
  try {
    const r = await db.query('SELECT id,label,url FROM sites ORDER BY id');
    for (let i = 0; i < r.rows.length; i += 5) await Promise.all(r.rows.slice(i, i + 5).map(s => checkSite(s).catch(e => console.error('check failed', s.url, e.message))));
  } catch (e) { console.error('patrol failed:', e.message); }
  running = false;
}

setupDatabase().then(() => {
  app.listen(PORT, () => console.log('Velo Kinetix API listening on ' + PORT));
  setInterval(patrol, CHECK_MINUTES * 60e3); setTimeout(patrol, 15e3);
}).catch(e => { console.error('Database setup failed:', e.message); process.exit(1); });
