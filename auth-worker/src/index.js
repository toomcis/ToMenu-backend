/**
 * tomenu-auth — Cloudflare Worker
 * Handles: register, login, logout, /me (session check)
 *
 * Endpoints:
 *   POST /auth/register   { email, password, display_name? }
 *   POST /auth/login      { email, password }
 *   POST /auth/logout     (requires Authorization: Bearer <token>)
 *   GET  /auth/me         (requires Authorization: Bearer <token>)
 *   DELETE /auth/sessions (requires Authorization: Bearer <token>) — revoke all sessions
 *
 * Rate limiting via KV:
 *   Key: "rl:<ip>:<endpoint>"  Value: count  TTL: window seconds
 */

// ── constants ─────────────────────────────────────────────────────────────────

const SESSION_TTL_DAYS  = 30;
const PBKDF2_ITERATIONS = 100_000;
const SALT_BYTES        = 16;
const TOKEN_BYTES       = 32;

const RATE_LIMITS = {
  register: { max: 5,  windowSec: 3600  },  // 5 registrations/hour/IP
  login:    { max: 10, windowSec: 300   },  // 10 login attempts/5min/IP
};

// ── router ────────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const method = request.method;
    const path   = url.pathname;

    // CORS preflight
    if (method === 'OPTIONS') return cors(new Response(null, { status: 204 }));

    try {
      if (method === 'POST' && path === '/auth/register')  return await handleRegister(request, env);
      if (method === 'POST' && path === '/auth/login')     return await handleLogin(request, env);
      if (method === 'POST' && path === '/auth/logout')    return await handleLogout(request, env);
      if (method === 'GET'  && path === '/auth/me')        return await handleMe(request, env);
      if (method === 'DELETE' && path === '/auth/sessions') return await handleRevokeAll(request, env);
      if (method === 'GET'  && path === '/health')         return cors(json({ ok: true }));

      return cors(json({ error: 'not found' }, 404));
    } catch (err) {
      console.error(err);
      return cors(json({ error: 'internal server error' }, 500));
    }
  },
};

// ── handlers ──────────────────────────────────────────────────────────────────

async function handleRegister(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const limited = await rateLimit(env, ip, 'register', RATE_LIMITS.register);
  if (limited) return cors(json({ error: 'too many requests — try again later' }, 429));

  const body = await parseBody(request);
  const { email, password, display_name } = body || {};

  if (!email || !password)
    return cors(json({ error: 'email and password are required' }, 400));
  if (!isValidEmail(email))
    return cors(json({ error: 'invalid email address' }, 400));
  if (password.length < 8)
    return cors(json({ error: 'password must be at least 8 characters' }, 400));

  const existing = await env.DB.prepare(
    'SELECT id FROM users WHERE email = ?'
  ).bind(email.toLowerCase()).first();

  if (existing)
    return cors(json({ error: 'email already registered' }, 409));

  const hash = await hashPassword(password);

  const result = await env.DB.prepare(
    'INSERT INTO users (email, password_hash, display_name) VALUES (?, ?, ?) RETURNING id, email, display_name, created_at'
  ).bind(email.toLowerCase(), hash, display_name || null).first();

  const { token, tokenHash, expiresAt } = await makeToken();
  const ua = request.headers.get('User-Agent') || null;

  await env.DB.prepare(
    'INSERT INTO sessions (id, user_id, expires_at, user_agent, ip) VALUES (?, ?, ?, ?, ?)'
  ).bind(tokenHash, result.id, expiresAt, ua, ip).run();

  return cors(json({
    token,
    expires_at: expiresAt,
    user: {
      id:           result.id,
      email:        result.email,
      display_name: result.display_name,
      created_at:   result.created_at,
      is_premium:   false,
    },
  }, 201));
}

async function handleLogin(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const limited = await rateLimit(env, ip, 'login', RATE_LIMITS.login);
  if (limited) return cors(json({ error: 'too many login attempts — try again later' }, 429));

  const body = await parseBody(request);
  const { email, password } = body || {};

  if (!email || !password)
    return cors(json({ error: 'email and password are required' }, 400));

  const user = await env.DB.prepare(
    'SELECT id, email, password_hash, display_name, created_at, is_premium FROM users WHERE email = ?'
  ).bind(email.toLowerCase()).first();

  // Always run a comparison to prevent timing attacks
  const dummyHash = '$dummy$dummy$dummy$dummy$dummy$dummy$dummy$dummy$dummy$';
  const match = user
    ? await verifyPassword(password, user.password_hash)
    : await verifyPassword(password, dummyHash).catch(() => false);

  if (!user || !match)
    return cors(json({ error: 'invalid email or password' }, 401));

  const { token, tokenHash, expiresAt } = await makeToken();
  const ua = request.headers.get('User-Agent') || null;

  await env.DB.prepare(
    'INSERT INTO sessions (id, user_id, expires_at, user_agent, ip) VALUES (?, ?, ?, ?, ?)'
  ).bind(tokenHash, user.id, expiresAt, ua, ip).run();

  return cors(json({
    token,
    expires_at: expiresAt,
    user: {
      id:           user.id,
      email:        user.email,
      display_name: user.display_name,
      created_at:   user.created_at,
      is_premium:   !!user.is_premium,
    },
  }));
}

async function handleLogout(request, env) {
  const { tokenHash, error } = await extractToken(request);
  if (error) return cors(json({ error }, 401));

  await env.DB.prepare(
    'DELETE FROM sessions WHERE id = ?'
  ).bind(tokenHash).run();

  return cors(json({ ok: true }));
}

async function handleMe(request, env) {
  const { tokenHash, error } = await extractToken(request);
  if (error) return cors(json({ error }, 401));

  const session = await env.DB.prepare(`
    SELECT s.id, s.expires_at, s.user_id,
           u.email, u.display_name, u.created_at, u.is_premium
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.id = ? AND s.expires_at > datetime('now')
  `).bind(tokenHash).first();

  if (!session) return cors(json({ error: 'session expired or invalid' }, 401));

  return cors(json({
    user: {
      id:           session.user_id,
      email:        session.email,
      display_name: session.display_name,
      created_at:   session.created_at,
      is_premium:   !!session.is_premium,
    },
    expires_at: session.expires_at,
  }));
}

async function handleRevokeAll(request, env) {
  const { tokenHash, error } = await extractToken(request);
  if (error) return cors(json({ error }, 401));

  const session = await env.DB.prepare(
    'SELECT user_id FROM sessions WHERE id = ? AND expires_at > datetime(\'now\')'
  ).bind(tokenHash).first();

  if (!session) return cors(json({ error: 'session expired or invalid' }, 401));

  const result = await env.DB.prepare(
    'DELETE FROM sessions WHERE user_id = ?'
  ).bind(session.user_id).run();

  return cors(json({ ok: true, sessions_revoked: result.meta?.changes ?? 0 }));
}

// ── crypto ────────────────────────────────────────────────────────────────────

async function hashPassword(password) {
  const enc     = new TextEncoder();
  const saltBuf = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const saltHex = bufToHex(saltBuf);

  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBuf, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial, 256
  );
  const hashHex = bufToHex(new Uint8Array(derivedBits));
  return `pbkdf2:${PBKDF2_ITERATIONS}:${saltHex}:${hashHex}`;
}

async function verifyPassword(password, stored) {
  const parts = stored.split(':');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;

  const [, itersStr, saltHex, storedHash] = parts;
  const iterations = parseInt(itersStr, 10);
  const saltBuf    = hexToBuf(saltHex);
  const enc        = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBuf, iterations, hash: 'SHA-256' },
    keyMaterial, 256
  );
  const hashHex = bufToHex(new Uint8Array(derivedBits));

  // constant-time compare
  return timingSafeEqual(hashHex, storedHash);
}

async function makeToken() {
  const tokenBuf  = crypto.getRandomValues(new Uint8Array(TOKEN_BYTES));
  const token     = bufToHex(tokenBuf);
  const hashBuf   = await crypto.subtle.digest('SHA-256', tokenBuf);
  const tokenHash = bufToHex(new Uint8Array(hashBuf));

  const expiresAt = new Date(
    Date.now() + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000
  ).toISOString().replace('T', ' ').slice(0, 19);

  return { token, tokenHash, expiresAt };
}

async function extractToken(request) {
  const header = request.headers.get('Authorization') || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
  if (!token) return { error: 'missing Authorization header' };

  const buf      = hexToBuf(token);
  const hashBuf  = await crypto.subtle.digest('SHA-256', buf);
  const tokenHash = bufToHex(new Uint8Array(hashBuf));
  return { tokenHash };
}

// ── rate limiting (KV) ────────────────────────────────────────────────────────

async function rateLimit(env, ip, endpoint, { max, windowSec }) {
  const key   = `rl:${ip}:${endpoint}`;
  const raw   = await env.RATE_LIMITS.get(key);
  const count = raw ? parseInt(raw, 10) : 0;

  if (count >= max) return true;  // blocked

  await env.RATE_LIMITS.put(key, String(count + 1), { expirationTtl: windowSec });
  return false;
}

// ── helpers ───────────────────────────────────────────────────────────────────

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function cors(response) {
  const r = new Response(response.body, response);
  r.headers.set('Access-Control-Allow-Origin', '*');
  r.headers.set('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  r.headers.set('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  return r;
}

async function parseBody(request) {
  try { return await request.json(); }
  catch { return null; }
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function bufToHex(buf) {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++)
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++)
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}