// ToMenu Auth Worker — v2
// Endpoints:
//   POST   /auth/register
//   POST   /auth/login
//   POST   /auth/logout
//   GET    /auth/me
//   PATCH  /auth/me                  — update display_name (weekly cooldown) + nickname
//   DELETE /auth/sessions            — revoke all sessions
//   GET    /auth/verify-email        — ?token=<hex> magic link (from email button)
//   POST   /auth/verify-email        — { email, code } manual code fallback
//   POST   /auth/resend-verification — (auth required)
//   POST   /auth/forgot-password     — { email }
//   POST   /auth/reset-password      — { email, code, new_password }
//   POST   /auth/totp/setup          — (auth required) → { secret, otpauth_url }
//   POST   /auth/totp/confirm        — (auth required) { code } → enables 2FA
//   POST   /auth/totp/verify         — { email, password, code } → full login w/ 2FA
//   DELETE /auth/totp                — (auth required) { code } → disables 2FA
//   GET    /health

const SESSION_TTL_DAYS           = 30;
const PBKDF2_ITERATIONS          = 100_000;
const SALT_BYTES                 = 16;
const TOKEN_BYTES                = 32;
const EMAIL_TTL_MIN              = 30;
const RESET_TTL_MIN              = 60;
const DISPLAY_NAME_COOLDOWN_DAYS = 7;

const RATE_LIMITS = {
  register:          { max: 5,  windowSec: 3600 },
  login:             { max: 10, windowSec: 300  },
  'forgot-password': { max: 3,  windowSec: 3600 },
  'resend-verify':   { max: 3,  windowSec: 3600 },
  'totp-verify':     { max: 5,  windowSec: 300  },
  'oauth':           { max: 10, windowSec: 300  },
};

// ── Router is defined at the bottom of this file in export default ────────────

// ── Register ──────────────────────────────────────────────────────────────────

// ── Auto-generate a unique handle ────────────────────────────────────────────
async function generateHandle(env, base) {
  // Slugify: lowercase, replace spaces/special chars with _, strip invalid, collapse
  let slug = base.toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '') // remove diacritics
    .replace(/[^a-z0-9_.\-]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^[_.-]+|[_.-]+$/g, '')
    .slice(0, 20) || 'user';

  // Try slug, then slug_2, slug_3 etc.
  for (let i = 0; i < 10; i++) {
    const candidate = i === 0 ? slug : `${slug}_${i + 1}`;
    const existing = await env.DB.prepare('SELECT id FROM users WHERE nickname = ?').bind(candidate).first();
    if (!existing) return candidate;
  }
  // Fallback to random suffix
  const rand = Math.random().toString(36).slice(2, 7);
  return `${slug}_${rand}`;
}

async function handleRegister(request, env) {
  const ip = ip_(request);
  if (await rateLimit(env, ip, 'register', RATE_LIMITS.register))
    return cors(json({ error: 'too many requests — try again later' }, 429));

  const body = await parseBody(request);
  const { email, password, display_name } = body || {};

  if (!email || !password)  return cors(json({ error: 'email and password are required' }, 400));
  if (!isValidEmail(email)) return cors(json({ error: 'invalid email address' }, 400));
  if (password.length < 8)  return cors(json({ error: 'password must be at least 8 characters' }, 400));

  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?')
    .bind(email.toLowerCase()).first();
  if (existing) return cors(json({ error: 'email already registered' }, 409));

  const hash   = await hashPassword(password);
  const result = await env.DB.prepare(
    'INSERT INTO users (email, password_hash, display_name) VALUES (?, ?, ?) RETURNING id, email, display_name, created_at'
  ).bind(email.toLowerCase(), hash, display_name || null).first();

  // Send verification email (non-blocking)
  const { code, codeHash, rawToken, linkHash } = await makeEmailToken();
  const emailExpiresAt = isoFromNow(EMAIL_TTL_MIN * 60);
  await env.DB.batch([
    env.DB.prepare('INSERT INTO email_tokens (token_hash, user_id, type, expires_at) VALUES (?, ?, ?, ?)')
      .bind(codeHash,  result.id, 'verify', emailExpiresAt),
    env.DB.prepare('INSERT INTO email_tokens (token_hash, user_id, type, expires_at) VALUES (?, ?, ?, ?)')
      .bind(linkHash, result.id, 'verify', emailExpiresAt),
  ]);
  sendEmail(env, email, 'Verify your ToMenu account', verifyEmailHtml(code, rawToken)).catch(console.error);

  // Auto-generate a unique handle from display_name or email prefix
  const autoHandle = await generateHandle(env, display_name || email.split('@')[0]);
  await env.DB.prepare('UPDATE users SET nickname = ? WHERE id = ?').bind(autoHandle, result.id).run();

  const { token, tokenHash, expiresAt } = await makeToken();
  await env.DB.prepare(
    'INSERT INTO sessions (id, user_id, expires_at, user_agent, ip) VALUES (?, ?, ?, ?, ?)'
  ).bind(tokenHash, result.id, expiresAt, request.headers.get('User-Agent') || null, ip).run();

  return cors(json({
    token,
    expires_at: expiresAt,
    user: publicUser({ ...result, email_verified: 0, is_premium: 0, nickname: autoHandle, totp_enabled: 0 }),
  }, 201));
}

// ── Login ─────────────────────────────────────────────────────────────────────

async function handleLogin(request, env) {
  const ip = ip_(request);
  if (await rateLimit(env, ip, 'login', RATE_LIMITS.login))
    return cors(json({ error: 'too many login attempts — try again later' }, 429));

  const body = await parseBody(request);
  const { email, password, totp_code } = body || {};
  if (!email || !password) return cors(json({ error: 'email and password are required' }, 400));

  const user = await env.DB.prepare(
    'SELECT id, email, password_hash, display_name, nickname, created_at, is_premium, email_verified, totp_secret, totp_enabled FROM users WHERE email = ?'
  ).bind(email.toLowerCase()).first();

  const dummy = 'pbkdf2:100000:00000000000000000000000000000000:00000000000000000000000000000000';
  const match = user
    ? await verifyPassword(password, user.password_hash)
    : await verifyPassword(password, dummy).catch(() => false);
  if (!user || !match) return cors(json({ error: 'invalid email or password' }, 401));

  // If 2FA enabled and no code provided yet — signal Flutter to show TOTP step
  if (user.totp_enabled) {
    if (!totp_code) return cors(json({ totp_required: true }, 200));
    if (await rateLimit(env, ip, 'totp-verify', RATE_LIMITS['totp-verify']))
      return cors(json({ error: 'too many attempts' }, 429));
    if (!await verifyTotp(user.totp_secret, totp_code))
      return cors(json({ error: 'invalid 2FA code' }, 401));
  }

  const { token, tokenHash, expiresAt } = await makeToken();
  await env.DB.prepare(
    'INSERT INTO sessions (id, user_id, expires_at, user_agent, ip) VALUES (?, ?, ?, ?, ?)'
  ).bind(tokenHash, user.id, expiresAt, request.headers.get('User-Agent') || null, ip).run();

  return cors(json({ token, expires_at: expiresAt, user: publicUser(user) }));
}

// ── Logout ────────────────────────────────────────────────────────────────────

async function handleLogout(request, env) {
  const { tokenHash, error } = await extractToken(request);
  if (error) return cors(json({ error }, 401));
  await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(tokenHash).run();
  return cors(json({ ok: true }));
}

// ── Me ────────────────────────────────────────────────────────────────────────

async function handleMe(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return cors(json({ error }, 401));
  return cors(json({ user: publicUser(user) }));
}

// ── Update profile ────────────────────────────────────────────────────────────

async function handleUpdateProfile(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return cors(json({ error }, 401));

  const body = await parseBody(request);
  const { display_name, nickname } = body || {};
  const updates = [], bindings = [];

  if (display_name !== undefined) {
    if (typeof display_name !== 'string' || !display_name.trim())
      return cors(json({ error: 'display_name must be a non-empty string' }, 400));
    if (display_name.trim().length > 50)
      return cors(json({ error: 'display_name too long (max 50 chars)' }, 400));
    updates.push('display_name = ?');
    bindings.push(display_name.trim());
  }

  if (nickname !== undefined) {
    if (!nickname || nickname === '') {
      updates.push('nickname = ?');
      bindings.push(null);
    } else {
      const clean = nickname.replace(/^@/, '').trim();
      if (!/^[a-zA-Z0-9_.\-]{3,24}$/.test(clean))
        return cors(json({ error: 'nickname must be 3–24 chars: letters, numbers, _ . -' }, 400));

      // 7-day cooldown on nickname changes
      if (user.nickname_changed_at) {
        const daysSince = (Date.now() - new Date(user.nickname_changed_at).getTime()) / 86_400_000;
        if (daysSince < DISPLAY_NAME_COOLDOWN_DAYS) {
          const next = new Date(new Date(user.nickname_changed_at).getTime() + DISPLAY_NAME_COOLDOWN_DAYS * 86_400_000);
          return cors(json({
            error: 'nickname can only be changed once per week',
            next_allowed_at: next.toISOString(),
          }, 429));
        }
      }
      updates.push('nickname = ?', 'nickname_changed_at = ?');
      bindings.push(clean, new Date().toISOString());
    }
  }

  if (!updates.length) return cors(json({ error: 'nothing to update' }, 400));

  bindings.push(user.id);
  await env.DB.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).bind(...bindings).run();

  const updated = await env.DB.prepare(
    'SELECT id, email, display_name, nickname, created_at, is_premium, email_verified, totp_enabled, display_name_changed_at, nickname_changed_at FROM users WHERE id = ?'
  ).bind(user.id).first();

  return cors(json({ user: publicUser(updated) }));
}

// ── Verify email via magic link (GET from email button) ───────────────────────

async function handleVerifyEmailLink(request, env) {
  const url   = new URL(request.url);
  const token = url.searchParams.get('token');
  if (!token) return htmlPage('Invalid link', 'This verification link is missing a token.', false);

  const tokenHash = await hashEmailCode(token);
  const row = await env.DB.prepare(`
    SELECT et.token_hash, et.user_id FROM email_tokens et
    WHERE et.token_hash = ? AND et.type = 'verify'
      AND et.expires_at > datetime('now') AND et.used = 0
  `).bind(tokenHash).first();

  if (!row) return htmlPage('Link expired', 'This verification link has already been used or has expired. Open the ToMenu app and request a new one.', false);

  await env.DB.batch([
    env.DB.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').bind(row.user_id),
    env.DB.prepare("UPDATE email_tokens SET used = 1 WHERE user_id = ? AND type = 'verify'").bind(row.user_id),
  ]);

  return htmlPage('Email verified!', 'Your ToMenu account is now verified. You can close this tab and return to the app.', true);
}

function htmlPage(title, message, success) {
  const color = success ? '#ff6b35' : '#888';
  const icon  = success ? '✓' : '✕';
  return new Response(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} — ToMenu</title></head>
<body style="font-family:sans-serif;max-width:420px;margin:80px auto;padding:0 24px;text-align:center">
  <div style="font-size:64px;color:${color}">${icon}</div>
  <h1 style="color:${color};font-size:24px;margin:16px 0 8px">${title}</h1>
  <p style="color:#555;font-size:15px;line-height:1.5">${message}</p>
  ${success ? '<p style="margin-top:32px"><a href="tomenu://verified" style="background:#ff6b35;color:#fff;padding:12px 28px;border-radius:10px;text-decoration:none;font-weight:700">Open ToMenu</a></p>' : ''}
</body></html>`, {
    status: success ? 200 : 400,
    headers: { 'Content-Type': 'text/html;charset=utf-8' },
  });
}

// ── Verify email via manual code (POST) ───────────────────────────────────────

async function handleVerifyEmail(request, env) {
  const body = await parseBody(request);
  const { email, code } = body || {};
  if (!email || !code) return cors(json({ error: 'email and code are required' }, 400));

  const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?')
    .bind(email.toLowerCase()).first();
  if (!user) return cors(json({ error: 'invalid code' }, 400));

  const codeHash = await hashEmailCode(code.toString().trim());
  const token = await env.DB.prepare(`
    SELECT token_hash FROM email_tokens
    WHERE token_hash = ? AND user_id = ? AND type = 'verify'
      AND expires_at > datetime('now') AND used = 0
  `).bind(codeHash, user.id).first();
  if (!token) return cors(json({ error: 'invalid or expired code' }, 400));

  await env.DB.batch([
    env.DB.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').bind(user.id),
    env.DB.prepare('UPDATE email_tokens SET used = 1 WHERE token_hash = ?').bind(codeHash),
  ]);

  return cors(json({ ok: true, message: 'email verified' }));
}

// ── Resend verification ───────────────────────────────────────────────────────

async function handleResendVerification(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return cors(json({ error }, 401));
  if (user.email_verified) return cors(json({ error: 'email already verified' }, 400));

  if (await rateLimit(env, ip_(request), 'resend-verify', RATE_LIMITS['resend-verify']))
    return cors(json({ error: 'too many requests' }, 429));

  await env.DB.prepare("UPDATE email_tokens SET used = 1 WHERE user_id = ? AND type = 'verify'")
    .bind(user.id).run();

  const { code, codeHash, rawToken, linkHash } = await makeEmailToken();
  const emailExpiresAt = isoFromNow(EMAIL_TTL_MIN * 60);
  await env.DB.batch([
    env.DB.prepare('INSERT INTO email_tokens (token_hash, user_id, type, expires_at) VALUES (?, ?, ?, ?)')
      .bind(codeHash,  user.id, 'verify', emailExpiresAt),
    env.DB.prepare('INSERT INTO email_tokens (token_hash, user_id, type, expires_at) VALUES (?, ?, ?, ?)')
      .bind(linkHash, user.id, 'verify', emailExpiresAt),
  ]);
  await sendEmail(env, user.email, 'Verify your ToMenu account', verifyEmailHtml(code, rawToken));

  return cors(json({ ok: true }));
}

// ── Forgot password ───────────────────────────────────────────────────────────

async function handleForgotPassword(request, env) {
  if (await rateLimit(env, ip_(request), 'forgot-password', RATE_LIMITS['forgot-password']))
    return cors(json({ error: 'too many requests' }, 429));

  const { email } = await parseBody(request) || {};
  if (!email) return cors(json({ error: 'email is required' }, 400));

  // Always return success — prevents email enumeration
  const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?')
    .bind(email.toLowerCase()).first();

  if (user) {
    await env.DB.prepare("UPDATE email_tokens SET used = 1 WHERE user_id = ? AND type = 'reset'")
      .bind(user.id).run();
    const { code, codeHash } = await makeEmailToken();
    await env.DB.prepare('INSERT INTO email_tokens (token_hash, user_id, type, expires_at) VALUES (?, ?, ?, ?)')
      .bind(codeHash, user.id, 'reset', isoFromNow(RESET_TTL_MIN * 60)).run();
    sendEmail(env, email, 'Reset your ToMenu password', resetEmailHtml(code)).catch(console.error);
  }

  return cors(json({ ok: true, message: 'if that email exists, a reset code was sent' }));
}

// ── Reset password ────────────────────────────────────────────────────────────

async function handleResetPassword(request, env) {
  const body = await parseBody(request);
  const { email, code, new_password } = body || {};
  if (!email || !code || !new_password)
    return cors(json({ error: 'email, code and new_password are required' }, 400));
  if (new_password.length < 8)
    return cors(json({ error: 'password must be at least 8 characters' }, 400));

  const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?')
    .bind(email.toLowerCase()).first();
  if (!user) return cors(json({ error: 'invalid code' }, 400));

  const codeHash = await hashEmailCode(code.toString().trim());
  const token = await env.DB.prepare(`
    SELECT token_hash FROM email_tokens
    WHERE token_hash = ? AND user_id = ? AND type = 'reset'
      AND expires_at > datetime('now') AND used = 0
  `).bind(codeHash, user.id).first();
  if (!token) return cors(json({ error: 'invalid or expired code' }, 400));

  const newHash = await hashPassword(new_password);
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(newHash, user.id),
    env.DB.prepare('UPDATE email_tokens SET used = 1 WHERE token_hash = ?').bind(codeHash),
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id), // revoke all
  ]);

  return cors(json({ ok: true, message: 'password reset — please log in again' }));
}

// ── TOTP setup ────────────────────────────────────────────────────────────────

async function handleTotpSetup(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return cors(json({ error }, 401));
  if (user.totp_enabled) return cors(json({ error: '2FA already enabled' }, 400));

  const secret  = generateTotpSecret();
  const otpauth = `otpauth://totp/ToMenu:${encodeURIComponent(user.email)}?secret=${secret}&issuer=ToMenu&algorithm=SHA1&digits=6&period=30`;

  await env.DB.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').bind(secret, user.id).run();

  return cors(json({ secret, otpauth_url: otpauth }));
}

// ── TOTP confirm ──────────────────────────────────────────────────────────────

async function handleTotpConfirm(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return cors(json({ error }, 401));
  if (!user.totp_secret) return cors(json({ error: 'call /auth/totp/setup first' }, 400));

  const { code } = await parseBody(request) || {};
  if (!code) return cors(json({ error: 'code is required' }, 400));
  if (!await verifyTotp(user.totp_secret, code.toString().trim()))
    return cors(json({ error: 'invalid code — check your authenticator app and try again' }, 400));

  await env.DB.prepare('UPDATE users SET totp_enabled = 1 WHERE id = ?').bind(user.id).run();
  return cors(json({ ok: true, message: '2FA enabled' }));
}

// ── TOTP verify (used when 2FA login flow requires separate step) ─────────────

async function handleTotpVerify(request, env) {
  const ip = ip_(request);
  if (await rateLimit(env, ip, 'totp-verify', RATE_LIMITS['totp-verify']))
    return cors(json({ error: 'too many attempts' }, 429));

  const body = await parseBody(request);
  const { email, password, code } = body || {};
  if (!email || !password || !code)
    return cors(json({ error: 'email, password and code are required' }, 400));

  const user = await env.DB.prepare(
    'SELECT id, email, password_hash, display_name, nickname, created_at, is_premium, email_verified, totp_secret, totp_enabled FROM users WHERE email = ?'
  ).bind(email.toLowerCase()).first();

  if (!user || !await verifyPassword(password, user.password_hash))
    return cors(json({ error: 'invalid credentials' }, 401));
  if (!user.totp_enabled || !user.totp_secret)
    return cors(json({ error: '2FA not enabled on this account' }, 400));
  if (!await verifyTotp(user.totp_secret, code.toString().trim()))
    return cors(json({ error: 'invalid 2FA code' }, 401));

  const { token, tokenHash, expiresAt } = await makeToken();
  await env.DB.prepare(
    'INSERT INTO sessions (id, user_id, expires_at, user_agent, ip) VALUES (?, ?, ?, ?, ?)'
  ).bind(tokenHash, user.id, expiresAt, request.headers.get('User-Agent') || null, ip).run();

  return cors(json({ token, expires_at: expiresAt, user: publicUser(user) }));
}

// ── TOTP disable ──────────────────────────────────────────────────────────────

async function handleTotpDisable(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return cors(json({ error }, 401));

  const { code } = await parseBody(request) || {};
  if (!code) return cors(json({ error: 'authenticator code is required to disable 2FA' }, 400));
  if (!await verifyTotp(user.totp_secret, code.toString().trim()))
    return cors(json({ error: 'invalid 2FA code' }, 401));

  await env.DB.prepare('UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?')
    .bind(user.id).run();

  return cors(json({ ok: true, message: '2FA disabled' }));
}

// ── Revoke all sessions ───────────────────────────────────────────────────────

async function handleRevokeAll(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return cors(json({ error }, 401));
  const result = await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run();
  return cors(json({ ok: true, sessions_revoked: result.meta?.changes ?? 0 }));
}

// ── Email sending (Resend) ────────────────────────────────────────────────────

async function sendEmail(env, to, subject, html) {
  if (!env.RESEND_API_KEY) throw new Error('RESEND_API_KEY secret not set');

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type':  'application/json',
    },
    body: JSON.stringify({
      from:    'ToMenu <noreply@tomenu.sk>',
      to:      [to],
      subject,
      html,
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Resend ${res.status}: ${text}`);
  }
}

function verifyEmailHtml(code, rawToken) {
  const link = `https://auth.tomenu.sk/auth/verify-email?token=${rawToken}`;
  return `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="font-family:sans-serif;max-width:480px;margin:40px auto;padding:0 24px;background:#fff">
  <h2 style="color:#ff6b35;margin-bottom:4px">ToMenu</h2>
  <p style="color:#333;font-size:15px">Tap the button below to verify your email address:</p>

  <div style="text-align:center;margin:32px 0">
    <a href="${link}"
       style="background:#ff6b35;color:#fff;padding:16px 40px;border-radius:12px;
              text-decoration:none;font-size:17px;font-weight:700;display:inline-block">
      Verify my account
    </a>
  </div>

  <hr style="border:none;border-top:1px solid #eee;margin:24px 0">

  <p style="color:#888;font-size:13px">Or enter this code manually in the app:</p>
  <div style="font-size:40px;font-weight:800;letter-spacing:8px;color:#ff6b35;margin:8px 0 16px">${code}</div>

  <p style="color:#aaa;font-size:12px">Expires in ${EMAIL_TTL_MIN} minutes. If you didn't create a ToMenu account, ignore this email.</p>
  <p style="color:#aaa;font-size:11px;word-break:break-all">Link: <a href="${link}" style="color:#aaa">${link}</a></p>
</body></html>`;
}

function resetEmailHtml(code) {
  return `<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:480px;margin:40px auto;padding:0 24px">
    <h2 style="color:#ff6b35;margin-bottom:4px">ToMenu</h2>
    <p style="color:#333">Your password reset code:</p>
    <div style="font-size:48px;font-weight:800;letter-spacing:10px;color:#ff6b35;margin:24px 0">${code}</div>
    <p style="color:#888;font-size:13px">Expires in ${RESET_TTL_MIN} minutes. If you didn't request a reset, ignore this email.</p>
  </body></html>`;
}

// ── TOTP — RFC 6238 ───────────────────────────────────────────────────────────

function generateTotpSecret(len = 20) {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  return Array.from(crypto.getRandomValues(new Uint8Array(len)))
    .map(b => alpha[b % 32]).join('');
}

function base32Decode(str) {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0;
  const out = [];
  for (const ch of str.toUpperCase().replace(/=+$/, '')) {
    value = (value << 5) | alpha.indexOf(ch);
    bits += 5;
    if (bits >= 8) { bits -= 8; out.push((value >> bits) & 0xff); }
  }
  return new Uint8Array(out);
}

async function totpCode(secret, time = Date.now()) {
  const counter = Math.floor(time / 1000 / 30);
  const msg     = new ArrayBuffer(8);
  new DataView(msg).setUint32(4, counter);  // big-endian 64-bit
  const key  = await crypto.subtle.importKey(
    'raw', base32Decode(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const hash = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const off  = hash[hash.length - 1] & 0xf;
  const code = (
    ((hash[off]   & 0x7f) << 24) |
    ((hash[off+1] & 0xff) << 16) |
    ((hash[off+2] & 0xff) <<  8) |
     (hash[off+3] & 0xff)
  ) % 1_000_000;
  return code.toString().padStart(6, '0');
}

async function verifyTotp(secret, input) {
  const now = Date.now();
  // Accept current window ± 1 step (handles ~30s clock drift)
  for (const drift of [-30_000, 0, 30_000]) {
    const expected = await totpCode(secret, now + drift);
    if (timingSafeEqual(expected, input.toString().padStart(6, '0'))) return true;
  }
  return false;
}

// ── Auth helpers ──────────────────────────────────────────────────────────────

async function requireAuth(request, env) {
  const { tokenHash, error } = await extractToken(request);
  if (error) return { error };

  const row = await env.DB.prepare(`
    SELECT s.user_id, u.email, u.display_name, u.nickname, u.created_at,
           u.is_premium, u.email_verified, u.totp_secret, u.totp_enabled,
           u.display_name_changed_at, u.nickname_changed_at
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.id = ? AND s.expires_at > datetime('now')
  `).bind(tokenHash).first();

  if (!row) return { error: 'session expired or invalid' };

  // expose id as user_id alias
  return { user: { ...row, id: row.user_id } };
}

async function extractToken(request) {
  const header = request.headers.get('Authorization') || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
  if (!token) return { error: 'missing Authorization header' };
  try {
    const hashBuf   = await crypto.subtle.digest('SHA-256', hexToBuf(token));
    const tokenHash = bufToHex(new Uint8Array(hashBuf));
    return { tokenHash };
  } catch {
    return { error: 'malformed token' };
  }
}

function publicUser(u) {
  return {
    id:                      u.id   ?? u.user_id,
    email:                   u.email,
    display_name:            u.display_name             ?? null,
    nickname:                u.nickname                 ?? null,
    created_at:              u.created_at,
    is_premium:              !!u.is_premium,
    email_verified:          !!u.email_verified,
    totp_enabled:            !!u.totp_enabled,
    display_name_changed_at: u.display_name_changed_at  ?? null,
    nickname_changed_at:     u.nickname_changed_at      ?? null,
  };
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const key  = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, key, 256
  );
  return `pbkdf2:${PBKDF2_ITERATIONS}:${bufToHex(salt)}:${bufToHex(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
  const parts = stored.split(':');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const [, iters, saltHex, storedHash] = parts;
  const key  = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hexToBuf(saltHex), iterations: parseInt(iters, 10), hash: 'SHA-256' },
    key, 256
  );
  return timingSafeEqual(bufToHex(new Uint8Array(bits)), storedHash);
}

async function makeToken() {
  const buf       = crypto.getRandomValues(new Uint8Array(TOKEN_BYTES));
  const hash      = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
  return {
    token:     bufToHex(buf),
    tokenHash: bufToHex(hash),
    expiresAt: isoFromNow(SESSION_TTL_DAYS * 86400),
  };
}

async function makeEmailToken() {
  const rawToken  = bufToHex(crypto.getRandomValues(new Uint8Array(16)));
  const linkHash  = await hashEmailCode(rawToken);                          // for magic link
  const code      = Math.floor(100_000 + Math.random() * 900_000).toString();
  const codeHash  = await hashEmailCode(code);                              // for manual entry
  return { code, codeHash, rawToken, linkHash };
}

async function hashEmailCode(code) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(code.trim()));
  return bufToHex(new Uint8Array(buf));
}

async function rateLimit(env, key, endpoint, { max, windowSec }) {
  const k     = `rl:${key}:${endpoint}`;
  const count = parseInt(await env.RATE_LIMITS.get(k) || '0', 10);
  if (count >= max) return true;
  await env.RATE_LIMITS.put(k, String(count + 1), { expirationTtl: windowSec });
  return false;
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

function isoFromNow(seconds) {
  return new Date(Date.now() + seconds * 1000).toISOString().replace('T', ' ').slice(0, 19);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function cors(response) {
  const r = new Response(response.body, response);
  r.headers.set('Access-Control-Allow-Origin', '*');
  r.headers.set('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  r.headers.set('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  return r;
}

async function parseBody(req) {
  try { return await req.json(); } catch { return null; }
}

function isValidEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); }
function ip_(req)         { return req.headers.get('CF-Connecting-IP') || 'unknown'; }
function bufToHex(buf)    { return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join(''); }

function hexToBuf(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return b;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ── Google OAuth ──────────────────────────────────────────────────────────────
//
// Flow:
//   1. Flutter calls google_sign_in → gets an ID token (JWT) from Google
//   2. Flutter sends { id_token } to POST /auth/oauth/google
//   3. Worker verifies the JWT against Google's public keys
//   4. Worker finds or creates user in D1, links oauth_providers row
//   5. Returns { token, user } — same shape as /auth/login
//
// Optionally: if the request has a valid Bearer token, the Google account is
// LINKED to the existing session user instead of creating a new session.

async function handleOAuthGoogle(request, env) {
  const ip = ip_(request);
  if (await rateLimit(env, ip, 'oauth', RATE_LIMITS.oauth))
    return cors(json({ error: 'too many requests' }, 429));

  const body = await parseBody(request);
  const { id_token } = body || {};
  if (!id_token) return cors(json({ error: 'id_token is required' }, 400));

  // Verify the Google ID token
  let googleUser;
  try {
    googleUser = await verifyGoogleIdToken(id_token, env);
  } catch (err) {
    console.error('Google token verify failed:', err.message);
    return cors(json({ error: 'invalid Google token' }, 401));
  }

  const { sub: googleId, email, email_verified } = googleUser;
  if (!email) return cors(json({ error: 'Google account has no email' }, 400));

  // Check if this is a link request (user already logged in)
  const { user: sessionUser } = await requireAuth(request, env).catch(() => ({ user: null }));

  if (sessionUser) {
    // ── Link mode: attach Google to existing account ──
    const existing = await env.DB.prepare(
      'SELECT user_id FROM oauth_providers WHERE provider = ? AND provider_id = ?'
    ).bind('google', googleId).first();

    if (existing && existing.user_id !== sessionUser.id)
      return cors(json({ error: 'This Google account is linked to a different ToMenu account' }, 409));

    if (!existing) {
      await env.DB.prepare(
        'INSERT INTO oauth_providers (user_id, provider, provider_id, email) VALUES (?, ?, ?, ?)'
      ).bind(sessionUser.id, 'google', googleId, email).run();
    }

    const updated = await env.DB.prepare(
      'SELECT id, email, display_name, nickname, created_at, is_premium, email_verified, totp_enabled, display_name_changed_at, nickname_changed_at FROM users WHERE id = ?'
    ).bind(sessionUser.id).first();
    return cors(json({ linked: true, user: publicUser(updated) }));
  }

  // ── Login / register mode ──
  // 1. Check if this Google ID is already linked to an account
  let userId;
  const oauthRow = await env.DB.prepare(
    'SELECT user_id FROM oauth_providers WHERE provider = ? AND provider_id = ?'
  ).bind('google', googleId).first();

  if (oauthRow) {
    userId = oauthRow.user_id;
  } else {
    // 2. Check if email already exists as a ToMenu account → auto-link
    const emailUser = await env.DB.prepare('SELECT id FROM users WHERE email = ?')
      .bind(email.toLowerCase()).first();

    if (emailUser) {
      userId = emailUser.id;
      await env.DB.prepare(
        'INSERT INTO oauth_providers (user_id, provider, provider_id, email) VALUES (?, ?, ?, ?)'
      ).bind(userId, 'google', googleId, email).run();
    } else {
      // 3. Brand new user — create account (no password)
      const displayName = googleUser.name || email.split('@')[0];
      const newUser = await env.DB.prepare(
        'INSERT INTO users (email, password_hash, display_name, email_verified) VALUES (?, ?, ?, ?) RETURNING id'
      ).bind(email.toLowerCase(), '', displayName, email_verified ? 1 : 0).first();
      userId = newUser.id;
      const autoHandle = await generateHandle(env, displayName || email.split('@')[0]);
      await env.DB.prepare('UPDATE users SET nickname = ? WHERE id = ?').bind(autoHandle, userId).run();
      await env.DB.prepare(
        'INSERT INTO oauth_providers (user_id, provider, provider_id, email) VALUES (?, ?, ?, ?)'
      ).bind(userId, 'google', googleId, email).run();
    }
  }

  // Create session
  const { token, tokenHash, expiresAt } = await makeToken();
  await env.DB.prepare(
    'INSERT INTO sessions (id, user_id, expires_at, user_agent, ip) VALUES (?, ?, ?, ?, ?)'
  ).bind(tokenHash, userId, expiresAt, request.headers.get('User-Agent') || null, ip).run();

  const user = await env.DB.prepare(
    'SELECT id, email, display_name, nickname, created_at, is_premium, email_verified, totp_enabled, display_name_changed_at, nickname_changed_at FROM users WHERE id = ?'
  ).bind(userId).first();

  return cors(json({ token, expires_at: expiresAt, user: publicUser(user) }));
}

async function handleOAuthProviders(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return cors(json({ error }, 401));
  const rows = await env.DB.prepare(
    'SELECT provider, email, created_at FROM oauth_providers WHERE user_id = ?'
  ).bind(user.id).all();
  return cors(json({ providers: rows.results }));
}

async function handleOAuthUnlink(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return cors(json({ error }, 401));
  const { provider } = await parseBody(request) || {};
  if (!provider) return cors(json({ error: 'provider is required' }, 400));

  // Safety: don't let them lock themselves out
  const hasPassword = await env.DB.prepare('SELECT password_hash FROM users WHERE id = ?')
    .bind(user.id).first();
  const otherProviders = await env.DB.prepare(
    'SELECT COUNT(*) as c FROM oauth_providers WHERE user_id = ? AND provider != ?'
  ).bind(user.id, provider).first();

  if (!hasPassword?.password_hash && otherProviders.c === 0)
    return cors(json({ error: 'Cannot unlink — set a password first or link another account' }, 400));

  await env.DB.prepare('DELETE FROM oauth_providers WHERE user_id = ? AND provider = ?')
    .bind(user.id, provider).run();
  return cors(json({ ok: true }));
}

// ── Google JWT verification ───────────────────────────────────────────────────
// Verifies Google ID tokens using Google's public keys (no external library needed)

async function verifyGoogleIdToken(idToken, env) {
  // Use Google tokeninfo endpoint - handles key rotation, expiry, and audience automatically
  const res = await fetch(
    `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`tokeninfo rejected: ${res.status} ${text}`);
  }
  const payload = await res.json();

  if (!payload.sub) throw new Error('no sub in token');

  // Verify it belongs to our app - check both aud and azp fields
  if (env.GOOGLE_CLIENT_IDS) {
    const allowed = env.GOOGLE_CLIENT_IDS.split(',').map(s => s.trim());
    if (!allowed.includes(payload.aud) && !allowed.includes(payload.azp))
      throw new Error(`wrong audience: aud="${payload.aud}" azp="${payload.azp}"`);
  }

  return payload;
}

// ── FCM Push Tokens ───────────────────────────────────────────────────────────

async function handleFcmRegister(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return cors(json({ error }, 401));
  const { token, platform = 'android' } = await parseBody(request) || {};
  if (!token) return cors(json({ error: 'token is required' }, 400));

  await env.DB.prepare(`
    INSERT INTO fcm_tokens (token, user_id, platform, last_seen)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(token) DO UPDATE SET user_id = excluded.user_id, last_seen = datetime('now')
  `).bind(token, user.id, platform).run();

  return cors(json({ ok: true }));
}

async function handleFcmRemove(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return cors(json({ error }, 401));
  const { token } = await parseBody(request) || {};
  if (token) {
    await env.DB.prepare('DELETE FROM fcm_tokens WHERE token = ? AND user_id = ?')
      .bind(token, user.id).run();
  } else {
    // Remove all tokens for this user (full logout)
    await env.DB.prepare('DELETE FROM fcm_tokens WHERE user_id = ?').bind(user.id).run();
  }
  return cors(json({ ok: true }));
}

// ── Send push notification ────────────────────────────────────────────────────
//
// POST /internal/notify
// Protected by INTERNAL_SECRET header (set as wrangler secret).
//
// Body:
//   { user_id: 4, title: "New menu!", body: "Koliba has lunch today", data: { screen: "home" } }
//   OR
//   { broadcast: true, title: "...", body: "..." }   ← sends to ALL users with tokens
//
// FCM HTTP v1 requires a short-lived OAuth2 access token signed with your
// Firebase service account private key. We do the full JWT flow here using
// only Web Crypto — no external libraries needed.
//
// Secrets required (set via wrangler secret put):
//   FCM_PROJECT_ID         — e.g. "tomenu-app"
//   FCM_CLIENT_EMAIL       — from service account JSON
//   FCM_PRIVATE_KEY        — from service account JSON (full PEM string)

async function handleSendNotification(request, env) {
  // Simple shared-secret auth for internal calls
  const secret = request.headers.get('X-Internal-Secret');
  if (!env.INTERNAL_SECRET || secret !== env.INTERNAL_SECRET)
    return json({ error: 'forbidden' }, 403);

  const body = await parseBody(request);
  const { user_id, broadcast, title, body: msgBody, data = {} } = body || {};

  if (!title || !msgBody) return json({ error: 'title and body are required' }, 400);
  if (!broadcast && !user_id) return json({ error: 'user_id or broadcast required' }, 400);

  // Get FCM tokens
  let tokens;
  if (broadcast) {
    const rows = await env.DB.prepare('SELECT token FROM fcm_tokens').all();
    tokens = rows.results.map(r => r.token);
  } else {
    const rows = await env.DB.prepare('SELECT token FROM fcm_tokens WHERE user_id = ?').bind(user_id).all();
    tokens = rows.results.map(r => r.token);
  }

  if (tokens.length === 0) return json({ ok: true, sent: 0, message: 'no tokens found' });

  // Get FCM access token
  let accessToken;
  try {
    accessToken = await getFcmAccessToken(env);
  } catch (err) {
    console.error('FCM auth error:', err.message);
    return json({ error: 'FCM authentication failed — check FCM secrets' }, 500);
  }

  // Send to all tokens (FCM v1 is one message per token)
  const results = await Promise.allSettled(
    tokens.map(token => sendFcmMessage(accessToken, env.FCM_PROJECT_ID, token, title, msgBody, data))
  );

  // Clean up invalid tokens (FCM returns 404 for unregistered tokens)
  const invalidTokens = [];
  results.forEach((result, i) => {
    if (result.status === 'fulfilled' && result.value?.invalid) {
      invalidTokens.push(tokens[i]);
    }
  });
  if (invalidTokens.length > 0) {
    await Promise.all(
      invalidTokens.map(t => env.DB.prepare('DELETE FROM fcm_tokens WHERE token = ?').bind(t).run())
    );
  }

  const sent    = results.filter(r => r.status === 'fulfilled' && !r.value?.invalid).length;
  const failed  = results.length - sent;
  return json({ ok: true, sent, failed, cleaned_up: invalidTokens.length });
}

async function sendFcmMessage(accessToken, projectId, deviceToken, title, body, data = {}) {
  const res = await fetch(
    `https://fcm.googleapis.com/v1/projects/${projectId}/messages:send`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        message: {
          token: deviceToken,
          notification: { title, body },
          android: {
            priority: 'high',
            notification: { sound: 'default', click_action: 'FLUTTER_NOTIFICATION_CLICK' },
          },
          data: Object.fromEntries(Object.entries(data).map(([k, v]) => [k, String(v)])),
        },
      }),
    }
  );

  if (res.status === 404) return { invalid: true };  // unregistered token
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`FCM ${res.status}: ${text}`);
  }
  return { ok: true };
}

// ── FCM OAuth2 — sign a JWT with the service account private key ──────────────
// Google requires a short-lived (1hr) OAuth2 token. We mint a JWT ourselves
// using the RSA private key from the Firebase service account JSON.

async function getFcmAccessToken(env) {
  const { FCM_CLIENT_EMAIL, FCM_PRIVATE_KEY } = env;
  if (!FCM_CLIENT_EMAIL || !FCM_PRIVATE_KEY)
    throw new Error('FCM_CLIENT_EMAIL and FCM_PRIVATE_KEY secrets not set');

  const now     = Math.floor(Date.now() / 1000);
  const header  = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const payload = btoa(JSON.stringify({
    iss:   FCM_CLIENT_EMAIL,
    sub:   FCM_CLIENT_EMAIL,
    aud:   'https://oauth2.googleapis.com/token',
    iat:   now,
    exp:   now + 3600,
    scope: 'https://www.googleapis.com/auth/firebase.messaging',
  })).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

  const signingInput = new TextEncoder().encode(`${header}.${payload}`);

  // Import RSA private key from PEM
  const pemBody = FCM_PRIVATE_KEY
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s+/g, '');
  const keyDer = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));
  const privateKey = await crypto.subtle.importKey(
    'pkcs8', keyDer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['sign']
  );

  const sigBuf = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, signingInput);
  const sig    = btoa(String.fromCharCode(...new Uint8Array(sigBuf))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const jwt    = `${header}.${payload}.${sig}`;

  // Exchange JWT for access token
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`OAuth2 token exchange failed: ${text}`);
  }

  const { access_token } = await res.json();
  return access_token;
}

// ── Notification preferences ──────────────────────────────────────────────────

async function handleGetNotifyPrefs(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return cors(json({ error }, 401));
  const row = await env.DB.prepare(
    'SELECT notify_enabled, notify_time FROM users WHERE id = ?'
  ).bind(user.id).first();
  return cors(json({ notify_enabled: !!row.notify_enabled, notify_time: row.notify_time ?? '10:30' }));
}

async function handleSetNotifyPrefs(request, env) {
  const { user, error } = await requireAuth(request, env);
  if (error) return cors(json({ error }, 401));
  const { notify_enabled, notify_time } = await parseBody(request) || {};

  const updates = [], bindings = [];

  if (notify_enabled !== undefined) {
    updates.push('notify_enabled = ?');
    bindings.push(notify_enabled ? 1 : 0);
  }
  if (notify_time !== undefined) {
    // Validate HH:MM format
    if (!/^\d{2}:\d{2}$/.test(notify_time)) 
      return cors(json({ error: 'notify_time must be in HH:MM format' }, 400));
    updates.push('notify_time = ?');
    bindings.push(notify_time);
  }

  if (!updates.length) return cors(json({ error: 'nothing to update' }, 400));
  bindings.push(user.id);
  await env.DB.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).bind(...bindings).run();
  return cors(json({ ok: true, notify_enabled: !!notify_enabled, notify_time: notify_time ?? '10:30' }));
}

// ── Cron: daily lunch reminder ────────────────────────────────────────────────
// Runs every minute via Cloudflare cron trigger.
// Add to wrangler.toml:
//   [triggers]
//   crons = ["* * * * *"]

export default {
  fetch: (request, env) => {
    // delegate to the main router defined at top of file
    const url    = new URL(request.url);
    const method = request.method;
    const path   = url.pathname;
    if (method === 'OPTIONS') return cors(new Response(null, { status: 204 }));
    try {
      if (method === 'POST'   && path === '/auth/register')            return handleRegister(request, env);
      if (method === 'POST'   && path === '/auth/login')               return handleLogin(request, env);
      if (method === 'POST'   && path === '/auth/logout')              return handleLogout(request, env);
      if (method === 'GET'    && path === '/auth/me')                  return handleMe(request, env);
      if (method === 'PATCH'  && path === '/auth/me')                  return handleUpdateProfile(request, env);
      if (method === 'DELETE' && path === '/auth/sessions')            return handleRevokeAll(request, env);
      if (method === 'GET'    && path === '/auth/verify-email')        return handleVerifyEmailLink(request, env);
      if (method === 'POST'   && path === '/auth/verify-email')        return handleVerifyEmail(request, env);
      if (method === 'POST'   && path === '/auth/resend-verification') return handleResendVerification(request, env);
      if (method === 'POST'   && path === '/auth/forgot-password')     return handleForgotPassword(request, env);
      if (method === 'POST'   && path === '/auth/reset-password')      return handleResetPassword(request, env);
      if (method === 'POST'   && path === '/auth/totp/setup')          return handleTotpSetup(request, env);
      if (method === 'POST'   && path === '/auth/totp/confirm')        return handleTotpConfirm(request, env);
      if (method === 'POST'   && path === '/auth/totp/verify')         return handleTotpVerify(request, env);
      if (method === 'DELETE' && path === '/auth/totp')                return handleTotpDisable(request, env);
      if (method === 'POST'   && path === '/auth/oauth/google')        return handleOAuthGoogle(request, env);
      if (method === 'DELETE' && path === '/auth/oauth/unlink')        return handleOAuthUnlink(request, env);
      if (method === 'GET'    && path === '/auth/oauth/providers')     return handleOAuthProviders(request, env);
      if (method === 'POST'   && path === '/auth/fcm')                 return handleFcmRegister(request, env);
      if (method === 'DELETE' && path === '/auth/fcm')                 return handleFcmRemove(request, env);
      if (method === 'POST'   && path === '/internal/notify')          return handleSendNotification(request, env);
      if (method === 'GET'    && path === '/auth/notify-prefs')        return handleGetNotifyPrefs(request, env);
      if (method === 'PATCH'  && path === '/auth/notify-prefs')        return handleSetNotifyPrefs(request, env);
      if (method === 'GET'    && path === '/health')                   return cors(json({ ok: true }));
      return cors(json({ error: 'not found' }, 404));
    } catch (err) {
      console.error(err);
      return cors(json({ error: 'internal server error' }, 500));
    }
  },

  async scheduled(event, env, ctx) {
    const now   = new Date();
    const hh    = now.getUTCHours().toString().padStart(2, '0');
    const mm    = now.getUTCMinutes().toString().padStart(2, '0');
    const time  = `${hh}:${mm}`;

    // Find all users with notifications enabled at this time who have FCM tokens
    const rows = await env.DB.prepare(`
      SELECT u.id, u.display_name, f.token
      FROM users u
      JOIN fcm_tokens f ON f.user_id = u.id
      WHERE u.notify_enabled = 1 AND u.notify_time = ?
    `).bind(time).all();

    if (rows.results.length === 0) return;

    let accessToken;
    try {
      accessToken = await getFcmAccessToken(env);
    } catch (err) {
      console.error('Cron FCM auth error:', err.message);
      return;
    }

    const results = await Promise.allSettled(
      rows.results.map(row =>
        sendFcmMessage(
          accessToken,
          env.FCM_PROJECT_ID,
          row.token,
          '🍽️ Lunch time!',
          'Today\'s menus are ready. Check what\'s for lunch!',
          { screen: 'home' }
        )
      )
    );

    // Clean up invalid tokens
    const invalidTokens = rows.results
      .filter((_, i) => results[i].status === 'fulfilled' && results[i].value?.invalid)
      .map(r => r.token);

    if (invalidTokens.length > 0) {
      await Promise.all(
        invalidTokens.map(t => env.DB.prepare('DELETE FROM fcm_tokens WHERE token = ?').bind(t).run())
      );
    }

    console.log(`Cron ${time}: sent ${results.filter(r => r.status === 'fulfilled' && !r.value?.invalid).length}, cleaned ${invalidTokens.length} invalid tokens`);
  },
};