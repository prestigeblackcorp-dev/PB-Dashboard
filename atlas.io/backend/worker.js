/* Atlas Rental.io - Cloudflare Worker (the ONLY real authority)
 *
 * The client is an untrusted rendering layer. Identity, tenant, role, plan, comp
 * status and every dollar amount are decided HERE, from a verified session cookie -
 * never from the request body or a client flag.
 *
 * Bindings (wrangler.toml):
 *   [[d1_databases]] binding = "DB"        database_name = "atlas"
 * Secrets (wrangler secret put ...):
 *   SESSION_KEY   - 32+ random bytes (HMAC/enc base for anything signed)
 *   ENC_KEY       - 32-byte base64 (AES-GCM key for integration secrets at rest; ciphertext is AAD-bound to tenant+provider)
 *   ENC_KEY_2     - optional 32-byte base64; when set, new writes use it (key rotation) while ENC_KEY still decrypts old blobs
 *   OWNER_EMAIL   - the platform owner's email (always admin)
 *   STRIPE_SECRET, STRIPE_WEBHOOK_SECRET, RESEND_KEY, TWILIO_SID, TWILIO_TOKEN,
 *   ANTHROPIC_KEY, OPENAI_KEY, GEMINI_KEY - the Atlas.io council (Claude + GPT + Gemini); add all three to make the AI live
 *   DYNADOT_KEY  - filled in per integration phase
 *
 * This foundation covers P0 items 1-5 + 9 of SECURITY.md. Payments/webhooks/
 * reseller endpoints plug into the same router in their phases.
 */

const JSON_HEADERS = { 'Content-Type': 'application/json' };

// ---------------------------------------------------------------- security headers
function securityHeaders(origin) {
  return {
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "frame-ancestors 'none'",
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(self), camera=(), microphone=(), payment=(self)',
  };
}
// Cross-origin: the app (atlasrental.io / github.io / localhost) calls this Worker on a different
// origin. Only these exact origins get CORS; anything else gets none (unknown sites can't use creds).
const ALLOWED_ORIGINS = [
  'https://atlasrental.io', 'https://www.atlasrental.io',
  'https://prestigeblackcorp-dev.github.io',
];   // production only. localhost was removed: with a SameSite=None session cookie, any page an owner loads on http://localhost:4321 could read their tenant data cross-origin. For local dev of the worker, temporarily add it back or set a DEV env gate.
function corsHeaders(origin) {
  if (ALLOWED_ORIGINS.indexOf(origin) < 0) return {};
  return { 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Credentials': 'true', 'Vary': 'Origin' };
}
function json(body, status, extra) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: Object.assign({}, JSON_HEADERS, securityHeaders(), extra || {}),
  });
}
function err(status, message) { return json({ error: message }, status); }

// ---------------------------------------------------------------- crypto helpers
function b64(buf) { return btoa(String.fromCharCode.apply(null, new Uint8Array(buf))); }
function unb64(s) { const b = atob(s); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
function randId(bytes) { const u = new Uint8Array(bytes || 32); crypto.getRandomValues(u); return b64(u).replace(/[+/=]/g, '').slice(0, (bytes || 32)); }
function enc(str) { return new TextEncoder().encode(str); }

// Password hashing. Cloudflare caps a SINGLE native PBKDF2 call at 100k iterations, so we CHAIN 6 rounds
// (each round's 256-bit output feeds the next as key material) for 600k effective iterations -- OWASP's
// PBKDF2-SHA256 floor. New hashes are tagged 'p2$'; legacy single-100k hashes (untagged) still verify and
// are transparently re-hashed to the 600k scheme on the user's next successful login (see login handler).
const PBKDF2_ITERS = 100000;
const PBKDF2_ROUNDS = 6;               // 6 x 100k = 600k effective
async function _pbkdf2(materialBytes, salt) {
  const key = await crypto.subtle.importKey('raw', materialBytes, 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: PBKDF2_ITERS, hash: 'SHA-256' }, key, 256));
}
async function hashPassword(password, saltB64) {
  const salt = saltB64 ? unb64(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  let bits = enc(password);
  for (let i = 0; i < PBKDF2_ROUNDS; i++) bits = await _pbkdf2(bits, salt);
  return { hash: 'p2$' + b64(bits), salt: b64(salt) };
}
function _ctEq(a, b) {                  // constant-time string compare (no early-exit)
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let diff = 0; for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
async function verifyPassword(password, saltB64, storedHash) {
  const salt = unb64(saltB64 || b64(new Uint8Array(16)));
  let expected;
  if (typeof storedHash === 'string' && storedHash.slice(0, 3) === 'p2$') {   // current 600k scheme
    let bits = enc(password);
    for (let i = 0; i < PBKDF2_ROUNDS; i++) bits = await _pbkdf2(bits, salt);
    expected = 'p2$' + b64(bits);
  } else {                                                                     // legacy single-100k hash
    expected = b64(await _pbkdf2(enc(password), salt));
  }
  return _ctEq(expected, storedHash);
}
// A stored hash lacking the 'p2$' tag predates the 600k scheme -> re-hash on next successful login.
function pwNeedsUpgrade(storedHash) { return !(typeof storedHash === 'string' && storedHash.slice(0, 3) === 'p2$'); }

// AES-GCM for integration secrets at rest, hardened two ways:
//  1) AAD (additionalData) binds each ciphertext to its tenant+provider, so a stolen/duplicated blob
//     cannot be replayed under a different tenant or provider row -- GCM auth fails if the context differs.
//  2) Key VERSIONING for rotation: the blob is "k<v>:<iv>:<ct>". Set ENC_KEY_2 to introduce a new key;
//     new writes use the highest version while old ciphertext still decrypts under its own key. Rotate by
//     re-encrypting lazily (decrypt old -> encrypt new) or in a migration. Legacy "<iv>:<ct>" blobs
//     (pre-versioning, no AAD) still decrypt for back-compat.
function _encKeys(env) {                     // highest version first
  const ks = [];
  if (env.ENC_KEY_2) ks.push({ v: 2, raw: env.ENC_KEY_2 });
  if (env.ENC_KEY)   ks.push({ v: 1, raw: env.ENC_KEY });
  return ks;
}
async function encSecret(env, plain, aad) {
  const ks = _encKeys(env); if (!ks.length) throw new Error('no ENC_KEY');
  const { v, raw } = ks[0];                  // encrypt with the newest key
  const key = await crypto.subtle.importKey('raw', unb64(raw), 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const params = { name: 'AES-GCM', iv };
  if (aad != null) params.additionalData = enc(String(aad));
  const ct = await crypto.subtle.encrypt(params, key, enc(plain));
  return 'k' + v + ':' + b64(iv) + ':' + b64(ct);
}
async function decSecret(env, blob, aad) {
  const parts = String(blob).split(':');
  let v = 0, ivB, ctB;
  if (parts.length === 3 && parts[0][0] === 'k') { v = parseInt(parts[0].slice(1), 10) || 0; ivB = parts[1]; ctB = parts[2]; }
  else { ivB = parts[0]; ctB = parts[1]; }   // legacy unversioned blob (no AAD)
  const params = { name: 'AES-GCM', iv: unb64(ivB) };
  if (v && aad != null) params.additionalData = enc(String(aad));   // AAD only on versioned (new) blobs
  const cand = v ? _encKeys(env).filter(k => k.v === v) : _encKeys(env);
  for (const k of cand) {
    try {
      const key = await crypto.subtle.importKey('raw', unb64(k.raw), 'AES-GCM', false, ['decrypt']);
      const pt = await crypto.subtle.decrypt(params, key, unb64(ctB));
      return new TextDecoder().decode(pt);
    } catch (e) { /* wrong key/version -> try the next */ }
  }
  throw new Error('decrypt failed');
}

// ---------------------------------------------------------------- cookies + sessions
function parseCookies(req) {
  const out = {}; const h = req.headers.get('Cookie') || '';
  h.split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) { try { out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); } catch (e) { /* skip a malformed cookie pair instead of 500-ing */ } } });
  return out;
}
function sessionCookie(id) {
  // HttpOnly so JS can't read it; Secure + SameSite=None; 30-day cap (idle also enforced server-side)
  return `atlas_sid=${id}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=2592000`;
}
const IDLE_MS = 1000 * 60 * 60 * 24;      // 24h idle
const ABS_MS = 1000 * 60 * 60 * 24 * 30;   // 30d absolute

async function createSession(env, user, req) {
  const id = randId(32), csrf = randId(24), now = Date.now();
  await env.DB.prepare(
    'INSERT INTO sessions (id,user_id,tenant_id,csrf,created_at,idle_at,expires_at,ip,ua) VALUES (?,?,?,?,?,?,?,?,?)')
    .bind(id, user.id, user.tenant_id, csrf, now, now, now + ABS_MS,
      req.headers.get('CF-Connecting-IP') || '', (req.headers.get('User-Agent') || '').slice(0, 240)).run();
  return { id, csrf };
}
async function resolveSession(env, req) {
  const sid = parseCookies(req).atlas_sid;
  if (!sid) return null;
  const s = await env.DB.prepare('SELECT * FROM sessions WHERE id = ?').bind(sid).first();
  if (!s || s.revoked_at) return null;
  const now = Date.now();
  if (now > s.expires_at || now - s.idle_at > IDLE_MS) { await env.DB.prepare('UPDATE sessions SET revoked_at=? WHERE id=?').bind(now, sid).run(); return null; }
  await env.DB.prepare('UPDATE sessions SET idle_at=? WHERE id=?').bind(now, sid).run();
  const user = await env.DB.prepare('SELECT id,email,tenant_id,role,caps FROM users WHERE id=?').bind(s.user_id).first();
  if (!user) return null;
  const comp = await env.DB.prepare('SELECT role FROM comp_grants WHERE email=?').bind(user.email).first();
  const isOwner = (user.email === env.OWNER_EMAIL) || (comp && comp.role === 'admin');
  return { session: s, user, tenant_id: s.tenant_id, isOwner: !!isOwner, comp: comp ? comp.role : null };
}
// state-changing requests must present a matching CSRF token + same-origin
function csrfOk(req, ctx) {
  const tok = req.headers.get('X-CSRF-Token');
  if (!tok || !ctx || tok !== ctx.session.csrf) return false;
  const origin = req.headers.get('Origin');
  if (origin && ALLOWED_ORIGINS.indexOf(origin) < 0) return false;   // was compared to req.url.host (the worker's own host) -> self-defeating cross-origin; validate against the allow-list
  return true;
}

// ---------------------------------------------------------------- rate limiting
async function rateLimit(env, bucket, max, windowMs) {
  const now = Date.now();
  const row = await env.DB.prepare('SELECT count,window_start FROM rate_limits WHERE bucket=?').bind(bucket).first();
  if (!row || now - row.window_start > windowMs) {
    await env.DB.prepare('INSERT INTO rate_limits (bucket,count,window_start) VALUES (?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=1,window_start=?').bind(bucket, now, now).run();
    return true;
  }
  if (row.count >= max) return false;
  await env.DB.prepare('UPDATE rate_limits SET count=count+1 WHERE bucket=?').bind(bucket).run();
  return true;
}

async function audit(env, ctx, req, action, meta) {
  try {
    await env.DB.prepare('INSERT INTO audit_log (tenant_id,actor,action,meta,ip,ua,at) VALUES (?,?,?,?,?,?,?)')
      .bind(ctx ? ctx.tenant_id : null, ctx ? ctx.user.email : 'anon', action, JSON.stringify(meta || {}),
        req.headers.get('CF-Connecting-IP') || '', (req.headers.get('User-Agent') || '').slice(0, 240), Date.now()).run();
  } catch (e) { /* audit must never break the request */ }
}

// ---------------------------------------------------------------- validation
function vEmail(s) { return typeof s === 'string' && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s) && s.length <= 254; }
function vStr(s, max) { return typeof s === 'string' && s.length > 0 && s.length <= (max || 200); }
function vInt(n) { return Number.isInteger(n); }
const COLLECTIONS = { assets: 'assets', bookings: 'bookings', customers: 'customers', charges: 'charges', ledger: 'ledger', promos: 'promos' };

// ============================================================ Atlas.io council
// The multi-model brain: Claude + GPT + Gemini answer in parallel, then one of them
// synthesizes a single best answer. The keys are the PLATFORM'S (env secrets),
// metered as the owner's Atlas credits - never a tenant's own third-party key.
// With no keys set, /api/aio returns {live:false} and the client uses its built-in
// heuristic council, so nothing breaks before the owner goes live.
const AIO_SAFETY_PROMPT =
  'You are Atlas.io, the AI operating ONE rental business inside a multi-tenant SaaS. ' +
  'Give concrete, practical, safe guidance that helps THIS owner run and grow their rental business. ' +
  'Hard rules: use only facts the owner gives you; never invent specific numbers, bookings, customers, or other tenants\' data; ' +
  'never reveal or reference another business; do not give binding legal, tax, or licensed financial/investment advice - point them to a professional instead; ' +
  'decline anything unsafe, discriminatory, or illegal. Be brief, specific, and actionable.';

function _aioCtx(context) { return context ? ('\n\nContext the owner shared about their business:\n' + String(context).slice(0, 800)) : ''; }

// Each asker returns the model's plain text, or '' on any error (never throws).
async function askClaude(key, q, context) {
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'claude-sonnet-5', max_tokens: 700,
        system: AIO_SAFETY_PROMPT + _aioCtx(context), messages: [{ role: 'user', content: q }] })
    });
    const j = await r.json().catch(() => ({}));
    return (j && j.content && j.content[0] && j.content[0].text) ? j.content[0].text.trim() : '';
  } catch (e) { return ''; }   // network/DNS reject -> empty, never throws
}
async function askClaudeSchedule(key, system, userMsg) {   // dedicated JSON-schedule call: own system prompt + a higher token budget than the advisory askClaude
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'claude-sonnet-5', max_tokens: 2500, system: system, messages: [{ role: 'user', content: userMsg }] })
    });
    const j = await r.json().catch(() => ({}));
    return (j && j.content && j.content[0] && j.content[0].text) ? j.content[0].text.trim() : '';
  } catch (e) { return ''; }
}
async function askGPT(key, q, context) {
  try {
    const r = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'authorization': 'Bearer ' + key, 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'gpt-4o', max_tokens: 700,
        messages: [{ role: 'system', content: AIO_SAFETY_PROMPT + _aioCtx(context) }, { role: 'user', content: q }] })
    });
    const j = await r.json().catch(() => ({}));
    return (j && j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content) ? j.choices[0].message.content.trim() : '';
  } catch (e) { return ''; }
}
async function askGemini(key, q, context) {
  try {
    const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=' + encodeURIComponent(key), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ systemInstruction: { parts: [{ text: AIO_SAFETY_PROMPT + _aioCtx(context) }] },
        contents: [{ parts: [{ text: q }] }] })
    });
    const j = await r.json().catch(() => ({}));
    return (j.candidates[0].content.parts[0].text || '').trim();
  } catch (e) { return ''; }
}

// ================================================================ router
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;
    const cors = corsHeaders(req.headers.get('Origin') || '');

    // CORS preflight (browsers send this before a credentialed cross-origin write)
    if (method === 'OPTIONS') return new Response(null, { status: 204, headers: Object.assign({}, securityHeaders(), cors, {
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-CSRF-Token', 'Access-Control-Max-Age': '86400' }) });

    const resp = await (async () => {
    try {
      // ---- HEALTH: pinpoint setup problems (safe: booleans only, no secrets) -
      if (path === '/api/health' && method === 'GET') {
        const h = { ok: false, db_bound: typeof env.DB !== 'undefined', user_tables: 0, schema_loaded: false,
          secrets: { SESSION_KEY: !!env.SESSION_KEY, ENC_KEY: !!env.ENC_KEY, OWNER_EMAIL: !!env.OWNER_EMAIL } };
        try {
          const r = await env.DB.prepare("SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'").first();
          h.user_tables = r ? r.n : 0;
          h.schema_loaded = h.user_tables >= 15;
        } catch (e) { h.db_ok = false; }   // don't leak DB internals to an unauthenticated caller
        h.ok = h.db_bound && h.schema_loaded && h.secrets.SESSION_KEY && h.secrets.ENC_KEY && h.secrets.OWNER_EMAIL;
        return json(h);
      }

      // ---- AUTH: signup -----------------------------------------------------
      if (path === '/api/auth/signup' && method === 'POST') {
        const ip = req.headers.get('CF-Connecting-IP') || 'x';
        if (!await rateLimit(env, 'signup:' + ip, 5, 3600000)) return err(429, 'Too many attempts. Try later.');
        const body = await req.json().catch(() => ({}));
        if (!vEmail(body.email) || !vStr(body.password, 200) || body.password.length < 8) return err(400, 'Valid email and 8+ char password required.');
        if (!vStr(body.business, 120)) return err(400, 'Business name required.');
        const exists = await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(body.email.toLowerCase()).first();
        if (exists) return err(409, 'That email already has an account.');
        const now = Date.now();
        const tid = 't' + randId(12), uid = 'u' + randId(12);
        const { hash, salt } = await hashPassword(body.password);
        const fleet = (typeof body.fleet === 'string' && body.fleet) ? body.fleet.slice(0, 40) : 'cars';   // a non-string fleet (object/array) used to reach .bind() and 500; coerce to a safe string -> clean result
        await env.DB.prepare('INSERT INTO tenants (id,name,fleet_type,plan,trial_ends,created_at,updated_at) VALUES (?,?,?,?,?,?,?)')
          .bind(tid, body.business.slice(0, 120), fleet, 'trial', now + 7 * 24 * 3600 * 1000, now, now).run();
        await env.DB.prepare('INSERT INTO users (id,email,pw_hash,pw_salt,tenant_id,role,created_at) VALUES (?,?,?,?,?,?,?)')
          .bind(uid, body.email.toLowerCase(), hash, salt, tid, 'owner', now).run();
        const user = { id: uid, email: body.email.toLowerCase(), tenant_id: tid };
        const sess = await createSession(env, user, req);
        await audit(env, { tenant_id: tid, user }, req, 'signup', { email: user.email });
        return json({ ok: true, csrf: sess.csrf, tenant_id: tid, trial_ends: now + 7 * 24 * 3600 * 1000 }, 200, { 'Set-Cookie': sessionCookie(sess.id) });
      }

      // ---- AUTH: login ------------------------------------------------------
      if (path === '/api/auth/login' && method === 'POST') {
        const ip = req.headers.get('CF-Connecting-IP') || 'x';
        const body = await req.json().catch(() => ({}));
        if (!vEmail(body.email) || !vStr(body.password, 200)) return err(400, 'Email and password required.');
        if (!await rateLimit(env, 'login:' + ip, 10, 900000)) return err(429, 'Too many attempts. Try again in a few minutes.');
        if (!await rateLimit(env, 'login:' + body.email.toLowerCase(), 8, 900000)) return err(429, 'Too many attempts for this account.');
        const user = await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(body.email.toLowerCase()).first();
        // Always run the FULL 600k KDF (even when the email is unknown) so response time can't reveal
        // whether an account exists.
        let ok;
        if (user) ok = await verifyPassword(body.password, user.pw_salt, user.pw_hash);
        else { await hashPassword(body.password, b64(new Uint8Array(16))); ok = false; }
        if (!user || !ok) { await audit(env, null, req, 'login_fail', { email: body.email.toLowerCase() }); return err(401, 'Wrong email or password.'); }
        await env.DB.prepare('UPDATE users SET last_login=? WHERE id=?').bind(Date.now(), user.id).run();
        // Transparently upgrade a legacy single-100k hash to the 600k scheme now that we hold the plaintext.
        if (pwNeedsUpgrade(user.pw_hash)) { try { const _up = await hashPassword(body.password); await env.DB.prepare('UPDATE users SET pw_hash=?,pw_salt=? WHERE id=?').bind(_up.hash, _up.salt, user.id).run(); } catch (e) {} }
        const sess = await createSession(env, user, req);
        await audit(env, { tenant_id: user.tenant_id, user }, req, 'login', {});
        return json({ ok: true, csrf: sess.csrf, tenant_id: user.tenant_id }, 200, { 'Set-Cookie': sessionCookie(sess.id) });
      }

      // ---- everything below requires a valid session ------------------------
      const ctx = await resolveSession(env, req);

      if (path === '/api/auth/logout' && method === 'POST') {
        if (ctx) await env.DB.prepare('UPDATE sessions SET revoked_at=? WHERE id=?').bind(Date.now(), ctx.session.id).run();
        return json({ ok: true }, 200, { 'Set-Cookie': 'atlas_sid=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0' });
      }
      if (!ctx) return err(401, 'Not signed in.');

      if (path === '/api/auth/me' && method === 'GET') {
        const t = await env.DB.prepare('SELECT id,name,fleet_type,plan,trial_ends,brand,money,settings FROM tenants WHERE id=?').bind(ctx.tenant_id).first();
        return json({ user: { email: ctx.user.email, role: ctx.user.role, isOwner: ctx.isOwner, comp: ctx.comp }, tenant: t, csrf: ctx.session.csrf });
      }

      // ---- generic tenant-scoped collection CRUD (the store seam) -----------
      // /api/data/<collection>[/<id>]  -- every query is scoped to ctx.tenant_id
      const dm = path.match(/^\/api\/data\/([a-z]+)(?:\/([\w-]+))?$/);
      if (dm) {
        const coll = Object.prototype.hasOwnProperty.call(COLLECTIONS, dm[1]) ? COLLECTIONS[dm[1]] : null; const id = dm[2];
        if (!coll) return err(404, 'Unknown collection.');   // hasOwnProperty so 'constructor'/proto names don't slip past as truthy

        if (method === 'GET') {
          if (id) {   // /api/data/<coll>/<id> -> return the ONE row (tenant-scoped), not the whole collection
            const one = await env.DB.prepare(`SELECT * FROM ${coll} WHERE tenant_id=? AND id=? LIMIT 1`).bind(ctx.tenant_id, id).first();
            return one ? json({ item: one }) : err(404, 'Not found.');
          }
          const rows = await env.DB.prepare(`SELECT * FROM ${coll} WHERE tenant_id=? ORDER BY created_at DESC LIMIT 1000`).bind(ctx.tenant_id).all();
          return json({ items: rows.results || [] });
        }
        // all writes: CSRF + origin
        if (!csrfOk(req, ctx)) return err(403, 'Bad CSRF token.');
        // server-side RBAC floor: a read-only member can never mutate tenant data, even with a valid session + CSRF
        if (ctx.user && ctx.user.role === 'viewer') return err(403, 'Your role is read-only.');

        const hasUpd = (coll === 'assets' || coll === 'bookings');
        if (method === 'POST') {
          const body = await req.json().catch(() => ({}));
          const { cols, vals } = patchFields(coll, body);       // whitelisted domain fields
          for (const c of (REQUIRED[coll] || [])) if (cols.indexOf(c) < 0) return err(400, 'Missing required field: ' + c);
          const now = Date.now();
          let rid = (coll === 'bookings' && vStr(body.id, 40)) ? body.id : (coll.slice(0, 2).toUpperCase() + '-' + randId(10));
          // The client picks booking ids (BK-<n>) but the PK is global -> guard the collision instead of letting the INSERT 500:
          if (coll === 'bookings') {
            const clash = await env.DB.prepare('SELECT tenant_id FROM bookings WHERE id=?').bind(rid).first();
            if (clash) {
              if (clash.tenant_id === ctx.tenant_id) {   // same tenant re-POSTing the same id -> UPDATE, don't duplicate or 500
                const uCols = cols.slice(), uVals = vals.slice(); uCols.push('updated_at'); uVals.push(now);
                await env.DB.prepare(`UPDATE bookings SET ${uCols.map(c => c + '=?').join(',')} WHERE id=? AND tenant_id=?`).bind(...uVals, rid, ctx.tenant_id).run();
                await audit(env, ctx, req, 'bookings.update', { id: rid });
                return json({ ok: true, id: rid, updated: true });
              }
              rid = 'BK-' + randId(10);   // id taken by ANOTHER tenant on the global PK -> mint a fresh server id so this booking is never lost
            }
          }
          // ONE atomic insert: base columns + all provided fields (respects NOT NULL constraints)
          const allCols = ['id', 'tenant_id', 'created_at'].concat(hasUpd ? ['updated_at'] : []).concat(cols);
          const allVals = [rid, ctx.tenant_id, now].concat(hasUpd ? [now] : []).concat(vals);
          await env.DB.prepare(`INSERT INTO ${coll} (${allCols.join(',')}) VALUES (${allCols.map(() => '?').join(',')})`).bind(...allVals).run();
          await audit(env, ctx, req, coll + '.create', { id: rid });
          return json({ ok: true, id: rid });
        }
        if (method === 'PUT' && id) {
          const owns = await env.DB.prepare(`SELECT id FROM ${coll} WHERE id=? AND tenant_id=?`).bind(id, ctx.tenant_id).first();
          if (!owns) return err(404, 'Not found.');           // cross-tenant writes are denied here
          const body = await req.json().catch(() => ({}));
          const { cols, vals } = patchFields(coll, body);
          if (!cols.length) return json({ ok: true });          // nothing to change
          const setCols = cols.slice(), setVals = vals.slice();
          if (hasUpd) { setCols.push('updated_at'); setVals.push(Date.now()); }
          await env.DB.prepare(`UPDATE ${coll} SET ${setCols.map(c => c + '=?').join(',')} WHERE id=? AND tenant_id=?`).bind(...setVals, id, ctx.tenant_id).run();
          await audit(env, ctx, req, coll + '.update', { id });
          return json({ ok: true });
        }
        if (method === 'DELETE' && id) {
          const r = await env.DB.prepare(`DELETE FROM ${coll} WHERE id=? AND tenant_id=?`).bind(id, ctx.tenant_id).run();
          await audit(env, ctx, req, coll + '.delete', { id });
          return json({ ok: true, deleted: r.meta ? r.meta.changes : 0 });
        }
      }

      // ---- admin/owner only: comp registry ----------------------------------
      if (path === '/api/admin/comp' && (method === 'POST' || method === 'DELETE')) {
        if (!ctx.isOwner) return err(403, 'Owner only.');        // re-checked server-side, every request
        if (!csrfOk(req, ctx)) return err(403, 'Bad CSRF token.');
        const body = await req.json().catch(() => ({}));
        if (!vEmail(body.email)) return err(400, 'Valid email required.');
        if (method === 'POST') {
          if (['admin', 'gold', 'free'].indexOf(body.role) < 0) return err(400, 'Bad role.');
          await env.DB.prepare('INSERT INTO comp_grants (email,role,granted_by,granted_at) VALUES (?,?,?,?) ON CONFLICT(email) DO UPDATE SET role=?,granted_at=?')
            .bind(body.email.toLowerCase(), body.role, ctx.user.email, Date.now(), body.role, Date.now()).run();
          await audit(env, ctx, req, 'comp.grant', { email: body.email, role: body.role });
        } else {
          await env.DB.prepare('DELETE FROM comp_grants WHERE email=?').bind(body.email.toLowerCase()).run();
          await audit(env, ctx, req, 'comp.revoke', { email: body.email });
        }
        return json({ ok: true });
      }

      // ---- integrations: store a tenant key (encrypted; never returned) ------
      if (path === '/api/integrations/connect' && method === 'POST') {
        if (!csrfOk(req, ctx)) return err(403, 'Bad CSRF token.');
        const body = await req.json().catch(() => ({}));
        if (!vStr(body.provider, 40) || !vStr(body.secret, 400)) return err(400, 'Provider and key required.');
        const secret_enc = await encSecret(env, body.secret, ctx.tenant_id + '|' + body.provider);   // AAD binds this ciphertext to this tenant+provider
        await env.DB.prepare('INSERT INTO integrations (tenant_id,provider,kind,secret_enc,meta,connected_at) VALUES (?,?,?,?,?,?) ON CONFLICT(tenant_id,provider) DO UPDATE SET secret_enc=?,meta=?,connected_at=?')
          .bind(ctx.tenant_id, body.provider, (typeof body.kind === 'string' ? body.kind : ''), secret_enc, JSON.stringify(body.meta || {}), Date.now(), secret_enc, JSON.stringify(body.meta || {}), Date.now()).run();
        await audit(env, ctx, req, 'integration.connect', { provider: body.provider });
        return json({ ok: true, connected: body.provider });       // UI shows masked "Connected", never the key
      }

      // ---- Atlas.io council: Claude + GPT + Gemini in concert, one synthesis --
      if (path === '/api/aio' && method === 'POST') {
        if (!csrfOk(req, ctx)) return err(403, 'Bad CSRF token.');
        // per-tenant daily cap: each call fans out to up to 4 paid LLM requests on the PLATFORM's keys -> stop one tenant draining the AI budget
        const _day = new Date().toISOString().slice(0, 10);
        if (!await rateLimit(env, 'aio:' + ctx.tenant_id + ':' + _day, 120, 86400000)) return err(429, 'Daily Atlas.io limit reached. It resets tomorrow.');
        if (!await rateLimit(env, 'aio:global:' + _day, 5000, 86400000)) return err(429, 'Atlas.io is temporarily at capacity. Please try again later.');   // platform-wide ceiling so no set of tenants can run the AI bill away
        const body = await req.json().catch(() => ({}));
        const q = (typeof body.q === 'string' ? body.q : '').slice(0, 2000).trim();
        if (!q) return err(400, 'Ask a question.');
        const context = typeof body.context === 'string' ? body.context : '';
        const panelDefs = [
          { name: 'Claude', ask: askClaude, key: env.ANTHROPIC_KEY },
          { name: 'GPT-4o', ask: askGPT, key: env.OPENAI_KEY },
          { name: 'Gemini', ask: askGemini, key: env.GEMINI_KEY }
        ].filter(m => m.key);
        if (!panelDefs.length) return json({ live: false });   // no keys yet -> client uses its built-in council
        // ask every configured model in parallel; a failed one just drops out
        const settled = await Promise.all(panelDefs.map(m =>
          m.ask(m.key, q, context).then(text => ({ name: m.name, text })).catch(() => ({ name: m.name, text: '' }))
        ));
        const models = settled.filter(m => m.text);
        if (!models.length) return json({ live: true, models: [], synthesis: '', error: 'The council could not be reached - try again.' });
        // one model synthesizes the panel into a single owner-facing answer
        let synthesis = models[0].text;
        if (models.length > 1) {
          const judgeAsk = env.ANTHROPIC_KEY ? askClaude : (env.OPENAI_KEY ? askGPT : askGemini);
          const judgeKey = env.ANTHROPIC_KEY || env.OPENAI_KEY || env.GEMINI_KEY;
          const panel = models.map(m => '### ' + m.name + '\n' + m.text).join('\n\n');
          const jq = 'You chair a rental-business advisory council. The owner asked:\n"' + q + '"\n\n' +
            'Your ' + models.length + ' advisors answered:\n\n' + panel + '\n\n' +
            'Write the single best answer for the owner in 3-6 sentences: keep what they agree on, resolve any conflict with the safest practical choice, and end with one clear next step. Do not invent numbers and do not name the advisors.';
          try { const s = await judgeAsk(judgeKey, jq, context); if (s) synthesis = s; } catch (e) { /* keep first answer */ }
        }
        await audit(env, ctx, req, 'aio.council', { models: models.map(m => m.name), chars: q.length });
        return json({ live: true, models, synthesis });
      }

      // ---- AI schedule builder: plain-language staff constraints -> structured weekly schedule (single strong model, JSON only) --
      if (path === '/api/schedule' && method === 'POST') {
        if (!csrfOk(req, ctx)) return err(403, 'Bad CSRF token.');
        const _sday = new Date().toISOString().slice(0, 10);
        if (!await rateLimit(env, 'sched:' + ctx.tenant_id + ':' + _sday, 60, 86400000)) return err(429, 'Daily schedule-AI limit reached. It resets tomorrow.');
        if (!env.ANTHROPIC_KEY) return json({ live: false });   // no key -> client falls back to its built-in parser + solver
        const sbody = await req.json().catch(() => ({}));
        const freeText = (typeof sbody.freeText === 'string' ? sbody.freeText : '').slice(0, 4000).trim();
        if (!freeText) return err(400, 'Describe the schedule you want.');
        const roster = Array.isArray(sbody.roster) ? sbody.roster.slice(0, 60) : [];
        const positions = Array.isArray(sbody.positions) ? sbody.positions.slice(0, 30) : [];
        const weekStart = (typeof sbody.weekStart === 'string' ? sbody.weekStart : '').slice(0, 10);
        const sys = 'You build staff schedules for a rental business. Output STRICT JSON ONLY - no prose, no markdown fences. '
          + 'Roster (only these people can be scheduled): ' + JSON.stringify(roster).slice(0, 3000) + '. '
          + 'Positions: ' + JSON.stringify(positions).slice(0, 1000) + '. Week starts ' + (weekStart || 'the upcoming Monday') + ' (day codes MO TU WE TH FR SA SU). '
          + 'Return exactly: {"shifts":[{"empRef":"<roster name>","role":"<position>","day":"MO","start":"HH:MM","end":"HH:MM"}],'
          + '"openShifts":[{"role":"","day":"","start":"","end":"","reason":""}],"clarifications":["..."]}. '
          + 'Use 24h times. Only assign a person to hours that fit their stated availability and to a role they hold. '
          + 'If a required slot cannot be filled by an available qualified person, put it in openShifts instead of forcing it. Match names to roster entries; if a name is unknown, add a clarification and do not schedule them.';
        try {
          let raw = await askClaudeSchedule(env.ANTHROPIC_KEY, sys, freeText);
          raw = String(raw || '').replace(/^```(?:json)?/i, '').replace(/```\s*$/, '').trim();
          let parsed = null; try { parsed = JSON.parse(raw); } catch (e) { parsed = null; }
          if (!parsed || typeof parsed !== 'object') return json({ live: true, ok: false, error: 'Could not read a schedule from that - try rephrasing.' });
          await audit(env, ctx, req, 'schedule.ai', { chars: freeText.length });
          return json({ live: true, ok: true, result: parsed });
        } catch (e) {
          return json({ live: true, ok: false, error: 'The scheduler could not be reached - built locally instead.' });
        }
      }

      return err(404, 'Not found.');
    } catch (e) {
      return err(500, 'Server error.');   // never leak internals
    }
    })();
    for (const k in cors) resp.headers.set(k, cors[k]);   // CORS on every response
    return resp;
  },
};

// NOT NULL columns that must be present on create (else a clean 400, not a DB 500).
const REQUIRED = { assets: ['name'], charges: ['amount_cents'], ledger: ['kind'], promos: ['code'] };

// Whitelisted domain fields per collection -> {cols, vals}. NEVER id/tenant_id/timestamps
// (server sets those) so a client can't cross tenants or forge revenue. Used by INSERT and UPDATE.
function patchFields(coll, body) {
  const cols = [], vals = [];
  const set = (c, v) => { cols.push(c); vals.push(v); };
  if (coll === 'assets') {
    if (vStr(body.name, 160)) set('name', body.name);
    if (vStr(body.type, 60)) set('type', body.type);
    if (vStr(body.status, 40)) set('status', body.status);
    if (vInt(body.day_rate_cents)) set('day_rate_cents', body.day_rate_cents);
    if (body.info) set('info', JSON.stringify(body.info));
    if (body.blackouts) set('blackouts', JSON.stringify(body.blackouts));
  } else if (coll === 'bookings') {
    if (vStr(body.customer_id, 40)) set('customer_id', body.customer_id);
    if (vStr(body.asset_id, 40)) set('asset_id', body.asset_id);
    if (vInt(body.starts)) set('starts', body.starts);
    if (vInt(body.ends)) set('ends', body.ends);
    if (vStr(body.status, 30)) set('status', body.status);
    // revenue_cents is NOT settable from the client - server recomputes from money-rules (payments phase)
    if (body.data) set('data', JSON.stringify(body.data));
  } else if (coll === 'customers') {
    if (vStr(body.name, 160)) set('name', body.name);
    if (body.email != null && vEmail(body.email)) set('email', body.email);
    if (vStr(body.phone, 40)) set('phone', body.phone);
    if (body.data) set('data', JSON.stringify(body.data));
  } else if (coll === 'charges') {
    if (vStr(body.booking_id, 40)) set('booking_id', body.booking_id);
    if (vStr(body.label, 160)) set('label', body.label);
    if (vInt(body.amount_cents)) set('amount_cents', body.amount_cents);
    if (vStr(body.kind, 20)) set('kind', body.kind);
    // status flips to 'paid' only via the Stripe webhook, never here
  } else if (coll === 'ledger') {
    if (['income', 'expense'].indexOf(body.kind) >= 0) set('kind', body.kind);
    if (vStr(body.label, 160)) set('label', body.label);
    if (vInt(body.amount_cents)) set('amount_cents', body.amount_cents);
    if (vStr(body.on_date, 20)) set('on_date', body.on_date);
  } else if (coll === 'promos') {
    if (vStr(body.code, 40)) set('code', body.code);
    if (['pct', 'amount'].indexOf(body.disc_type) >= 0) set('disc_type', body.disc_type);
    if (vInt(body.disc_value)) set('disc_value', body.disc_value);
    if (vStr(body.scope, 30)) set('scope', body.scope);
    if (body.active === 0 || body.active === 1) set('active', body.active);
  }
  return { cols, vals };
}
