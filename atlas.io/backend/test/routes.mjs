// Atlas worker route tests -- second CI gate, beyond smoke. Deterministic (mock D1 + stubbed Stripe), no network,
// no production. Covers the MONEY path (payment go-live self-test) + richer health fields.
// Run locally (Node 20+):  node test/routes.mjs
// CI live (2026-07-19): D1 bound + CLOUDFLARE_API_TOKEN/ACCOUNT_ID secrets set -- this gate now guards auto-deploy.

import worker, { _b32decode, _hotp, _totpAt, _meterAI, _aiUsageFrom, AI_PRICES } from '../worker.js';
import crypto from 'node:crypto';

// --- switchable Stripe mock (read-only endpoints the self-test calls) ---
let scn = 'ready';
let dyn = 'ok';   // dynadot registrar self-test scenario
globalThis.fetch = (u) => {
  const s = String(u);
  if (s.indexOf('dynadot.com') >= 0) return Promise.resolve({ ok: true, status: 200, json: async () => (dyn === 'ok' ? { SearchResponse: { SearchResults: [{ Available: 'yes', Price: '10.99 in USD' }] } } : { Error: 'bad key' }) });
  if (s.indexOf('api.stripe.com/v1/account') >= 0) return Promise.resolve({ ok: true, status: 200, json: async () => (scn === 'ready' ? { id: 'acct_live', country: 'US', default_currency: 'usd', charges_enabled: true, payouts_enabled: true, details_submitted: true } : { id: 'acct_test', country: 'US', default_currency: 'usd', charges_enabled: true, payouts_enabled: false, details_submitted: false }) });
  if (s.indexOf('api.stripe.com/v1/webhook_endpoints') >= 0) return Promise.resolve({ ok: true, status: 200, json: async () => (scn === 'ready' ? { data: [{ url: 'https://atlasrental.io/api/stripe/webhook', status: 'enabled', enabled_events: ['*'] }] } : { data: [] }) });
  if (s.indexOf('api.stripe.com/v1/charges') >= 0) return Promise.resolve({ ok: true, status: 200, json: async () => ({ data: [{ amount: 12999, currency: 'usd', status: 'succeeded', paid: true, refunded: false, created: 1721000000, description: 'BK-1 deposit' }] }) });
  return Promise.resolve({ ok: false, status: 0, headers: { get: () => null }, text: async () => '', json: async () => ({}) });
};

function mockDB() {
  function stmt(sql) {
    let args = [];
    const api = {
      bind: (...a) => { args = a; return api; },
      first: async () => { if (/FROM sqlite_master/.test(sql)) return { n: 25 }; if (/FROM platform_config/.test(sql)) return null; if (/FROM rate_limits/.test(sql)) return null; return null; },
      all: async () => ({ results: [] }),
      run: async () => ({ success: true, meta: { changes: 1 } }),
    };
    return api;
  }
  return { prepare: stmt };
}
const ctx = { waitUntil() {}, passThroughOnException() {} };
function mkReq(method, path, opts = {}) { return new Request('https://atlasrental.io' + path, { method, headers: Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {}) }); }
let fails = 0;
function ok(c, m) { if (c) console.log('  ok  ' + m); else { fails++; console.error('  FAIL ' + m); } }
const H = { 'X-Admin-Token': 'k' };

console.log('Atlas worker route tests');

// health: build + r2 flag present
let r = await worker.fetch(mkReq('GET', '/api/health'), { DB: mockDB(), SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' }, ctx);
let j = await r.json();
ok(typeof j.build === 'string' && j.build.length > 0, 'health exposes a build stamp');
ok('r2' in j && 'cron_age_min' in j, 'health exposes r2 + cron freshness');

// payments self-test: LIVE ready
scn = 'ready';
r = await worker.fetch(mkReq('GET', '/api/admin/payments/selftest', { headers: H }), { DB: mockDB(), ADMIN_TOKEN: 'k', PLATFORM_STRIPE_KEY: 'sk_live_x', STRIPE_WEBHOOK_SECRET: 'whsec_x' }, ctx);
j = await r.json();
ok(r.status === 200 && j.mode === 'live', 'selftest detects live mode');
ok(j.ready_for_live === true, 'selftest: ready_for_live when key+charges+webhook all good');
ok((j.recent_payments || []).length === 1 && j.recent_payments[0].amount === 12999, 'selftest lists recent payments (the full-circle proof)');

// payments self-test: TEST mode, no webhook -> test loop not ready + honest guidance
scn = 'notready';
r = await worker.fetch(mkReq('GET', '/api/admin/payments/selftest', { headers: H }), { DB: mockDB(), ADMIN_TOKEN: 'k', PLATFORM_STRIPE_KEY: 'sk_test_x' }, ctx);
j = await r.json();
ok(j.mode === 'test', 'selftest detects test/sandbox mode');
ok(j.ready_for_live === false && j.test_ready === false, 'selftest: test loop not ready without a test webhook');
ok((j.notes || []).some((n) => /4242/.test(n)), 'selftest tells you to pay with the test card');

// payments self-test still enforces admin auth
r = await worker.fetch(mkReq('GET', '/api/admin/payments/selftest', { headers: { 'X-Admin-Token': 'WRONG' } }), { DB: mockDB(), ADMIN_TOKEN: 'k', PLATFORM_STRIPE_KEY: 'sk_live_x' }, ctx);
ok(r.status === 401 || r.status === 403, 'selftest rejects a bad admin token');

// registrar (domain) self-test: NO key -> not ready + honest guidance (never buys)
r = await worker.fetch(mkReq('GET', '/api/admin/domains/selftest', { headers: H }), { DB: mockDB(), ADMIN_TOKEN: 'k', SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' }, ctx);
j = await r.json();
ok(r.status === 200 && j.key_set === false && j.ready === false, 'domains selftest: no DYNADOT_KEY -> not ready');
ok((j.notes || []).some((n) => /DYNADOT_KEY/.test(n)), 'domains selftest: tells you to set DYNADOT_KEY');

// registrar self-test: valid key + read-only search -> ready, and it confirms nothing was charged
dyn = 'ok';
r = await worker.fetch(mkReq('GET', '/api/admin/domains/selftest', { headers: H }), { DB: mockDB(), ADMIN_TOKEN: 'k', SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com', DYNADOT_KEY: 'dyn_x' }, ctx);
j = await r.json();
ok(j.key_set === true && j.ready === true && j.checks.key_valid === true, 'domains selftest: valid key -> ready via read-only search');
ok((j.notes || []).some((n) => /Nothing was charged/.test(n)), 'domains selftest: confirms the test never buys');

// registrar self-test still enforces admin auth
r = await worker.fetch(mkReq('GET', '/api/admin/domains/selftest', { headers: { 'X-Admin-Token': 'WRONG' } }), { DB: mockDB(), ADMIN_TOKEN: 'k', DYNADOT_KEY: 'dyn_x' }, ctx);
ok(r.status === 401 || r.status === 403, 'domains selftest rejects a bad admin token');

// ---- Developer API v1: gated OFF by default, key-authenticated, tenant-scoped, read-only ----
function devDB(scn) {
  function stmt(sql) {
    let a = [];
    const api = {
      bind: (...x) => { a = x; return api; },
      first: async () => {
        if (/FROM platform_config/.test(sql)) return scn === 'off' ? null : { v: '1' };
        if (/FROM api_keys WHERE key_hash/.test(sql)) return scn === 'ok' ? { id: 'k1', tenant_id: 't_1', revoked_at: null } : null;
        if (/FROM rate_limits/.test(sql)) return null;
        if (/FROM tenants WHERE id/.test(sql)) return { id: 't_1', name: 'Alpha', subdomain: 'alpha', fleet_type: 'cars', plan: 'pro' };
        if (/sqlite_master/.test(sql)) return { n: 30 };
        return null;
      },
      all: async () => { if (/FROM bookings WHERE tenant_id/.test(sql)) return { results: [{ id: 'bk1', customer_id: 'c1', asset_id: 'a1', starts: 1, ends: 2, status: 'confirmed', revenue_cents: 1000, created_at: 1, updated_at: 1 }] }; return { results: [] }; },
      run: async () => ({ success: true, meta: { changes: 1 } }),
    };
    return api;
  }
  return { prepare: stmt };
}
const devEnv = (scn) => ({ DB: devDB(scn), SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' });
r = await worker.fetch(mkReq('GET', '/api/v1/me'), devEnv('off'), ctx); j = await r.json();
ok(r.status === 503 && j.error === 'api_disabled', 'v1 gated OFF by default -> 503');
r = await worker.fetch(mkReq('GET', '/api/v1/me'), devEnv('nokey'), ctx);
ok(r.status === 401, 'v1 ON without a key -> 401');
r = await worker.fetch(mkReq('GET', '/api/v1/bookings', { headers: { Authorization: 'Bearer atl_live_test' } }), devEnv('ok'), ctx); j = await r.json();
ok(r.status === 200 && j.count === 1 && j.bookings[0].id === 'bk1', 'v1 valid key -> tenant-scoped bookings');
r = await worker.fetch(mkReq('POST', '/api/v1/me', { headers: { Authorization: 'Bearer atl_live_test' } }), devEnv('ok'), ctx);
ok(r.status === 405, 'v1 is read-only -> POST 405');

// ---- Atlas Counsel: admin-gated institutional-memory feed; works WITHOUT an AI key ----
const cEnv = () => ({ DB: mockDB(), ADMIN_TOKEN: 'k', SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' });
r = await worker.fetch(mkReq('GET', '/api/admin/counsel', { headers: H }), cEnv(), ctx); j = await r.json();
ok(r.status === 200 && j.ok === true && Array.isArray(j.items), 'counsel GET -> 200 + items array');
r = await worker.fetch(mkReq('POST', '/api/admin/counsel/act', { headers: H }), cEnv(), ctx);
ok(r.status === 400, 'counsel/act rejects a missing id+status');
r = await worker.fetch(mkReq('POST', '/api/admin/counsel/run', { headers: H }), cEnv(), ctx); j = await r.json();
ok(r.status === 200 && j.ok === true && !!j.ran, 'counsel/run computes deterministically with no AI key');
r = await worker.fetch(mkReq('GET', '/api/admin/counsel', { headers: { 'X-Admin-Token': 'WRONG' } }), cEnv(), ctx);
ok(r.status === 401 || r.status === 403, 'counsel rejects a bad admin token');

// ---- Developer platform pt.3: outbound webhooks (session-gated tenant mgmt + signed dispatch, HMAC-verified) ----
{
  const NOW = Date.now(), SID = 'sid_wh', CSRF = 'CSRFwh', TEN = 't_wh';
  const hooks = new Map();
  function whDB() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM sessions WHERE id/.test(sql)) return a[0] === SID ? { id: SID, user_id: 'u', tenant_id: TEN, csrf: CSRF, expires_at: NOW + 1e12, idle_at: NOW, revoked_at: null } : null;
          if (/FROM users WHERE id/.test(sql)) return { id: 'u', email: 'o@x.com', tenant_id: TEN, role: 'owner', caps: null };
          if (/FROM comp_grants/.test(sql)) return null;
          if (/COUNT\(\*\) c FROM webhook_endpoints/.test(sql)) { let n = 0; for (const v of hooks.values()) if (v.tenant_id === a[0]) n++; return { c: n }; }
          if (/FROM webhook_endpoints WHERE id=\? AND tenant_id=\?/.test(sql)) { const v = hooks.get(a[0]); return (v && v.tenant_id === a[1]) ? v : null; }
          if (/FROM platform_config/.test(sql)) return null;
          if (/FROM rate_limits/.test(sql)) return null;
          if (/sqlite_master/.test(sql)) return { n: 30 };
          return null;
        },
        all: async () => { if (/FROM webhook_endpoints WHERE tenant_id=\? ORDER BY/.test(sql)) return { results: [...hooks.values()].filter((v) => v.tenant_id === a[0]).map((v) => ({ id: v.id, url: v.url, events: v.events, active: v.active, created_at: v.created_at, last_status: v.last_status, last_attempt_at: v.last_attempt_at, fail_count: v.fail_count })) }; return { results: [] }; },
        run: async () => {
          if (/INSERT INTO webhook_endpoints/.test(sql)) hooks.set(a[0], { id: a[0], tenant_id: a[1], url: a[2], secret: a[3], events: a[4], active: 1, created_at: a[5], last_status: null, last_attempt_at: null, fail_count: 0 });
          else if (/UPDATE webhook_endpoints SET last_status/.test(sql)) { const id = a[a.length - 1], v = hooks.get(id); if (v) { v.last_status = a[0]; v.last_attempt_at = a[1]; v.fail_count = a[2]; } }
          else if (/DELETE FROM webhook_endpoints/.test(sql)) { const v = hooks.get(a[0]); if (v && v.tenant_id === a[1]) hooks.delete(a[0]); }
          return { success: true, meta: { changes: 1 } };
        },
      };
      return api;
    }
    return { prepare: stmt };
  }
  const wenv = { DB: whDB(), SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' };
  let sent = [];
  globalThis.fetch = (u, opts) => { sent.push({ url: String(u), opts: opts || {} }); return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ({}) }); };
  // hand-rolled request so we can set the Cookie header (undici forbids it on a real Request); worker uses method/url/headers.get/json here.
  const whReq = (method, path, body, over) => { const headers = Object.assign({ 'content-type': 'application/json', 'cookie': 'atlas_sid=' + SID, 'x-csrf-token': CSRF, 'origin': 'https://atlasrental.io' }, over || {}); return { method, url: 'https://atlasrental.io' + path, headers: { get: (k) => { const v = headers[String(k).toLowerCase()]; return v === undefined ? null : v; } }, json: async () => (body || {}), text: async () => JSON.stringify(body || {}) }; };

  let wr = await worker.fetch(whReq('POST', '/api/tenant/webhooks', { url: 'https://hooks.example.com/atlas' }), wenv, ctx);
  let wj = await wr.json();
  ok(wr.status === 200 && /^whsec_/.test(wj.secret || '') && !!wj.id, 'webhooks: create -> id + whsec_ signing secret (shown once)');
  const WID = wj.id, SECRET = wj.secret;
  wr = await worker.fetch(whReq('POST', '/api/tenant/webhooks', { url: 'http://169.254.169.254/x' }), wenv, ctx);
  ok(wr.status === 400, 'webhooks: SSRF/private/non-https URL rejected');
  sent = [];
  wr = await worker.fetch(whReq('POST', '/api/tenant/webhooks', { test: WID }), wenv, ctx); wj = await wr.json();
  ok(wr.status === 200 && wj.delivered === true, 'webhooks: signed test ping delivered');
  const sig = (sent[0] && (sent[0].opts.headers || {})['X-Atlas-Signature']) || '';
  const exp = 'sha256=' + crypto.createHmac('sha256', SECRET).update(sent[0].opts.body).digest('hex');
  ok(sig === exp, 'webhooks: X-Atlas-Signature is a valid HMAC-SHA256 of the exact body');
  wr = await worker.fetch(whReq('DELETE', '/api/tenant/webhooks?id=' + WID), wenv, ctx);
  ok(wr.status === 200, 'webhooks: delete -> 200');
  wr = await worker.fetch(whReq('POST', '/api/tenant/webhooks', { url: 'https://a.example.com/h' }, { 'x-csrf-token': 'WRONG' }), wenv, ctx);
  ok(wr.status === 403, 'webhooks: bad CSRF -> 403');
  wr = await worker.fetch(whReq('GET', '/api/tenant/webhooks', null, { 'cookie': '' }), wenv, ctx);
  ok(wr.status === 401 || wr.status === 403, 'webhooks: no session -> 401/403 (not public)');
}

// ---- security hardening (2026-07-22): security headers everywhere, test-endpoint authz, competitor SSRF guard ----
{
  // H2: a served HTML page that never sets security headers itself (the public /api/unsub landing page) still gets
  // them from the final response merge in fetch().
  const hr = await worker.fetch(mkReq('GET', '/api/unsub'), { DB: mockDB(), SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' }, ctx);
  ok(hr.headers.get('x-content-type-options') === 'nosniff', 'security headers: nosniff present on a served HTML page');
  ok(hr.headers.get('x-frame-options') === 'DENY', 'security headers: X-Frame-Options present on a served HTML page');
  ok(!!hr.headers.get('strict-transport-security'), 'security headers: HSTS present on a served HTML page');
}

{
  // M4: /api/email/test + /api/sms/test refuse a signed-in viewer (no `settings` capability) before any send is attempted.
  const NOW = Date.now(), SID = 'sid_view', CSRF = 'CSRFview', TEN = 't_view';
  function viewDB() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM sessions WHERE id/.test(sql)) return a[0] === SID ? { id: SID, user_id: 'u_v', tenant_id: TEN, csrf: CSRF, expires_at: NOW + 1e12, idle_at: NOW, revoked_at: null } : null;
          if (/FROM users WHERE id/.test(sql)) return { id: 'u_v', email: 'viewer@x.com', tenant_id: TEN, role: 'viewer', caps: null };
          if (/FROM comp_grants/.test(sql)) return null;
          if (/FROM rate_limits/.test(sql)) return null;
          if (/sqlite_master/.test(sql)) return { n: 30 };
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => ({ success: true, meta: { changes: 1 } }),
      };
      return api;
    }
    return { prepare: stmt };
  }
  const venv = { DB: viewDB(), SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' };
  // hand-rolled request (mirrors whReq above): a real Request can't carry a Cookie header via undici
  const vReq = (path) => { const headers = { 'content-type': 'application/json', 'cookie': 'atlas_sid=' + SID, 'x-csrf-token': CSRF, 'origin': 'https://atlasrental.io' }; return { method: 'POST', url: 'https://atlasrental.io' + path, headers: { get: (k) => { const v = headers[String(k).toLowerCase()]; return v === undefined ? null : v; } }, json: async () => ({}), text: async () => '{}' }; };
  let vr = await worker.fetch(vReq('/api/email/test'), venv, ctx);
  ok(vr.status === 403, 'email/test: viewer with no settings capability -> 403 (got ' + vr.status + ')');
  vr = await worker.fetch(vReq('/api/sms/test'), venv, ctx);
  ok(vr.status === 403, 'sms/test: viewer with no settings capability -> 403 (got ' + vr.status + ')');
}

{
  // M5: competitor-watchlist add rejects a link-local/private URL (SSRF guard) even though it passes the basic http(s) shape check.
  const ssrfReq = new Request('https://atlasrental.io/api/admin/competitors', { method: 'POST', headers: Object.assign({ 'Content-Type': 'application/json' }, H), body: JSON.stringify({ url: 'http://169.254.169.254/latest/meta-data', label: 'ssrf' }) });
  const sr = await worker.fetch(ssrfReq, { DB: mockDB(), ADMIN_TOKEN: 'k', SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' }, ctx);
  ok(sr.status === 400, 'competitor add: SSRF-blocked private URL -> 400 (got ' + sr.status + ')');
}

// ---- password reset (audit gap #17): forgot-password never reveals whether an email has an account; GET/POST
//      /api/auth/reset re-validate the SAME signed token (never trust the GET), and a successful reset revokes
//      every session for that user. ----
{
  const users = new Map();   // email(lower) -> {id,email,pw_hash,pw_salt}
  users.set('known@x.com', { id: 'u_pw1', email: 'known@x.com', pw_hash: 'p2$old', pw_salt: 'saltold' });
  const sessionsRevokedFor = [];
  function pwDB() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM users WHERE email=\?/.test(sql)) return users.get(a[0]) || null;
          if (/FROM rate_limits/.test(sql)) return null;
          if (/sqlite_master/.test(sql)) return { n: 25 };
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => {
          if (/UPDATE users SET pw_hash=\?, pw_salt=\? WHERE id=\? AND lower\(email\)=\?/.test(sql)) {
            const [hash, salt, id, email] = a;
            const u = users.get(email);
            if (u && u.id === id) { u.pw_hash = hash; u.pw_salt = salt; return { success: true, meta: { changes: 1 } }; }
            return { success: true, meta: { changes: 0 } };
          }
          if (/UPDATE sessions SET revoked_at=\? WHERE user_id=\?/.test(sql)) { sessionsRevokedFor.push(a[1]); return { success: true, meta: { changes: 1 } }; }
          return { success: true, meta: { changes: 1 } };
        },
      };
      return api;
    }
    return { prepare: stmt };
  }
  const pwEnv = { DB: pwDB(), SESSION_KEY: 'sek', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com', RESEND_KEY: 'rk_test' };
  const pReq = (method, path, body) => new Request('https://atlasrental.io' + path, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });

  // capture the outbound "email" so we can pull out a genuinely-signed link for the positive-path checks below
  // (mirrors how the webhooks test above recovers the signed payload -- there is no other way to get a valid
  // token from outside the worker, since _resetSig is intentionally not exported).
  let sent = [];
  const _origFetch = globalThis.fetch;
  globalThis.fetch = (u, opts) => { sent.push(String((opts && opts.body) || '')); return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ({ id: 'm1' }) }); };

  // 1) forgot-password: an EXISTING email -> generic ok (no enumeration)
  let pr = await worker.fetch(pReq('POST', '/api/auth/forgot-password', { email: 'Known@X.com' }), pwEnv, ctx);
  let pj = await pr.json();
  ok(pr.status === 200 && pj.ok === true && /reset link is on the way/i.test(pj.message || ''), 'forgot-password: existing email -> generic ok + message');

  // 2) forgot-password: a NON-existing email -> the SAME generic response (no enumeration)
  let pr2 = await worker.fetch(pReq('POST', '/api/auth/forgot-password', { email: 'nobody@x.com' }), pwEnv, ctx);
  let pj2 = await pr2.json();
  ok(pr2.status === 200 && pj2.ok === true && pj2.message === pj.message, 'forgot-password: unknown email -> identical generic response (no enumeration)');

  const sentMail = sent.map((b) => { try { return JSON.parse(b); } catch (e) { return {}; } }).find((b) => b.html && /Reset your password/i.test(b.html));
  const linkM = ((sentMail && sentMail.html) || '').match(/href="([^"]+)"/);
  const link = linkM ? linkM[1].replace(/&amp;/g, '&') : '';
  const goodQ = link ? link.slice(link.indexOf('?')) : '';
  ok(!!goodQ, 'forgot-password actually emailed a /api/auth/reset link (precondition for the checks below)');

  // 3) GET reset with a BAD signature -> serves the invalid/expired page, never the password form
  let gr = await worker.fetch(mkReq('GET', '/api/auth/reset?uid=u_pw1&e=known@x.com&exp=' + (Date.now() + 999999) + '&s=deadbeef'), pwEnv, ctx);
  let gt = await gr.text();
  ok(gr.status === 200 && /invalid or has expired/i.test(gt) && !/Choose a new password/i.test(gt), 'GET reset: bad signature -> invalid-link page, not the form');

  // 4) GET reset with the GENUINE link -> serves the set-new-password form
  if (goodQ) {
    let gr2 = await worker.fetch(mkReq('GET', '/api/auth/reset' + goodQ), pwEnv, ctx);
    let gt2 = await gr2.text();
    ok(gr2.status === 200 && /Choose a new password/i.test(gt2), 'GET reset: a genuine link renders the new-password form');
  }

  // 5) POST reset with a BAD signature -> rejected, stored password untouched
  let br = await worker.fetch(pReq('POST', '/api/auth/reset', { uid: 'u_pw1', e: 'known@x.com', exp: Date.now() + 999999, s: 'deadbeef', password: 'newpassword1' }), pwEnv, ctx);
  ok(br.status >= 400, 'POST reset: bad signature -> rejected (got ' + br.status + ')');
  ok(users.get('known@x.com').pw_hash === 'p2$old', 'POST reset: bad signature never touched the stored password');

  // 6) POST reset with the GENUINE token -> succeeds, hash changes, and every session for that user is revoked
  if (goodQ) {
    const qp = new URLSearchParams(goodQ);
    let gpr = await worker.fetch(pReq('POST', '/api/auth/reset', { uid: qp.get('uid'), e: qp.get('e'), exp: qp.get('exp'), s: qp.get('s'), password: 'brandNewPassw0rd' }), pwEnv, ctx);
    let gpj = await gpr.json();
    ok(gpr.status === 200 && gpj.ok === true, 'POST reset: genuine token + an 8+ char password -> ok:true');
    ok(users.get('known@x.com').pw_hash !== 'p2$old', 'POST reset: pw_hash actually changed');
    ok(sessionsRevokedFor.indexOf('u_pw1') >= 0, 'POST reset: every session for that user is revoked (UPDATE sessions SET revoked_at)');
  }

  globalThis.fetch = _origFetch;
}

// ---- Scale/perf (SCALING.md): /api/data/<collection> GET pagination -- default unchanged, limit/offset honored + clamped ----
{
  const NOW = Date.now(), SID = 'sid_pg', CSRF = 'CSRFpg', TEN = 't_pg';
  const allAssets = [
    { id: 'a1', tenant_id: TEN, name: 'Asset 1', created_at: 5 },
    { id: 'a2', tenant_id: TEN, name: 'Asset 2', created_at: 4 },
    { id: 'a3', tenant_id: TEN, name: 'Asset 3', created_at: 3 },
    { id: 'a4', tenant_id: TEN, name: 'Asset 4', created_at: 2 },
    { id: 'a5', tenant_id: TEN, name: 'Asset 5', created_at: 1 },
  ];
  function pgDB() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM sessions WHERE id/.test(sql)) return a[0] === SID ? { id: SID, user_id: 'u_pg', tenant_id: TEN, csrf: CSRF, expires_at: NOW + 1e12, idle_at: NOW, revoked_at: null } : null;
          if (/FROM users WHERE id/.test(sql)) return { id: 'u_pg', email: 'pg@x.com', tenant_id: TEN, role: 'owner', caps: null };
          if (/FROM comp_grants/.test(sql)) return null;
          if (/FROM rate_limits/.test(sql)) return null;
          if (/sqlite_master/.test(sql)) return { n: 30 };
          return null;
        },
        all: async () => {
          // mirrors the real SQL shape: SELECT * FROM assets WHERE tenant_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?
          if (/FROM assets WHERE tenant_id=\?/.test(sql) && /LIMIT \? OFFSET \?/.test(sql)) { const lim = a[1], off = a[2]; return { results: allAssets.slice(off, off + lim) }; }
          return { results: [] };
        },
        run: async () => ({ success: true, meta: { changes: 1 } }),
      };
      return api;
    }
    return { prepare: stmt };
  }
  const pgEnv = { DB: pgDB(), SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' };
  // hand-rolled request (mirrors whReq/vReq above): a real Request can't carry a Cookie header via undici
  const pgReq = (path) => { const headers = { 'content-type': 'application/json', 'cookie': 'atlas_sid=' + SID, 'x-csrf-token': CSRF, 'origin': 'https://atlasrental.io' }; return { method: 'GET', url: 'https://atlasrental.io' + path, headers: { get: (k) => { const v = headers[String(k).toLowerCase()]; return v === undefined ? null : v; } }, json: async () => ({}), text: async () => '' }; };

  let pr = await worker.fetch(pgReq('/api/data/assets'), pgEnv, ctx);
  let pj = await pr.json();
  ok(pr.status === 200 && pj.items.length === 5 && pj.limit === 1000 && pj.offset === 0 && pj.hasMore === false, 'data pagination: no query params -> default behavior unchanged (all 5 rows, limit 1000, offset 0)');

  pr = await worker.fetch(pgReq('/api/data/assets?limit=2'), pgEnv, ctx); pj = await pr.json();
  ok(pr.status === 200 && pj.items.length === 2 && pj.items[0].id === 'a1' && pj.items[1].id === 'a2' && pj.limit === 2 && pj.hasMore === true, 'data pagination: limit=2 -> first page of 2 + hasMore:true');

  pr = await worker.fetch(pgReq('/api/data/assets?limit=2&offset=2'), pgEnv, ctx); pj = await pr.json();
  ok(pr.status === 200 && pj.items.length === 2 && pj.items[0].id === 'a3' && pj.items[1].id === 'a4' && pj.offset === 2, 'data pagination: limit=2&offset=2 -> next page');

  pr = await worker.fetch(pgReq('/api/data/assets?limit=2&offset=4'), pgEnv, ctx); pj = await pr.json();
  ok(pr.status === 200 && pj.items.length === 1 && pj.items[0].id === 'a5' && pj.hasMore === false, 'data pagination: last partial page -> hasMore:false');

  pr = await worker.fetch(pgReq('/api/data/assets?limit=99999'), pgEnv, ctx); pj = await pr.json();
  ok(pr.status === 200 && pj.limit === 1000, 'data pagination: limit clamped to max 1000');

  pr = await worker.fetch(pgReq('/api/data/assets?limit=-5&offset=-5'), pgEnv, ctx); pj = await pr.json();
  ok(pr.status === 200 && pj.limit === 1 && pj.offset === 0, 'data pagination: negative limit clamped to min 1, negative offset clamped to 0');
}

// ---- Scale/perf (SCALING.md): _hqMetrics + /api/admin/overview bucketing moved from a full-tenant-table JS loop to SQL
// aggregates (COUNT/SUM CASE WHEN + GROUP BY). Parity with the old JS loop was verified separately on a 17-row mock
// dataset via a real SQLite engine (every field matched); this just guards the response SHAPE + wiring never regress. ----
{
  function ovDB() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/sqlite_master/.test(sql)) return { n: 30 };
          if (/FROM platform_config/.test(sql)) return null;
          if (/FROM rate_limits/.test(sql)) return null;
          // the new SQL-aggregate bucket query (replaces the old "SELECT plan,tier,... FROM tenants" + JS forEach)
          if (/COUNT\(\*\) total/.test(sql) && /SUM\(CASE WHEN plan IS 'active'/.test(sql)) return { total: 12, paid: 5, comped: 1, trials: 6, twc: 2 };
          if (/COALESCE\(SUM\(amount_cents\),0\)/.test(sql)) return { c: 0 };
          return null;
        },
        all: async () => {
          // the new by-tier GROUP BY query (replaces the old byTier JS forEach)
          if (/GROUP BY \(CASE WHEN tier IS NULL/.test(sql)) return { results: [{ tier: 'pro', n: 3 }, { tier: 'starter', n: 2 }] };
          return { results: [] };
        },
        run: async () => ({ success: true, meta: { changes: 1 } }),
      };
      return api;
    }
    return { prepare: stmt };
  }
  const ovEnv = { DB: ovDB(), ADMIN_TOKEN: 'k', SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' };
  const or_ = await worker.fetch(mkReq('GET', '/api/admin/overview', { headers: H }), ovEnv, ctx);
  const oj = await or_.json();
  ok(or_.status === 200 && oj.ok === true, '/api/admin/overview: 200 + ok:true after the SQL-aggregate rewrite');
  ok(oj.members && oj.members.total === 12 && oj.members.paid === 5 && oj.members.comped === 1 && oj.members.trials === 6 && oj.members.trials_with_card === 2, '/api/admin/overview: members bucket numbers come from the new SQL aggregate');
  ok(oj.members.by_tier && oj.members.by_tier.pro === 3 && oj.members.by_tier.starter === 2, '/api/admin/overview: by_tier comes from the new GROUP BY query');
  ok(typeof oj.revenue.mrr_cents === 'number' && oj.revenue.mrr_cents === (19900 * 3 + 4999 * 2), '/api/admin/overview: mrr_cents computed from the SQL-derived by_tier (unchanged JS math)');
  ok('signups' in oj && oj.visits && oj.installs && oj.bugs && oj.inbox && Array.isArray(oj.recent), '/api/admin/overview: full response shape unchanged (signups/visits/installs/bugs/inbox/recent present)');
}

// ---- MFA (two-factor authentication): additive, opt-in, OFF by default. Standalone RFC 6238 vector first (the
// official test key "12345678901234567890" @ unix time 59 must produce 287082 -- if this ever fails, the TOTP
// implementation is broken and nothing below can be trusted), then the full login/challenge/verify lifecycle
// through worker.fetch() against a stateful mock D1, exactly like every other block in this file. ----
{
  const rfcSecret = Buffer.from('12345678901234567890', 'ascii');   // RFC 6238's test key IS the raw ASCII bytes, not base32
  const rfcCode = await _totpAt(rfcSecret, 59, 30, 6);
  ok(rfcCode === '287082', 'RFC 6238 standalone vector: TOTP(ASCII secret "12345678901234567890", t=59) === 287082 (got ' + rfcCode + ')');
  const rfcCode8 = await _hotp(rfcSecret, 1, 8);
  ok(rfcCode8 === '94287082', 'RFC 6238 standalone vector: 8-digit HOTP at counter=1 === 94287082 (got ' + rfcCode8 + ', cross-checks the dynamic-truncation math)');

  const users = new Map();        // id -> row (mirrors the real `users` table's MFA columns)
  const usersByEmail = new Map();
  const sessions = new Map();
  const rateLimits = new Map();
  const platformConfig = new Map();
  const mfaCodes = new Map();
  function mfaDB() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM sessions WHERE id/.test(sql)) return sessions.get(a[0]) || null;
          if (/FROM comp_grants/.test(sql)) return null;
          if (/FROM users WHERE email=\?/.test(sql)) { const id = usersByEmail.get(a[0]); return id ? users.get(id) : null; }
          if (/FROM users WHERE id=\?/.test(sql)) return users.get(a[0]) || null;
          if (/mfa_pending_enc FROM users/.test(sql)) return users.get(a[0]) || null;
          if (/FROM rate_limits WHERE bucket=\?/.test(sql)) return rateLimits.get(a[0]) || null;
          if (/FROM platform_config WHERE k=\?/.test(sql)) { const v = platformConfig.get(a[0]); return v === undefined ? null : { v }; }
          if (/code_hash, expires_at FROM mfa_codes WHERE uid=\?/.test(sql)) return mfaCodes.get(a[0]) || null;
          if (/sqlite_master/.test(sql)) return { n: 25 };
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => {
          if (/INSERT INTO users \(id,email,pw_hash,pw_salt,tenant_id,role,created_at\)/.test(sql)) {
            const [id, email, pw_hash, pw_salt, tenant_id, role, created_at] = a;
            users.set(id, { id, email, pw_hash, pw_salt, tenant_id, role, created_at, email_verified: 1, mfa_method: null, mfa_secret_enc: null, mfa_pending_enc: null, mfa_backup_json: null, mfa_enabled_at: null });
            usersByEmail.set(email, id);
          } else if (/UPDATE users SET last_login=\? WHERE id=\?/.test(sql)) { const u = users.get(a[1]); if (u) u.last_login = a[0]; }
          else if (/UPDATE users SET mfa_pending_enc=\?, mfa_backup_json=\? WHERE id=\?/.test(sql)) { const u = users.get(a[2]); if (u) { u.mfa_pending_enc = a[0]; u.mfa_backup_json = a[1]; } }
          else if (/mfa_method='totp', mfa_secret_enc=mfa_pending_enc, mfa_pending_enc=NULL/.test(sql)) { const u = users.get(a[1]); if (u) { u.mfa_method = 'totp'; u.mfa_secret_enc = u.mfa_pending_enc; u.mfa_pending_enc = null; u.mfa_enabled_at = a[0]; } }
          else if (/mfa_method='email', mfa_secret_enc=NULL/.test(sql)) { const u = users.get(a[1]); if (u) { u.mfa_method = 'email'; u.mfa_secret_enc = null; u.mfa_pending_enc = null; u.mfa_backup_json = null; u.mfa_enabled_at = a[0]; } }
          else if (/mfa_method=NULL, mfa_secret_enc=NULL/.test(sql)) { const u = users.get(a[0]); if (u) { u.mfa_method = null; u.mfa_secret_enc = null; u.mfa_pending_enc = null; u.mfa_backup_json = null; u.mfa_enabled_at = null; } }
          else if (/UPDATE users SET mfa_backup_json=\? WHERE id=\?/.test(sql)) { const u = users.get(a[1]); if (u) u.mfa_backup_json = a[0]; }
          else if (/INSERT INTO rate_limits/.test(sql)) rateLimits.set(a[0], { count: 1, window_start: a[1] });
          else if (/UPDATE rate_limits SET count=count\+1/.test(sql)) { const r = rateLimits.get(a[0]); if (r) r.count++; }
          else if (/INSERT INTO platform_config/.test(sql)) platformConfig.set(a[0], a[1]);
          else if (/INSERT INTO mfa_codes/.test(sql)) mfaCodes.set(a[0], { code_hash: a[1], expires_at: a[2], created_at: a[3] });
          else if (/DELETE FROM mfa_codes WHERE uid=\?/.test(sql)) mfaCodes.delete(a[0]);
          else if (/INSERT INTO sessions/.test(sql)) sessions.set(a[0], { id: a[0], user_id: a[1], tenant_id: a[2], csrf: a[3], created_at: a[4], idle_at: a[5], expires_at: a[6], revoked_at: null });
          return { success: true, meta: { changes: 1 } };   // every ensurePlatformSchema CREATE/ALTER -- best-effort, always "succeeds"
        },
      };
      return api;
    }
    return { prepare: stmt };
  }
  const mfaEnv = { DB: mfaDB(), SESSION_KEY: 'test-session-key-not-a-real-secret', ENC_KEY: Buffer.alloc(32, 7).toString('base64'), OWNER_EMAIL: 'owner@x.com' };   // exactly 32 raw bytes, base64-encoded -- what encSecret/decSecret's AES-GCM key import expects
  const mfaReq = (method, path, body, cookie) => { const headers = { 'content-type': 'application/json', origin: 'https://atlasrental.io' }; if (cookie) headers['cookie'] = cookie; return { method, url: 'https://atlasrental.io' + path, headers: { get: (k) => { const v = headers[String(k).toLowerCase()]; return v === undefined ? null : v; } }, json: async () => (body || {}), text: async () => JSON.stringify(body || {}) }; };
  const mfaReqCsrf = (method, path, body, cookie, csrf) => { const rq = mfaReq(method, path, body, cookie); rq.headers = { get: (k) => { const m = { 'content-type': 'application/json', origin: 'https://atlasrental.io', cookie: cookie || '', 'x-csrf-token': csrf || '' }; const v = m[String(k).toLowerCase()]; return v === undefined || v === '' ? null : v; } }; return rq; };
  function newestSession() { let best = null; for (const s of sessions.values()) if (!best || s.created_at >= best.created_at) best = s; return best; }

  // (a) mfa-off login: unchanged -- a session issued in one round trip, no challenge
  let r = await worker.fetch(mfaReq('POST', '/api/auth/signup', { email: 'plain@x.com', password: 'correcthorsebatterystaple', business: 'Plain Co' }), mfaEnv, ctx);
  let j = await r.json();
  ok(r.status === 200 && j.ok === true, 'MFA: signup (no MFA) -> 200 ok');
  r = await worker.fetch(mfaReq('POST', '/api/auth/login', { email: 'plain@x.com', password: 'correcthorsebatterystaple' }), mfaEnv, ctx);
  j = await r.json();
  ok(r.status === 200 && j.ok === true && !!j.csrf && !j.mfa_required, 'MFA: mfa-off login issues a session directly, no mfa_required (unchanged path)');
  ok(newestSession() && newestSession().csrf === j.csrf, 'MFA: mfa-off login created a real session row matching the returned csrf');

  // (b) turn on TOTP for a second user, then confirm login now demands the challenge
  r = await worker.fetch(mfaReq('POST', '/api/auth/signup', { email: 'mfauser@x.com', password: 'correcthorsebatterystaple', business: 'MFA Co' }), mfaEnv, ctx);
  j = await r.json();
  const cookie1 = 'atlas_sid=' + newestSession().id, csrf1 = j.csrf;
  r = await worker.fetch(mfaReqCsrf('POST', '/api/auth/mfa/totp/setup', {}, cookie1, csrf1), mfaEnv, ctx);
  j = await r.json();
  ok(r.status === 200 && j.ok && j.secret && j.otpauth && Array.isArray(j.backup_codes) && j.backup_codes.length === 10, 'MFA: totp/setup returns a base32 secret + otpauth URI + 10 backup codes');
  const keyBytes = _b32decode(j.secret), backupCodes = j.backup_codes;
  const totpNow = () => _totpAt(keyBytes, Math.floor(Date.now() / 1000), 30, 6);
  r = await worker.fetch(mfaReqCsrf('POST', '/api/auth/mfa/totp/confirm', { code: 'wrongcode' }, cookie1, csrf1), mfaEnv, ctx);
  ok(r.status === 401, 'MFA: totp/confirm rejects a wrong code');
  r = await worker.fetch(mfaReqCsrf('POST', '/api/auth/mfa/totp/confirm', { code: await totpNow() }, cookie1, csrf1), mfaEnv, ctx);
  j = await r.json();
  ok(r.status === 200 && j.ok && j.method === 'totp', 'MFA: totp/confirm with the REAL current code activates mfa_method=totp');

  const sessCountBefore = sessions.size;
  r = await worker.fetch(mfaReq('POST', '/api/auth/login', { email: 'mfauser@x.com', password: 'correcthorsebatterystaple' }), mfaEnv, ctx);
  j = await r.json();
  ok(r.status === 200 && j.ok === false && j.mfa_required === true && j.method === 'totp' && !!j.challenge, 'MFA: mfa-on login returns mfa_required:true + method:totp + a challenge instead of a session');
  ok(sessions.size === sessCountBefore, 'MFA: mfa-on login created NO session row until the challenge is verified');
  const challenge = j.challenge;

  // (c) wrong code counts toward lockout; 5 bad codes lock the challenge (even a subsequently-correct one is refused)
  for (let i = 0; i < 5; i++) {
    r = await worker.fetch(mfaReq('POST', '/api/auth/mfa/verify', { challenge, code: '000000' }), mfaEnv, ctx);
    ok(r.status === 401, 'MFA: wrong code attempt #' + (i + 1) + ' rejected');
  }
  r = await worker.fetch(mfaReq('POST', '/api/auth/mfa/verify', { challenge, code: await totpNow() }), mfaEnv, ctx);
  ok(r.status === 401, 'MFA: after 5 bad codes the challenge is LOCKED -- even a correct code is now rejected');
  // the lock is scoped per-account (bucket "mfabad:<uid>"), not per-challenge, so a fresh login challenge for the
  // SAME account is deliberately still covered by it -- reset the bucket here (simulating the window elapsing)
  rateLimits.delete('mfabad:' + usersByEmail.get('mfauser@x.com'));

  // (d) a correct TOTP code on a fresh challenge issues a real session + (with remember_device) a trusted-device token
  r = await worker.fetch(mfaReq('POST', '/api/auth/login', { email: 'mfauser@x.com', password: 'correcthorsebatterystaple' }), mfaEnv, ctx);
  j = await r.json();
  const challenge2 = j.challenge;
  r = await worker.fetch(mfaReq('POST', '/api/auth/mfa/verify', { challenge: challenge2, code: await totpNow(), remember_device: true }), mfaEnv, ctx);
  j = await r.json();
  ok(r.status === 200 && j.ok === true && !!j.csrf && !!j.trusted_device, 'MFA: correct TOTP code -> real session + a trusted_device token (remember_device:true)');
  const trustedToken = j.trusted_device;

  // (e) that trusted-device token skips the challenge on the next login
  r = await worker.fetch(mfaReq('POST', '/api/auth/login', { email: 'mfauser@x.com', password: 'correcthorsebatterystaple', trusted_device: trustedToken }), mfaEnv, ctx);
  j = await r.json();
  ok(r.status === 200 && j.ok === true && !j.mfa_required, 'MFA: a valid trusted-device token skips the challenge entirely');

  // (f) a backup code clears a challenge once, then fails on reuse; a different backup code still works
  r = await worker.fetch(mfaReq('POST', '/api/auth/login', { email: 'mfauser@x.com', password: 'correcthorsebatterystaple' }), mfaEnv, ctx);
  j = await r.json();
  const challenge3 = j.challenge;
  r = await worker.fetch(mfaReq('POST', '/api/auth/mfa/verify', { challenge: challenge3, code: backupCodes[0] }), mfaEnv, ctx);
  j = await r.json();
  ok(r.status === 200 && j.ok === true, 'MFA: an unused backup code clears the challenge');
  r = await worker.fetch(mfaReq('POST', '/api/auth/login', { email: 'mfauser@x.com', password: 'correcthorsebatterystaple' }), mfaEnv, ctx);
  j = await r.json();
  const challenge4 = j.challenge;
  r = await worker.fetch(mfaReq('POST', '/api/auth/mfa/verify', { challenge: challenge4, code: backupCodes[0] }), mfaEnv, ctx);
  ok(r.status === 401, 'MFA: the SAME backup code fails the second time (single-use, already consumed)');
  r = await worker.fetch(mfaReq('POST', '/api/auth/mfa/verify', { challenge: challenge4, code: backupCodes[1] }), mfaEnv, ctx);
  j = await r.json();
  ok(r.status === 200 && j.ok === true, 'MFA: a different, still-unused backup code still works');

  // (g) platform kill switch: mfa_enabled=0 bypasses the challenge platform-wide, even for this mfa-on user
  platformConfig.set('mfa_enabled', '0');
  r = await worker.fetch(mfaReq('POST', '/api/auth/login', { email: 'mfauser@x.com', password: 'correcthorsebatterystaple' }), mfaEnv, ctx);
  j = await r.json();
  ok(r.status === 200 && j.ok === true && !j.mfa_required, 'MFA: kill switch (mfa_enabled=0) bypasses the challenge platform-wide');
  platformConfig.set('mfa_enabled', '1');

  // (h) disable requires a fresh code OR the account password -- neither present -> refused; password -> allowed
  r = await worker.fetch(mfaReqCsrf('POST', '/api/auth/mfa/disable', {}, cookie1, csrf1), mfaEnv, ctx);
  ok(r.status === 401, 'MFA: disable refuses with neither a password nor a code');
  r = await worker.fetch(mfaReq('POST', '/api/auth/login', { email: 'mfauser@x.com', password: 'correcthorsebatterystaple', trusted_device: trustedToken }), mfaEnv, ctx);
  j = await r.json();
  const cookieMfa = 'atlas_sid=' + newestSession().id, csrfMfa = j.csrf;
  r = await worker.fetch(mfaReqCsrf('POST', '/api/auth/mfa/disable', { password: 'correcthorsebatterystaple' }, cookieMfa, csrfMfa), mfaEnv, ctx);
  j = await r.json();
  ok(r.status === 200 && j.ok === true && j.method === 'off', 'MFA: the account password authorizes disabling');
  r = await worker.fetch(mfaReq('POST', '/api/auth/login', { email: 'mfauser@x.com', password: 'correcthorsebatterystaple' }), mfaEnv, ctx);
  j = await r.json();
  ok(r.status === 200 && j.ok === true && !j.mfa_required, 'MFA: after disable, login is unchanged again -- exactly like an mfa-off user');
}

// ---- Atlas.io real-actions planner (Phase 1): POST /api/aio/plan. The AI only ever PROPOSES {type,params};
// this endpoint's job is strict-JSON translation, mirroring /api/schedule's parse/fallback shape plus
// /api/aio's CSRF/viewer guard and credit spend. The CLIENT's own registry is authoritative for which action
// types are real, so a type outside the tenant's allow-list is tolerated here, never thrown. ----
{
  const NOW = Date.now(), SID = 'sid_plan', CSRF = 'CSRFplan', TEN = 't_plan';
  function planDB() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM sessions WHERE id/.test(sql)) return a[0] === SID ? { id: SID, user_id: 'u_plan', tenant_id: TEN, csrf: CSRF, expires_at: NOW + 1e12, idle_at: NOW, revoked_at: null } : null;
          if (/FROM users WHERE id/.test(sql)) return { id: 'u_plan', email: 'plan@x.com', tenant_id: TEN, role: 'owner', caps: null };
          if (/FROM comp_grants/.test(sql)) return null;
          if (/FROM tenants WHERE id/.test(sql)) return { tier: 'pro', credits_purchased: 0, credits_free: 500, credits_week: 999999999 };
          if (/FROM rate_limits/.test(sql)) return null;
          if (/sqlite_master/.test(sql)) return { n: 30 };
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => ({ success: true, meta: { changes: 1 } }),
      };
      return api;
    }
    return { prepare: stmt };
  }
  const planEnv = { DB: planDB(), SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com', ANTHROPIC_KEY: 'sk-ant-test' };
  const planReq = (body, over) => { const headers = Object.assign({ 'content-type': 'application/json', cookie: 'atlas_sid=' + SID, 'x-csrf-token': CSRF, origin: 'https://atlasrental.io' }, over || {}); return { method: 'POST', url: 'https://atlasrental.io/api/aio/plan', headers: { get: (k) => { const v = headers[String(k).toLowerCase()]; return v === undefined ? null : v; } }, json: async () => (body || {}), text: async () => JSON.stringify(body || {}) }; };

  // missing CSRF token -> 403 (never reaches the model)
  let pr = await worker.fetch(planReq({ q: 'make it dark', allowed: [] }, { 'x-csrf-token': undefined }), planEnv, ctx);
  ok(pr.status === 403, 'aio/plan: missing CSRF token -> 403 (got ' + pr.status + ')');

  // valid request -> parses the model's proposed action + reply
  const claudeJson = JSON.stringify({ reply: 'Sure, switching to dark mode.', actions: [{ type: 'theme.set', params: { mode: 'dark' }, because: 'you asked for dark mode' }], unsupported: [], clarify: [] });
  globalThis.fetch = (u, opts) => Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ({ content: [{ type: 'text', text: claudeJson }] }) });
  pr = await worker.fetch(planReq({ q: 'make it dark', allowed: [{ type: 'theme.set', params: ['mode'] }] }), planEnv, ctx);
  let pj = await pr.json();
  ok(pr.status === 200 && pj.live === true && pj.ok === true, 'aio/plan: valid request -> live:true ok:true (got ' + JSON.stringify(pj) + ')');
  ok(Array.isArray(pj.actions) && pj.actions.length === 1 && pj.actions[0].type === 'theme.set' && pj.actions[0].params.mode === 'dark', 'aio/plan: parses the model\'s proposed action + params');
  ok(typeof pj.reply === 'string' && pj.reply.length > 0, 'aio/plan: carries the model\'s reply text');

  // a type outside the tenant's allow-list is TOLERATED (passed through, never thrown) -- the CLIENT registry
  // (AIO_ACTIONS + _aioValidateAction) is what actually decides whether an action is real; the server just relays.
  const unknownJson = JSON.stringify({ reply: '', actions: [{ type: 'booking.cancel', params: { id: 'bk1' }, because: 'test' }], unsupported: [], clarify: [] });
  globalThis.fetch = (u, opts) => Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ({ content: [{ type: 'text', text: unknownJson }] }) });
  pr = await worker.fetch(planReq({ q: 'cancel booking 1', allowed: [{ type: 'theme.set', params: ['mode'] }] }), planEnv, ctx);
  pj = await pr.json();
  ok(pr.status === 200 && pj.ok === true && pj.actions[0].type === 'booking.cancel', 'aio/plan: an out-of-allow-list type from the model passes through unthrown (client registry is what filters it)');

  // malformed (non-JSON) model output -> ok:false, never throws
  globalThis.fetch = (u, opts) => Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ({ content: [{ type: 'text', text: 'not json at all' }] }) });
  pr = await worker.fetch(planReq({ q: 'do something', allowed: [] }), planEnv, ctx);
  pj = await pr.json();
  ok(pr.status === 200 && pj.live === true && pj.ok === false && typeof pj.error === 'string' && pj.error.length > 0, 'aio/plan: malformed model output -> {live:true,ok:false} with an error, never throws');

  // viewer role -> 403 (read-only), same guard as /api/aio and /api/schedule
  function viewerPlanDB() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM sessions WHERE id/.test(sql)) return a[0] === SID ? { id: SID, user_id: 'u_plan_v', tenant_id: TEN, csrf: CSRF, expires_at: NOW + 1e12, idle_at: NOW, revoked_at: null } : null;
          if (/FROM users WHERE id/.test(sql)) return { id: 'u_plan_v', email: 'planviewer@x.com', tenant_id: TEN, role: 'viewer', caps: null };
          if (/FROM comp_grants/.test(sql)) return null;
          if (/FROM rate_limits/.test(sql)) return null;
          if (/sqlite_master/.test(sql)) return { n: 30 };
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => ({ success: true, meta: { changes: 1 } }),
      };
      return api;
    }
    return { prepare: stmt };
  }
  const viewerPlanEnv = { DB: viewerPlanDB(), SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com', ANTHROPIC_KEY: 'sk-ant-test' };
  pr = await worker.fetch(planReq({ q: 'make it dark', allowed: [] }), viewerPlanEnv, ctx);
  ok(pr.status === 403, 'aio/plan: viewer role -> 403 read-only (got ' + pr.status + ')');
}

// ---- SECURITY (comp/grant rework): owner/platform-admin authority is EMAIL-ONLY -- no comp_grants role, including
// a legacy role='admin' row left over from before this was retired, may ever confer it. ------------------------------
{
  const NOW = Date.now();
  // scn: 'owner' (OWNER_EMAIL, no comp row) | 'gold' | 'free' | 'legacyadmin' (non-owner email, comp_grants.role='admin')
  function compEnvFor(scn) {
    const SID = 'sid_comp_' + scn, CSRF = 'csrf_comp_' + scn, TEN = 't_comp_' + scn, UID = 'u_comp_' + scn;
    const email = scn === 'owner' ? 'o@x.com' : (scn + '@member.com');
    const compRole = scn === 'owner' ? null : (scn === 'legacyadmin' ? 'admin' : scn);
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM sessions WHERE id/.test(sql)) return a[0] === SID ? { id: SID, user_id: UID, tenant_id: TEN, csrf: CSRF, expires_at: NOW + 1e12, idle_at: NOW, revoked_at: null } : null;
          if (/FROM users WHERE id/.test(sql)) return { id: UID, email: email, tenant_id: TEN, role: 'owner', caps: null };
          if (/FROM comp_grants WHERE email/.test(sql)) return compRole ? { role: compRole } : null;
          if (/FROM tenants WHERE id/.test(sql)) return null;
          if (/FROM rate_limits/.test(sql)) return null;
          if (/sqlite_master/.test(sql)) return { n: 30 };
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => ({ success: true, meta: { changes: 1 } }),
      };
      return api;
    }
    return { DB: { prepare: stmt }, SID, CSRF };
  }
  const compReq = (method, path, cfg, body) => { const headers = { 'content-type': 'application/json', 'cookie': 'atlas_sid=' + cfg.SID, 'x-csrf-token': cfg.CSRF, 'origin': 'https://atlasrental.io' }; return { method, url: 'https://atlasrental.io' + path, headers: { get: (k) => { const v = headers[String(k).toLowerCase()]; return v === undefined ? null : v; } }, json: async () => (body || {}), text: async () => JSON.stringify(body || {}) }; };

  // (a) OWNER_EMAIL session -> isOwner true
  const dOwner = compEnvFor('owner');
  let r = await worker.fetch(compReq('GET', '/api/auth/me', dOwner), { DB: dOwner.DB, SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' }, ctx);
  let j = await r.json();
  ok(r.status === 200 && j.user.isOwner === true, 'isOwner: OWNER_EMAIL session -> true');

  // (b) a comp_grants role for a NON-owner email -- gold, free, and a legacy 'admin' row -- must NEVER read as owner
  for (const scn of ['gold', 'free', 'legacyadmin']) {
    const d = compEnvFor(scn);
    let rr = await worker.fetch(compReq('GET', '/api/auth/me', d), { DB: d.DB, SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' }, ctx);
    let jj = await rr.json();
    ok(rr.status === 200 && jj.user.isOwner === false, 'isOwner: non-owner email w/ comp_grants.role=' + scn + ' -> false (got ' + JSON.stringify(jj.user) + ')');
  }
  ok((await (await worker.fetch(compReq('GET', '/api/auth/me', compEnvFor('legacyadmin')), { DB: compEnvFor('legacyadmin').DB, SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' }, ctx)).json()).user.comp === 'gold',
    'isOwner: a legacy admin comp row read-time-coerces to comp="gold" (never surfaced as admin)');

  // (c) the owner-session comp endpoint rejects role='admin' outright, but still grants gold/free
  const dGrant = compEnvFor('owner');
  let cr = await worker.fetch(compReq('POST', '/api/admin/comp', dGrant, { email: 'newmember@x.com', role: 'admin' }), { DB: dGrant.DB, SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' }, ctx);
  ok(cr.status === 400, 'comp endpoint: role=admin is rejected (got ' + cr.status + ')');
  let cr2 = await worker.fetch(compReq('POST', '/api/admin/comp', dGrant, { email: 'newmember@x.com', role: 'gold' }), { DB: dGrant.DB, SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' }, ctx);
  ok(cr2.status === 200, 'comp endpoint: role=gold still accepted (got ' + cr2.status + ')');
}

// ---- #276 PAYMENT-DELINQUENCY ACCESS GATING: server-authoritative 402 gate, flag-gated OFF by default.
// Flag OFF -> byte-identical (no request behaves differently). Flag ON -> locks past_due/canceled/expired-trial
// tenants; NEVER locks the platform owner, a comped (gold/free) account, an active plan, or an active trial;
// and /api/auth/* + /api/billing/* stay reachable even while locked (mirrors the compEnvFor pattern above). ----
{
  const NOW = Date.now();
  // scn picks the tenant/user shape; gateOn picks platform_config.payment_gate_enabled for that one request.
  function pgEnvFor(scn, gateOn) {
    const SID = 'sid_pg_' + scn, CSRF = 'csrf_pg_' + scn, TEN = 't_pg_' + scn, UID = 'u_pg_' + scn;
    const email = scn === 'owner' ? 'owner@x.com' : (scn + '@member.com');
    const compRole = scn === 'goldcomp' ? 'gold' : null;
    // 'past_due' | 'owner' | 'goldcomp' all sit on an otherwise-delinquent tenant ON PURPOSE -- proving the
    // owner/comp overrides win even when the tenant row itself looks locked.
    const tenantRow =
      scn === 'active' ? { plan: 'active', trial_ends: null, tier: 'pro', stripe_sub: 'sub_x' } :
      scn === 'trial_ok' ? { plan: 'trial', trial_ends: NOW + 7 * 24 * 3600 * 1000, tier: null, stripe_sub: null } :
      scn === 'trial_expired' ? { plan: 'trial', trial_ends: NOW - 1000, tier: null, stripe_sub: null } :
      scn === 'canceled' ? { plan: 'canceled', trial_ends: null, tier: 'pro', stripe_sub: null } :
      { plan: 'past_due', trial_ends: null, tier: 'pro', stripe_sub: 'sub_x' };
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM sessions WHERE id/.test(sql)) return a[0] === SID ? { id: SID, user_id: UID, tenant_id: TEN, csrf: CSRF, expires_at: NOW + 1e12, idle_at: NOW, revoked_at: null } : null;
          if (/FROM users WHERE id/.test(sql)) return { id: UID, email: email, tenant_id: TEN, role: 'owner', caps: null };
          if (/FROM comp_grants WHERE email/.test(sql)) return compRole ? { role: compRole } : null;
          if (/FROM tenants WHERE id/.test(sql)) return tenantRow;
          if (/FROM platform_config WHERE k=\?/.test(sql)) return (a[0] === 'payment_gate_enabled' && gateOn) ? { v: '1' } : null;
          if (/FROM rate_limits/.test(sql)) return null;
          if (/sqlite_master/.test(sql)) return { n: 30 };
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => ({ success: true, meta: { changes: 1 } }),
      };
      return api;
    }
    return { SID, CSRF, env: { DB: { prepare: stmt }, SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'owner@x.com' } };
  }
  const pgReq = (method, path, cfg, body) => { const headers = { 'content-type': 'application/json', cookie: 'atlas_sid=' + cfg.SID, 'x-csrf-token': cfg.CSRF, origin: 'https://atlasrental.io' }; return { method, url: 'https://atlasrental.io' + path, headers: { get: (k) => { const v = headers[String(k).toLowerCase()]; return v === undefined ? null : v; } }, json: async () => (body || {}), text: async () => JSON.stringify(body || {}) }; };

  // (a) flag OFF: a past_due tenant hitting a normal authenticated endpoint is completely unaffected (proves the feature is inert)
  let cfg = pgEnvFor('past_due', false);
  let r = await worker.fetch(pgReq('GET', '/api/data/bookings', cfg), cfg.env, ctx);
  ok(r.status === 200, '#276 flag OFF: past_due tenant GET /api/data/bookings -> 200, byte-identical to today (got ' + r.status + ')');

  // (b) flag ON: each locked reason -> 402 payment_required with the matching billing_state
  for (const [scn, expectBs] of [['past_due', 'past_due'], ['trial_expired', 'trial_expired'], ['canceled', 'canceled']]) {
    cfg = pgEnvFor(scn, true);
    r = await worker.fetch(pgReq('GET', '/api/data/bookings', cfg), cfg.env, ctx);
    let j = await r.json();
    ok(r.status === 402 && j.error === 'payment_required' && j.billing_state === expectBs, '#276 flag ON: ' + scn + ' -> 402 payment_required billing_state=' + expectBs + ' (got ' + r.status + ' ' + JSON.stringify(j) + ')');
  }

  // (c) flag ON, never-lock invariants: active plan, an ACTIVE trial, a comped gold user, and the platform owner
  //     all still read 200 -- even the goldcomp/owner cases sit on a tenant row that otherwise looks past_due.
  for (const scn of ['active', 'trial_ok', 'goldcomp', 'owner']) {
    cfg = pgEnvFor(scn, true);
    r = await worker.fetch(pgReq('GET', '/api/data/bookings', cfg), cfg.env, ctx);
    ok(r.status === 200, '#276 flag ON: never-lock case "' + scn + '" -> 200 (got ' + r.status + ')');
  }

  // (d) flag ON + locked tenant: /api/billing/portal is never 402'd by the gate. No Stripe key is configured in
  //     this env, so a request that gets PAST the gate lands on the route's own "not configured" 400 -- proving
  //     it reached the route at all (a 402 would only ever come from the gate, never from _platStripe).
  cfg = pgEnvFor('past_due', true);
  r = await worker.fetch(pgReq('POST', '/api/billing/portal', cfg, {}), cfg.env, ctx);
  ok(r.status === 400 && r.status !== 402, '#276 flag ON + locked: /api/billing/portal never 402s (reaches its own "not configured" 400 instead) (got ' + r.status + ')');

  // (e) flag ON + locked tenant: /api/auth/me (same /api/auth/ prefix as login) never 402s, and reports the real state
  cfg = pgEnvFor('past_due', true);
  r = await worker.fetch(pgReq('GET', '/api/auth/me', cfg), cfg.env, ctx);
  let jme = await r.json();
  ok(r.status === 200 && jme.billing_state === 'past_due', '#276 flag ON + locked: /api/auth/me never 402s and reports billing_state (got ' + r.status + ' ' + JSON.stringify(jme) + ')');
}

// ---- #276 (cont.): the REAL /api/auth/signup + /api/auth/login path -- through actual password hashing/
// verification, not a session mock -- also never 402s a locked tenant, and its 200 responses carry the true
// billing_state (what the client paywall keys off on auth). Mirrors the MFA block's stateful-mock pattern above. ----
{
  const users = new Map(), usersByEmail = new Map(), sessions = new Map(), tenants = new Map(), rateLimits = new Map(), platformConfig = new Map();
  function loginDB() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM users WHERE email=\?/.test(sql)) { const id = usersByEmail.get(a[0]); return id ? users.get(id) : null; }
          if (/id,email,tenant_id,role,caps FROM users/.test(sql)) return users.get(a[0]) || null;
          if (/FROM users WHERE id=\?/.test(sql)) return users.get(a[0]) || null;
          if (/FROM sessions WHERE id/.test(sql)) return sessions.get(a[0]) || null;
          if (/FROM comp_grants/.test(sql)) return null;
          if (/FROM tenants WHERE id/.test(sql)) return tenants.get(a[0]) || null;
          if (/FROM platform_config WHERE k=\?/.test(sql)) { const v = platformConfig.get(a[0]); return v === undefined ? null : { v }; }
          if (/FROM rate_limits WHERE bucket=\?/.test(sql)) return rateLimits.get(a[0]) || null;
          if (/sqlite_master/.test(sql)) return { n: 30 };
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => {
          if (/INSERT INTO tenants \(id,name,fleet_type,plan,trial_ends,created_at,updated_at,tz\)/.test(sql)) { const [id, name, fleet, plan, trial_ends, created_at, updated_at, tz] = a; tenants.set(id, { id, name, fleet_type: fleet, plan, trial_ends, tier: null, stripe_sub: null, created_at, updated_at, tz }); }
          else if (/INSERT INTO users \(id,email,pw_hash,pw_salt,tenant_id,role,created_at\)/.test(sql)) { const [id, email, pw_hash, pw_salt, tenant_id, role, created_at] = a; users.set(id, { id, email, pw_hash, pw_salt, tenant_id, role, created_at, email_verified: 1, mfa_method: null, caps: null }); usersByEmail.set(email, id); }
          else if (/UPDATE users SET last_login/.test(sql)) { const u = users.get(a[1]); if (u) u.last_login = a[0]; }
          else if (/UPDATE users SET email_verified/.test(sql)) { const u = users.get(a[1]); if (u) u.email_verified = a[0]; }
          else if (/INSERT INTO sessions/.test(sql)) sessions.set(a[0], { id: a[0], user_id: a[1], tenant_id: a[2], csrf: a[3], created_at: a[4], idle_at: a[5], expires_at: a[6], revoked_at: null });
          else if (/INSERT INTO platform_config/.test(sql)) platformConfig.set(a[0], a[1]);
          return { success: true, meta: { changes: 1 } };
        },
      };
      return api;
    }
    return { prepare: stmt };
  }
  const loginEnv = { DB: loginDB(), SESSION_KEY: 'test-session-key-not-a-real-secret', ENC_KEY: Buffer.alloc(32, 7).toString('base64'), OWNER_EMAIL: 'owner@x.com' };
  const loginReq = (method, path, body, cookie) => { const headers = { 'content-type': 'application/json', origin: 'https://atlasrental.io' }; if (cookie) headers['cookie'] = cookie; return { method, url: 'https://atlasrental.io' + path, headers: { get: (k) => { const v = headers[String(k).toLowerCase()]; return v === undefined ? null : v; } }, json: async () => (body || {}), text: async () => JSON.stringify(body || {}) }; };
  function newestSession() { let best = null; for (const s of sessions.values()) if (!best || s.created_at >= best.created_at) best = s; return best; }

  let r = await worker.fetch(loginReq('POST', '/api/auth/signup', { email: 'delinquent@x.com', password: 'correcthorsebatterystaple', business: 'Delinquent Co' }), loginEnv, ctx);
  let j = await r.json();
  ok(r.status === 200 && j.ok === true && j.billing_state === 'ok', '#276: signup response carries billing_state:"ok" (gate is off by default) (got ' + JSON.stringify(j) + ')');
  const tid = j.tenant_id;

  // simulate real life: this tenant's subscription is now past_due, AND the owner has since turned the gate on
  tenants.get(tid).plan = 'past_due';
  platformConfig.set('payment_gate_enabled', '1');

  // login again with the SAME real credentials (through actual PBKDF2 password verification) -- must NOT 402
  r = await worker.fetch(loginReq('POST', '/api/auth/login', { email: 'delinquent@x.com', password: 'correcthorsebatterystaple' }), loginEnv, ctx);
  j = await r.json();
  ok(r.status === 200 && j.ok === true && !!j.csrf, '#276: login for a past_due tenant with the gate ON still succeeds -- never 402s (got ' + r.status + ' ' + JSON.stringify(j) + ')');
  ok(j.billing_state === 'past_due', '#276: that same login response carries billing_state:"past_due" so the client shows the paywall right on auth (got ' + j.billing_state + ')');

  // and confirm the resulting session really IS locked for an ordinary endpoint -- proving login's carve-out is
  // deliberate (the allow-list), not evidence the gate silently failed to engage at all
  const cookie = 'atlas_sid=' + newestSession().id;
  r = await worker.fetch(loginReq('GET', '/api/data/bookings', null, cookie), loginEnv, ctx);
  j = await r.json();
  ok(r.status === 402 && j.error === 'payment_required', '#276: that same locked session -> 402 on an ordinary endpoint (the gate is genuinely active) (got ' + r.status + ')');
}

// ---- #276 admin toggle: GET/POST /api/admin/config surfaces payment_gate_enabled + a tenants_locked count ----
{
  const NOWc = Date.now();
  const tenantsC = new Map([
    ['t_c1', { plan: 'past_due', trial_ends: null }],
    ['t_c2', { plan: 'trial', trial_ends: NOWc - 1000 }],     // expired trial -> counts as locked
    ['t_c3', { plan: 'trial', trial_ends: NOWc + 1000000 }],  // active trial -> does NOT count
    ['t_c4', { plan: 'active', trial_ends: null }],           // active -> does NOT count
    ['t_c5', { plan: 'deleted', trial_ends: null }],          // deleted -> does NOT count (handled elsewhere)
  ]);
  let gateFlag = null;   // null == unset (reads as default '0'/off); '1'/'0' once toggled via POST
  function cfgDB() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM platform_config WHERE k=\?/.test(sql)) return (a[0] === 'payment_gate_enabled' && gateFlag != null) ? { v: gateFlag } : null;
          if (/COUNT\(\*\) c FROM tenants/.test(sql)) {
            const now = a[0]; let n = 0;
            for (const t of tenantsC.values()) { if (t.plan === 'deleted' || t.plan === 'active') continue; if (t.plan === 'trial' && Number(t.trial_ends) >= now) continue; n++; }
            return { c: n };
          }
          if (/sqlite_master/.test(sql)) return { n: 30 };
          if (/FROM rate_limits/.test(sql)) return null;
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => { if (/INSERT INTO platform_config/.test(sql) && a[0] === 'payment_gate_enabled') gateFlag = a[1]; return { success: true, meta: { changes: 1 } }; },
      };
      return api;
    }
    return { prepare: stmt };
  }
  const cfgEnv = { DB: cfgDB(), ADMIN_TOKEN: 'k', SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' };
  const cfgReq = (method, headers, body) => new Request('https://atlasrental.io/api/admin/config', { method, headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}), body: body !== undefined ? JSON.stringify(body) : undefined });

  let r = await worker.fetch(cfgReq('GET', H), cfgEnv, ctx);
  let j = await r.json();
  ok(r.status === 200 && j.enterprise.payment_gate_enabled === false, '#276 admin config: payment_gate_enabled defaults to false (got ' + JSON.stringify(j.enterprise && j.enterprise.payment_gate_enabled) + ')');
  ok(j.enterprise.tenants_locked === 2, '#276 admin config: tenants_locked counts past_due + expired-trial only (t_c1+t_c2) -- not active/active-trial/deleted (got ' + j.enterprise.tenants_locked + ', want 2)');

  r = await worker.fetch(cfgReq('POST', H, { payment_gate_enabled: true }), cfgEnv, ctx);
  j = await r.json();
  ok(r.status === 200 && j.enterprise.payment_gate_enabled === true, '#276 admin config: POST payment_gate_enabled:true flips it on (got ' + JSON.stringify(j.enterprise && j.enterprise.payment_gate_enabled) + ')');

  r = await worker.fetch(cfgReq('POST', { 'X-Admin-Token': 'WRONG' }, { payment_gate_enabled: false }), cfgEnv, ctx);
  ok(r.status === 401 || r.status === 403, '#276 admin config: a bad admin token cannot flip the gate (got ' + r.status + ')');
}

// ---- #264 staff-auth regression (deferred from build v): owner env-token is the ONLY owner identity (checked
// with NO DB access), a present-but-wrong credential fails CLOSED, a spoofed X-Admin-Actor header is completely
// inert, staff can never mint themselves (or anyone) an 'owner' row or a row for the reserved OWNER_EMAIL, and an
// empty/absent admin_staff table never locks the owner out. ----
{
  const staff = new Map();   // id -> {id,email,name,role,token_hash,token_prefix,active,created_by,created_at,last_seen_at,revoked_at}
  function staffDB() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM admin_staff WHERE token_hash=\?/.test(sql)) { for (const v of staff.values()) if (v.token_hash === a[0]) return v; return null; }
          if (/FROM admin_staff WHERE email=\?/.test(sql)) { for (const v of staff.values()) if (v.email === a[0]) return { id: v.id }; return null; }
          if (/FROM admin_staff WHERE id=\?/.test(sql)) return staff.get(a[0]) || null;
          if (/sqlite_master/.test(sql)) return { n: 30 };
          if (/FROM platform_config/.test(sql)) return null;
          if (/FROM rate_limits/.test(sql)) return null;
          return null;
        },
        all: async () => { if (/FROM admin_staff/.test(sql)) return { results: [...staff.values()] }; return { results: [] }; },
        run: async () => {
          if (/INSERT INTO admin_staff/.test(sql)) { const [id, email, name, role, token_hash, token_prefix, created_by, created_at] = a; staff.set(id, { id, email, name, role, token_hash, token_prefix, active: 1, created_by, created_at, last_seen_at: null, revoked_at: null }); }
          else if (/UPDATE admin_staff SET last_seen_at/.test(sql)) { const v = staff.get(a[1]); if (v) v.last_seen_at = a[0]; }
          return { success: true, meta: { changes: 1 } };
        },
      };
      return api;
    }
    return { prepare: stmt };
  }
  const OWNER_EMAIL = 'owner@x.com';
  const senv = { DB: staffDB(), ADMIN_TOKEN: 'realowner', SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL };

  // (a) owner env-token works
  let r = await worker.fetch(mkReq('GET', '/api/admin/staff', { headers: { 'X-Admin-Token': 'realowner' } }), senv, ctx);
  ok(r.status === 200, '#264: owner env-token -> 200 on /api/admin/staff (got ' + r.status + ')');

  // (b) NO-LOCKOUT: admin_staff is empty/absent -- owner env-token still works. Uses /api/admin/config (touches
  // only platform_config, no admin_staff/revenue tables) so this isolates exactly the no-lockout scenario.
  ok(staff.size === 0, '#264 precondition: admin_staff is empty for the no-lockout check');
  let r0 = await worker.fetch(mkReq('GET', '/api/admin/config', { headers: { 'X-Admin-Token': 'realowner' } }), senv, ctx);
  ok(r0.status === 200, '#264 NO-LOCKOUT: owner env-token still 200 with admin_staff absent/empty (got ' + r0.status + ')');

  // (c) no token at all -> 403
  let r1 = await worker.fetch(mkReq('GET', '/api/admin/staff'), senv, ctx);
  ok(r1.status === 403, '#264: no X-Admin-Token -> 403 (got ' + r1.status + ')');

  // (d) a garbage atlst_-shaped token matching no row -> 403 (fails CLOSED, never silently treated as owner)
  let r2 = await worker.fetch(mkReq('GET', '/api/admin/staff', { headers: { 'X-Admin-Token': 'atlst_garbage_no_such_token' } }), senv, ctx);
  ok(r2.status === 403, '#264: garbage atlst_ token matching no row -> 403 (got ' + r2.status + ')');

  // (e) seed a real, active 'support' staff row -- its token authenticates as role=support, and a spoofed
  // X-Admin-Actor header claiming to be the owner is completely inert (identity comes only from the hashed row).
  const supportSecret = 'atlst_' + crypto.randomBytes(20).toString('hex');
  const supportHash = crypto.createHash('sha256').update(supportSecret).digest('hex');
  staff.set('s_support1', { id: 's_support1', email: 'support@member.com', name: 'Support One', role: 'support', token_hash: supportHash, token_prefix: supportSecret.slice(0, 12), active: 1, created_by: 'owner@x.com', created_at: Date.now(), last_seen_at: null, revoked_at: null });
  let r3 = await worker.fetch(mkReq('GET', '/api/admin/config', { headers: { 'X-Admin-Token': supportSecret, 'X-Admin-Actor': 'owner@x.com' } }), senv, ctx);
  let j3 = await r3.json();
  ok(r3.status === 200 && j3.you && j3.you.actor === 'support@member.com' && j3.you.role === 'support' && j3.you.via === 'staff-token', '#264: seeded support-role token authenticates as support@member.com/support/staff-token even with a spoofed X-Admin-Actor: owner@... header (got ' + JSON.stringify(j3.you) + ')');

  // the same support token is still refused on an OWNER_ONLY route (e.g. /api/admin/staff itself)
  let r4 = await worker.fetch(mkReq('GET', '/api/admin/staff', { headers: { 'X-Admin-Token': supportSecret } }), senv, ctx);
  ok(r4.status === 403, '#264: support-role token is refused on the owner-only /api/admin/staff route (got ' + r4.status + ')');

  // (f) POST /api/admin/staff role:'owner' -> 400 (no self-escalation, even attempted by the real owner)
  let r5 = await worker.fetch(new Request('https://atlasrental.io/api/admin/staff', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Admin-Token': 'realowner' }, body: JSON.stringify({ email: 'newstaff@member.com', role: 'owner' }) }), senv, ctx);
  ok(r5.status === 400, "#264: POST /api/admin/staff role:'owner' -> 400 (got " + r5.status + ')');

  // (g) POST /api/admin/staff email===OWNER_EMAIL -> 400 (the owner's own email can never be issued a staff token)
  let r6 = await worker.fetch(new Request('https://atlasrental.io/api/admin/staff', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Admin-Token': 'realowner' }, body: JSON.stringify({ email: OWNER_EMAIL, role: 'support' }) }), senv, ctx);
  ok(r6.status === 400, '#264: POST /api/admin/staff email===OWNER_EMAIL -> 400 (got ' + r6.status + ')');
}

// ---- #253 observability: the single top-level catch now best-effort records the error (never changes the
// response) + rate-limits an owner-email alert. Forces a REAL throw via a DB-fault-injection mock hitting an
// EXISTING, unwrapped admin route (/api/admin/overview's first query has no local try/catch -- like every other
// route, the top-level catch is the ONLY safety net, which is exactly what this exercises). ----
{
  const inserted = [];
  const rl = new Map();
  let mailSent = 0;
  const _origFetch = globalThis.fetch;
  globalThis.fetch = (u) => { if (String(u).indexOf('api.resend.com') >= 0) mailSent++; return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ({ id: 'm1' }) }); };
  function errDB() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM platform_transactions/.test(sql)) throw new Error('sentinel boom: platform_transactions unreachable');
          if (/sqlite_master/.test(sql)) return { n: 30 };
          if (/FROM rate_limits WHERE bucket=\?/.test(sql)) return rl.get(a[0]) || null;
          if (/FROM platform_config/.test(sql)) return null;
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => {
          if (/INSERT INTO platform_errors/.test(sql)) inserted.push(a);
          else if (/INSERT INTO rate_limits/.test(sql)) rl.set(a[0], { count: 1, window_start: a[1] });
          else if (/UPDATE rate_limits SET count=count\+1/.test(sql)) { const row = rl.get(a[0]); if (row) row.count++; }
          return { success: true, meta: { changes: 1 } };
        },
      };
      return api;
    }
    return { prepare: stmt };
  }
  const eenv = { DB: errDB(), ADMIN_TOKEN: 'k', SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com', RESEND_KEY: 'rk_test' };
  let waited = [];
  const eCtx = { waitUntil(p) { waited.push(p); }, passThroughOnException() {} };

  let r = await worker.fetch(mkReq('GET', '/api/admin/overview', { headers: H }), eenv, eCtx);
  ok(r.status === 500, 'sentinel throw inside a route -> the request still gets a response, status 500 (got ' + r.status + ')');
  let j = await r.json();
  ok(j && j.error === 'Server error.' && Object.keys(j).length === 1, 'sentinel throw -> byte-identical {"error":"Server error."}, no stack/details leaked (got ' + JSON.stringify(j) + ')');
  await Promise.all(waited); waited.length = 0;
  ok(inserted.length === 1, '_recordError captured exactly one platform_errors INSERT for the thrown error (got ' + inserted.length + ')');
  ok(mailSent === 1, '_recordError attempted exactly one owner-alert email for a new error signature (got ' + mailSent + ')');

  // hit the SAME sentinel again (same name+path -> same sig): recording still happens (count++), but the
  // per-signature rate limit (1/hr) means NO second email
  let r2 = await worker.fetch(mkReq('GET', '/api/admin/overview', { headers: H }), eenv, eCtx);
  ok(r2.status === 500, 'sentinel throw #2 -> still 500 (got ' + r2.status + ')');
  await Promise.all(waited); waited.length = 0;
  ok(inserted.length === 2, '_recordError ran again on the second throw (2nd INSERT attempt, count++ semantics) (got ' + inserted.length + ')');
  ok(mailSent === 1, 'per-signature rate limit: the SAME error signature does not send a second email within the hour (got ' + mailSent + ')');

  globalThis.fetch = _origFetch;
}

// ---- #253 observability: owner-only denials + logout are audited (owner.denied / logout) ----
{
  const NOW = Date.now(), SID = 'sid_secaudit', CSRF = 'csrf_secaudit', TEN = 't_secaudit', UID = 'u_secaudit';
  const auditRows = [];
  function auditDB() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM sessions WHERE id/.test(sql)) return a[0] === SID ? { id: SID, user_id: UID, tenant_id: TEN, csrf: CSRF, expires_at: NOW + 1e12, idle_at: NOW, revoked_at: null } : null;
          if (/FROM users WHERE id/.test(sql)) return { id: UID, email: 'notowner@member.com', tenant_id: TEN, role: 'owner', caps: null };   // tenant-level "owner" role (owns THEIR OWN business) -- NOT the platform OWNER_EMAIL, so isOwner must still read false
          if (/FROM comp_grants/.test(sql)) return null;
          if (/FROM rate_limits/.test(sql)) return null;
          if (/sqlite_master/.test(sql)) return { n: 30 };
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => {
          if (/INSERT INTO audit_log/.test(sql)) auditRows.push({ actor: a[1], action: a[2], meta: a[3] });
          return { success: true, meta: { changes: 1 } };
        },
      };
      return api;
    }
    return { prepare: stmt };
  }
  const aenv = { DB: auditDB(), SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'the-real-owner@x.com' };
  const aReq = (method, path, body) => { const headers = { 'content-type': 'application/json', cookie: 'atlas_sid=' + SID, 'x-csrf-token': CSRF, origin: 'https://atlasrental.io' }; return { method, url: 'https://atlasrental.io' + path, headers: { get: (k) => { const v = headers[String(k).toLowerCase()]; return v === undefined ? null : v; } }, json: async () => (body || {}), text: async () => JSON.stringify(body || {}) }; };

  // (a) a signed-in, non-platform-owner user hitting the owner-only /api/admin/comp -> 403 + an owner.denied audit row
  let r = await worker.fetch(aReq('POST', '/api/admin/comp', { email: 'x@y.com', role: 'gold' }), aenv, ctx);
  ok(r.status === 403, '#253: /api/admin/comp without the platform owner -> 403 (got ' + r.status + ')');
  ok(auditRows.some((row) => row.action === 'owner.denied'), '#253: owner-only denial recorded an owner.denied audit row (got ' + JSON.stringify(auditRows) + ')');

  // (b) POST /api/auth/logout -> a logout audit row
  auditRows.length = 0;
  let r2 = await worker.fetch(aReq('POST', '/api/auth/logout', {}), aenv, ctx);
  ok(r2.status === 200, '#253: POST /api/auth/logout -> 200 (got ' + r2.status + ')');
  ok(auditRows.some((row) => row.action === 'logout'), '#253: logout recorded a logout audit row (got ' + JSON.stringify(auditRows) + ')');
}

// ---- #253 observability: GET /api/admin/security-log -- owner-gated, allow-list filtered, filter/q narrow the result ----
{
  const NOW = Date.now();
  const rows = [
    { tenant_id: null, actor: 'a@x.com', action: 'login', meta: '{}', ip: '1.1.1.1', ua: 'UA', at: NOW - 1000 },
    { tenant_id: null, actor: 'a@x.com', action: 'login_fail', meta: '{"email":"a@x.com"}', ip: '1.1.1.1', ua: 'UA', at: NOW - 2000 },
    { tenant_id: null, actor: 'b@x.com', action: 'mfa.verify_fail', meta: '{}', ip: '2.2.2.2', ua: 'UA', at: NOW - 3000 },
    { tenant_id: null, actor: 'atlas-hq', action: 'admin.denied', meta: '{"reason":"role"}', ip: '3.3.3.3', ua: 'UA', at: NOW - 4000 },
    { tenant_id: null, actor: 'checkout', action: 'billing.checkout', meta: '{}', ip: '4.4.4.4', ua: 'UA', at: NOW - 5000 }   // NOT in the security allow-list -- must be excluded entirely
  ];
  function slDB() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => { if (/sqlite_master/.test(sql)) return { n: 30 }; if (/FROM rate_limits/.test(sql)) return null; if (/FROM platform_config/.test(sql)) return null; return null; },
        all: async () => { if (/FROM audit_log WHERE at>=\? AND at<\?/.test(sql)) return { results: rows }; return { results: [] }; },
        run: async () => ({ success: true, meta: { changes: 1 } }),
      };
      return api;
    }
    return { prepare: stmt };
  }
  const slEnv = { DB: slDB(), ADMIN_TOKEN: 'k', SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' };

  let r = await worker.fetch(mkReq('GET', '/api/admin/security-log', { headers: H }), slEnv, ctx);
  let j = await r.json();
  ok(r.status === 200 && j.ok === true && Array.isArray(j.events), 'security-log: 200 + events array');
  ok(!j.events.some((e) => e.action === 'billing.checkout'), 'security-log: an action outside the allow-list is excluded even if the mock DB returned it');
  ok(j.total === 4 && j.events.length === 4, 'security-log: default filter=all returns all 4 allow-listed rows (got ' + j.events.length + ')');

  r = await worker.fetch(mkReq('GET', '/api/admin/security-log?filter=fail', { headers: H }), slEnv, ctx);
  j = await r.json();
  ok(j.events.length === 2 && j.events.every((e) => e.action === 'login_fail' || e.action === 'mfa.verify_fail'), 'security-log: filter=fail narrows to failures/lockouts only (got ' + JSON.stringify(j.events.map((e) => e.action)) + ')');

  r = await worker.fetch(mkReq('GET', '/api/admin/security-log?q=b@x.com', { headers: H }), slEnv, ctx);
  j = await r.json();
  ok(j.events.length === 1 && j.events[0].actor === 'b@x.com', 'security-log: q= narrows by actor substring (got ' + JSON.stringify(j.events) + ')');

  r = await worker.fetch(mkReq('GET', '/api/admin/security-log', { headers: { 'X-Admin-Token': 'WRONG' } }), slEnv, ctx);
  ok(r.status === 403, 'security-log: wrong admin token -> 403 (got ' + r.status + ')');
}

// ---- #274 visit tracking: POST /api/visit-ping (+ its GET pixel fallback) records page_views + active_now under
// the reserved '_site'/'_app' ids (never a real tenant); rate-limit-over-cap still returns 204 and writes nothing
// (never errors, never blocks the caller); /api/admin/overview + /api/admin/visits surface the results ----
{
  // -- part A: the rate limit (6 per 10s per IP) actually engages, and even then the endpoint stays 204 --
  {
    const pv = new Map(), an = new Map(), rl = new Map();
    function rlDB() {
      function stmt(sql) {
        let a = [];
        const api = {
          bind: (...x) => { a = x; return api; },
          first: async () => {
            if (/FROM sqlite_master/.test(sql)) return { n: 30 };
            if (/FROM rate_limits WHERE bucket=\?/.test(sql)) return rl.get(a[0]) || null;
            if (/FROM platform_config/.test(sql)) return null;
            return null;
          },
          all: async () => ({ results: [] }),
          run: async () => {
            if (/INSERT INTO page_views/.test(sql)) pv.set(a[0], (pv.get(a[0]) || 0) + 1);
            else if (/INSERT INTO active_now/.test(sql)) an.set(a[0], { last_at: a[1], src: a[2] });
            else if (/INSERT INTO rate_limits/.test(sql)) rl.set(a[0], { count: 1, window_start: a[1] });
            else if (/UPDATE rate_limits SET count=count\+1/.test(sql)) { const row = rl.get(a[0]); if (row) row.count++; }
            return { success: true, meta: { changes: 1 } };
          },
        };
        return api;
      }
      return { prepare: stmt };
    }
    const rlEnv = { DB: rlDB(), ADMIN_TOKEN: 'k', SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' };
    let waited = [];
    const rlCtx = { waitUntil(p) { waited.push(p); }, passThroughOnException() {} };
    const vpReq = (body) => new Request('https://atlasrental.io/api/visit-ping', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

    // 6 distinct visitors from the same (unset -> 'x') IP all fit under the 6/10s cap
    for (let i = 1; i <= 6; i++) {
      const rr = await worker.fetch(vpReq({ src: 'site', sid: 'sid_rl_' + i }), rlEnv, rlCtx);
      ok(rr.status === 204, 'visit-ping #' + i + ' within the rate limit -> 204 (got ' + rr.status + ')');
    }
    await Promise.all(waited); waited.length = 0;
    ok(pv.get('_site') === 6, 'all 6 within-limit pings recorded a page_views bump under _site (got ' + pv.get('_site') + ')');
    ok(an.size === 6, 'all 6 within-limit pings recorded a distinct active_now row (got ' + an.size + ')');

    // an unrecognized src is silently ignored -- no DB write AT ALL (never consumes a rate-limit unit), still 204
    let rr = await worker.fetch(vpReq({ src: 'evil', sid: 'sid_rl_bogus' }), rlEnv, rlCtx);
    ok(rr.status === 204, 'visit-ping with an unrecognized src -> still 204, never an error (got ' + rr.status + ')');
    await Promise.all(waited); waited.length = 0;
    ok(pv.get('_site') === 6 && !an.has('sid_rl_bogus'), 'an unrecognized src writes nothing (page_views unchanged, no active_now row) (got pv=' + pv.get('_site') + ', an has bogus=' + an.has('sid_rl_bogus') + ')');

    // the 7th VALID visitor is over the cap -> rate-limited -> still 204, but nothing new is recorded
    rr = await worker.fetch(vpReq({ src: 'site', sid: 'sid_rl_7' }), rlEnv, rlCtx);
    ok(rr.status === 204, 'visit-ping #7 (over the rate limit) -> still 204, NEVER an error/block (got ' + rr.status + ')');
    await Promise.all(waited); waited.length = 0;
    ok(pv.get('_site') === 6, 'the rate-limited 7th ping did not bump page_views (still 6, got ' + pv.get('_site') + ')');
    ok(!an.has('sid_rl_7'), 'the rate-limited 7th ping did not create an active_now row (got ' + an.has('sid_rl_7') + ')');
  }

  // -- part B: 'site' and 'app' are tracked separately, the GET pixel fallback works, and the admin reads surface it --
  {
    const pv = new Map(), an = new Map();
    function vbDB() {
      function stmt(sql) {
        let a = [];
        const api = {
          bind: (...x) => { a = x; return api; },
          first: async () => {
            if (/FROM sqlite_master/.test(sql)) return { n: 30 };
            if (/FROM rate_limits/.test(sql)) return null;   // not under test here -- always allow
            if (/FROM platform_config/.test(sql)) return null;
            if (/COUNT\(\*\) AS c FROM active_now WHERE last_at>\?/.test(sql)) { let c = 0; an.forEach(function (row) { if (row.last_at > a[0]) c++; }); return { c: c }; }
            if (/AS c FROM/.test(sql)) return { c: 0 };   // every other admin-overview aggregate -- not under test here, but must not be null
            return null;
          },
          all: async () => {
            // /api/admin/visits "top" query (aliased pv./t. -- the LEFT JOIN leaves name NULL for _site/_app since neither has a tenants row)
            if (/pv\.tenant_id/.test(sql)) return { results: [...pv.keys()].map(function (tid) { return { tenant_id: tid, name: null, views: pv.get(tid) }; }) };
            return { results: [] };
          },
          run: async () => {
            if (/INSERT INTO page_views/.test(sql)) pv.set(a[0], (pv.get(a[0]) || 0) + 1);
            else if (/INSERT INTO active_now/.test(sql)) an.set(a[0], { last_at: a[1], src: a[2] });
            return { success: true, meta: { changes: 1 } };
          },
        };
        return api;
      }
      return { prepare: stmt };
    }
    const vbEnv = { DB: vbDB(), ADMIN_TOKEN: 'k', SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' };
    let waited = [];
    const vbCtx = { waitUntil(p) { waited.push(p); }, passThroughOnException() {} };
    const vpReq = (body) => new Request('https://atlasrental.io/api/visit-ping', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

    let r2 = await worker.fetch(vpReq({ src: 'site', sid: 'sid_vb_site' }), vbEnv, vbCtx);
    ok(r2.status === 204, 'visit-ping src=site -> 204 (got ' + r2.status + ')');
    r2 = await worker.fetch(vpReq({ src: 'app', sid: 'sid_vb_app' }), vbEnv, vbCtx);
    ok(r2.status === 204, 'visit-ping src=app -> 204 (got ' + r2.status + ')');
    // the GET pixel/sendBeacon-fallback shape (query string, not a JSON body) is accepted too
    r2 = await worker.fetch(mkReq('GET', '/api/visit-ping?src=site&sid=sid_vb_pixel'), vbEnv, vbCtx);
    ok(r2.status === 204, 'visit-ping GET pixel fallback -> 204 (got ' + r2.status + ')');
    await Promise.all(waited); waited.length = 0;
    ok(pv.get('_site') === 2 && pv.get('_app') === 1, '_site and _app are tracked as SEPARATE reserved ids, never colliding with each other or a real tenant (got ' + JSON.stringify([...pv]) + ')');
    ok(an.size === 3, 'three distinct sids each landed their own active_now row (got ' + an.size + ')');

    let r3 = await worker.fetch(mkReq('GET', '/api/admin/overview', { headers: H }), vbEnv, ctx);
    let j3 = await r3.json();
    ok(r3.status === 200 && j3.ok === true, 'GET /api/admin/overview -> 200 ok:true (got ' + r3.status + ')');
    ok(typeof j3.active_now === 'number' && j3.active_now === 3, 'overview.active_now is a number reflecting all 3 live sids (got ' + JSON.stringify(j3.active_now) + ')');

    let r4 = await worker.fetch(mkReq('GET', '/api/admin/visits', { headers: H }), vbEnv, ctx);
    let j4 = await r4.json();
    const top = j4.top || [];
    const siteRow = top.filter(function (t) { return t.tenant_id === '_site'; })[0];
    const appRow = top.filter(function (t) { return t.tenant_id === '_app'; })[0];
    ok(siteRow && siteRow.name === 'Atlas marketing site', "visits.top gives '_site' a friendly name instead of the raw id (got " + JSON.stringify(siteRow) + ')');
    ok(appRow && appRow.name === 'App / dashboard', "visits.top gives '_app' a friendly name instead of the raw id (got " + JSON.stringify(appRow) + ')');
  }
}

// ---- #278 FEATURE-LEVEL PAYMENT GATING: server-authoritative 402 on a NEW un-entitled publish / custom-domain
// connect, flag-gated OFF by default (platform_config.feature_gate_enabled). Flag OFF -> byte-identical (the whole
// gate block never even reads the tenant row). Flag ON -> NEVER locks the platform owner, a comped (gold/free)
// account, Enterprise+ tier, or a tenant with website_addon set; and NEVER takes down a site/domain that was
// already published/connected before the gate could ever have blocked it (grandfather). Mirrors the #276 block's
// pgEnvFor/pgReq pattern above, adapted for an authenticated PUT + POST instead of a GET. ----
{
  // opts: { scn, gateOn, tier, website_addon, curSettings, custom_domain, compRole, email }
  function wgEnvFor(opts) {
    const SID = 'sid_wg_' + opts.scn, CSRF = 'csrf_wg_' + opts.scn, TEN = 't_wg_' + opts.scn, UID = 'u_wg_' + opts.scn;
    const email = opts.email || (opts.scn + '@member.com');
    const tenantRow = { id: TEN, tier: opts.tier || 'starter', website_addon: opts.website_addon || null, settings: JSON.stringify(opts.curSettings || {}), custom_domain: opts.custom_domain || null };
    let _lastUpdate = null;   // #279: captures the args bound to the tenants UPDATE, so a test can inspect what was actually WRITTEN (not just the response status) -- purely additive, existing call sites that never read getLastUpdate() are unaffected.
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM sessions WHERE id/.test(sql)) return a[0] === SID ? { id: SID, user_id: UID, tenant_id: TEN, csrf: CSRF, expires_at: Date.now() + 1e12, idle_at: Date.now(), revoked_at: null } : null;
          if (/FROM users WHERE id/.test(sql)) return { id: UID, email: email, tenant_id: TEN, role: 'owner', caps: null };
          if (/FROM comp_grants WHERE email/.test(sql)) return opts.compRole ? { role: opts.compRole } : null;
          // #276's OWN flag must stay OFF throughout -- only 'feature_gate_enabled' is ever driven by this helper.
          if (/FROM platform_config WHERE k=\?/.test(sql)) return (a[0] === 'feature_gate_enabled' && opts.gateOn) ? { v: '1' } : null;
          if (/SELECT id,tier,website_addon,settings FROM tenants WHERE id=\?/.test(sql)) return tenantRow;
          if (/SELECT id,tier,website_addon,custom_domain FROM tenants WHERE id=\?/.test(sql)) return tenantRow;
          if (/SELECT id FROM tenants WHERE custom_domain=\? AND id<>\?/.test(sql)) return null;   // never a clash in these tests
          if (/FROM rate_limits/.test(sql)) return null;
          if (/sqlite_master/.test(sql)) return { n: 30 };
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => { if (/^UPDATE tenants SET/.test(sql)) _lastUpdate = { sql, args: a }; return { success: true, meta: { changes: 1 } }; },
      };
      return api;
    }
    return { SID, CSRF, TEN, env: { DB: { prepare: stmt }, SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'owner@x.com' }, getLastUpdate: () => _lastUpdate };
  }
  const wgReq = (method, path, cfg, body) => { const headers = { 'content-type': 'application/json', cookie: 'atlas_sid=' + cfg.SID, 'x-csrf-token': cfg.CSRF, origin: 'https://atlasrental.io' }; return { method, url: 'https://atlasrental.io' + path, headers: { get: (k) => { const v = headers[String(k).toLowerCase()]; return v === undefined ? null : v; } }, json: async () => (body || {}), text: async () => JSON.stringify(body || {}) }; };

  // (a) flag OFF: an un-entitled tenant publishing for the first time still succeeds -- proves the whole feature is inert
  let cfg = wgEnvFor({ scn: 'off', gateOn: false, tier: 'starter', website_addon: null, curSettings: {} });
  let r = await worker.fetch(wgReq('PUT', '/api/tenant/profile', cfg, { settings: { publicSite: { published: true } } }), cfg.env, ctx);
  ok(r.status === 200, '#278 flag OFF: un-entitled tenant PUT publish:true -> 200, byte-identical to today (got ' + r.status + ')');

  // (b) flag ON, un-entitled, NOT already published -> the one real block: 402 website_addon_required
  cfg = wgEnvFor({ scn: 'unentitled_new', gateOn: true, tier: 'starter', website_addon: null, curSettings: {} });
  r = await worker.fetch(wgReq('PUT', '/api/tenant/profile', cfg, { settings: { publicSite: { published: true } } }), cfg.env, ctx);
  let j = await r.json();
  ok(r.status === 402 && j.error === 'website_addon_required', '#278 flag ON: un-entitled NEW publish -> 402 website_addon_required (got ' + r.status + ' ' + JSON.stringify(j) + ')');

  // (c) flag ON, NEVER-BREAK-A-LIVE-SITE grandfather: a tenant whose site is ALREADY published (read BEFORE this
  // update) is let through unchanged, even with zero entitlement -- proves flipping the gate on can never take
  // down an existing live site, only block a brand-new un-entitled publish.
  cfg = wgEnvFor({ scn: 'grandfather', gateOn: true, tier: 'starter', website_addon: null, curSettings: { publicSite: { published: true, headline: 'old' } } });
  r = await worker.fetch(wgReq('PUT', '/api/tenant/profile', cfg, { settings: { publicSite: { published: true, headline: 'new' } } }), cfg.env, ctx);
  ok(r.status === 200, '#278 flag ON: already-published tenant re-saving -> still 200 (grandfathered, never taken down) (got ' + r.status + ')');

  // (d) flag ON, every never-lock entitlement path -> 200: website_addon set (once-purchase), Enterprise+ tier,
  // a comped gold account, and the platform owner -- even though none of these tenant rows have a prior publish.
  for (const [scn, tierOverride, addonOverride, compOverride, emailOverride] of [
    ['addon_once', 'starter', 'once', null, null],
    ['addon_mo', 'starter', 'mo', null, null],
    ['tier_enterprise', 'enterprise', null, null, null],
    ['comp_gold', 'starter', null, 'gold', null],
    ['comp_free', 'starter', null, 'free', null],
    ['owner', 'starter', null, null, 'owner@x.com'],
  ]) {
    cfg = wgEnvFor({ scn: 'ent_' + scn, gateOn: true, tier: tierOverride, website_addon: addonOverride, curSettings: {}, compRole: compOverride, email: emailOverride });
    r = await worker.fetch(wgReq('PUT', '/api/tenant/profile', cfg, { settings: { publicSite: { published: true } } }), cfg.env, ctx);
    ok(r.status === 200, '#278 flag ON: entitled (' + scn + ') NEW publish -> 200 (got ' + r.status + ')');
  }

  // (e) building/editing/previewing (NOT publishing) is always free, flag on or off, entitled or not -- the gate
  // only ever looks at settings.publicSite.published===true, so an ordinary settings save is untouched.
  cfg = wgEnvFor({ scn: 'edit_only', gateOn: true, tier: 'starter', website_addon: null, curSettings: {} });
  r = await worker.fetch(wgReq('PUT', '/api/tenant/profile', cfg, { settings: { theme: 'dark' } }), cfg.env, ctx);
  ok(r.status === 200, '#278 flag ON: an un-entitled tenant saving unrelated settings (no publish) -> 200, never gated (got ' + r.status + ')');

  // (f) custom-domain connect mirrors the same posture: OFF -> inert; ON + un-entitled + no existing domain -> 402;
  // ON + already has a domain connected (any status, from before the gate existed) -> grandfathered through; ON +
  // entitled -> 200.
  cfg = wgEnvFor({ scn: 'dom_off', gateOn: false, tier: 'starter', website_addon: null, custom_domain: null });
  r = await worker.fetch(wgReq('POST', '/api/domain/connect', cfg, { domain: 'example.com' }), cfg.env, ctx);
  ok(r.status === 200, '#278 flag OFF: custom-domain connect for an un-entitled tenant -> 200, inert (got ' + r.status + ')');

  cfg = wgEnvFor({ scn: 'dom_new', gateOn: true, tier: 'starter', website_addon: null, custom_domain: null });
  r = await worker.fetch(wgReq('POST', '/api/domain/connect', cfg, { domain: 'example.com' }), cfg.env, ctx);
  j = await r.json();
  ok(r.status === 402 && j.error === 'website_addon_required', '#278 flag ON: un-entitled custom-domain connect (no prior domain) -> 402 (got ' + r.status + ' ' + JSON.stringify(j) + ')');

  cfg = wgEnvFor({ scn: 'dom_grandfather', gateOn: true, tier: 'starter', website_addon: null, custom_domain: 'old-domain.com' });
  r = await worker.fetch(wgReq('POST', '/api/domain/connect', cfg, { domain: 'new-domain.com' }), cfg.env, ctx);
  ok(r.status === 200, '#278 flag ON: tenant with an already-connected domain reconnecting -> still 200 (grandfathered) (got ' + r.status + ')');

  cfg = wgEnvFor({ scn: 'dom_entitled', gateOn: true, tier: 'starter', website_addon: 'mo', custom_domain: null });
  r = await worker.fetch(wgReq('POST', '/api/domain/connect', cfg, { domain: 'example.com' }), cfg.env, ctx);
  ok(r.status === 200, '#278 flag ON: entitled tenant custom-domain connect (no prior domain) -> 200 (got ' + r.status + ')');

// ---- #279 LIVE-SITE CRITICAL: PUT /api/tenant/profile settings=? must MERGE, never blind-replace. Two real
// callers PUT partial settings objects (publishBookingSite sends only {comms,publicSite}; the generic auto-mirror
// _srvMirrorProfile dumps every OTHER top-level key but never models publicSite at all) -- a blind replace let
// either one silently erase what the other owns, including dropping a LIVE customer booking link's publicSite
// off the server while the dashboard still showed it published. Reuses the #278 wgEnvFor/wgReq harness (same
// endpoint) plus its getLastUpdate() capture to inspect what was actually WRITTEN, not just the response status.
// (Runs inside the #278 block above so it reuses that section's wgEnvFor/wgReq/getLastUpdate harness -- a bare
// { } block here would put those helpers out of scope: ReferenceError wgEnvFor, which is what broke CI at build aa.) ----
  // (a) an auto-mirror-shaped save (settings lacks publicSite entirely) must NOT drop a publicSite already stored.
  cfg = wgEnvFor({ scn: 'merge_keep_pubsite', gateOn: false, tier: 'starter', website_addon: null,
    curSettings: { publicSite: { published: true, headline: 'Live site' }, website: { built: true, tagline: 'old tagline' } } });
  r = await worker.fetch(wgReq('PUT', '/api/tenant/profile', cfg, { settings: { comms: { email: true } } }), cfg.env, ctx);
  ok(r.status === 200, '#279 (a) settings save with no publicSite key -> 200 (got ' + r.status + ')');
  let upd = cfg.getLastUpdate();
  let written = upd ? JSON.parse(upd.args[0]) : null;
  ok(!!written && written.publicSite && written.publicSite.published === true, '#279 (a) MERGE: previously-stored publicSite.published survives a settings save that never mentions it (got ' + JSON.stringify(written && written.publicSite) + ')');
  ok(!!written && written.website && written.website.built === true, '#279 (a) MERGE: other previously-stored top-level keys (e.g. settings.website) also survive (got ' + JSON.stringify(written && written.website) + ')');
  ok(!!written && written.comms && written.comms.email === true, '#279 (a) the NEW key the body actually sent (comms) is applied (got ' + JSON.stringify(written && written.comms) + ')');

  // (b) a publishBookingSite-shaped save (settings = {comms,publicSite} only) still stores publicSite -- and must
  // NOT wipe an unrelated previously-stored key (e.g. settings.trackers) that publishBookingSite never mentions.
  cfg = wgEnvFor({ scn: 'merge_publish', gateOn: false, tier: 'starter', website_addon: null,
    curSettings: { trackers: { ga: 'UA-123' }, legal: { cancelPolicy: 'strict' } } });
  r = await worker.fetch(wgReq('PUT', '/api/tenant/profile', cfg, { settings: { comms: { email: true }, publicSite: { published: true, headline: 'Rent with us' } } }), cfg.env, ctx);
  ok(r.status === 200, '#279 (b) publish (settings has publicSite) -> 200 (got ' + r.status + ')');
  upd = cfg.getLastUpdate();
  written = upd ? JSON.parse(upd.args[0]) : null;
  ok(!!written && written.publicSite && written.publicSite.published === true, '#279 (b) publishing still stores publicSite.published:true (got ' + JSON.stringify(written && written.publicSite) + ')');
  ok(!!written && written.trackers && written.trackers.ga === 'UA-123', '#279 (b) MERGE: publishBookingSite\'s narrow payload no longer wipes an unrelated stored key like settings.trackers (got ' + JSON.stringify(written && written.trackers) + ')');
  ok(!!written && written.legal && written.legal.cancelPolicy === 'strict', '#279 (b) MERGE: ...or settings.legal (got ' + JSON.stringify(written && written.legal) + ')');

  // (c) invariant check: a top-level key that IS present in the body must still fully REPLACE (not union/append)
  // the stored value -- this is how "delete a promo" / "hide a nav item" already work (resend the whole trimmed
  // array/object under its unchanged top-level key), and the merge must not turn that into an accidental restore.
  cfg = wgEnvFor({ scn: 'merge_replace_not_union', gateOn: false, tier: 'starter', website_addon: null,
    curSettings: { promos: [{ id: 'p1', code: 'SAVE10' }, { id: 'p2', code: 'SAVE20' }] } });
  r = await worker.fetch(wgReq('PUT', '/api/tenant/profile', cfg, { settings: { promos: [{ id: 'p1', code: 'SAVE10' }] } }), cfg.env, ctx);
  ok(r.status === 200, '#279 (c) resending a trimmed settings.promos array -> 200 (got ' + r.status + ')');
  upd = cfg.getLastUpdate();
  written = upd ? JSON.parse(upd.args[0]) : null;
  ok(!!written && Array.isArray(written.promos) && written.promos.length === 1 && written.promos[0].id === 'p1', '#279 (c) a PRESENT top-level key still fully replaces (deleting promo p2 by resending the trimmed array actually removes it, merge does not resurrect it) (got ' + JSON.stringify(written && written.promos) + ')');
}

// ---- #278 (cont.): the PUBLIC served site is NEVER blocked by this feature -- only the PUBLISH/CONNECT actions
// above ever return a 402. A published site with zero entitlement still serves (200) with the gate ON, proving
// the grandfather posture holds end-to-end at the serve layer too, not just at the write path. ----
{
  function pubDB(gateOn, tenantRow) {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM tenants WHERE subdomain=\?/.test(sql)) return tenantRow;
          if (/FROM platform_config WHERE k=\?/.test(sql)) return (a[0] === 'feature_gate_enabled' && gateOn) ? { v: '1' } : null;
          if (/FROM rate_limits/.test(sql)) return null;
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => ({ success: true, meta: { changes: 1 } }),
      };
      return api;
    }
    return { prepare: stmt };
  }
  const pubCtx = { waitUntil(p) { p.catch(function () {}); }, passThroughOnException() {} };
  const tRow = { id: 't_pub_278', tier: 'starter', website_addon: null, settings: JSON.stringify({ publicSite: { published: true, headline: 'Hi', assets: [], config: {} } }) };

  let r = await worker.fetch(mkReq('GET', '/api/public/pubslug278'), { DB: pubDB(false, tRow), SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' }, pubCtx);
  ok(r.status === 200, '#278 flag OFF: published site still serves -> 200 (got ' + r.status + ')');

  r = await worker.fetch(mkReq('GET', '/api/public/pubslug278'), { DB: pubDB(true, tRow), SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' }, pubCtx);
  ok(r.status === 200, '#278 flag ON: a published-but-UN-ENTITLED site still serves -> 200, never taken down (got ' + r.status + ')');
}

// ---- #280 CARD-REQUIRED-FOR-TRIAL ACCESS GATING: server-authoritative 402 gate, flag-gated OFF by default,
// INDEPENDENT of #276's payment_gate_enabled (two separate flags, two separate checks -- this fires even with
// #276 OFF, and vice versa). Flag OFF -> byte-identical (no request behaves differently). Flag ON -> locks a
// tenant with neither card_on_file nor a stripe_sub; NEVER locks the platform owner or a comped (gold/free)
// account; unlocks the instant EITHER card_on_file OR stripe_sub is set; /api/auth/* + /api/billing/* stay
// reachable even while locked. Mirrors the #276 pgEnvFor/pgReq pattern above (self-contained, own helpers). ----
{
  const NOW = Date.now();
  // scn picks the tenant/user shape; cardGateOn picks platform_config.trial_requires_card for that one request.
  function cgEnvFor(scn, cardGateOn) {
    const SID = 'sid_cg_' + scn, CSRF = 'csrf_cg_' + scn, TEN = 't_cg_' + scn, UID = 'u_cg_' + scn;
    const email = scn === 'owner' ? 'owner@x.com' : (scn + '@member.com');
    const compRole = scn === 'goldcomp' ? 'gold' : null;
    const tenantRow =
      scn === 'has_card' ? { card_on_file: 1, stripe_sub: null } :
      scn === 'has_sub_no_card' ? { card_on_file: 0, stripe_sub: 'sub_x' } :
      { card_on_file: 0, stripe_sub: null };   // 'no_card', 'owner', 'goldcomp' -- the owner/comp overrides must win even though the row itself looks cardless
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM sessions WHERE id/.test(sql)) return a[0] === SID ? { id: SID, user_id: UID, tenant_id: TEN, csrf: CSRF, expires_at: NOW + 1e12, idle_at: NOW, revoked_at: null } : null;
          if (/FROM users WHERE id/.test(sql)) return { id: UID, email: email, tenant_id: TEN, role: 'owner', caps: null };
          if (/FROM comp_grants WHERE email/.test(sql)) return compRole ? { role: compRole } : null;
          if (/card_on_file,stripe_sub FROM tenants WHERE id=\?/.test(sql)) return tenantRow;
          if (/FROM platform_config WHERE k=\?/.test(sql)) return (a[0] === 'trial_requires_card' && cardGateOn) ? { v: '1' } : null;   // #276's OWN flag must stay OFF throughout this block -- proves independence
          if (/FROM rate_limits/.test(sql)) return null;
          if (/sqlite_master/.test(sql)) return { n: 30 };
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => ({ success: true, meta: { changes: 1 } }),
      };
      return api;
    }
    return { SID, CSRF, env: { DB: { prepare: stmt }, SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'owner@x.com' } };
  }
  const cgReq = (method, path, cfg, body) => { const headers = { 'content-type': 'application/json', cookie: 'atlas_sid=' + cfg.SID, 'x-csrf-token': cfg.CSRF, origin: 'https://atlasrental.io' }; return { method, url: 'https://atlasrental.io' + path, headers: { get: (k) => { const v = headers[String(k).toLowerCase()]; return v === undefined ? null : v; } }, json: async () => (body || {}), text: async () => JSON.stringify(body || {}) }; };

  // (a) flag OFF: a cardless tenant hitting a normal authenticated endpoint is completely unaffected (proves the feature is inert)
  let cfg = cgEnvFor('no_card', false);
  let r = await worker.fetch(cgReq('GET', '/api/data/bookings', cfg), cfg.env, ctx);
  ok(r.status === 200, '#280 flag OFF: cardless tenant GET /api/data/bookings -> 200, byte-identical to today (got ' + r.status + ')');

  // (b) flag ON, no card and no stripe_sub -> 402 payment_required billing_state=needs_card
  cfg = cgEnvFor('no_card', true);
  r = await worker.fetch(cgReq('GET', '/api/data/bookings', cfg), cfg.env, ctx);
  let j = await r.json();
  ok(r.status === 402 && j.error === 'payment_required' && j.billing_state === 'needs_card', '#280 flag ON: cardless tenant -> 402 payment_required billing_state=needs_card (got ' + r.status + ' ' + JSON.stringify(j) + ')');

  // (c) flag ON, never-lock invariants + the "OR" unlock: card_on_file alone, stripe_sub alone, a comped gold user,
  //     and the platform owner all read 200 -- even goldcomp/owner sit on a tenant row with neither card nor sub.
  for (const scn of ['has_card', 'has_sub_no_card', 'goldcomp', 'owner']) {
    cfg = cgEnvFor(scn, true);
    r = await worker.fetch(cgReq('GET', '/api/data/bookings', cfg), cfg.env, ctx);
    ok(r.status === 200, '#280 flag ON: never-lock/unlock case "' + scn + '" -> 200 (got ' + r.status + ')');
  }

  // (d) flag ON + cardless tenant: /api/billing/checkout is never 402'd by the gate. No Stripe key configured in
  //     this env, so a request that gets PAST the gate lands on the route's own "not configured" 400 -- proving
  //     it reached the route at all (a 402 would only ever come from the gate, never from _platStripe).
  cfg = cgEnvFor('no_card', true);
  r = await worker.fetch(cgReq('POST', '/api/billing/checkout', cfg, { kind: 'trial', tier: 'pro' }), cfg.env, ctx);
  ok(r.status === 400 && r.status !== 402, '#280 flag ON + cardless: /api/billing/checkout never 402s (reaches its own "not configured" 400 instead) (got ' + r.status + ')');

  // (e) flag ON + cardless tenant: /api/auth/me (same /api/auth/ prefix as login) never 402s, and reports needs_card
  cfg = cgEnvFor('no_card', true);
  r = await worker.fetch(cgReq('GET', '/api/auth/me', cfg), cfg.env, ctx);
  let jme = await r.json();
  ok(r.status === 200 && jme.billing_state === 'needs_card', '#280 flag ON + cardless: /api/auth/me never 402s and reports billing_state (got ' + r.status + ' ' + JSON.stringify(jme) + ')');

  // (f) independence from #276: with BOTH flags on, but the #276 check reading 'ok' on its own (this mock's tenant
  //     row carries no plan/trial_ends data, so _billingState fails open), the tenant is still blocked by #280
  //     alone -- proving the two gates are genuinely separate checks, not one piggybacking on the other.
  function bothEnvFor(cardOn) {
    const SID = 'sid_both280', CSRF = 'csrf_both280', TEN = 't_both280', UID = 'u_both280';
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM sessions WHERE id/.test(sql)) return a[0] === SID ? { id: SID, user_id: UID, tenant_id: TEN, csrf: CSRF, expires_at: NOW + 1e12, idle_at: NOW, revoked_at: null } : null;
          if (/FROM users WHERE id/.test(sql)) return { id: UID, email: 'both@member.com', tenant_id: TEN, role: 'owner', caps: null };
          if (/FROM comp_grants/.test(sql)) return null;
          if (/plan,trial_ends,tier,stripe_sub FROM tenants WHERE id=\?/.test(sql)) return {};   // #276 sees no plan column at all -> fails open 'ok'
          if (/card_on_file,stripe_sub FROM tenants WHERE id=\?/.test(sql)) return { card_on_file: 0, stripe_sub: null };
          if (/FROM platform_config WHERE k=\?/.test(sql)) { if (a[0] === 'trial_requires_card') return cardOn ? { v: '1' } : null; if (a[0] === 'payment_gate_enabled') return { v: '1' }; return null; }
          if (/FROM rate_limits/.test(sql)) return null;
          if (/sqlite_master/.test(sql)) return { n: 30 };
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => ({ success: true, meta: { changes: 1 } }),
      };
      return api;
    }
    return { SID, CSRF, env: { DB: { prepare: stmt }, SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'owner@x.com' } };
  }
  let bcfg = bothEnvFor(true);
  r = await worker.fetch(cgReq('GET', '/api/data/bookings', bcfg), bcfg.env, ctx);
  j = await r.json();
  ok(r.status === 402 && j.billing_state === 'needs_card', '#280 independence: #276 reads ok (no plan data) but #280 still blocks a cardless tenant on its own flag (got ' + r.status + ' ' + JSON.stringify(j) + ')');
  bcfg = bothEnvFor(false);
  r = await worker.fetch(cgReq('GET', '/api/data/bookings', bcfg), bcfg.env, ctx);
  ok(r.status === 200, '#280 independence: with trial_requires_card OFF, the SAME cardless tenant is unaffected even though payment_gate_enabled is ON in this env (got ' + r.status + ')');
}

// ---- #280 (cont.): the REAL /api/auth/signup + /api/auth/login path -- through actual password hashing/
// verification, not a session mock -- carries the true (independent) card-required-for-trial billing_state, and
// completing the trial-card checkout (webhook sets card_on_file+stripe_sub) unlocks it on the VERY NEXT login.
// Mirrors the #276 loginDB stateful-mock pattern above (own Maps, own helpers -- this is its OWN { } block). ----
{
  const users = new Map(), usersByEmail = new Map(), sessions = new Map(), tenants = new Map(), rateLimits = new Map(), platformConfig = new Map();
  function loginDB2() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM users WHERE email=\?/.test(sql)) { const id = usersByEmail.get(a[0]); return id ? users.get(id) : null; }
          if (/id,email,tenant_id,role,caps FROM users/.test(sql)) return users.get(a[0]) || null;
          if (/FROM users WHERE id=\?/.test(sql)) return users.get(a[0]) || null;
          if (/FROM sessions WHERE id/.test(sql)) return sessions.get(a[0]) || null;
          if (/FROM comp_grants/.test(sql)) return null;
          if (/card_on_file,stripe_sub FROM tenants WHERE id=\?/.test(sql)) return tenants.get(a[0]) || null;
          if (/FROM tenants WHERE id/.test(sql)) return tenants.get(a[0]) || null;
          if (/FROM platform_config WHERE k=\?/.test(sql)) { const v = platformConfig.get(a[0]); return v === undefined ? null : { v }; }
          if (/FROM rate_limits WHERE bucket=\?/.test(sql)) return rateLimits.get(a[0]) || null;
          if (/sqlite_master/.test(sql)) return { n: 30 };
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => {
          if (/INSERT INTO tenants \(id,name,fleet_type,plan,trial_ends,created_at,updated_at,tz\)/.test(sql)) { const [id, name, fleet, plan, trial_ends, created_at, updated_at, tz] = a; tenants.set(id, { id, name, fleet_type: fleet, plan, trial_ends, tier: null, stripe_sub: null, card_on_file: 0, created_at, updated_at, tz }); }
          else if (/INSERT INTO users \(id,email,pw_hash,pw_salt,tenant_id,role,created_at\)/.test(sql)) { const [id, email, pw_hash, pw_salt, tenant_id, role, created_at] = a; users.set(id, { id, email, pw_hash, pw_salt, tenant_id, role, created_at, email_verified: 1, mfa_method: null, caps: null }); usersByEmail.set(email, id); }
          else if (/UPDATE users SET last_login/.test(sql)) { const u = users.get(a[1]); if (u) u.last_login = a[0]; }
          else if (/UPDATE users SET email_verified/.test(sql)) { const u = users.get(a[1]); if (u) u.email_verified = a[0]; }
          else if (/INSERT INTO sessions/.test(sql)) sessions.set(a[0], { id: a[0], user_id: a[1], tenant_id: a[2], csrf: a[3], created_at: a[4], idle_at: a[5], expires_at: a[6], revoked_at: null });
          else if (/INSERT INTO platform_config/.test(sql)) platformConfig.set(a[0], a[1]);
          return { success: true, meta: { changes: 1 } };
        },
      };
      return api;
    }
    return { prepare: stmt };
  }
  const loginEnv2 = { DB: loginDB2(), SESSION_KEY: 'test-session-key-not-a-real-secret', ENC_KEY: Buffer.alloc(32, 7).toString('base64'), OWNER_EMAIL: 'owner@x.com' };
  const loginReq2 = (method, path, body, cookie) => { const headers = { 'content-type': 'application/json', origin: 'https://atlasrental.io' }; if (cookie) headers['cookie'] = cookie; return { method, url: 'https://atlasrental.io' + path, headers: { get: (k) => { const v = headers[String(k).toLowerCase()]; return v === undefined ? null : v; } }, json: async () => (body || {}), text: async () => JSON.stringify(body || {}) }; };
  function newestSession2() { let best = null; for (const s of sessions.values()) if (!best || s.created_at >= best.created_at) best = s; return best; }

  let r = await worker.fetch(loginReq2('POST', '/api/auth/signup', { email: 'cardless@x.com', password: 'correcthorsebatterystaple', business: 'Cardless Co' }), loginEnv2, ctx);
  let j = await r.json();
  ok(r.status === 200 && j.ok === true && j.billing_state === 'ok', '#280: signup response carries billing_state:"ok" (gate is off by default) (got ' + JSON.stringify(j) + ')');
  const tid = j.tenant_id;

  // owner turns the card gate ON; this tenant has never added a card
  platformConfig.set('trial_requires_card', '1');

  // login again with the SAME real credentials (through actual PBKDF2 password verification) -- must NOT 402
  r = await worker.fetch(loginReq2('POST', '/api/auth/login', { email: 'cardless@x.com', password: 'correcthorsebatterystaple' }), loginEnv2, ctx);
  j = await r.json();
  ok(r.status === 200 && j.ok === true && !!j.csrf, '#280: login for a cardless tenant with the gate ON still succeeds -- never 402s (got ' + r.status + ' ' + JSON.stringify(j) + ')');
  ok(j.billing_state === 'needs_card', '#280: that same login response carries billing_state:"needs_card" so the client shows the card gate right on auth (got ' + j.billing_state + ')');

  // confirm the resulting session really IS locked for an ordinary endpoint -- proving login's carve-out is
  // deliberate (the allow-list), not evidence the gate silently failed to engage at all
  let cookie = 'atlas_sid=' + newestSession2().id;
  r = await worker.fetch(loginReq2('GET', '/api/data/bookings', null, cookie), loginEnv2, ctx);
  j = await r.json();
  ok(r.status === 402 && j.error === 'payment_required' && j.billing_state === 'needs_card', '#280: that same locked session -> 402 needs_card on an ordinary endpoint (the gate is genuinely active) (got ' + r.status + ')');

  // now simulate the real trial-checkout webhook completing (worker.js checkout.session.completed, md.billing==='trial'): card_on_file=1 + stripe_sub set
  const t = tenants.get(tid); t.card_on_file = 1; t.stripe_sub = 'sub_new';

  // login again -- unlocked, billing_state back to 'ok', and the ordinary endpoint is reachable again
  r = await worker.fetch(loginReq2('POST', '/api/auth/login', { email: 'cardless@x.com', password: 'correcthorsebatterystaple' }), loginEnv2, ctx);
  j = await r.json();
  ok(j.billing_state === 'ok', '#280: after the trial-card checkout lands (card_on_file+stripe_sub), the SAME tenant logs in with billing_state:"ok" again (got ' + j.billing_state + ')');
  cookie = 'atlas_sid=' + newestSession2().id;
  r = await worker.fetch(loginReq2('GET', '/api/data/bookings', null, cookie), loginEnv2, ctx);
  ok(r.status === 200, '#280: after adding a card, the same tenant reaches an ordinary endpoint again -> 200 (got ' + r.status + ')');
}

// ---- #280 admin toggle: GET/POST /api/admin/config surfaces trial_requires_card, independently of payment_gate_enabled ----
{
  let cardFlag = null, payFlag = null;   // null == unset (reads as default '0'/off); '1'/'0' once toggled via POST
  function cfgDB2() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM platform_config WHERE k=\?/.test(sql)) {
            if (a[0] === 'trial_requires_card') return cardFlag != null ? { v: cardFlag } : null;
            if (a[0] === 'payment_gate_enabled') return payFlag != null ? { v: payFlag } : null;
            return null;
          }
          if (/COUNT\(\*\) c FROM tenants/.test(sql)) return { c: 0 };
          if (/sqlite_master/.test(sql)) return { n: 30 };
          if (/FROM rate_limits/.test(sql)) return null;
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => {
          if (/INSERT INTO platform_config/.test(sql)) { if (a[0] === 'trial_requires_card') cardFlag = a[1]; else if (a[0] === 'payment_gate_enabled') payFlag = a[1]; }
          return { success: true, meta: { changes: 1 } };
        },
      };
      return api;
    }
    return { prepare: stmt };
  }
  const cfgEnv2 = { DB: cfgDB2(), ADMIN_TOKEN: 'k', SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' };
  const cfgReq2 = (method, headers, body) => new Request('https://atlasrental.io/api/admin/config', { method, headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}), body: body !== undefined ? JSON.stringify(body) : undefined });

  let r = await worker.fetch(cfgReq2('GET', H), cfgEnv2, ctx);
  let j = await r.json();
  ok(r.status === 200 && j.enterprise.trial_requires_card === false, '#280 admin config: trial_requires_card defaults to false (got ' + JSON.stringify(j.enterprise && j.enterprise.trial_requires_card) + ')');

  r = await worker.fetch(cfgReq2('POST', H, { trial_requires_card: true }), cfgEnv2, ctx);
  j = await r.json();
  ok(r.status === 200 && j.enterprise.trial_requires_card === true, '#280 admin config: POST trial_requires_card:true flips it on (got ' + JSON.stringify(j.enterprise && j.enterprise.trial_requires_card) + ')');
  ok(j.enterprise.payment_gate_enabled === false, '#280 admin config: flipping trial_requires_card leaves payment_gate_enabled untouched (independent flags) (got ' + JSON.stringify(j.enterprise && j.enterprise.payment_gate_enabled) + ')');

  r = await worker.fetch(cfgReq2('POST', { 'X-Admin-Token': 'WRONG' }, { trial_requires_card: false }), cfgEnv2, ctx);
  ok(r.status === 401 || r.status === 403, '#280 admin config: a bad admin token cannot flip the gate (got ' + r.status + ')');
  ok(cardFlag === '1', '#280 admin config: the bad-token POST above never actually wrote to platform_config (still "1" from the earlier real POST) (got ' + JSON.stringify(cardFlag) + ')');
}

// ---- #281 PUBLIC-SITE TAKEDOWN: a tenant delinquent (past_due) for MORE than a 3-day grace period gets a
// friendly "temporarily unavailable" page swapped in for their PUBLIC booking site (both serve paths: the
// custom-domain front door and /api/book/<slug>); settings.publicSite.published is never touched, and paying
// (plan back to 'active') restores the real site instantly. Flag-gated OFF by default via
// platform_config.site_takedown_enabled. Self-contained: own mock D1 + own request builders/helpers below --
// references nothing from any sibling block (see the wgEnvFor scope-bug lesson noted near the #279 block above,
// which is exactly the mistake this pattern avoids). ----
{
  const DAY281 = 86400000;
  // tenantRow shape returned by BOTH real call sites: SELECT * (subdomain path) and the named, widened SELECT
  // (custom-domain path) -- both must carry .plan + .delinquent_since alongside the usual profile fields.
  function tdRow(plan, delinquentSince) {
    return {
      id: 't_td281', subdomain: 'td281', fleet_type: 'cars', plan: plan, tier: 'starter', website_addon: null,
      custom_domain: 'td281-custom.example', custom_domain_status: 'live',
      brand: JSON.stringify({ color: '#123456' }), money: JSON.stringify({}),
      settings: JSON.stringify({ publicSite: { published: true, headline: 'Hi', assets: [], config: {} } }),
      delinquent_since: delinquentSince,
    };
  }
  function tdDB(tenantRow, flagOn) {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM tenants WHERE subdomain=\?/.test(sql)) return tenantRow;                 // subdomain path (SELECT *)
          if (/FROM tenants WHERE custom_domain=\?/.test(sql)) return tenantRow;              // custom-domain path (named SELECT)
          if (/FROM platform_config WHERE k=\?/.test(sql)) return (a[0] === 'site_takedown_enabled' && flagOn) ? { v: '1' } : null;
          if (/FROM rate_limits/.test(sql)) return null;
          if (/sqlite_master/.test(sql)) return { n: 30 };
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => ({ success: true, meta: { changes: 1 } }),
      };
      return api;
    }
    return { prepare: stmt };
  }
  const tdCtx = { waitUntil(p) { p.catch(function () {}); }, passThroughOnException() {} };
  const tdEnv = (tenantRow, flagOn) => ({ DB: tdDB(tenantRow, flagOn), SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' });
  const tdCustomReq = (hostname) => new Request('https://' + hostname + '/', { method: 'GET', headers: { 'Content-Type': 'application/json' } });
  const isUnavailable = (s) => s.indexOf('Temporarily unavailable') >= 0;
  const isRealPage = (s) => s.indexOf('id="app"') >= 0 && !isUnavailable(s);

  // (a) flag OFF: even a long-past_due tenant's real site still serves -- proves the feature is fully inert when off
  let r = await worker.fetch(mkReq('GET', '/api/book/td281'), tdEnv(tdRow('past_due', Date.now() - 30 * DAY281), false), tdCtx);
  let t = await r.text();
  ok(r.status === 200 && isRealPage(t), '#281 flag OFF: long-past_due tenant still serves the real booking page (got status ' + r.status + ')');

  // (b) flag ON, delinquent 1 day (< 3-day grace): still inside the grace period -> real site
  r = await worker.fetch(mkReq('GET', '/api/book/td281'), tdEnv(tdRow('past_due', Date.now() - 1 * DAY281), true), tdCtx);
  t = await r.text();
  ok(r.status === 200 && isRealPage(t), '#281 flag ON, delinquent 1 day (< 3-day grace): real booking page still serves (got status ' + r.status + ')');

  // (c) flag ON, delinquent 4 days (> 3-day grace): the friendly unavailable page, HTTP 200, no billing language
  r = await worker.fetch(mkReq('GET', '/api/book/td281'), tdEnv(tdRow('past_due', Date.now() - 4 * DAY281), true), tdCtx);
  t = await r.text();
  ok(r.status === 200 && isUnavailable(t), '#281 flag ON, delinquent 4 days (> 3-day grace): serves the "temporarily unavailable" page (got status ' + r.status + ', marker=' + isUnavailable(t) + ')');
  ok(t.toLowerCase().indexOf('payment') < 0 && t.toLowerCase().indexOf('billing') < 0 && t.toLowerCase().indexOf('delinquent') < 0 && t.toLowerCase().indexOf('past due') < 0, '#281 unavailable page never mentions payment/billing/delinquency (customer-facing -- must never embarrass the tenant)');

  // (d) belt-and-suspenders: plan==='active' is ALWAYS served, even with a very stale delinquent_since + flag ON
  r = await worker.fetch(mkReq('GET', '/api/book/td281'), tdEnv(tdRow('active', Date.now() - 999 * DAY281), true), tdCtx);
  t = await r.text();
  ok(r.status === 200 && isRealPage(t), '#281 plan=active is NEVER taken down even with a stale delinquent_since (got status ' + r.status + ')');

  // (e) null delinquent_since is ALWAYS served, flag ON, plan past_due (never delinquent, or already recovered)
  r = await worker.fetch(mkReq('GET', '/api/book/td281'), tdEnv(tdRow('past_due', null), true), tdCtx);
  t = await r.text();
  ok(r.status === 200 && isRealPage(t), '#281 null delinquent_since is NEVER taken down (got status ' + r.status + ')');

  // (f) the SAME gate applies at the OTHER call site (custom-domain front door), not just /api/book/<slug>
  r = await worker.fetch(tdCustomReq('td281-custom.example'), tdEnv(tdRow('past_due', Date.now() - 4 * DAY281), true), tdCtx);
  t = await r.text();
  ok(r.status === 200 && isUnavailable(t), '#281 custom-domain serve path: flag ON + >3 days -> unavailable page too (got status ' + r.status + ')');
  r = await worker.fetch(tdCustomReq('td281-custom.example'), tdEnv(tdRow('past_due', Date.now() - 4 * DAY281), false), tdCtx);
  t = await r.text();
  ok(r.status === 200 && isRealPage(t), '#281 custom-domain serve path: flag OFF -> real site (got status ' + r.status + ')');
}

// ---- #281 admin toggle: GET/POST /api/admin/config surfaces site_takedown_enabled, independently of the other
// gates (mirrors the #280 cfgDB2/cfgEnv2/cfgReq2 pattern above -- self-contained, own helpers). ----
{
  let takedownFlag = null;   // null == unset (reads as default '0'/off); '1'/'0' once toggled via POST
  function cfgDB3() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM platform_config WHERE k=\?/.test(sql)) return (a[0] === 'site_takedown_enabled' && takedownFlag != null) ? { v: takedownFlag } : null;
          if (/COUNT\(\*\) c FROM tenants/.test(sql)) return { c: 0 };
          if (/sqlite_master/.test(sql)) return { n: 30 };
          if (/FROM rate_limits/.test(sql)) return null;
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => {
          if (/INSERT INTO platform_config/.test(sql)) { if (a[0] === 'site_takedown_enabled') takedownFlag = a[1]; }
          return { success: true, meta: { changes: 1 } };
        },
      };
      return api;
    }
    return { prepare: stmt };
  }
  const cfgEnv3 = { DB: cfgDB3(), ADMIN_TOKEN: 'k', SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' };
  const cfgReq3 = (method, headers, body) => new Request('https://atlasrental.io/api/admin/config', { method, headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}), body: body !== undefined ? JSON.stringify(body) : undefined });

  let r = await worker.fetch(cfgReq3('GET', H), cfgEnv3, ctx);
  let j = await r.json();
  ok(r.status === 200 && j.enterprise.site_takedown_enabled === false, '#281 admin config: site_takedown_enabled defaults to false (got ' + JSON.stringify(j.enterprise && j.enterprise.site_takedown_enabled) + ')');

  r = await worker.fetch(cfgReq3('POST', H, { site_takedown_enabled: true }), cfgEnv3, ctx);
  j = await r.json();
  ok(r.status === 200 && j.enterprise.site_takedown_enabled === true, '#281 admin config: POST site_takedown_enabled:true flips it on (got ' + JSON.stringify(j.enterprise && j.enterprise.site_takedown_enabled) + ')');
  ok(j.enterprise.payment_gate_enabled === false, '#281 admin config: flipping site_takedown_enabled leaves payment_gate_enabled untouched (independent flags) (got ' + JSON.stringify(j.enterprise && j.enterprise.payment_gate_enabled) + ')');

  r = await worker.fetch(cfgReq3('POST', { 'X-Admin-Token': 'WRONG' }, { site_takedown_enabled: false }), cfgEnv3, ctx);
  ok(r.status === 401 || r.status === 403, '#281 admin config: a bad admin token cannot flip the gate (got ' + r.status + ')');
  ok(takedownFlag === '1', '#281 admin config: the bad-token POST above never actually wrote to platform_config (still "1" from the earlier real POST) (got ' + JSON.stringify(takedownFlag) + ')');
}

// ---- #280/#282: website-addon + domain cancel-at-period-end. Fixes the real #280 billing bug (the client "Cancel"
// button on the hosted-website add-on never called any endpoint, so a monthly Stripe subscription kept billing
// forever) and implements #282's universal policy (every cancel is cancel_at_period_end, never immediate, never a
// refund). Own self-contained mock/helpers below -- does NOT reference wgEnvFor/wgReq or any other block's names.
// AUTHORED WITHOUT A NODE RUNTIME AVAILABLE (hand-traced against worker.js only, not executed locally) -- CI's
// `node test/routes.mjs` run is this block's first real execution. If something here mismatches, check these SQL
// regexes first against the exact query text in /api/billing/website-cancel + /api/billing/domain-cancel. ----
{
  // Local Stripe mock: a single-subscription POST (cancel_at_period_end) is distinguished from the fallback
  // LIST-by-customer GET; 'stripe_fail' simulates Stripe rejecting the cancel. Captures the last cancel POST's
  // url+body so a test can prove the RIGHT subscription was targeted with cancel_at_period_end=true (never an
  // immediate cancel).
  let wcLastCancelCall = null;
  function wcFetchMock(scenario) {
    return async function (url, opts) {
      const u = String(url), method = (opts && opts.method) || 'GET', body = (opts && opts.body) || '';
      if (/\/v1\/subscriptions\?customer=/.test(u)) {
        if (scenario === 'fallback_notfound') return { ok: true, status: 200, json: async () => ({ data: [] }) };
        return { ok: true, status: 200, json: async () => ({ data: [{ id: 'sub_found_fb', metadata: { billing: 'website' }, status: 'active' }] }) };
      }
      if (/\/v1\/subscriptions\/[^/?]+$/.test(u) && method === 'POST') {
        wcLastCancelCall = { url: u, body: body };
        if (scenario === 'stripe_fail') return { ok: false, status: 402, json: async () => ({ error: { message: 'Your card was declined.' } }) };
        const id = decodeURIComponent(u.split('/').pop());
        return { ok: true, status: 200, json: async () => ({ id: id, cancel_at_period_end: /cancel_at_period_end=true/.test(body), current_period_end: 1893456000 }) };
      }
      return { ok: false, status: 404, json: async () => ({}) };
    };
  }
  const wcOrigFetch = globalThis.fetch;   // restored at the end of this block -- never leaks into whatever runs after

  // opts: { scn, website_sub, website_addon, stripe_customer, custom_domain, domainSub, denyCap }
  function wcEnvFor(opts) {
    const SID = 'sid_wc_' + opts.scn, CSRF = 'csrf_wc_' + opts.scn, TEN = 't_wc_' + opts.scn, UID = 'u_wc_' + opts.scn;
    const tenantRow = { id: TEN, website_sub: (opts.website_sub != null ? opts.website_sub : null), website_addon: opts.website_addon || null, stripe_customer: opts.stripe_customer || null, custom_domain: opts.custom_domain || null };
    const domainRow = opts.domainSub ? { stripe_sub: opts.domainSub } : null;
    let websiteSubPersisted = null;
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM sessions WHERE id/.test(sql)) return a[0] === SID ? { id: SID, user_id: UID, tenant_id: TEN, csrf: CSRF, expires_at: Date.now() + 1e12, idle_at: Date.now(), revoked_at: null } : null;
          if (/FROM users WHERE id/.test(sql)) return { id: UID, email: opts.denyCap ? 'staff@member.com' : 'owner@x.com', tenant_id: TEN, role: opts.denyCap ? 'staff' : 'owner', caps: opts.denyCap ? JSON.stringify({ caps: { billing: false } }) : null };
          if (/FROM comp_grants WHERE email/.test(sql)) return null;
          if (/FROM platform_config WHERE k=\?/.test(sql)) return null;   // payment_gate_enabled / trial_requires_card / payments_test_mode all read their fallback (off/live)
          if (/SELECT website_sub, website_addon, stripe_customer FROM tenants WHERE id=\?/.test(sql)) return tenantRow;
          if (/SELECT custom_domain FROM tenants WHERE id=\?/.test(sql)) return tenantRow;
          if (/SELECT stripe_sub FROM domains_sold WHERE tenant_id=\? AND domain=\?/.test(sql)) return domainRow;
          if (/FROM rate_limits/.test(sql)) return null;
          if (/sqlite_master/.test(sql)) return { n: 30 };
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => {
          if (/^UPDATE tenants SET website_sub=\? WHERE id=\?$/.test(sql)) websiteSubPersisted = a[0];
          return { success: true, meta: { changes: 1 } };
        },
      };
      return api;
    }
    return { SID: SID, CSRF: CSRF, TEN: TEN, env: { DB: { prepare: stmt }, SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'owner@x.com', PLATFORM_STRIPE_KEY: 'sk_live_x' }, getPersistedWebsiteSub: () => websiteSubPersisted };
  }
  const wcReq = (method, path, cfg, body, headerOverrides) => {
    const headers = Object.assign({ 'content-type': 'application/json', cookie: 'atlas_sid=' + cfg.SID, 'x-csrf-token': cfg.CSRF, origin: 'https://atlasrental.io' }, headerOverrides || {});
    return { method: method, url: 'https://atlasrental.io' + path, headers: { get: (k) => { const v = headers[String(k).toLowerCase()]; return v === undefined ? null : v; } }, json: async () => (body || {}), text: async () => JSON.stringify(body || {}) };
  };

  globalThis.fetch = wcFetchMock('ok');

  // (a) website_sub already stored -> cancels that EXACT subscription (cancel_at_period_end=true), returns ok + cancel_at
  let cfg = wcEnvFor({ scn: 'has_sub', website_sub: 'sub_existing123', website_addon: 'mo', stripe_customer: 'cus_abc' });
  let r = await worker.fetch(wcReq('POST', '/api/billing/website-cancel', cfg, {}), cfg.env, ctx);
  let j = await r.json();
  ok(r.status === 200 && j.ok === true && j.when === 'period_end', 'website-cancel: website_sub set -> 200 ok period_end (got ' + r.status + ' ' + JSON.stringify(j) + ')');
  ok(j.cancel_at === 1893456000, 'website-cancel: returns Stripe current_period_end as cancel_at (got ' + j.cancel_at + ')');
  ok(!!wcLastCancelCall && wcLastCancelCall.url.indexOf('sub_existing123') >= 0 && /cancel_at_period_end=true/.test(wcLastCancelCall.body), 'website-cancel: called Stripe with the stored sub id + cancel_at_period_end=true, never an immediate cancel (got ' + JSON.stringify(wcLastCancelCall) + ')');

  // (b) website_sub is null but website_addon='mo' (a sub bought before this column existed) -> fallback finds it by
  //     listing the tenant's Stripe customer's subscriptions for metadata.billing==='website', cancels it, AND
  //     persists the id into website_sub so a future cancel is a direct lookup.
  wcLastCancelCall = null;
  cfg = wcEnvFor({ scn: 'fallback', website_sub: null, website_addon: 'mo', stripe_customer: 'cus_fallback' });
  r = await worker.fetch(wcReq('POST', '/api/billing/website-cancel', cfg, {}), cfg.env, ctx);
  j = await r.json();
  ok(r.status === 200 && j.ok === true, 'website-cancel: fallback (no stored website_sub, addon=mo) still finds + cancels via the customer subscriptions list (got ' + r.status + ' ' + JSON.stringify(j) + ')');
  ok(!!wcLastCancelCall && wcLastCancelCall.url.indexOf('sub_found_fb') >= 0, 'website-cancel: fallback cancels the subscription matched by metadata.billing===website (got ' + JSON.stringify(wcLastCancelCall) + ')');
  ok(cfg.getPersistedWebsiteSub() === 'sub_found_fb', 'website-cancel: fallback persists the found sub id into website_sub for next time (got ' + cfg.getPersistedWebsiteSub() + ')');

  // (c) a ONE-TIME ('once') website purchase has no subscription -> clear "nothing recurring to cancel" message,
  //     never a fake success (this tenant keeps the site forever; there is simply nothing to cancel)
  cfg = wcEnvFor({ scn: 'once', website_sub: null, website_addon: 'once', stripe_customer: 'cus_once' });
  r = await worker.fetch(wcReq('POST', '/api/billing/website-cancel', cfg, {}), cfg.env, ctx);
  j = await r.json();
  ok(r.status === 400 && /one-time/i.test(j.error || ''), 'website-cancel: \'once\' addon -> clear nothing-recurring message, not a fake success (got ' + r.status + ' ' + JSON.stringify(j) + ')');

  // (d) guard: missing/wrong CSRF token -> 403, never reaches Stripe
  wcLastCancelCall = null;
  cfg = wcEnvFor({ scn: 'badcsrf', website_sub: 'sub_existing123', website_addon: 'mo', stripe_customer: 'cus_abc' });
  r = await worker.fetch(wcReq('POST', '/api/billing/website-cancel', cfg, {}, { 'x-csrf-token': 'WRONG' }), cfg.env, ctx);
  ok(r.status === 403, 'website-cancel: bad CSRF token -> 403 (got ' + r.status + ')');
  ok(wcLastCancelCall === null, 'website-cancel: bad CSRF token never reaches Stripe (got ' + JSON.stringify(wcLastCancelCall) + ')');

  // (e) guard: authenticated but lacking the 'billing' capability -> 403, never reaches Stripe
  wcLastCancelCall = null;
  cfg = wcEnvFor({ scn: 'nocap', website_sub: 'sub_existing123', website_addon: 'mo', stripe_customer: 'cus_abc', denyCap: true });
  r = await worker.fetch(wcReq('POST', '/api/billing/website-cancel', cfg, {}), cfg.env, ctx);
  ok(r.status === 403, 'website-cancel: caller without the billing capability -> 403 (got ' + r.status + ')');
  ok(wcLastCancelCall === null, 'website-cancel: no-cap caller never reaches Stripe (got ' + JSON.stringify(wcLastCancelCall) + ')');

  // (f) Stripe itself rejects the cancel call -> surfaces the real error and status, NEVER reports ok:true (the
  //     SAFETY invariant: never report a cancel as succeeded unless Stripe actually accepted it)
  globalThis.fetch = wcFetchMock('stripe_fail');
  cfg = wcEnvFor({ scn: 'stripefail', website_sub: 'sub_existing123', website_addon: 'mo', stripe_customer: 'cus_abc' });
  r = await worker.fetch(wcReq('POST', '/api/billing/website-cancel', cfg, {}), cfg.env, ctx);
  j = await r.json();
  ok(r.status === 502 && j.ok !== true && /declined/i.test(j.error || ''), 'website-cancel: a Stripe failure surfaces the real error and NEVER reports ok:true (got ' + r.status + ' ' + JSON.stringify(j) + ')');
  globalThis.fetch = wcFetchMock('ok');

  // (g) domain-cancel happy path: no {domain} in the body -> defaults to the tenant's connected custom_domain,
  //     looks up domains_sold for that (tenant,domain), cancels that subscription at period end
  cfg = wcEnvFor({ scn: 'domain', custom_domain: 'example.com', domainSub: 'sub_domain999' });
  r = await worker.fetch(wcReq('POST', '/api/billing/domain-cancel', cfg, {}), cfg.env, ctx);
  j = await r.json();
  ok(r.status === 200 && j.ok === true && j.domain === 'example.com', 'domain-cancel: defaults to the tenant\'s connected custom_domain -> 200 ok (got ' + r.status + ' ' + JSON.stringify(j) + ')');
  ok(!!wcLastCancelCall && wcLastCancelCall.url.indexOf('sub_domain999') >= 0 && /cancel_at_period_end=true/.test(wcLastCancelCall.body), 'domain-cancel: cancels domains_sold.stripe_sub via cancel_at_period_end, never an immediate delete (got ' + JSON.stringify(wcLastCancelCall) + ')');

  // (h) domain-cancel: no matching domains_sold row for that domain -> clear failure, never a fake success
  cfg = wcEnvFor({ scn: 'domain_none', custom_domain: 'example.com', domainSub: null });
  r = await worker.fetch(wcReq('POST', '/api/billing/domain-cancel', cfg, {}), cfg.env, ctx);
  j = await r.json();
  ok(r.status === 400 && j.ok !== true, 'domain-cancel: no recurring subscription on file -> clear failure, never a fake success (got ' + r.status + ' ' + JSON.stringify(j) + ')');

  globalThis.fetch = wcOrigFetch;
}

// ---- #286 AI-spend metering: _meterAI upserts + ACCUMULATES per (day, model); a usage-less provider response
// records nothing and never throws; an unrecognized model falls back to the default rate rather than $0. Own
// self-contained mock (does not reference any other block's helper). ----
{
  const spend = new Map();
  function aiSpendDB() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => null,
        all: async () => ({ results: [] }),
        run: async () => {
          if (/INSERT INTO platform_ai_spend/.test(sql)) {
            const [day, model, inTok, outTok, costMicros] = a;
            const key = day + '|' + model;
            const cur = spend.get(key) || { day, model, calls: 0, input_tokens: 0, output_tokens: 0, cost_micros: 0 };
            cur.calls += 1; cur.input_tokens += inTok; cur.output_tokens += outTok; cur.cost_micros += costMicros;
            spend.set(key, cur);
          }
          return { success: true, meta: { changes: 1 } };
        },
      };
      return api;
    }
    return { prepare: stmt };
  }
  const aiEnv = { DB: aiSpendDB() };
  const today = new Date().toISOString().slice(0, 10);

  // (a) first claude-sonnet-5 call: 1000 input + 500 output tokens @ $3.00/$15.00 per 1M -> exact cost_micros
  const expectA = Math.round(1000 * AI_PRICES['claude-sonnet-5'].input + 500 * AI_PRICES['claude-sonnet-5'].output);
  await _meterAI(aiEnv, 'claude-sonnet-5', { input_tokens: 1000, output_tokens: 500 });
  let row = spend.get(today + '|claude-sonnet-5');
  ok(!!row && row.calls === 1 && row.input_tokens === 1000 && row.output_tokens === 500 && row.cost_micros === expectA, '#286 _meterAI: first claude-sonnet-5 call upserts the exact cost_micros=' + expectA + ' (got ' + JSON.stringify(row) + ')');

  // (b) a SECOND claude-sonnet-5 call the same day ACCUMULATES (calls/tokens/cost summed), never overwrites
  const expectB2 = Math.round(200 * AI_PRICES['claude-sonnet-5'].input + 100 * AI_PRICES['claude-sonnet-5'].output);
  await _meterAI(aiEnv, 'claude-sonnet-5', { input_tokens: 200, output_tokens: 100 });
  row = spend.get(today + '|claude-sonnet-5');
  ok(!!row && row.calls === 2 && row.input_tokens === 1200 && row.output_tokens === 600 && row.cost_micros === expectA + expectB2, '#286 _meterAI: a second same-day call ACCUMULATES rather than overwriting (got ' + JSON.stringify(row) + ', expected cost_micros=' + (expectA + expectB2) + ')');

  // (c) a DIFFERENT model gets its OWN row, priced at its OWN rate -- not merged with claude-sonnet-5's
  const expectGpt = Math.round(2000 * AI_PRICES['gpt-4o'].input + 1000 * AI_PRICES['gpt-4o'].output);
  await _meterAI(aiEnv, 'gpt-4o', { input_tokens: 2000, output_tokens: 1000 });
  const gptRow = spend.get(today + '|gpt-4o');
  ok(!!gptRow && gptRow.calls === 1 && gptRow.cost_micros === expectGpt, '#286 _meterAI: a different model gets its own (day,model) row at its own rate (got ' + JSON.stringify(gptRow) + ', expected cost_micros=' + expectGpt + ')');
  ok(spend.size === 2, '#286 _meterAI: two distinct models produce two distinct rows, never merged (got ' + spend.size + ')');

  // (d) an unrecognized model falls back to AI_PRICES.default (never priced at $0/silently free)
  const expectDefault = Math.round(100 * AI_PRICES['default'].input + 100 * AI_PRICES['default'].output);
  await _meterAI(aiEnv, 'some-future-model-xyz', { input_tokens: 100, output_tokens: 100 });
  const unkRow = spend.get(today + '|some-future-model-xyz');
  ok(!!unkRow && unkRow.cost_micros === expectDefault, '#286 _meterAI: an unrecognized model falls back to the default rate, never treated as free (got ' + JSON.stringify(unkRow) + ', expected cost_micros=' + expectDefault + ')');

  // (e) a provider response with NO usable usage (error body) -> _aiUsageFrom normalizes to {0,0} and _meterAI
  // records NOTHING (no phantom zero-cost row) and never throws
  ok(JSON.stringify(_aiUsageFrom('anthropic', { error: { type: 'not_found_error' } })) === JSON.stringify({ input_tokens: 0, output_tokens: 0 }), '#286 _aiUsageFrom: an error body with no .usage normalizes to {0,0}, never guesses a nonzero count');
  ok(JSON.stringify(_aiUsageFrom('openai', {})) === JSON.stringify({ input_tokens: 0, output_tokens: 0 }), '#286 _aiUsageFrom: an empty OpenAI body normalizes to {0,0}');
  ok(JSON.stringify(_aiUsageFrom('gemini', {})) === JSON.stringify({ input_tokens: 0, output_tokens: 0 }), '#286 _aiUsageFrom: an empty Gemini body normalizes to {0,0}');
  const beforeSize = spend.size;
  let threw = false;
  try { await _meterAI(aiEnv, 'claude-sonnet-5', _aiUsageFrom('anthropic', { error: { type: 'not_found_error' } })); } catch (e) { threw = true; }
  ok(!threw, '#286 _meterAI: a usage-less call never throws');
  ok(spend.size === beforeSize, '#286 _meterAI: a usage-less call records NOTHING -- no phantom zero-cost row (size unchanged, got ' + spend.size + ' vs ' + beforeSize + ')');

  // (f) never throws even with a totally malformed env (defensive -- metering must NEVER surface to the AI path)
  threw = false;
  try { await _meterAI({}, 'claude-sonnet-5', { input_tokens: 10, output_tokens: 10 }); } catch (e) { threw = true; }
  ok(!threw, '#286 _meterAI: never throws even with no env.DB at all');
  threw = false;
  try { await _meterAI(null, 'claude-sonnet-5', { input_tokens: 10, output_tokens: 10 }); } catch (e) { threw = true; }
  ok(!threw, '#286 _meterAI: never throws even with a null env');
}

// ---- #286 GET /api/admin/pnl -- owner-gated P&L: net = revenue - (ai_spend + fixed_costs), using a mocked
// platform_transactions/platform_ai_spend/platform_config. Own self-contained mock (does not reference any other
// block's helper). Asserts the NET FORMULA AS AN IDENTITY against whatever the mocked sums produce (not a
// hand-computed prorated number) since fixed-cost proration depends on wall-clock time at test-run -- the
// deterministic parts (revenue, ai_spend, fixed_costs.monthly_total_cents, by-model breakdown) are asserted exactly. ----
{
  const FIXED = [{ label: 'Cloudflare', monthly_cents: 2000 }, { label: 'Resend', monthly_cents: 1000 }];
  const BY_MODEL = [
    { model: 'claude-sonnet-5', calls: 5, it: 3000, ot: 1500, cm: 700000 },
    { model: 'gpt-4o', calls: 2, it: 2000, ot: 500, cm: 300000 },
    { model: 'some-unpriced-model', calls: 1, it: 100, ot: 50, cm: 0 }
  ];
  function pnlDB(staffRow) {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM admin_staff WHERE token_hash=\?/.test(sql)) return staffRow || null;
          if (/FROM platform_config WHERE k=\?/.test(sql)) return (a[0] === 'platform_fixed_costs_json') ? { v: JSON.stringify(FIXED) } : null;
          if (/MIN\(created_at\)/.test(sql)) return { m: Date.now() - 200 * 86400000 };
          if (/amount_cents.*platform_transactions WHERE created_at>=\? AND created_at<\?/.test(sql)) return { c: 100000 };
          if (/amount_cents.*platform_transactions WHERE created_at>=\?/.test(sql)) return { c: 150000 };
          if (/amount_cents.*FROM platform_transactions/.test(sql) && !/WHERE/.test(sql)) return { c: 500000 };
          if (/cost_micros.*platform_ai_spend WHERE day>=\? AND day<=\?/.test(sql)) return { cm: 1000000, it: 5000, ot: 2000 };
          if (/cost_micros.*platform_ai_spend WHERE day>=\?/.test(sql)) return { cm: 1500000 };
          if (/cost_micros.*FROM platform_ai_spend/.test(sql) && !/WHERE/.test(sql)) return { cm: 5000000 };
          if (/sqlite_master/.test(sql)) return { n: 25 };
          if (/FROM rate_limits/.test(sql)) return null;
          return null;
        },
        all: async () => { if (/GROUP BY model/.test(sql)) return { results: BY_MODEL }; return { results: [] }; },
        run: async () => ({ success: true, meta: { changes: 1 } }),
      };
      return api;
    }
    return { prepare: stmt };
  }
  const pnlEnv = { DB: pnlDB(), ADMIN_TOKEN: 'k', SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' };

  let r = await worker.fetch(mkReq('GET', '/api/admin/pnl?range=30d', { headers: H }), pnlEnv, ctx);
  let j = await r.json();
  ok(r.status === 200 && j.ok === true, 'pnl: owner token -> 200 ok (got ' + r.status + ' ' + JSON.stringify(j).slice(0, 300) + ')');
  ok(j.revenue.range_cents === 100000 && j.revenue.month_cents === 150000 && j.revenue.total_cents === 500000, 'pnl: revenue.{range,month,total}_cents pass through the mocked platform_transactions sums exactly (got ' + JSON.stringify(j.revenue) + ')');
  ok(j.ai_spend.range_cents === 100 && j.ai_spend.month_cents === 150 && j.ai_spend.total_cents === 500, 'pnl: ai_spend cents = cost_micros/10000 exactly (1,000,000 micros -> 100 cents) (got ' + JSON.stringify(j.ai_spend) + ')');
  ok(j.ai_spend.tokens.input_tokens === 5000 && j.ai_spend.tokens.output_tokens === 2000, 'pnl: ai_spend.tokens passes through the range token sums (got ' + JSON.stringify(j.ai_spend.tokens) + ')');
  ok(Array.isArray(j.ai_spend.by_model) && j.ai_spend.by_model.length === 3, 'pnl: ai_spend.by_model has one row per model (got ' + JSON.stringify(j.ai_spend.by_model) + ')');
  const claudeRow = j.ai_spend.by_model.find((m) => m.model === 'claude-sonnet-5');
  const unpricedRow = j.ai_spend.by_model.find((m) => m.model === 'some-unpriced-model');
  ok(!!claudeRow && claudeRow.cost_cents === 70 && claudeRow.priced === true, 'pnl: by_model priced entry has exact cost_cents (700000 micros -> 70 cents) + priced:true (got ' + JSON.stringify(claudeRow) + ')');
  ok(!!unpricedRow && unpricedRow.priced === false, 'pnl: by_model flags an unrecognized model with priced:false so the UI can warn (got ' + JSON.stringify(unpricedRow) + ')');
  ok(j.fixed_costs.monthly_total_cents === 3000 && j.fixed_costs.items.length === 2, 'pnl: fixed_costs.monthly_total_cents sums the owner-entered items exactly; items pass through (got ' + JSON.stringify(j.fixed_costs.monthly_total_cents) + ', ' + j.fixed_costs.items.length + ' items)');
  // NET FORMULA as an identity against whatever the (time-dependent) proration produced -- this is what "net =
  // revenue - (ai + fixed)" means operationally, and it holds regardless of wall-clock time.
  ok(j.expenses.range_cents === j.ai_spend.range_cents + j.fixed_costs.range_cents, 'pnl: expenses.range_cents = ai_spend.range_cents + fixed_costs.range_cents (got ' + JSON.stringify(j.expenses) + ')');
  ok(j.expenses.month_cents === j.ai_spend.month_cents + j.fixed_costs.month_cents, 'pnl: expenses.month_cents = ai_spend.month_cents + fixed_costs.month_cents (got ' + JSON.stringify(j.expenses) + ')');
  ok(j.expenses.total_cents === j.ai_spend.total_cents + j.fixed_costs.total_cents, 'pnl: expenses.total_cents = ai_spend.total_cents + fixed_costs.total_cents (got ' + JSON.stringify(j.expenses) + ')');
  ok(j.net.range_cents === j.revenue.range_cents - j.expenses.range_cents, 'pnl: net.range_cents = revenue.range_cents - expenses.range_cents (got net=' + j.net.range_cents + ' revenue=' + j.revenue.range_cents + ' expenses=' + j.expenses.range_cents + ')');
  ok(j.net.month_cents === j.revenue.month_cents - j.expenses.month_cents, 'pnl: net.month_cents = revenue.month_cents - expenses.month_cents (got ' + JSON.stringify(j.net) + ')');
  ok(j.net.total_cents === j.revenue.total_cents - j.expenses.total_cents, 'pnl: net.total_cents = revenue.total_cents - expenses.total_cents (got ' + JSON.stringify(j.net) + ')');
  ok(j.fixed_costs.range_cents >= 0 && j.fixed_costs.month_cents >= 0 && j.fixed_costs.total_cents >= 0, 'pnl: prorated fixed-cost figures are never negative (got ' + JSON.stringify({ r: j.fixed_costs.range_cents, m: j.fixed_costs.month_cents, t: j.fixed_costs.total_cents }) + ')');

  // ---- owner-gate: a bad/garbage token never resolves an identity -> 403 ----
  r = await worker.fetch(mkReq('GET', '/api/admin/pnl?range=30d', { headers: { 'X-Admin-Token': 'WRONG' } }), pnlEnv, ctx);
  ok(r.status === 403, 'pnl: garbage admin token -> 403 (got ' + r.status + ')');

  // ---- owner-gate: a VALID staff token with a non-owner role (support) resolves an identity but is still
  // rejected -- /api/admin/pnl is OWNER_ONLY, matching how security-log/errors are gated ----
  const staffSecret = 'atlst_' + crypto.randomBytes(20).toString('hex');
  const staffHash = crypto.createHash('sha256').update(staffSecret).digest('hex');
  const staffRow = { id: 's_pnl1', email: 'support@member.com', role: 'support', active: 1, revoked_at: null };
  const pnlStaffEnv = { DB: pnlDB(staffRow), ADMIN_TOKEN: 'k', SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' };
  r = await worker.fetch(mkReq('GET', '/api/admin/pnl?range=30d', { headers: { 'X-Admin-Token': staffSecret } }), pnlStaffEnv, ctx);
  ok(r.status === 403, 'pnl: a VALID support-role staff token still gets 403 -- pnl is OWNER_ONLY, not just any authenticated admin (got ' + r.status + ')');
}

if (fails) { console.error('\nROUTE TESTS FAILED (' + fails + ') -- deploy blocked.'); process.exit(1); }
console.log('\nROUTE TESTS PASSED.');
