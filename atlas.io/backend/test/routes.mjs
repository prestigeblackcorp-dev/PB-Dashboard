// Atlas worker route tests -- second CI gate, beyond smoke. Deterministic (mock D1 + stubbed Stripe), no network,
// no production. Covers the MONEY path (payment go-live self-test) + richer health fields.
// Run locally (Node 20+):  node test/routes.mjs
// CI live (2026-07-19): D1 bound + CLOUDFLARE_API_TOKEN/ACCOUNT_ID secrets set -- this gate now guards auto-deploy.

import worker, { _b32decode, _hotp, _totpAt } from '../worker.js';
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

if (fails) { console.error('\nROUTE TESTS FAILED (' + fails + ') -- deploy blocked.'); process.exit(1); }
console.log('\nROUTE TESTS PASSED.');
