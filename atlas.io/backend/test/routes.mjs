// Atlas worker route tests -- second CI gate, beyond smoke. Deterministic (mock D1 + stubbed Stripe), no network,
// no production. Covers the MONEY path (payment go-live self-test) + richer health fields.
// Run locally (Node 20+):  node test/routes.mjs
// CI live (2026-07-19): D1 bound + CLOUDFLARE_API_TOKEN/ACCOUNT_ID secrets set -- this gate now guards auto-deploy.

import worker from '../worker.js';
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

if (fails) { console.error('\nROUTE TESTS FAILED (' + fails + ') -- deploy blocked.'); process.exit(1); }
console.log('\nROUTE TESTS PASSED.');
