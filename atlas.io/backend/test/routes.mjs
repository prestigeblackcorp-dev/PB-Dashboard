// Atlas worker route tests -- second CI gate, beyond smoke. Deterministic (mock D1 + stubbed Stripe), no network,
// no production. Covers the MONEY path (payment go-live self-test) + richer health fields.
// Run locally (Node 20+):  node test/routes.mjs
// CI live (2026-07-19): D1 bound + CLOUDFLARE_API_TOKEN/ACCOUNT_ID secrets set -- this gate now guards auto-deploy.

import worker from '../worker.js';

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

if (fails) { console.error('\nROUTE TESTS FAILED (' + fails + ') -- deploy blocked.'); process.exit(1); }
console.log('\nROUTE TESTS PASSED.');
