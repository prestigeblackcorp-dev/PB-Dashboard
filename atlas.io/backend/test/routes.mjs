// Atlas worker route tests -- second CI gate, beyond smoke. Deterministic (mock D1 + stubbed Stripe), no network,
// no production. Covers the MONEY path (payment go-live self-test) + richer health fields.
// Run locally (Node 20+):  node test/routes.mjs

import worker from '../worker.js';

// --- switchable Stripe mock (read-only endpoints the self-test calls) ---
let scn = 'ready';
globalThis.fetch = (u) => {
  const s = String(u);
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

if (fails) { console.error('\nROUTE TESTS FAILED (' + fails + ') -- deploy blocked.'); process.exit(1); }
console.log('\nROUTE TESTS PASSED.');
