// Atlas worker smoke test -- the CI gate. Runs on Node 20 (GitHub Actions) with a stateful mock D1 and a
// stubbed network, so it is fully deterministic and never touches production. A failure here blocks the deploy.
//
// It catches the exact classes of bug that have reached production before:
//   1. the worker not loading at all (syntax / top-level error),
//   2. the build stamp drifting from what the dashboard expects,
//   3. the competitor delete-by-query regression,
//   4. admin auth accepting a bad token.
//
// Run locally (needs Node 20+):  node test/smoke.mjs

import worker from '../worker.js';

// --- stub the network so no route makes a real request (competitor add snapshots a URL, etc.) ---
globalThis.fetch = () => Promise.resolve({ ok: false, status: 0, headers: { get: () => null }, text: async () => '', json: async () => ({}) });

// --- stateful mock D1: enough for the deterministic, DB-only routes we assert ---
function mockDB() {
  const comp = new Map();
  function stmt(sql) {
    let args = [];
    const api = {
      bind: (...a) => { args = a; return api; },
      first: async () => {
        if (/FROM competitor_watch WHERE id=\?/.test(sql)) return comp.get(args[0]) || null;
        if (/COUNT\(\*\) c FROM competitor_watch/.test(sql)) return { c: comp.size };
        if (/FROM sqlite_master/.test(sql)) return { n: 25 };            // schema_loaded
        if (/FROM platform_config WHERE k=\?/.test(sql)) return null;     // defaults everywhere
        if (/FROM rate_limits WHERE bucket=\?/.test(sql)) return null;    // rate limit: allow
        return null;
      },
      all: async () => {
        if (/FROM competitor_watch/.test(sql)) return { results: [...comp.values()] };
        return { results: [] };
      },
      run: async () => {
        if (/INSERT INTO competitor_watch/.test(sql)) comp.set(args[0], { id: args[0], url: args[1], label: args[2], added_at: args[3], last_json: null, intel: null });
        if (/DELETE FROM competitor_watch WHERE id=\?/.test(sql)) { const had = comp.delete(args[0]); return { success: true, meta: { changes: had ? 1 : 0 } }; }
        return { success: true, meta: { changes: 1 } };
      },
    };
    return api;
  }
  return { prepare: stmt };
}

const env = { DB: mockDB(), ADMIN_TOKEN: 'test-token', SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' };
const ctx = { waitUntil() {}, passThroughOnException() {} };
const EXPECT_BUILD = '2026.07.19g';   // keep in lockstep with ATLAS_BUILD in worker.js + ATLAS_EXPECT_BUILD in admin.html

function mkReq(method, path, opts = {}) {
  return new Request('https://atlasrental.io' + path, {
    method, headers: Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {}),
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
}

let fails = 0;
function ok(cond, msg) { if (cond) { console.log('  ok  ' + msg); } else { fails++; console.error('  FAIL ' + msg); } }

console.log('Atlas worker smoke test');

// 0) the worker module loaded and exposes a fetch handler
ok(worker && typeof worker.fetch === 'function', 'worker loaded with a fetch handler');

// 1) public health + build stamp
let r = await worker.fetch(mkReq('GET', '/api/health'), env, ctx);
let j = await r.json();
ok(r.status === 200, 'GET /api/health -> 200');
ok(j.build === EXPECT_BUILD, 'health build == ' + EXPECT_BUILD + ' (got ' + j.build + ')');

// 2) admin auth rejects a bad token
r = await worker.fetch(mkReq('GET', '/api/admin/competitors', { headers: { 'X-Admin-Token': 'WRONG' } }), env, ctx);
ok(r.status === 401 || r.status === 403, 'admin rejects a bad token (got ' + r.status + ')');

// 3) competitor add -> list -> delete-by-query round trip (the recurring regression)
const H = { 'X-Admin-Token': 'test-token' };
r = await worker.fetch(mkReq('POST', '/api/admin/competitors', { headers: H, body: { url: 'https://comp.example', label: 'Comp' } }), env, ctx);
j = await r.json();
ok(j.ok && j.id, 'competitor add');
const cid = j.id;
r = await worker.fetch(mkReq('GET', '/api/admin/competitors', { headers: H }), env, ctx);
j = await r.json();
ok(j.ok && j.competitors.length === 1, 'competitor list shows 1');
r = await worker.fetch(mkReq('DELETE', '/api/admin/competitors?id=' + encodeURIComponent(cid), { headers: H }), env, ctx);
j = await r.json();
ok(j.ok && j.removed === 1, 'competitor delete via query string -> removed:1 (got ' + JSON.stringify(j) + ')');
r = await worker.fetch(mkReq('GET', '/api/admin/competitors', { headers: H }), env, ctx);
j = await r.json();
ok((j.competitors || []).length === 0, 'competitor is gone after delete');

if (fails) { console.error('\nSMOKE FAILED (' + fails + ' assertion' + (fails > 1 ? 's' : '') + ') -- deploy blocked.'); process.exit(1); }
console.log('\nSMOKE PASSED -- safe to deploy.');
