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
const EXPECT_BUILD = '2026.07.19y';   // keep in lockstep with ATLAS_BUILD in worker.js + ATLAS_EXPECT_BUILD in admin.html

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

// 4) #264 regression (deferred from build v): admin/staff must NEVER accept a bad token, same shape as the
// competitors check above but for the staff-directory route specifically.
r = await worker.fetch(mkReq('GET', '/api/admin/staff', { headers: { 'X-Admin-Token': 'WRONG' } }), env, ctx);
ok(r.status === 403, 'admin/staff rejects a bad token, never 200 (got ' + r.status + ')');

// 5) #253 observability: health is still ok:true (unchanged) and now additionally carries cron_fresh
r = await worker.fetch(mkReq('GET', '/api/health'), env, ctx);
j = await r.json();
ok(j.ok === true, 'health ok:true (unchanged) (got ' + j.ok + ')');
ok(typeof j.cron_fresh === 'boolean', 'health now carries a boolean cron_fresh (got ' + JSON.stringify(j.cron_fresh) + ')');

// 6) #253 observability: security-log + errors are owner-only admin routes
r = await worker.fetch(mkReq('GET', '/api/admin/security-log', { headers: H }), env, ctx);
ok(r.status === 200, 'GET /api/admin/security-log with the owner token -> 200 (got ' + r.status + ')');
r = await worker.fetch(mkReq('GET', '/api/admin/security-log', { headers: { 'X-Admin-Token': 'WRONG' } }), env, ctx);
ok(r.status === 403, 'GET /api/admin/security-log rejects a bad token (got ' + r.status + ')');
r = await worker.fetch(mkReq('GET', '/api/admin/errors', { headers: { 'X-Admin-Token': 'WRONG' } }), env, ctx);
ok(r.status === 403, 'GET /api/admin/errors rejects a bad token (got ' + r.status + ')');
r = await worker.fetch(mkReq('GET', '/api/admin/errors', { headers: H }), env, ctx);
j = await r.json();
ok(r.status === 200 && j.ok === true && typeof j.count_24h === 'number', 'GET /api/admin/errors with the owner token -> 200 + count_24h (got ' + JSON.stringify(j) + ')');

// 7) #276 payment-delinquency access gate: OFF by default -> a past_due tenant is completely unaffected (inert).
// Full on/off/never-lock/allow-list coverage lives in test/routes.mjs; this is the one-line CI tripwire that
// the flag truly defaults OFF -- if this ever fails, EVERY tenant on the platform could be locked out on deploy.
{
  const SID = 'sid_smoke276', CSRF = 'csrf_smoke276', TEN = 't_smoke276', UID = 'u_smoke276';
  function pgDB() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM sessions WHERE id/.test(sql)) return a[0] === SID ? { id: SID, user_id: UID, tenant_id: TEN, csrf: CSRF, expires_at: Date.now() + 1e12, idle_at: Date.now(), revoked_at: null } : null;
          if (/FROM users WHERE id/.test(sql)) return { id: UID, email: 'tenant@smoke.com', tenant_id: TEN, role: 'owner', caps: null };
          if (/FROM comp_grants/.test(sql)) return null;
          if (/FROM tenants WHERE id/.test(sql)) return { plan: 'past_due', trial_ends: null, tier: 'pro', stripe_sub: 'sub_x' };   // deliberately delinquent
          if (/FROM platform_config WHERE k=\?/.test(sql)) return null;   // payment_gate_enabled unset -> defaults OFF
          if (/FROM rate_limits/.test(sql)) return null;
          if (/sqlite_master/.test(sql)) return { n: 25 };
          return null;
        },
        all: async () => ({ results: [] }),
        run: async () => ({ success: true, meta: { changes: 1 } }),
      };
      return api;
    }
    return { prepare: stmt };
  }
  const pgEnv = { DB: pgDB(), SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' };
  const pgReq = new Request('https://atlasrental.io/api/data/bookings', { method: 'GET', headers: { 'Content-Type': 'application/json', 'Cookie': 'atlas_sid=' + SID, 'X-CSRF-Token': CSRF, 'Origin': 'https://atlasrental.io' } });
  const pr = await worker.fetch(pgReq, pgEnv, ctx);
  ok(pr.status === 200, '#276: payment_gate_enabled unset (default OFF) -> a past_due tenant is unaffected, GET /api/data/bookings -> 200 (got ' + pr.status + ')');
}

// 8) #274 visit tracking: POST /api/visit-ping records page_views + active_now under the reserved '_site' id
// (never a real tenant); GET /api/admin/overview then surfaces that as a numeric active_now live-presence count.
// waitUntil is captured (not the shared no-op ctx above) so the deferred, best-effort write can be awaited before
// asserting on it -- same pattern test/routes.mjs already uses for other waitUntil-deferred writes.
{
  const pv = new Map(), an = new Map();
  function vpingDB() {
    function stmt(sql) {
      let a = [];
      const api = {
        bind: (...x) => { a = x; return api; },
        first: async () => {
          if (/FROM sqlite_master/.test(sql)) return { n: 25 };
          if (/FROM rate_limits/.test(sql)) return null;      // always "first time" -> rateLimit allows
          if (/FROM platform_config/.test(sql)) return null;
          if (/COUNT\(\*\) AS c FROM active_now WHERE last_at>\?/.test(sql)) { let c = 0; an.forEach(function (row) { if (row.last_at > a[0]) c++; }); return { c: c }; }
          if (/AS c FROM/.test(sql)) return { c: 0 };          // every other admin-overview aggregate (revenue/signups/etc.) -- not under test here, but must not be null (the handler dereferences .c directly on a few of these)
          return null;
        },
        all: async () => ({ results: [] }),
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
  const vpEnv = { DB: vpingDB(), ADMIN_TOKEN: 'test-token', SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' };
  let waited = [];
  const vpCtx = { waitUntil(p) { waited.push(p); }, passThroughOnException() {} };

  let vr = await worker.fetch(mkReq('POST', '/api/visit-ping', { body: { src: 'site', sid: 'sid_smoke_1' } }), vpEnv, vpCtx);
  ok(vr.status === 204, 'POST /api/visit-ping -> 204 (got ' + vr.status + ')');
  await Promise.all(waited); waited.length = 0;
  ok(pv.get('_site') === 1, 'visit-ping recorded page_views under the reserved _site id, never a real tenant (got ' + JSON.stringify([...pv]) + ')');
  ok(an.has('sid_smoke_1'), 'visit-ping recorded an active_now row for the sid (got ' + JSON.stringify([...an]) + ')');

  vr = await worker.fetch(mkReq('GET', '/api/admin/overview', { headers: H }), vpEnv, ctx);
  let vj = await vr.json();
  ok(vr.status === 200 && vj.ok === true, 'GET /api/admin/overview -> 200 ok:true (got ' + vr.status + ')');
  ok(typeof vj.active_now === 'number' && vj.active_now === 1, 'overview.active_now is a number reflecting the live sid visit-ping recorded (got ' + JSON.stringify(vj.active_now) + ')');
}

if (fails) { console.error('\nSMOKE FAILED (' + fails + ' assertion' + (fails > 1 ? 's' : '') + ') -- deploy blocked.'); process.exit(1); }
console.log('\nSMOKE PASSED -- safe to deploy.');
