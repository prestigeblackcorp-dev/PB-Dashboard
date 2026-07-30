// Real-D1 test harness. A D1-compatible adapter backed by node:sqlite, loaded from schema.sql + the worker's own
// migrations (ensurePlatformSchema), driving the ACTUAL worker routes against a real database. Because it runs real
// SQLite, the mock can NEVER drift from the SQL -- the drift in the hand-written regex mocks is exactly what silently
// blocked deploys for days (see commit 23c756f). This is where schema-batch / CAS-monotonic / RTBF become provable.
//
// Run: node --experimental-sqlite test/d1harness.mjs        (needs Node >= 22.5 for node:sqlite)
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import worker, { ensurePlatformSchema, _bkPatch, _schemaVer, __resetSchemaReady } from '../worker.js';

const SCHEMA = readFileSync(import.meta.dirname + '/../schema.sql', 'utf8');

// ---- D1 adapter over node:sqlite (matches env.DB.prepare().bind().run()/first()/all() + .batch()) ----
function makeDB() {
  const db = new DatabaseSync(':memory:');
  db.exec(SCHEMA);
  db.exec('PRAGMA foreign_keys=OFF');   // schema.sql sets it ON, but Cloudflare D1 does NOT enforce FKs -- match prod
  const coerce = (a) => a.map((x) => (x === undefined || x === null) ? null : (x === true ? 1 : (x === false ? 0 : (typeof x === 'bigint' ? Number(x) : x))));
  const fix = (row) => { if (row == null) return row; for (const k in row) if (typeof row[k] === 'bigint') row[k] = Number(row[k]); return row; };
  return {
    _db: db,
    prepare(sql) {
      let args = [];
      const s = {
        bind(...a) { args = coerce(a); return s; },
        async run() { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: Number(r.changes) || 0, last_row_id: Number(r.lastInsertRowid) || 0 } }; },
        async first(col) { const row = db.prepare(sql).get(...args); if (row == null) return null; fix(row); return (col != null) ? row[col] : row; },
        async all() { const rows = db.prepare(sql).all(...args).map(fix); return { results: rows, success: true, meta: {} }; },
      };
      return s;
    },
    async batch(stmts) { const out = []; db.exec('BEGIN'); try { for (const st of stmts) out.push(await st.run()); db.exec('COMMIT'); } catch (e) { try { db.exec('ROLLBACK'); } catch (_) {} throw e; } return out; },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}

function makeEnv() {
  return { DB: makeDB(), ADMIN_TOKEN: 'test-admin-token', SESSION_KEY: 'test-session-key-not-real', ENC_KEY: Buffer.alloc(32, 7).toString('base64'), OWNER_EMAIL: 'owner@x.com', OWNER_SETUP_TOKEN: 'setup-tok' };
}
function mkReq(method, path, opts = {}) {
  const headers = Object.assign({ 'content-type': 'application/json', origin: 'https://atlasrental.io' }, opts.headers || {});
  const lc = {}; for (const k in headers) lc[k.toLowerCase()] = headers[k];
  const body = opts.body;
  return { method, url: 'https://atlasrental.io' + path, headers: { get: (k) => { const v = lc[String(k).toLowerCase()]; return v === undefined ? null : v; } }, json: async () => (body || {}), text: async () => (typeof body === 'string' ? body : JSON.stringify(body || {})), cf: { country: 'US' } };
}
const ctx = { waitUntil: (p) => { if (p && p.catch) p.catch(() => {}); } };

let PASS = 0, FAIL = 0;
function ok(name, cond, extra) { if (cond) { PASS++; console.log('  PASS ' + name); } else { FAIL++; console.log('  FAIL ' + name + (extra ? ' -- ' + extra : '')); } }

ok('worker module loaded with fetch handler', worker && typeof worker.fetch === 'function');

const env = makeEnv();
await ensurePlatformSchema(env);   // warm up: apply the ALTER migrations (tz + ~48 others) so a fresh DB matches a live D1

let r = await worker.fetch(mkReq('GET', '/api/health'), env, ctx);
let j = await r.json();
ok('GET /api/health -> 200 ok:true (real sqlite)', r.status === 200 && j.ok === true, 'status=' + r.status);

// real signup writes tenant+user into real sqlite (exercises the real INSERTs incl the tz column the regex mock never checked)
r = await worker.fetch(mkReq('POST', '/api/auth/signup', { body: { email: 'harness@x.com', password: 'correcthorsebatterystaple', business: 'Harness Co' } }), env, ctx);
j = await r.json();
ok('signup -> 200 ok + tenant_id (real INSERT into tenants+users)', r.status === 200 && j.ok === true && !!j.tenant_id, 'status=' + r.status + ' ' + JSON.stringify(j).slice(0, 140));
ok('real DB has 1 tenant row after signup', Number(env.DB._db.prepare('SELECT COUNT(*) c FROM tenants').get().c) === 1);
ok('ensurePlatformSchema created platform_config in real sqlite', !!env.DB._db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='platform_config'").get());

// rate-limit conditional UPDATE (WHERE count<?) -- the exact behavior the regex mock could not emulate
env.DB._db.exec("INSERT INTO rate_limits (bucket,count,window_start) VALUES ('t:x',1," + 1 + ")");
const rl1 = await env.DB.prepare('UPDATE rate_limits SET count=count+1 WHERE bucket=? AND count<?').bind('t:x', 2).run();
const rl2 = await env.DB.prepare('UPDATE rate_limits SET count=count+1 WHERE bucket=? AND count<?').bind('t:x', 2).run();
ok('rate_limit conditional UPDATE: 1st increments (changes=1)', rl1.meta.changes === 1);
ok('rate_limit conditional UPDATE: 2nd at cap refused (changes=0)', rl2.meta.changes === 0, 'changes=' + rl2.meta.changes);

// CAS updated_at IS ? -- stale-value write must fail (the regex mock used its own now(), hiding same-ms ABA)
env.DB._db.exec("INSERT INTO bookings (id,tenant_id,customer_id,asset_id,starts,ends,status,revenue_cents,data,created_at,updated_at) VALUES ('BK1','T1','C1','A',1,2,'confirmed',100,'{}',1,5000)");
const cas1 = await env.DB.prepare('UPDATE bookings SET revenue_cents=?, updated_at=? WHERE id=? AND tenant_id=? AND updated_at IS ?').bind(200, 6000, 'BK1', 'T1', 5000).run();
const casStale = await env.DB.prepare('UPDATE bookings SET revenue_cents=?, updated_at=? WHERE id=? AND tenant_id=? AND updated_at IS ?').bind(999, 7000, 'BK1', 'T1', 5000).run();
ok('CAS: matching updated_at commits (changes=1)', cas1.meta.changes === 1);
ok('CAS: STALE updated_at rejected (changes=0)', casStale.meta.changes === 0, 'changes=' + casStale.meta.changes);

// RTBF erase END-TO-END through the real route + real DB (proves the shipped endpoint, not just the patch logic)
const tid = env.DB._db.prepare('SELECT id FROM tenants LIMIT 1').get().id;
const sess = env.DB._db.prepare('SELECT id, csrf FROM sessions WHERE tenant_id=? ORDER BY created_at DESC LIMIT 1').get(tid);
if (sess) {
  await env.DB.prepare('INSERT INTO customers (id,tenant_id,name,email,phone,data,created_at) VALUES (?,?,?,?,?,?,?)').bind('CUS1', tid, 'Jane Doe', 'jane@x.com', '555-1212', '{}', 1).run();
  await env.DB.prepare('INSERT INTO bookings (id,tenant_id,customer_id,asset_id,starts,ends,status,revenue_cents,data,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)').bind('BKX', tid, 'CUS1', 'A', 1, 2, 'confirmed', 45000, JSON.stringify({ cust: 'Jane Doe', custEmail: 'jane@x.com', custPhone: '555-1212', quote: { totalCents: 45000 }, paid: { reserve: { amountCents: 10000 } } }), 1, 100).run();
  await env.DB.prepare('INSERT INTO signatures (id,tenant_id,booking_id,signer_name,signed_at) VALUES (?,?,?,?,?)').bind('SIG1', tid, 'BKX', 'Jane Doe', 1).run();
  r = await worker.fetch(mkReq('POST', '/api/customers/CUS1/erase', { headers: { cookie: 'atlas_sid=' + sess.id, 'x-csrf-token': sess.csrf }, body: {} }), env, ctx);
  j = await r.json();
  ok('RTBF erase route -> 200 ok (real auth + real DB)', r.status === 200 && j.ok === true, 'status=' + r.status + ' ' + JSON.stringify(j).slice(0, 140));
  const c = env.DB._db.prepare("SELECT name,email FROM customers WHERE id='CUS1'").get();
  const bkRow = env.DB._db.prepare("SELECT data,revenue_cents FROM bookings WHERE id='BKX'").get();
  const b = JSON.parse(bkRow.data);
  const sig = env.DB._db.prepare("SELECT signer_name FROM signatures WHERE id='SIG1'").get().signer_name;
  ok('RTBF: customer PII redacted in real DB', c.name === '[erased]' && c.email === '', JSON.stringify(c));
  ok('RTBF: booking PII redacted in real DB', b.custEmail === '' && b.cust === '[erased]' && b.custPhone === '');
  ok('RTBF: booking financials KEPT (revenue + quote + paid)', b.quote.totalCents === 45000 && Number(bkRow.revenue_cents) === 45000 && b.paid.reserve.amountCents === 10000);
  ok('RTBF: signature signer_name redacted', sig === '[erased]');
} else { ok('RTBF setup: found a session', false, 'no session from signup'); }

// signature-fabrication: the generic booking write drops a "signed" claim unless a real signatures row backs it -- but keeps it when one does.
if (sess) {
  const H = { cookie: 'atlas_sid=' + sess.id, 'x-csrf-token': sess.csrf };
  // (a) FABRICATE on create: no signatures row -> portal.signedAt must be stripped
  await worker.fetch(mkReq('POST', '/api/data/bookings', { headers: H, body: { id: 'FAKEBK', asset_id: 'A', starts: 1, ends: 2, status: 'confirmed', data: { cust: 'X', portal: { signedAt: 999999, signerName: 'Forged' }, quote: { totalCents: 100 } } } }), env, ctx);
  const fbRow = env.DB._db.prepare("SELECT data FROM bookings WHERE id='FAKEBK'").get();
  const fb = fbRow ? JSON.parse(fbRow.data) : { portal: { signedAt: 'MISSING' } };
  ok('sig-fab: unbacked signedAt STRIPPED on create (no signatures row)', !fb.portal.signedAt && !fb.portal.signerName, JSON.stringify(fb.portal));
  // (b) LEGIT: a booking WITH a real signatures row keeps signedAt on update
  await env.DB.prepare("INSERT INTO bookings (id,tenant_id,customer_id,asset_id,starts,ends,status,revenue_cents,data,portal_token,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)").bind('REALBK', tid, 'C', 'A', 1, 2, 'confirmed', 100, '{}', 'ptok', 1, 1).run();
  await env.DB.prepare("INSERT INTO signatures (id,tenant_id,booking_id,signer_name,signed_at) VALUES (?,?,?,?,?)").bind('SIGR', tid, 'REALBK', 'Real Signer', 123).run();
  await worker.fetch(mkReq('PUT', '/api/data/bookings/REALBK', { headers: H, body: { data: { cust: 'Y', portal: { signedAt: 555, signerName: 'Real Signer' } } } }), env, ctx);
  const rb = JSON.parse(env.DB._db.prepare("SELECT data FROM bookings WHERE id='REALBK'").get().data);
  ok('sig-fab: signedAt KEPT when a real signatures row backs it (legit sign not broken)', rb.portal.signedAt === 555, JSON.stringify(rb.portal));
}

// CAS-monotonic: updated_at must strictly advance even when the wall clock is frozen (the same-ms ABA where two writers
// read the same stamp, both write it back unchanged, and BOTH pass "WHERE updated_at IS ?"). Fails on the bug, passes on the fix.
{
  const env2 = makeEnv(); await ensurePlatformSchema(env2);
  const Tm = 5000000;
  await env2.DB.prepare('INSERT INTO bookings (id,tenant_id,customer_id,asset_id,starts,ends,status,revenue_cents,data,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)').bind('BKM', 'TENM', 'C', 'A', 1, 2, 'confirmed', 100, '{}', 1, Tm).run();
  const realNow = Date.now; globalThis.Date.now = () => Tm;   // freeze the clock to the row's current updated_at (same ms)
  await _bkPatch(env2, 'BKM', 'TENM', function (fd) { fd.m = 1; });
  globalThis.Date.now = realNow;
  const uaM = env2.DB._db.prepare("SELECT updated_at FROM bookings WHERE id='BKM'").get().updated_at;
  ok('CAS-monotonic: updated_at advances even at same-ms clock (ABA closed)', uaM === Tm + 1, 'updated_at=' + uaM + ' (the bug leaves it ' + Tm + ')');
}

// schema-gate: a cold isolate whose DB is already at this schema version SKIPS the ~138 CREATE/INDEX/ALTER statements;
// a version mismatch (a schema edit changes the source-hash version) RE-RUNS them. Proven WITHOUT a call counter by
// dropping a table and checking whether the gated pass recreates it.
ok('schema version stamped in platform_config after warmup', (await env.DB.prepare("SELECT v FROM platform_config WHERE k='_schema_ver'").first('v')) === _schemaVer());
__resetSchemaReady();
env.DB._db.exec('DROP TABLE platform_feedback');
await ensurePlatformSchema(env);   // version still matches -> SKIP -> the dropped table must NOT be recreated
ok('version-gate SKIPS on matching version (dropped table NOT recreated -> ~138 statements skipped)', !env.DB._db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='platform_feedback'").get());
__resetSchemaReady();
env.DB._db.exec("UPDATE platform_config SET v='STALE' WHERE k='_schema_ver'");
await ensurePlatformSchema(env);   // version mismatch -> RE-RUN -> table recreated (a schema change auto-invalidates)
ok('version-gate RE-RUNS on version mismatch (table recreated -> auto-invalidation works)', !!env.DB._db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='platform_feedback'").get());

console.log('\nD1 HARNESS: PASS=' + PASS + ' FAIL=' + FAIL + (FAIL ? '  -- FAILURES' : '  -- all green'));
process.exit(FAIL ? 1 : 0);
