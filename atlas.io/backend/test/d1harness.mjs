// Real-D1 test harness. A D1-compatible adapter backed by node:sqlite, loaded from schema.sql + the worker's own
// migrations (ensurePlatformSchema), driving the ACTUAL worker routes against a real database. Because it runs real
// SQLite, the mock can NEVER drift from the SQL -- the drift in the hand-written regex mocks is exactly what silently
// blocked deploys for days (see commit 23c756f). This is where schema-batch / CAS-monotonic / RTBF become provable.
//
// Run: node --experimental-sqlite test/d1harness.mjs        (needs Node >= 22.5 for node:sqlite)
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import worker, { ensurePlatformSchema, _bkPatch, _schemaVer, __resetSchemaReady, rateLimit, sendSms, sendEmail, _qbSyncBooking, _xeroSyncBooking, _paypalCreateOrder, _paypalCapture, _paypalCreditBooking, _squareCreateCheckout, _squareVerifyPaid, _squareCreditBooking, _trackerFetch, TRK_PROVIDERS, _b32decode, _totpAt, _creditOp, _runDunning } from '../worker.js';

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

// ---- rateLimit() single-hop UPSERT...RETURNING (real SQLite): exactly `max` calls per window pass, then refused; a
// rolled-over window allows again. Proves the new one-statement limiter against a real DB (the money/auth-critical gate). ----
{
  const envR = makeEnv(); await ensurePlatformSchema(envR);
  let allowed = 0;
  for (let i = 0; i < 6; i++) { if (await rateLimit(envR, 'rl_test', 3, 60000)) allowed++; }
  ok('rateLimit: exactly max(3) calls allowed in a window, the rest refused', allowed === 3, 'allowed=' + allowed);
  const cRow = envR.DB._db.prepare("SELECT count FROM rate_limits WHERE bucket='rl_test'").get();
  ok('rateLimit: single row, count advanced past the cap (one UPSERT per call, no 2nd statement)', cRow && Number(cRow.count) === 6, 'count=' + (cRow && cRow.count));
  envR.DB._db.prepare("UPDATE rate_limits SET window_start=1 WHERE bucket='rl_test'").run();   // force the window to have expired
  ok('rateLimit: allows again after the window rolls over (reset branch)', (await rateLimit(envR, 'rl_test', 3, 60000)) === true);
  const rRow = envR.DB._db.prepare("SELECT count FROM rate_limits WHERE bucket='rl_test'").get();
  ok('rateLimit: window reset dropped count back to 1', rRow && Number(rRow.count) === 1, 'count=' + (rRow && rRow.count));
}

// ---- MONEY PATH (real SQLite): a signature-verified Stripe webhook credits revenue correctly, and a dual-fire / replay is
// idempotent (never double-counts). This is the exact webhook CAS + revenue math the regex mocks (run()->{changes:1}) can't exercise.
{
  const envP = makeEnv(); await ensurePlatformSchema(envP);
  envP.STRIPE_WEBHOOK_SECRET = 'whsec_harness';
  const _realFetch = globalThis.fetch;
  globalThis.fetch = () => Promise.resolve({ ok: false, status: 0, headers: { get: () => null }, text: async () => '', json: async () => ({}) });   // stub network (receipt email) so no throw/real request
  await envP.DB.prepare("INSERT INTO tenants (id,name,created_at,updated_at) VALUES (?,?,?,?)").bind('TENP', 'Pay Co', 1, 1).run();
  // a confirmed booking carrying a G5 cash-ESTIMATE (revenue_cents == quote total, no prior online payment)
  await envP.DB.prepare("INSERT INTO bookings (id,tenant_id,customer_id,asset_id,starts,ends,status,revenue_cents,data,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
    .bind('BKP', 'TENP', 'C', 'A', 1, 2, 'confirmed', 50000, JSON.stringify({ quote: { totalCents: 50000 }, paid: {} }), 1, 1000).run();
  const evt = { id: 'evt_pay1', type: 'payment_intent.succeeded', data: { object: { id: 'pi_h1', object: 'payment_intent', amount: 50000, payment_intent: 'pi_h1', metadata: { booking: 'BKP', tenant: 'TENP', kind: 'reserve' } } } };
  const body = JSON.stringify(evt);
  const ts = Math.floor(Date.now() / 1000);
  const mkSig = () => 't=' + ts + ',v1=' + createHmac('sha256', 'whsec_harness').update(ts + '.' + body).digest('hex');
  // (a) first delivery -> credits the reserve, settles the G5 estimate (REPLACE not stack): revenue stays 50000
  const rp = await worker.fetch(mkReq('POST', '/api/stripe/webhook', { headers: { 'stripe-signature': mkSig() }, body: body }), envP, ctx);
  const jp = await rp.json();
  const row1 = envP.DB._db.prepare("SELECT revenue_cents,data FROM bookings WHERE id='BKP'").get();
  const d1 = JSON.parse(row1.data);
  ok('money: signature-verified webhook accepted (200)', rp.status === 200 && jp && jp.ok !== false, 'status=' + rp.status + ' ' + JSON.stringify(jp).slice(0, 80));
  ok('money: reserve recorded in d.paid (real DB write)', !!(d1.paid && d1.paid.reserve && d1.paid.reserve.amountCents === 50000), JSON.stringify(d1.paid));
  ok('money: revenue settled to 50000 (G5 estimate REPLACED, not stacked to 100000)', Number(row1.revenue_cents) === 50000, 'revenue_cents=' + row1.revenue_cents);
  // (b) DUAL-FIRE / replay of the SAME event -> idempotent: revenue must NOT double
  const rp2 = await worker.fetch(mkReq('POST', '/api/stripe/webhook', { headers: { 'stripe-signature': mkSig() }, body: body }), envP, ctx);
  const row2 = envP.DB._db.prepare("SELECT revenue_cents FROM bookings WHERE id='BKP'").get();
  ok('money: replayed webhook stays 200 (idempotent ACK)', rp2.status === 200, 'status=' + rp2.status);
  ok('money: DUAL-FIRE did NOT double-count revenue (still 50000, not 100000)', Number(row2.revenue_cents) === 50000, 'revenue_cents=' + row2.revenue_cents);
  // (c) a tampered/bad signature can never credit revenue
  const rp3 = await worker.fetch(mkReq('POST', '/api/stripe/webhook', { headers: { 'stripe-signature': 't=' + ts + ',v1=deadbeef' }, body: body }), envP, ctx);
  ok('money: bad Stripe signature -> 400 (unsigned event rejected)', rp3.status === 400, 'status=' + rp3.status);
  globalThis.fetch = _realFetch;
}

// ---- INTEGRATIONS (BYO-sender, "make it real"): a tenant's OWN Twilio/Resend creds are stored ENCRYPTED via the real
// owner-gated route and are actually USED by sendSms/sendEmail; with no tenant integration, sends fall back to the platform. ----
if (sess) {
  const tidP = env.DB._db.prepare('SELECT id FROM tenants LIMIT 1').get().id;
  const HI = { cookie: 'atlas_sid=' + sess.id, 'x-csrf-token': sess.csrf };
  await worker.fetch(mkReq('POST', '/api/integrations/connect', { headers: HI, body: { provider: 'twilio', secret: 'TENANT_TWILIO_TOKEN', meta: { sid: 'ACtenant', from: '+15550001111' } } }), env, ctx);
  await worker.fetch(mkReq('POST', '/api/integrations/connect', { headers: HI, body: { provider: 'resend', secret: 're_tenantkey', meta: { from: 'noreply@tenant.com' } } }), env, ctx);
  const twRow = env.DB._db.prepare("SELECT secret_enc FROM integrations WHERE tenant_id=? AND provider='twilio'").get(tidP);
  ok('integrations: tenant Twilio token stored ENCRYPTED (route encrypts; not plaintext at rest)', !!(twRow && twRow.secret_enc) && String(twRow.secret_enc).indexOf('TENANT_TWILIO_TOKEN') < 0, 'row=' + JSON.stringify(twRow));
  const _rf = globalThis.fetch; let _cap = [];
  globalThis.fetch = (url, opts) => { _cap.push({ url: String(url), opts: opts || {} }); return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, json: async () => ({ sid: 'SM1', id: 'em1' }), text: async () => '' }); };
  env.TWILIO_SID = 'ACplatform'; env.TWILIO_TOKEN = 'PLATTOKEN'; env.TWILIO_FROM = '+15559999999'; env.RESEND_KEY = 're_platform'; env.MAIL_FROM = 'hello@atlasrental.io';
  _cap = []; await sendSms(env, tidP, { to: '+15551234567', body: 'hi' });
  const sReq = _cap.find(c => c.url.indexOf('api.twilio.com') >= 0);
  ok('integrations: sendSms used the TENANT Twilio account (URL carries ACtenant, not ACplatform)', !!sReq && sReq.url.indexOf('ACtenant') >= 0, sReq && sReq.url);
  ok('integrations: sendSms authed with the TENANT token (Basic ACtenant:token)', !!sReq && String((sReq.opts.headers || {}).Authorization || '').indexOf(btoa('ACtenant:TENANT_TWILIO_TOKEN')) >= 0);
  _cap = []; await sendSms(env, 'TEN_NONE', { to: '+15551234567', body: 'hi' });
  const sReq2 = _cap.find(c => c.url.indexOf('api.twilio.com') >= 0);
  ok('integrations: sendSms FALLS BACK to the platform Twilio when the tenant has none', !!sReq2 && sReq2.url.indexOf('ACplatform') >= 0, sReq2 && sReq2.url);
  _cap = []; await sendEmail(env, { tenant: tidP, to: 'x@y.com', subject: 's', html: 'h', transactional: true });
  const eReq = _cap.find(c => c.url.indexOf('api.resend.com') >= 0);
  ok('integrations: sendEmail authed with the TENANT Resend key', !!eReq && String((eReq.opts.headers || {}).Authorization || '').indexOf('re_tenantkey') >= 0);
  ok('integrations: sendEmail sent from the TENANT verified sender', !!eReq && String(eReq.opts.body || '').indexOf('noreply@tenant.com') >= 0);
  _cap = []; await sendEmail(env, { tenant: 'TEN_NONE', to: 'x@y.com', subject: 's', html: 'h', transactional: true });
  const eReq2 = _cap.find(c => c.url.indexOf('api.resend.com') >= 0);
  ok('integrations: sendEmail FALLS BACK to the platform Resend key when the tenant has none', !!eReq2 && String((eReq2.opts.headers || {}).Authorization || '').indexOf('re_platform') >= 0);
  globalThis.fetch = _rf;
}

// ---- QUICKBOOKS ONLINE (per-tenant OAuth accounting sync, "make it real"): (a) connect is HONEST when the Intuit app is
// unconfigured; (b) the callback exchanges the code with Basic auth + stores tokens ENCRYPTED per tenant (+ realmId); (c)
// _qbSyncBooking posts a SalesReceipt carrying the tenant's own Bearer token + realmId + paid total; (d) a 2nd sync of the
// same booking is IDEMPOTENT (no double-post). All Intuit endpoints are mocked; globalThis.fetch is restored after. ----
{
  const envQ = makeEnv(); __resetSchemaReady(); await ensurePlatformSchema(envQ);   // fresh DB -> run the FULL migration pass (adds the ALTER-only columns signup INSERTs); the module _pReady flag would otherwise skip them
  await worker.fetch(mkReq('POST', '/api/auth/signup', { body: { email: 'qb@x.com', password: 'correcthorsebatterystaple', business: 'QB Co' } }), envQ, ctx);
  const tidQ = envQ.DB._db.prepare('SELECT id FROM tenants LIMIT 1').get().id;
  const sQ = envQ.DB._db.prepare('SELECT id,csrf FROM sessions WHERE tenant_id=? ORDER BY created_at DESC LIMIT 1').get(tidQ);
  const HQ = { cookie: 'atlas_sid=' + sQ.id, 'x-csrf-token': sQ.csrf };

  // (a) connect with NO Intuit app configured -> honest not_configured (never a fake URL)
  let rq = await worker.fetch(mkReq('POST', '/api/integrations/quickbooks/connect', { headers: HQ, body: {} }), envQ, ctx);
  let jq = await rq.json();
  ok('qbo(a): connect -> not_configured when QBO_CLIENT_ID unset (honest)', jq && jq.ok === false && jq.reason === 'not_configured', JSON.stringify(jq).slice(0, 120));

  // owner registers the Intuit app (sets the Cloudflare secrets)
  envQ.QBO_CLIENT_ID = 'ABCclientid'; envQ.QBO_CLIENT_SECRET = 'SECRETxyz';

  rq = await worker.fetch(mkReq('POST', '/api/integrations/quickbooks/connect', { headers: HQ, body: {} }), envQ, ctx);
  jq = await rq.json();
  ok('qbo(a): connect (configured) -> real Intuit authorize URL bound to a state', !!(jq && jq.ok === true && typeof jq.url === 'string' && jq.url.indexOf('appcenter.intuit.com/connect/oauth2') >= 0 && jq.url.indexOf('client_id=ABCclientid') >= 0 && jq.url.indexOf('com.intuit.quickbooks.accounting') >= 0), (jq && jq.url ? jq.url : JSON.stringify(jq)).slice(0, 180));
  const stateQ = jq && jq.url ? new URL(jq.url).searchParams.get('state') : '';
  ok('qbo(a): connect stored a one-time state in platform_config (oauth:<state>)', !!(stateQ && envQ.DB._db.prepare('SELECT v FROM platform_config WHERE k=?').get('oauth:' + stateQ)));

  // mock the Intuit endpoints (token exchange, customer query/create, salesreceipt)
  const _rfQ = globalThis.fetch; let _capQ = [];
  const _resp = (obj) => Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, json: async () => obj, text: async () => '' });
  globalThis.fetch = (u, o) => {
    const su = String(u); _capQ.push({ url: su, opts: o || {} });
    if (su.indexOf('oauth.platform.intuit.com') >= 0) return _resp({ access_token: 'ACCESS-TOK-QB', refresh_token: 'REFRESH-TOK-QB', expires_in: 3600, token_type: 'bearer' });
    if (su.indexOf('/query?') >= 0) return _resp({ QueryResponse: {} });                 // customer lookup -> none found
    if (su.indexOf('/customer') >= 0) return _resp({ Customer: { Id: '77', DisplayName: 'Jane Doe' } });
    if (su.indexOf('/salesreceipt') >= 0) return _resp({ SalesReceipt: { Id: 'SR-1001' } });
    return Promise.resolve({ ok: false, status: 404, headers: { get: () => null }, json: async () => ({}), text: async () => '' });
  };

  // (b) callback exchanges the code + stores ENCRYPTED tokens + realmId, then 302s back
  const cbUrl = '/api/integrations/quickbooks/callback?code=AUTHCODE123&state=' + encodeURIComponent(stateQ) + '&realmId=REALM-42';
  const rcb = await worker.fetch(mkReq('GET', cbUrl), envQ, ctx);
  ok('qbo(b): callback 302-redirects back to the dashboard', rcb.status === 302, 'status=' + rcb.status);
  const tokReq = _capQ.find(c => c.url.indexOf('oauth.platform.intuit.com') >= 0);
  ok('qbo(b): callback exchanged the code at the Intuit token endpoint with Basic auth', !!tokReq && String((tokReq.opts.headers || {}).Authorization || '') === ('Basic ' + Buffer.from('ABCclientid:SECRETxyz').toString('base64')), tokReq && JSON.stringify(tokReq.opts.headers));
  const intRow = envQ.DB._db.prepare("SELECT secret_enc, meta FROM integrations WHERE tenant_id=? AND provider='quickbooks'").get(tidQ);
  ok('qbo(b): tokens stored ENCRYPTED at rest (ciphertext, not the plaintext access/refresh token)', !!(intRow && intRow.secret_enc) && String(intRow.secret_enc).indexOf('ACCESS-TOK-QB') < 0 && String(intRow.secret_enc).indexOf('REFRESH-TOK-QB') < 0, 'enc=' + (intRow && String(intRow.secret_enc).slice(0, 24)));
  ok('qbo(b): realmId stored in meta', !!(intRow && String(intRow.meta).indexOf('REALM-42') >= 0), intRow && intRow.meta);
  const stRow = envQ.DB._db.prepare('SELECT v FROM platform_config WHERE k=?').get('oauth:' + stateQ);
  ok('qbo(b): one-time state CONSUMED after callback (no replay)', !stRow || !stRow.v, 'v=' + (stRow && stRow.v));

  // (c) _qbSyncBooking posts a SalesReceipt carrying the tenant Bearer token + realmId + paid total
  await envQ.DB.prepare('INSERT INTO bookings (id,tenant_id,customer_id,asset_id,starts,ends,status,revenue_cents,data,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
    .bind('BKQ', tidQ, 'C', 'A', 1, 2, 'confirmed', 50000, JSON.stringify({ custName: 'Jane Doe', asset: 'Model X', quote: { totalCents: 50000 }, paid: { reserve: { amountCents: 50000 } } }), 1, 1000).run();
  _capQ = [];
  const bkObj = Object.assign({ id: 'BKQ' }, JSON.parse(envQ.DB._db.prepare("SELECT data FROM bookings WHERE id='BKQ'").get().data));
  await _qbSyncBooking(envQ, tidQ, bkObj);
  const srReq = _capQ.find(c => c.url.indexOf('/salesreceipt') >= 0);
  ok('qbo(c): _qbSyncBooking POSTed a SalesReceipt', !!srReq && srReq.opts.method === 'POST', srReq && srReq.url);
  ok('qbo(c): SalesReceipt carried the tenant OWN Bearer access token', !!srReq && String((srReq.opts.headers || {}).Authorization || '') === 'Bearer ACCESS-TOK-QB', srReq && JSON.stringify(srReq.opts.headers));
  ok('qbo(c): SalesReceipt POSTed to the tenant realmId company', !!srReq && srReq.url.indexOf('/v3/company/REALM-42/') >= 0, srReq && srReq.url);
  const srBody = srReq ? JSON.parse(srReq.opts.body || '{}') : {};
  ok('qbo(c): SalesReceipt line carries the paid total ($500.00) + customer ref', !!(srBody.Line && srBody.Line[0] && srBody.Line[0].Amount === 500 && srBody.CustomerRef && srBody.CustomerRef.value === '77'), JSON.stringify(srBody.Line && srBody.Line[0]) + ' cust=' + JSON.stringify(srBody.CustomerRef));
  const bkAfter = JSON.parse(envQ.DB._db.prepare("SELECT data FROM bookings WHERE id='BKQ'").get().data);
  ok('qbo(c): booking stamped qbSyncedAt + qbRef after a successful post', !!bkAfter.qbSyncedAt && bkAfter.qbRef === 'SR-1001', JSON.stringify({ at: bkAfter.qbSyncedAt, ref: bkAfter.qbRef }));

  // (d) a 2nd sync of the SAME booking must NOT double-post (idempotent by the qbSyncedAt marker)
  _capQ = [];
  await _qbSyncBooking(envQ, tidQ, bkObj);
  const srReq2 = _capQ.find(c => c.url.indexOf('/salesreceipt') >= 0);
  ok('qbo(d): 2nd sync is IDEMPOTENT (no duplicate SalesReceipt POST)', !srReq2, srReq2 && srReq2.url);

  globalThis.fetch = _rfQ;
}

// ---- XERO (per-tenant OAuth accounting sync -- the fast-follow TWIN of QuickBooks, "make it real"): (a) connect is HONEST
// when the Xero app is unconfigured; (b) the callback exchanges the code with Basic auth, GETs /connections for the org
// tenantId, and stores tokens ENCRYPTED per tenant (+ xeroTenant); (c) _xeroSyncBooking posts a Contact + an AUTHORISED
// ACCREC Invoice carrying the tenant's own Bearer token + the Xero-tenant-id header + paid total; (d) a 2nd sync of the same
// booking is IDEMPOTENT (no double-post). All Xero endpoints are mocked; globalThis.fetch is restored after. ----
{
  const envX = makeEnv(); __resetSchemaReady(); await ensurePlatformSchema(envX);   // fresh DB -> full migration pass
  await worker.fetch(mkReq('POST', '/api/auth/signup', { body: { email: 'xero@x.com', password: 'correcthorsebatterystaple', business: 'Xero Co' } }), envX, ctx);
  const tidX = envX.DB._db.prepare('SELECT id FROM tenants LIMIT 1').get().id;
  const sX = envX.DB._db.prepare('SELECT id,csrf FROM sessions WHERE tenant_id=? ORDER BY created_at DESC LIMIT 1').get(tidX);
  const HX = { cookie: 'atlas_sid=' + sX.id, 'x-csrf-token': sX.csrf };

  // (a) connect with NO Xero app configured -> honest not_configured (never a fake URL)
  let rx = await worker.fetch(mkReq('POST', '/api/integrations/xero/connect', { headers: HX, body: {} }), envX, ctx);
  let jx = await rx.json();
  ok('xero(a): connect -> not_configured when XERO_CLIENT_ID unset (honest)', jx && jx.ok === false && jx.reason === 'not_configured', JSON.stringify(jx).slice(0, 120));

  // owner registers the Xero app (sets the Cloudflare secrets)
  envX.XERO_CLIENT_ID = 'XEROclientid'; envX.XERO_CLIENT_SECRET = 'XEROsecret';

  rx = await worker.fetch(mkReq('POST', '/api/integrations/xero/connect', { headers: HX, body: {} }), envX, ctx);
  jx = await rx.json();
  ok('xero(a): connect (configured) -> real Xero authorize URL bound to a state', !!(jx && jx.ok === true && typeof jx.url === 'string' && jx.url.indexOf('login.xero.com/identity/connect/authorize') >= 0 && jx.url.indexOf('client_id=XEROclientid') >= 0 && jx.url.indexOf('accounting.transactions') >= 0 && jx.url.indexOf('offline_access') >= 0), (jx && jx.url ? jx.url : JSON.stringify(jx)).slice(0, 200));
  const stateX = jx && jx.url ? new URL(jx.url).searchParams.get('state') : '';
  ok('xero(a): connect stored a one-time state in platform_config (oauth:<state>)', !!(stateX && envX.DB._db.prepare('SELECT v FROM platform_config WHERE k=?').get('oauth:' + stateX)));

  // mock the Xero endpoints (token exchange, connections, contact query/create, invoice)
  const _rfX = globalThis.fetch; let _capX = [];
  const _respX = (obj) => Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, json: async () => obj, text: async () => '' });
  globalThis.fetch = (u, o) => {
    const su = String(u); const m = (o && o.method) || 'GET'; _capX.push({ url: su, opts: o || {} });
    if (su.indexOf('identity.xero.com/connect/token') >= 0) return _respX({ access_token: 'ACCESS-TOK-XERO', refresh_token: 'REFRESH-TOK-XERO', expires_in: 1800, token_type: 'Bearer' });
    if (su.indexOf('/connections') >= 0) return _respX([{ id: 'CONN-1', tenantId: 'XT-ORG-9', tenantType: 'ORGANISATION', tenantName: 'Xero Co' }]);
    if (su.indexOf('/Contacts') >= 0) return m === 'POST' ? _respX({ Contacts: [{ ContactID: 'CID-77', Name: 'Jane Doe' }] }) : _respX({ Contacts: [] });   // GET -> none found; POST -> created
    if (su.indexOf('/Invoices') >= 0) return _respX({ Invoices: [{ InvoiceID: 'INV-1001', InvoiceNumber: 'INV-0001' }] });
    return Promise.resolve({ ok: false, status: 404, headers: { get: () => null }, json: async () => ({}), text: async () => '' });
  };

  // (b) callback exchanges the code + fetches /connections + stores ENCRYPTED tokens + xeroTenant, then 302s back
  const cbUrlX = '/api/integrations/xero/callback?code=XCODE123&state=' + encodeURIComponent(stateX);
  const rcbX = await worker.fetch(mkReq('GET', cbUrlX), envX, ctx);
  ok('xero(b): callback 302-redirects back to the dashboard', rcbX.status === 302, 'status=' + rcbX.status);
  const tokReqX = _capX.find(c => c.url.indexOf('identity.xero.com/connect/token') >= 0);
  ok('xero(b): callback exchanged the code at the Xero token endpoint with Basic auth', !!tokReqX && String((tokReqX.opts.headers || {}).Authorization || '') === ('Basic ' + Buffer.from('XEROclientid:XEROsecret').toString('base64')), tokReqX && JSON.stringify(tokReqX.opts.headers));
  const connReqX = _capX.find(c => c.url.indexOf('/connections') >= 0);
  ok('xero(b): callback fetched /connections with the fresh Bearer token', !!connReqX && String((connReqX.opts.headers || {}).Authorization || '') === 'Bearer ACCESS-TOK-XERO', connReqX && JSON.stringify(connReqX.opts.headers));
  const intRowX = envX.DB._db.prepare("SELECT secret_enc, meta FROM integrations WHERE tenant_id=? AND provider='xero'").get(tidX);
  ok('xero(b): tokens stored ENCRYPTED at rest (ciphertext, not the plaintext access/refresh token)', !!(intRowX && intRowX.secret_enc) && String(intRowX.secret_enc).indexOf('ACCESS-TOK-XERO') < 0 && String(intRowX.secret_enc).indexOf('REFRESH-TOK-XERO') < 0, 'enc=' + (intRowX && String(intRowX.secret_enc).slice(0, 24)));
  ok('xero(b): xero org tenantId stored in meta (Xero-tenant-id source)', !!(intRowX && String(intRowX.meta).indexOf('XT-ORG-9') >= 0), intRowX && intRowX.meta);
  const stRowX = envX.DB._db.prepare('SELECT v FROM platform_config WHERE k=?').get('oauth:' + stateX);
  ok('xero(b): one-time state CONSUMED after callback (no replay)', !stRowX || !stRowX.v, 'v=' + (stRowX && stRowX.v));

  // (c) _xeroSyncBooking posts a Contact + an AUTHORISED ACCREC Invoice carrying the tenant Bearer token + Xero-tenant-id + paid total
  await envX.DB.prepare('INSERT INTO bookings (id,tenant_id,customer_id,asset_id,starts,ends,status,revenue_cents,data,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
    .bind('BKX', tidX, 'C', 'A', 1, 2, 'confirmed', 50000, JSON.stringify({ custName: 'Jane Doe', asset: 'Model X', quote: { totalCents: 50000 }, paid: { reserve: { amountCents: 50000 } } }), 1, 1000).run();
  _capX = [];
  const bkObjX = Object.assign({ id: 'BKX' }, JSON.parse(envX.DB._db.prepare("SELECT data FROM bookings WHERE id='BKX'").get().data));
  await _xeroSyncBooking(envX, tidX, bkObjX);
  const cPostX = _capX.find(c => c.url.indexOf('/Contacts') >= 0 && (c.opts.method || 'GET') === 'POST');
  ok('xero(c): _xeroSyncBooking POSTed a Contact when none was found', !!cPostX && String((cPostX.opts.headers || {})['Xero-tenant-id'] || '') === 'XT-ORG-9', cPostX && JSON.stringify(cPostX.opts.headers));
  const invReq = _capX.find(c => c.url.indexOf('/Invoices') >= 0);
  ok('xero(c): _xeroSyncBooking POSTed an Invoice', !!invReq && invReq.opts.method === 'POST', invReq && invReq.url);
  ok('xero(c): Invoice carried the tenant OWN Bearer access token', !!invReq && String((invReq.opts.headers || {}).Authorization || '') === 'Bearer ACCESS-TOK-XERO', invReq && JSON.stringify(invReq.opts.headers));
  ok('xero(c): Invoice carried the Xero-tenant-id header (connected org)', !!invReq && String((invReq.opts.headers || {})['Xero-tenant-id'] || '') === 'XT-ORG-9', invReq && JSON.stringify(invReq.opts.headers));
  const invBody = invReq ? JSON.parse(invReq.opts.body || '{}') : {};
  ok('xero(c): Invoice is an AUTHORISED ACCREC with the paid total ($500.00) + contact ref', !!(invBody.Type === 'ACCREC' && invBody.Status === 'AUTHORISED' && invBody.LineItems && invBody.LineItems[0] && invBody.LineItems[0].UnitAmount === 500 && invBody.Contact && invBody.Contact.ContactID === 'CID-77'), JSON.stringify(invBody.LineItems && invBody.LineItems[0]) + ' contact=' + JSON.stringify(invBody.Contact));
  const bkAfterX = JSON.parse(envX.DB._db.prepare("SELECT data FROM bookings WHERE id='BKX'").get().data);
  ok('xero(c): booking stamped xeroSyncedAt + xeroRef after a successful post', !!bkAfterX.xeroSyncedAt && bkAfterX.xeroRef === 'INV-1001', JSON.stringify({ at: bkAfterX.xeroSyncedAt, ref: bkAfterX.xeroRef }));

  // (d) a 2nd sync of the SAME booking must NOT double-post (idempotent by the xeroSyncedAt marker)
  _capX = [];
  await _xeroSyncBooking(envX, tidX, bkObjX);
  const invReq2 = _capX.find(c => c.url.indexOf('/Invoices') >= 0);
  ok('xero(d): 2nd sync is IDEMPOTENT (no duplicate Invoice POST)', !invReq2, invReq2 && invReq2.url);

  globalThis.fetch = _rfX;
}

// ---- PAYPAL MONEY PATH (BYO per-tenant, Orders v2, "make it real"): (a) create-order authenticates with the tenant's OWN
// client-id (HTTP Basic) + posts the correct 2dp decimal amount; (b) the return route captures the order and CREDITS the
// booking -- revenue_cents += amount, d.paid[kind] carries the capture id, status -> confirmed; (c) a SECOND return of the
// same order is IDEMPOTENT (no re-capture, revenue does NOT double); (d) G5 -- a PayPal payment settling a cash-ESTIMATE
// booking (revenue_cents == quote total, no prior online pay) REPLACES the estimate, it does not stack. All PayPal endpoints
// are mocked; globalThis.fetch is restored after. This MIRRORS the Stripe money-path test above and never touches it.
{
  const envPP = makeEnv(); __resetSchemaReady(); await ensurePlatformSchema(envPP);   // fresh DB -> full migration pass
  await worker.fetch(mkReq('POST', '/api/auth/signup', { body: { email: 'pp@x.com', password: 'correcthorsebatterystaple', business: 'PayPal Co' } }), envPP, ctx);
  const tidPP = envPP.DB._db.prepare('SELECT id FROM tenants LIMIT 1').get().id;
  const sPP = envPP.DB._db.prepare('SELECT id,csrf FROM sessions WHERE tenant_id=? ORDER BY created_at DESC LIMIT 1').get(tidPP);
  const HPP = { cookie: 'atlas_sid=' + sPP.id, 'x-csrf-token': sPP.csrf };

  // owner connects their OWN PayPal REST app via the SAME encrypted /api/integrations/connect (secret -> secret_enc; client-id + sandbox -> meta)
  await worker.fetch(mkReq('POST', '/api/integrations/connect', { headers: HPP, body: { provider: 'paypal', secret: 'PP_SECRET_XYZ', meta: { client_id: 'PPCLIENTID', sandbox: true } } }), envPP, ctx);
  const ppRow = envPP.DB._db.prepare("SELECT secret_enc, meta FROM integrations WHERE tenant_id=? AND provider='paypal'").get(tidPP);
  ok('paypal: secret stored ENCRYPTED at rest (route encrypts; plaintext secret never stored)', !!(ppRow && ppRow.secret_enc) && String(ppRow.secret_enc).indexOf('PP_SECRET_XYZ') < 0, 'row=' + JSON.stringify(ppRow && ppRow.meta));
  ok('paypal: client-id + sandbox flag stored in meta (non-secret)', !!(ppRow && String(ppRow.meta).indexOf('PPCLIENTID') >= 0 && /"sandbox":true/.test(String(ppRow.meta))), ppRow && ppRow.meta);

  // status route reports a TRUTHFUL connected badge (no secret leaked)
  let rStat = await worker.fetch(mkReq('GET', '/api/integrations/paypal/status', { headers: HPP }), envPP, ctx);
  let jStat = await rStat.json();
  ok('paypal: /status -> connected:true, sandbox:true, last-4 hint, NO secret', jStat && jStat.ok === true && jStat.connected === true && jStat.sandbox === true && /ID$/.test(String(jStat.clientHint || '')) && JSON.stringify(jStat).indexOf('PP_SECRET_XYZ') < 0, JSON.stringify(jStat));

  // a booking with a portal token + a quote (deposit $200 of a $500 total); revenue starts at 0 (not an estimate yet). ends is in
  // the FUTURE so the portal link is not treated as expired (the START route is a portal action; the expiry check runs before it).
  const NOWPP = Date.now();
  await envPP.DB.prepare("INSERT INTO bookings (id,tenant_id,customer_id,asset_id,starts,ends,status,revenue_cents,data,portal_token,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind('BKPP', tidPP, 'C', 'A', NOWPP, NOWPP + 3 * 86400000, 'pending', 0, JSON.stringify({ asset: 'Model S', periods: 2, custEmail: 'cust@x.com', quote: { totalCents: 50000, depositCents: 20000 }, paid: {} }), 'PPTOKEN12345678', 1, 1000).run();

  // mock the PayPal endpoints (capture matched BEFORE create -- the capture URL also contains /v2/checkout/orders)
  const _rfPP = globalThis.fetch; let _capPP = [];
  const _respPP = (obj) => Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, json: async () => obj, text: async () => '' });
  globalThis.fetch = (u, o) => {
    const su = String(u); _capPP.push({ url: su, opts: o || {} });
    if (su.indexOf('/v1/oauth2/token') >= 0) return _respPP({ access_token: 'PP-ACCESS-TOK', token_type: 'Bearer', expires_in: 32400 });
    if (/\/v2\/checkout\/orders\/[^/]+\/capture$/.test(su)) return _respPP({ id: 'ORDER-PP1', status: 'COMPLETED', purchase_units: [{ custom_id: 'BKPP|deposit', payments: { captures: [{ id: 'CAP-PP1', status: 'COMPLETED', amount: { currency_code: 'USD', value: '200.00' }, custom_id: 'BKPP|deposit' }] } }] });
    if (su.indexOf('/v2/checkout/orders') >= 0) return _respPP({ id: 'ORDER-PP1', status: 'CREATED', links: [{ rel: 'approve', href: 'https://www.sandbox.paypal.com/checkoutnow?token=ORDER-PP1' }, { rel: 'self', href: 'https://api-m.sandbox.paypal.com/v2/checkout/orders/ORDER-PP1' }] });
    return Promise.resolve({ ok: false, status: 404, headers: { get: () => null }, json: async () => ({}), text: async () => '' });
  };

  // (a) START creates a PayPal order for the deposit; authenticates Basic with the tenant's client-id + posts the correct decimal amount
  _capPP = [];
  const rStart = await worker.fetch(mkReq('POST', '/api/portal/PPTOKEN12345678/paypal', { body: { kind: 'deposit' } }), envPP, ctx);
  const jStart = await rStart.json();
  ok('paypal(a): START -> approve URL + order id (offered because PayPal is connected)', jStart && jStart.ok === true && String(jStart.payUrl || '').indexOf('checkoutnow') >= 0 && jStart.orderId === 'ORDER-PP1', JSON.stringify(jStart).slice(0, 140));
  const tokReqPP = _capPP.find(c => c.url.indexOf('/v1/oauth2/token') >= 0);
  ok('paypal(a): token obtained with HTTP Basic of the TENANT client-id:secret', !!tokReqPP && String((tokReqPP.opts.headers || {}).Authorization || '') === ('Basic ' + Buffer.from('PPCLIENTID:PP_SECRET_XYZ').toString('base64')), tokReqPP && JSON.stringify(tokReqPP.opts.headers));
  ok('paypal(a): create used the tenant SANDBOX base (meta.sandbox=true)', !!tokReqPP && tokReqPP.url.indexOf('api-m.sandbox.paypal.com') >= 0, tokReqPP && tokReqPP.url);
  const createReqPP = _capPP.find(c => /\/v2\/checkout\/orders$/.test(c.url));
  const createBody = createReqPP ? JSON.parse(createReqPP.opts.body || '{}') : {};
  ok('paypal(a): create-order intent CAPTURE + amount "200.00" (cents/100, 2dp) + custom_id booking|kind', !!(createBody.intent === 'CAPTURE' && createBody.purchase_units && createBody.purchase_units[0].amount.value === '200.00' && createBody.purchase_units[0].custom_id === 'BKPP|deposit'), JSON.stringify(createBody.purchase_units && createBody.purchase_units[0]));

  // (b) RETURN captures the order + credits the booking (revenue += amount, d.paid.deposit carries the capture id, status confirmed)
  _capPP = [];
  const rRet = await worker.fetch(mkReq('GET', '/api/paypal/return?pt=PPTOKEN12345678&token=ORDER-PP1'), envPP, ctx);
  const bkPP1 = envPP.DB._db.prepare("SELECT revenue_cents,status,data FROM bookings WHERE id='BKPP'").get();
  const dPP1 = JSON.parse(bkPP1.data);
  ok('paypal(b): return route 302-redirects back to the portal as paid', rRet.status === 302 && String(rRet.headers.get('Location') || '').indexOf('/api/portal/PPTOKEN12345678?paid=1') >= 0, 'status=' + rRet.status + ' loc=' + rRet.headers.get('Location'));
  ok('paypal(b): capture recorded in d.paid.deposit with the PayPal capture id + amount', !!(dPP1.paid && dPP1.paid.deposit && dPP1.paid.deposit.paypal === 'CAP-PP1' && dPP1.paid.deposit.amountCents === 20000 && dPP1.paid.deposit.order === 'ORDER-PP1'), JSON.stringify(dPP1.paid));
  ok('paypal(b): revenue credited to 20000 + booking confirmed', Number(bkPP1.revenue_cents) === 20000 && bkPP1.status === 'confirmed' && dPP1.status === 'Confirmed', 'rev=' + bkPP1.revenue_cents + ' status=' + bkPP1.status);

  // (c) a SECOND return of the SAME order is idempotent: NO second capture call, and revenue does NOT double
  _capPP = [];
  const rRet2 = await worker.fetch(mkReq('GET', '/api/paypal/return?pt=PPTOKEN12345678&token=ORDER-PP1'), envPP, ctx);
  const bkPP2 = envPP.DB._db.prepare("SELECT revenue_cents FROM bookings WHERE id='BKPP'").get();
  const captured2 = _capPP.find(c => /\/capture$/.test(c.url));
  ok('paypal(c): duplicate return did NOT re-capture (order-level idempotency)', !captured2 && rRet2.status === 302, 'reCaptured=' + !!captured2 + ' status=' + rRet2.status);
  ok('paypal(c): duplicate return did NOT double revenue (still 20000, not 40000)', Number(bkPP2.revenue_cents) === 20000, 'revenue_cents=' + bkPP2.revenue_cents);

  // credit-level idempotency: crediting the SAME capture id twice via _paypalCreditBooking is a no-op the 2nd time (keyed on the capture id in d.paid)
  const dupRes = await _paypalCreditBooking(envPP, tidPP, 'BKPP', 'deposit', 'CAP-PP1', 'ORDER-PP1', 20000);
  const bkPP3 = envPP.DB._db.prepare("SELECT revenue_cents FROM bookings WHERE id='BKPP'").get();
  ok('paypal(c): re-crediting the same capture id is a dup no-op (revenue unchanged)', dupRes.dup === true && dupRes.credited === false && Number(bkPP3.revenue_cents) === 20000, 'dup=' + dupRes.dup + ' rev=' + bkPP3.revenue_cents);

  // (d) G5: a committed booking carrying a cash-ESTIMATE (revenue_cents == quote total, no prior online pay). A first PayPal
  // payment SETTLES it -> REPLACE the estimate (revenue stays == the amount), never stack to double.
  await envPP.DB.prepare("INSERT INTO bookings (id,tenant_id,customer_id,asset_id,starts,ends,status,revenue_cents,data,portal_token,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind('BKPPG5', tidPP, 'C', 'A', 1, 2, 'confirmed', 50000, JSON.stringify({ asset: 'Model X', quote: { totalCents: 50000 }, paid: {} }), 'PPTOKENG5000000', 1, 1000).run();
  const g5Res = await _paypalCreditBooking(envPP, tidPP, 'BKPPG5', 'paypal', 'CAP-G5', 'ORDER-G5', 50000);
  const bkG5 = envPP.DB._db.prepare("SELECT revenue_cents,status,data FROM bookings WHERE id='BKPPG5'").get();
  const dG5 = JSON.parse(bkG5.data);
  ok('paypal(d): G5 estimate REPLACED, not stacked (revenue stays 50000, not 100000)', g5Res.credited === true && Number(bkG5.revenue_cents) === 50000, 'rev=' + bkG5.revenue_cents);
  ok('paypal(d): the generic d.paid.paypal slot carries the capture id', !!(dG5.paid && dG5.paid.paypal && dG5.paid.paypal.paypal === 'CAP-G5' && dG5.paid.paypal.amountCents === 50000), JSON.stringify(dG5.paid));

  // honest gating: a tenant with NO PayPal connected is never offered the option (the START route returns no_paypal)
  await envPP.DB.prepare("INSERT INTO tenants (id,name,created_at,updated_at) VALUES (?,?,?,?)").bind('TEN_NOPP', 'No PayPal Co', 1, 1).run();
  await envPP.DB.prepare("INSERT INTO bookings (id,tenant_id,customer_id,asset_id,starts,ends,status,revenue_cents,data,portal_token,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind('BKNOPP', 'TEN_NOPP', 'C', 'A', NOWPP, NOWPP + 3 * 86400000, 'pending', 0, JSON.stringify({ quote: { totalCents: 10000, depositCents: 5000 }, paid: {} }), 'NOPPTOKEN00000', 1, 1).run();
  const rNoPP = await worker.fetch(mkReq('POST', '/api/portal/NOPPTOKEN00000/paypal', { body: { kind: 'deposit' } }), envPP, ctx);
  const jNoPP = await rNoPP.json();
  ok('paypal: honest gating -> no connected PayPal, START returns no_paypal (never offered)', jNoPP && jNoPP.ok === false && jNoPP.reason === 'no_paypal', JSON.stringify(jNoPP));

  globalThis.fetch = _rfPP;
}

// ---- SQUARE money-path (BYO per-tenant, Payment Links / Orders v2), MIRRORS the PayPal test above: (a) the START route creates a
// Square hosted checkout authenticating as the TENANT (Bearer Access Token) + posts the correct cents amount + location_id to the
// SANDBOX base; (b) the return route verifies the order paid and CREDITS the booking -- revenue_cents += amount, d.paid[kind] carries
// the Square payment id, status -> confirmed; (c) a SECOND return of the same order is IDEMPOTENT (no re-verify, revenue does NOT
// double); (d) G5 -- a Square payment settling a cash-ESTIMATE booking (revenue_cents == quote total, no prior online pay) REPLACES
// the estimate, it does not stack. All Square endpoints are mocked; globalThis.fetch is restored after. Never touches Stripe/PayPal.
{
  const envSQ = makeEnv(); __resetSchemaReady(); await ensurePlatformSchema(envSQ);   // fresh DB -> full migration pass
  await worker.fetch(mkReq('POST', '/api/auth/signup', { body: { email: 'sq@x.com', password: 'correcthorsebatterystaple', business: 'Square Co' } }), envSQ, ctx);
  const tidSQ = envSQ.DB._db.prepare('SELECT id FROM tenants LIMIT 1').get().id;
  const sSQ = envSQ.DB._db.prepare('SELECT id,csrf FROM sessions WHERE tenant_id=? ORDER BY created_at DESC LIMIT 1').get(tidSQ);
  const HSQ = { cookie: 'atlas_sid=' + sSQ.id, 'x-csrf-token': sSQ.csrf };

  // owner connects their OWN Square via the SAME encrypted /api/integrations/connect (Access Token -> secret_enc; location-id + sandbox -> meta)
  await worker.fetch(mkReq('POST', '/api/integrations/connect', { headers: HSQ, body: { provider: 'square', secret: 'SQ_ACCESS_TOKEN_XYZ', meta: { location_id: 'LOCSQ123', sandbox: true } } }), envSQ, ctx);
  const sqRow = envSQ.DB._db.prepare("SELECT secret_enc, meta FROM integrations WHERE tenant_id=? AND provider='square'").get(tidSQ);
  ok('square: Access Token stored ENCRYPTED at rest (route encrypts; plaintext token never stored)', !!(sqRow && sqRow.secret_enc) && String(sqRow.secret_enc).indexOf('SQ_ACCESS_TOKEN_XYZ') < 0, 'row=' + JSON.stringify(sqRow && sqRow.meta));
  ok('square: location-id + sandbox flag stored in meta (non-secret)', !!(sqRow && String(sqRow.meta).indexOf('LOCSQ123') >= 0 && /"sandbox":true/.test(String(sqRow.meta))), sqRow && sqRow.meta);

  // status route reports a TRUTHFUL connected badge (no Access Token leaked)
  let rStatSQ = await worker.fetch(mkReq('GET', '/api/integrations/square/status', { headers: HSQ }), envSQ, ctx);
  let jStatSQ = await rStatSQ.json();
  ok('square: /status -> connected:true, sandbox:true, last-4 hint, NO secret', jStatSQ && jStatSQ.ok === true && jStatSQ.connected === true && jStatSQ.sandbox === true && /123$/.test(String(jStatSQ.locHint || '')) && JSON.stringify(jStatSQ).indexOf('SQ_ACCESS_TOKEN_XYZ') < 0, JSON.stringify(jStatSQ));

  // a booking with a portal token + a quote (deposit $200 of a $500 total); revenue starts at 0 (not an estimate yet). ends is FUTURE
  // so the portal link is not treated as expired (the START route is a portal action; the expiry check runs before it).
  const NOWSQ = Date.now();
  await envSQ.DB.prepare("INSERT INTO bookings (id,tenant_id,customer_id,asset_id,starts,ends,status,revenue_cents,data,portal_token,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind('BKSQ', tidSQ, 'C', 'A', NOWSQ, NOWSQ + 3 * 86400000, 'pending', 0, JSON.stringify({ asset: 'Model S', periods: 2, custEmail: 'cust@x.com', quote: { totalCents: 50000, depositCents: 20000 }, paid: {} }), 'SQTOKEN12345678', 1, 1000).run();

  // mock the Square endpoints (create payment-link + get-order are distinct paths -- no ordering concern)
  const _rfSQ = globalThis.fetch; let _capSQ = [];
  const _respSQ = (obj) => Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, json: async () => obj, text: async () => '' });
  globalThis.fetch = (u, o) => {
    const su = String(u); _capSQ.push({ url: su, opts: o || {} });
    if (su.indexOf('/v2/online-checkout/payment-links') >= 0) return _respSQ({ payment_link: { id: 'PL-SQ1', version: 1, order_id: 'ORDER-SQ1', url: 'https://square.link/u/checkoutSQ1' } });
    if (su.indexOf('/v2/orders/') >= 0) return _respSQ({ order: { id: 'ORDER-SQ1', location_id: 'LOCSQ123', state: 'COMPLETED', total_money: { amount: 20000, currency: 'USD' }, net_amount_due_money: { amount: 0, currency: 'USD' }, tenders: [{ id: 'TENDER-SQ1', type: 'CARD', amount_money: { amount: 20000, currency: 'USD' }, card_details: { status: 'CAPTURED' } }] } });
    return Promise.resolve({ ok: false, status: 404, headers: { get: () => null }, json: async () => ({}), text: async () => '' });
  };

  // (a) START creates a Square checkout for the deposit; authenticates Bearer with the tenant's Access Token + posts the correct cents amount + location_id
  _capSQ = [];
  const rStartSQ = await worker.fetch(mkReq('POST', '/api/portal/SQTOKEN12345678/square', { body: { kind: 'deposit' } }), envSQ, ctx);
  const jStartSQ = await rStartSQ.json();
  ok('square(a): START -> hosted URL + order id (offered because Square is connected)', jStartSQ && jStartSQ.ok === true && String(jStartSQ.payUrl || '').indexOf('square.link') >= 0 && jStartSQ.orderId === 'ORDER-SQ1', JSON.stringify(jStartSQ).slice(0, 140));
  const createReqSQ = _capSQ.find(c => c.url.indexOf('/v2/online-checkout/payment-links') >= 0);
  ok('square(a): create authenticates as the TENANT (Bearer Access Token) + pinned Square-Version', !!createReqSQ && String((createReqSQ.opts.headers || {}).Authorization || '') === 'Bearer SQ_ACCESS_TOKEN_XYZ' && String((createReqSQ.opts.headers || {})['Square-Version'] || '') === '2024-07-17', createReqSQ && JSON.stringify(createReqSQ.opts.headers));
  ok('square(a): create used the tenant SANDBOX base (meta.sandbox=true)', !!createReqSQ && createReqSQ.url.indexOf('connect.squareupsandbox.com') >= 0, createReqSQ && createReqSQ.url);
  const createBodySQ = createReqSQ ? JSON.parse(createReqSQ.opts.body || '{}') : {};
  ok('square(a): quick_pay amount 20000 (cents) + USD + tenant location_id', !!(createBodySQ.quick_pay && createBodySQ.quick_pay.price_money && createBodySQ.quick_pay.price_money.amount === 20000 && createBodySQ.quick_pay.price_money.currency === 'USD' && createBodySQ.quick_pay.location_id === 'LOCSQ123'), JSON.stringify(createBodySQ.quick_pay));
  ok('square(a): redirect_url encodes the booking id + kind (so the return credits the right slot)', !!(createBodySQ.checkout_options && /[?&]bk=BKSQ(&|$)/.test(String(createBodySQ.checkout_options.redirect_url)) && /[?&]kind=deposit(&|$)/.test(String(createBodySQ.checkout_options.redirect_url))), createBodySQ.checkout_options && createBodySQ.checkout_options.redirect_url);

  // (b) RETURN verifies the order + credits the booking (revenue += amount, d.paid.deposit carries the Square payment id, status confirmed).
  // Square appends ?orderId=... to our redirect_url; our own pt/bk/kind params ride along (they were baked into redirect_url at create).
  _capSQ = [];
  const rRetSQ = await worker.fetch(mkReq('GET', '/api/square/return?pt=SQTOKEN12345678&bk=BKSQ&kind=deposit&orderId=ORDER-SQ1'), envSQ, ctx);
  const bkSQ1 = envSQ.DB._db.prepare("SELECT revenue_cents,status,data FROM bookings WHERE id='BKSQ'").get();
  const dSQ1 = JSON.parse(bkSQ1.data);
  ok('square(b): return route 302-redirects back to the portal as paid', rRetSQ.status === 302 && String(rRetSQ.headers.get('Location') || '').indexOf('/api/portal/SQTOKEN12345678?paid=1') >= 0, 'status=' + rRetSQ.status + ' loc=' + rRetSQ.headers.get('Location'));
  ok('square(b): payment recorded in d.paid.deposit with the Square payment id + amount + order', !!(dSQ1.paid && dSQ1.paid.deposit && dSQ1.paid.deposit.square === 'TENDER-SQ1' && dSQ1.paid.deposit.amountCents === 20000 && dSQ1.paid.deposit.order === 'ORDER-SQ1'), JSON.stringify(dSQ1.paid));
  ok('square(b): revenue credited to 20000 + booking confirmed', Number(bkSQ1.revenue_cents) === 20000 && bkSQ1.status === 'confirmed' && dSQ1.status === 'Confirmed', 'rev=' + bkSQ1.revenue_cents + ' status=' + bkSQ1.status);

  // (c) a SECOND return of the SAME order is idempotent: NO second get-order call, and revenue does NOT double
  _capSQ = [];
  const rRetSQ2 = await worker.fetch(mkReq('GET', '/api/square/return?pt=SQTOKEN12345678&bk=BKSQ&kind=deposit&orderId=ORDER-SQ1'), envSQ, ctx);
  const bkSQ2 = envSQ.DB._db.prepare("SELECT revenue_cents FROM bookings WHERE id='BKSQ'").get();
  const verified2 = _capSQ.find(c => c.url.indexOf('/v2/orders/') >= 0);
  ok('square(c): duplicate return did NOT re-verify (order-level idempotency)', !verified2 && rRetSQ2.status === 302, 'reVerified=' + !!verified2 + ' status=' + rRetSQ2.status);
  ok('square(c): duplicate return did NOT double revenue (still 20000, not 40000)', Number(bkSQ2.revenue_cents) === 20000, 'revenue_cents=' + bkSQ2.revenue_cents);

  // credit-level idempotency: crediting the SAME payment id twice via _squareCreditBooking is a no-op the 2nd time (keyed on the payment id in d.paid)
  const dupResSQ = await _squareCreditBooking(envSQ, tidSQ, 'BKSQ', 'deposit', 'TENDER-SQ1', 'ORDER-SQ1', 20000);
  const bkSQ3 = envSQ.DB._db.prepare("SELECT revenue_cents FROM bookings WHERE id='BKSQ'").get();
  ok('square(c): re-crediting the same payment id is a dup no-op (revenue unchanged)', dupResSQ.dup === true && dupResSQ.credited === false && Number(bkSQ3.revenue_cents) === 20000, 'dup=' + dupResSQ.dup + ' rev=' + bkSQ3.revenue_cents);

  // (d) G5: a committed booking carrying a cash-ESTIMATE (revenue_cents == quote total, no prior online pay). A first Square payment
  // SETTLES it -> REPLACE the estimate (revenue stays == the amount), never stack to double.
  await envSQ.DB.prepare("INSERT INTO bookings (id,tenant_id,customer_id,asset_id,starts,ends,status,revenue_cents,data,portal_token,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind('BKSQG5', tidSQ, 'C', 'A', 1, 2, 'confirmed', 50000, JSON.stringify({ asset: 'Model X', quote: { totalCents: 50000 }, paid: {} }), 'SQTOKENG5000000', 1, 1000).run();
  const g5ResSQ = await _squareCreditBooking(envSQ, tidSQ, 'BKSQG5', 'square', 'PAY-G5', 'ORDER-G5', 50000);
  const bkSQG5 = envSQ.DB._db.prepare("SELECT revenue_cents,status,data FROM bookings WHERE id='BKSQG5'").get();
  const dSQG5 = JSON.parse(bkSQG5.data);
  ok('square(d): G5 estimate REPLACED, not stacked (revenue stays 50000, not 100000)', g5ResSQ.credited === true && Number(bkSQG5.revenue_cents) === 50000, 'rev=' + bkSQG5.revenue_cents);
  ok('square(d): the generic d.paid.square slot carries the payment id', !!(dSQG5.paid && dSQG5.paid.square && dSQG5.paid.square.square === 'PAY-G5' && dSQG5.paid.square.amountCents === 50000), JSON.stringify(dSQG5.paid));

  // honest gating: a tenant with NO Square connected is never offered the option (the START route returns no_square)
  await envSQ.DB.prepare("INSERT INTO tenants (id,name,created_at,updated_at) VALUES (?,?,?,?)").bind('TEN_NOSQ', 'No Square Co', 1, 1).run();
  await envSQ.DB.prepare("INSERT INTO bookings (id,tenant_id,customer_id,asset_id,starts,ends,status,revenue_cents,data,portal_token,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind('BKNOSQ', 'TEN_NOSQ', 'C', 'A', NOWSQ, NOWSQ + 3 * 86400000, 'pending', 0, JSON.stringify({ quote: { totalCents: 10000, depositCents: 5000 }, paid: {} }), 'NOSQTOKEN00000', 1, 1).run();
  const rNoSQ = await worker.fetch(mkReq('POST', '/api/portal/NOSQTOKEN00000/square', { body: { kind: 'deposit' } }), envSQ, ctx);
  const jNoSQ = await rNoSQ.json();
  ok('square: honest gating -> no connected Square, START returns no_square (never offered)', jNoSQ && jNoSQ.ok === false && jNoSQ.reason === 'no_square', JSON.stringify(jNoSQ));

  globalThis.fetch = _rfSQ;
}

// ===================== #202 live GPS trackers: newly-real providers parse REAL positions; unsupported/unconnected yield NO fake position =====================
// _trackerFetch is the server-side poller (provider creds never touch the browser). For each newly-real provider we mock its
// API and assert the {lat,lng,...} we parse matches the mocked response; and we prove an unconnected/unsupported provider
// NEVER fabricates a position -- the honesty invariant. (Simulated positions are a CLIENT-only labeled preview, never served.)
{
  const _rfTrk = globalThis.fetch;

  // Geotab: Authenticate -> Get DeviceStatusInfo (+ best-effort Get Device for name/VIN). Speed is km/h -> mph.
  globalThis.fetch = (u, o) => {
    const url = String(u); let b = {}; try { b = JSON.parse((o && o.body) || '{}'); } catch (e) {}
    if (url.indexOf('/apiv1') >= 0 && b.method === 'Authenticate') return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ({ result: { credentials: { database: 'db', userName: 'u', sessionId: 'SID' }, path: 'ThisServer' } }) });
    if (url.indexOf('/apiv1') >= 0 && b.method === 'Get' && b.params && b.params.typeName === 'DeviceStatusInfo') return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ({ result: [{ device: { id: 'b1' }, latitude: 30.27, longitude: -97.74, speed: 100, bearing: 90, dateTime: '2026-07-31T00:00:00Z', isDriving: true }] }) });
    if (url.indexOf('/apiv1') >= 0 && b.method === 'Get' && b.params && b.params.typeName === 'Device') return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ({ result: [{ id: 'b1', name: 'Unit 7', vehicleIdentificationNumber: '1FT-VIN-777' }] }) });
    return Promise.resolve({ ok: false, status: 404, headers: { get: () => null }, text: async () => '', json: async () => ({}) });
  };
  const gRes = await _trackerFetch(env, 'geotab', JSON.stringify({ server: 'my.geotab.com', database: 'db', user: 'u', password: 'p' }), {});
  ok('geotab: _trackerFetch parses REAL {lat,lng} from DeviceStatusInfo', gRes.ok && gRes.positions.length === 1 && gRes.positions[0].lat === 30.27 && gRes.positions[0].lng === -97.74, JSON.stringify(gRes).slice(0, 160));
  ok('geotab: speed km/h -> mph + device name/VIN mapped', gRes.ok && Math.round(gRes.positions[0].speed) === 62 && gRes.positions[0].vin === '1FT-VIN-777' && gRes.positions[0].label === 'Unit 7', JSON.stringify(gRes.positions[0]));

  // GPSWOX: GET /api/get_devices -> groups[].items[] with (possibly string) lat/lng. Speed km/h -> mph.
  globalThis.fetch = (u) => {
    if (String(u).indexOf('/api/get_devices') >= 0) return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ([{ id: 1, title: 'Fleet', items: [{ id: 55, name: 'Van A', lat: '40.7128', lng: '-74.0060', speed: 50, course: 270, time: '2026-07-31 00:00:00', online: 'online' }] }]) });
    return Promise.resolve({ ok: false, status: 404, headers: { get: () => null }, text: async () => '', json: async () => ({}) });
  };
  const wRes = await _trackerFetch(env, 'gpswox', 'HASH123', { host: 'https://gps.example.com' });
  ok('gpswox: _trackerFetch parses REAL {lat,lng} from get_devices items (string coords)', wRes.ok && wRes.positions.length === 1 && wRes.positions[0].lat === 40.7128 && wRes.positions[0].lng === -74.006, JSON.stringify(wRes).slice(0, 160));
  ok('gpswox: label + moving derived, speed km/h -> mph', wRes.positions[0].label === 'Van A' && wRes.positions[0].moving === true && Math.round(wRes.positions[0].speed) === 31, JSON.stringify(wRes.positions[0]));

  // flespi: GET /gw/devices/all/telemetry/position -> result[].telemetry.position (nested {value:{...},ts}). Speed km/h -> mph.
  globalThis.fetch = (u) => {
    if (String(u).indexOf('flespi.io/gw/devices') >= 0) return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ({ result: [{ id: 900, telemetry: { position: { value: { latitude: 51.5074, longitude: -0.1278, speed: 80, direction: 180 }, ts: 1785000000 } } }] }) });
    return Promise.resolve({ ok: false, status: 404, headers: { get: () => null }, text: async () => '', json: async () => ({}) });
  };
  const fRes = await _trackerFetch(env, 'flespi', 'FLESPITOKEN', {});
  ok('flespi: _trackerFetch parses REAL {lat,lng} from telemetry.position', fRes.ok && fRes.positions.length === 1 && fRes.positions[0].lat === 51.5074 && fRes.positions[0].lng === -0.1278, JSON.stringify(fRes).slice(0, 160));
  ok('flespi: heading + ts + speed km/h -> mph parsed', fRes.positions[0].heading === 180 && Math.round(fRes.positions[0].speed) === 50 && !!fRes.positions[0].ts, JSON.stringify(fRes.positions[0]));

  // HONESTY: an unsupported provider fabricates NOTHING (ok:false, no positions) even though the client offers its name.
  globalThis.fetch = () => Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ({ result: [{ latitude: 1, longitude: 2 }] }) });
  const uRes = await _trackerFetch(env, 'lojack', 'anything', {});
  ok('honesty: unsupported provider (lojack) -> ok:false unknown_provider, NO position', uRes.ok === false && uRes.reason === 'unknown_provider' && !uRes.positions, JSON.stringify(uRes));

  // SSRF: GPSWOX pointed at a private/metadata host is refused (never probes the internal network), no position.
  const sRes = await _trackerFetch(env, 'gpswox', 'HASH', { host: 'https://169.254.169.254' });
  ok('ssrf: gpswox private/metadata host refused (blocked_host), NO position', sRes.ok === false && !sRes.positions, JSON.stringify(sRes));

  ok('TRK_PROVIDERS lists the 13 original + 3 marine/equipment dedicated + generic (all really-integrated)', Array.isArray(TRK_PROVIDERS) && TRK_PROVIDERS.length === 17 && ['bouncie', 'samsara', 'traccar', 'geotab', 'gpswox', 'flespi', 'wialon', 'navixy', 'motive', 'webfleet', 'zubie', 'azuga', 'onestepgps', 'marinetraffic', 'trackunit', 'garmininreach', 'generic'].every((p) => TRK_PROVIDERS.indexOf(p) >= 0), JSON.stringify(TRK_PROVIDERS));

  globalThis.fetch = _rfTrk;
}

// ===================== marine / equipment verticals: new dedicated blocks parse REAL lat/lng; routed brands fabricate NOTHING =====================
// MarineTraffic (AIS by MMSI), Trackunit (equipment GeoJSON) and Garmin inReach (MapShare KML) are keyed per-asset / fleet-level.
// Starlink + Spire are deliberately NOT dedicated (client routes them to the universal connector -- their public field-level GPS
// could not be confirmed), so _trackerFetch returns unknown_provider for them: the honesty invariant, never a fabricated position.
{
  const _rfMar = globalThis.fetch;
  const _mkr = (obj, txt) => Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, json: async () => obj, text: async () => (txt || '') });

  // MarineTraffic Single Vessel Positions (PS01): GET /api/exportvessel/<key>?v=6&protocol=jsono&mmsi=<MMSI> -> [{LAT,LON,SPEED(knots*10),COURSE,HEADING,TIMESTAMP,SHIPNAME,MMSI}]. HEADING 511 = n/a -> COURSE. knots -> mph.
  globalThis.fetch = (u) => { const mm = (String(u).match(/mmsi=([0-9]+)/) || [])[1] || '0'; return _mkr([{ MMSI: mm, LAT: '37.8', LON: '-122.4', SPEED: '105', COURSE: '90', HEADING: '511', TIMESTAMP: '2026-07-31T00:00:00', SHIPNAME: 'Sea Otter ' + mm }]); };
  const mt = await _trackerFetch(env, 'marinetraffic', 'KEY40HEX', { mmsi: '366998410, 366998411' });
  ok('marinetraffic: parses REAL {lat,lng} from LAT/LON per MMSI (2 vessels)', mt.ok && mt.positions.length === 2 && mt.positions[0].lat === 37.8 && mt.positions[0].lng === -122.4, JSON.stringify(mt).slice(0, 180));
  ok('marinetraffic: SPEED(knots*10)->mph, HEADING 511->COURSE, MMSI/SHIPNAME mapped', Math.abs(mt.positions[0].speed - 12.08) < 0.05 && mt.positions[0].heading === 90 && mt.positions[1].deviceId === '366998411', JSON.stringify(mt.positions[0]));
  const mtNo = await _trackerFetch(env, 'marinetraffic', 'KEY', {});
  ok('marinetraffic: no MMSI -> ok:false no_mmsi, NO position (honest)', mtNo.ok === false && mtNo.reason === 'no_mmsi' && !mtNo.positions, JSON.stringify(mtNo));

  // Trackunit Iris Location API: GET /api/location/v1/locations -> GeoJSON FeatureCollection; geometry.coordinates = [lng,lat,(alt)].
  globalThis.fetch = (u, o) => _mkr({ type: 'FeatureCollection', features: [{ type: 'Feature', id: 'loc1', geometry: { type: 'Point', coordinates: [-97.74, 30.27, 210] }, properties: { assetId: 'EXC-12', name: 'Excavator 12', time: '2026-07-31T00:00:00Z', speed: 0, _auth: (o && o.headers && o.headers['Authorization']) || '' } }] });
  const tu = await _trackerFetch(env, 'trackunit', 'TU_APIKEY', {});
  ok('trackunit: parses REAL {lat,lng} from GeoJSON coordinates [lng,lat]', tu.ok && tu.positions.length === 1 && tu.positions[0].lat === 30.27 && tu.positions[0].lng === -97.74, JSON.stringify(tu).slice(0, 180));
  ok('trackunit: asset id + name mapped; Authorization: Bearer <key> sent', tu.positions[0].deviceId === 'EXC-12' && tu.positions[0].label === 'Excavator 12', JSON.stringify(tu.positions[0]));

  // Garmin inReach MapShare Raw KML: newest Point by <when> (order-independent); prefer ExtendedData Latitude/Longitude; Velocity km/h -> mph.
  const KML = '<kml><Document><Folder>'
    + '<Placemark><TimeStamp><when>2026-07-31T09:00:00Z</when></TimeStamp><ExtendedData><Data name="IMEI"><value>300000000000001</value></Data><Data name="Name"><value>Reef Runner</value></Data><Data name="Latitude"><value>25.10</value></Data><Data name="Longitude"><value>-80.20</value></Data><Data name="Velocity"><value>18.5 km/h</value></Data><Data name="Course"><value>270.00 degrees True</value></Data></ExtendedData><Point><coordinates>-80.20,25.10,0.0</coordinates></Point></Placemark>'
    + '<Placemark><TimeStamp><when>2026-07-31T10:00:00Z</when></TimeStamp><ExtendedData><Data name="IMEI"><value>300000000000001</value></Data><Data name="Name"><value>Reef Runner</value></Data><Data name="Latitude"><value>25.55</value></Data><Data name="Longitude"><value>-80.44</value></Data><Data name="Velocity"><value>0.0 km/h</value></Data></ExtendedData><Point><coordinates>-80.44,25.55,0.0</coordinates></Point></Placemark>'
    + '<Placemark><LineString><coordinates>-80.20,25.10,0 -80.44,25.55,0</coordinates></LineString></Placemark>'
    + '</Folder></Document></kml>';
  globalThis.fetch = () => _mkr(null, KML);
  const gi = await _trackerFetch(env, 'garmininreach', 'none', { shareUrl: 'https://share.garmin.com/Feed/Share/REEF' });
  ok('inreach: KML -> NEWEST point by timestamp (order-independent), ExtendedData lat/lng', gi.ok && gi.positions.length === 1 && gi.positions[0].lat === 25.55 && gi.positions[0].lng === -80.44, JSON.stringify(gi).slice(0, 180));
  ok('inreach: IMEI + name mapped, Velocity km/h -> mph, moving derived', gi.positions[0].deviceId === '300000000000001' && gi.positions[0].label === 'Reef Runner' && gi.positions[0].speed === 0 && gi.positions[0].moving === false, JSON.stringify(gi.positions[0]));
  const giBad = await _trackerFetch(env, 'garmininreach', 'none', { shareUrl: 'https://evil.example.com/Feed/Share/X' });
  ok('inreach: non-Garmin host refused (0 positions, never followed)', giBad.ok === true && giBad.positions.length === 0, JSON.stringify(giBad));
  const giNo = await _trackerFetch(env, 'garmininreach', 'none', {});
  ok('inreach: no share URL -> ok:false no_share_url, NO position (honest)', giNo.ok === false && giNo.reason === 'no_share_url' && !giNo.positions, JSON.stringify(giNo));

  // HONESTY: Starlink + Spire are routed to the universal connector client-side, NOT dedicated -> _trackerFetch fabricates nothing.
  globalThis.fetch = () => _mkr([{ latitude: 1, longitude: 2 }]);
  const sl = await _trackerFetch(env, 'starlink', 'anything', {});
  const spr = await _trackerFetch(env, 'spire', 'anything', {});
  ok('honesty: starlink + spire are NOT dedicated -> unknown_provider, NO fabricated position', sl.ok === false && sl.reason === 'unknown_provider' && !sl.positions && spr.ok === false && spr.reason === 'unknown_provider' && !spr.positions, JSON.stringify([sl, spr]));

  globalThis.fetch = _rfMar;
}

// ===================== #202b UNIVERSAL generic connector: ANY REST GPS platform connects for real (no simulation) =====================
// The tenant supplies api_url + an auth spec + JSON dot-paths; the token lives in the encrypted secret. We assert we parse REAL
// {lat,lng} from a mock feed, honor the configured field paths + auth styles, and REFUSE a private/SSRF host (no fake position).
{
  const _rfG = globalThis.fetch;

  // (a) plain array feed, default field names, Bearer auth, km/h -> mph
  globalThis.fetch = (u, o) => {
    const hdr = (o && o.headers) || {};
    return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ([{ id: 'd1', name: 'Van 1', lat: '30.27', lng: '-97.74', speed: 50, heading: 90, timestamp: '2026-07-31T00:00:00Z', _auth: hdr['Authorization'] }]) });
  };
  let g = await _trackerFetch(env, 'generic', 'TOK123', { api_url: 'https://gps.example.com/api/devices', auth: { type: 'bearer' }, speedUnit: 'kmh' });
  ok('generic: parses REAL {lat,lng} from a plain array feed (default paths)', g.ok && g.positions.length === 1 && g.positions[0].lat === 30.27 && g.positions[0].lng === -97.74, JSON.stringify(g).slice(0, 160));
  ok('generic: km/h -> mph + label/id/heading mapped', Math.round(g.positions[0].speed) === 31 && g.positions[0].label === 'Van 1' && g.positions[0].deviceId === 'd1' && g.positions[0].heading === 90, JSON.stringify(g.positions[0]));

  // (b) nested container + CUSTOM dot-paths + query-param auth (token appended to the URL)
  let capUrl = '';
  globalThis.fetch = (u) => { capUrl = String(u); return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ({ result: { devices: [{ serial: 'X9', gps: { coords: { y: 40.7128, x: -74.006 }, spd: 12 } }] } }) }); };
  g = await _trackerFetch(env, 'generic', 'KEY9', { api_url: 'https://host.example.com/v1/list', auth: { type: 'query', name: 'api-key' }, paths: { list: 'result.devices', lat: 'gps.coords.y', lng: 'gps.coords.x', speed: 'gps.spd', id: 'serial' } });
  ok('generic: custom dot-paths resolve nested lat/lng/id', g.ok && g.positions.length === 1 && g.positions[0].lat === 40.7128 && g.positions[0].lng === -74.006 && g.positions[0].deviceId === 'X9', JSON.stringify(g).slice(0, 160));
  ok('generic: query-param auth appends the token to the URL', capUrl.indexOf('api-key=KEY9') >= 0, capUrl);

  // (c) object-map of id->device (no list path) + custom header auth
  let capHdr = null;
  globalThis.fetch = (u, o) => { capHdr = (o && o.headers) || {}; return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ({ '55': { latitude: 51.5074, longitude: -0.1278, course: 180 }, '56': { latitude: 52.0, longitude: -1.0 } }) }); };
  g = await _trackerFetch(env, 'generic', 'SEKRET', { api_url: 'https://y.example.com/all', auth: { type: 'header', name: 'X-Api-Key' } });
  ok('generic: object-map of devices -> array of positions', g.ok && g.positions.length === 2 && g.positions[0].lat === 51.5074, JSON.stringify(g).slice(0, 160));
  ok('generic: custom header auth sets the named header to the token', capHdr && capHdr['X-Api-Key'] === 'SEKRET', JSON.stringify(capHdr));

  // (d) SSRF + honesty: a private/metadata/non-https api_url is REFUSED with NO fetch and NO fabricated position
  let fetched = false; globalThis.fetch = () => { fetched = true; return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ([{ lat: 1, lng: 2 }]) }); };
  const gSsrf = await _trackerFetch(env, 'generic', 'T', { api_url: 'https://169.254.169.254/latest/meta', auth: { type: 'bearer' } });
  ok('generic SSRF: metadata host refused, NO network call, NO position', gSsrf.ok === false && !gSsrf.positions && fetched === false, JSON.stringify(gSsrf) + ' fetched=' + fetched);
  const gHttp = await _trackerFetch(env, 'generic', 'T', { api_url: 'http://gps.example.com/x', auth: { type: 'bearer' } });
  ok('generic SSRF: non-https api_url refused (https_required), NO position', gHttp.ok === false && !gHttp.positions, JSON.stringify(gHttp));
  const gPriv = await _trackerFetch(env, 'generic', 'T', { api_url: 'https://10.0.0.5/x', auth: { type: 'bearer' } });
  ok('generic SSRF: private 10.x api_url refused (blocked_host), NO position', gPriv.ok === false && !gPriv.positions, JSON.stringify(gPriv));

  globalThis.fetch = _rfG;
}

// ===================== #202c newly-real DEDICATED providers parse REAL {lat,lng} from mocked official-API responses =====================
// Each brand's block is validated against a response shaped like its vendor's documented API (Wialon pos{x,y,s,c,t};
// Navixy get_states gps.location; Motive vehicle.current_location; Webfleet micro-degrees; Zubie vehicle_location.point;
// Azuga data[] epoch-ms; One Step GPS defensive latest_device_point). Speed-unit conversions + auth failures are asserted too.
{
  const _rfD = globalThis.fetch;
  const R = (json) => Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => json });

  // Wialon: token/login -> eid, then core/search_items -> items[].pos {x:lng, y:lat, s:km/h, c:course, t:unix}
  globalThis.fetch = (u) => { const s = String(u); if (s.indexOf('svc=token/login') >= 0) return R({ eid: 'SID123', user: { nm: 'a' } }); if (s.indexOf('/wialon/ajax.html') >= 0) return R({ items: [{ nm: 'Truck 1', id: 501, cls: 2, pos: { t: 1785000000, y: 30.27, x: -97.74, s: 100, c: 90 } }] }); return R({}); };
  let d = await _trackerFetch(env, 'wialon', 'WTOKEN', {});
  ok('wialon: REAL {lat,lng} from items[].pos (x=lng,y=lat) + km/h->mph + name', d.ok && d.positions.length === 1 && d.positions[0].lat === 30.27 && d.positions[0].lng === -97.74 && Math.round(d.positions[0].speed) === 62 && d.positions[0].label === 'Truck 1', JSON.stringify(d).slice(0, 180));
  globalThis.fetch = (u) => { if (String(u).indexOf('token/login') >= 0) return R({ error: 8 }); return R({}); };
  d = await _trackerFetch(env, 'wialon', 'BAD', {});
  ok('wialon: bad token -> auth, NO position (never fabricated)', d.ok === false && d.reason === 'auth' && !d.positions, JSON.stringify(d));

  // Navixy: /tracker/list then /tracker/get_states -> states{<id>:{gps:{location{lat,lng},speed(km/h),heading}}}
  globalThis.fetch = (u) => { const s = String(u); if (s.indexOf('/tracker/list') >= 0) return R({ success: true, list: [{ id: 111, label: 'Sprinter' }] }); if (s.indexOf('/tracker/get_states') >= 0) return R({ success: true, states: { '111': { gps: { updated: '2024-08-01 13:45:18', location: { lat: 45.0888968, lng: 10.0343262 }, speed: 64, heading: 304 }, movement_status: 'moving' } } }); return R({}); };
  d = await _trackerFetch(env, 'navixy', 'HASH', {});
  ok('navixy: REAL {lat,lng} from gps.location + km/h->mph + heading + label + moving', d.ok && d.positions.length === 1 && d.positions[0].lat === 45.0888968 && d.positions[0].lng === 10.0343262 && Math.round(d.positions[0].speed) === 40 && d.positions[0].heading === 304 && d.positions[0].label === 'Sprinter' && d.positions[0].moving === true, JSON.stringify(d).slice(0, 200));
  let navUrl = ''; globalThis.fetch = (u) => { navUrl = String(u); return R({ success: true, list: [] }); };
  d = await _trackerFetch(env, 'navixy', 'H', { host: 'https://api.eu.navixy.com/v2' });
  ok('navixy: honors the tenant region base host+path (eu /v2)', navUrl.indexOf('https://api.eu.navixy.com/v2/tracker/list') >= 0, navUrl);
  d = await _trackerFetch(env, 'navixy', 'H', { host: 'https://10.1.2.3/v2' });
  ok('navixy: SSRF private host refused, NO position', d.ok === false && !d.positions, JSON.stringify(d));

  // Motive v1: vehicles[].vehicle.current_location {lat, lon, speed(MPH), located_at, description}
  globalThis.fetch = (u, o) => R({ vehicles: [{ vehicle: { id: 23, number: 'V-1000', vin: '1FT123', current_location: { lat: 47.565647, lon: -122.276261, description: 'Seattle, WA', speed: 65.1, located_at: '2016-03-17T12:12:07Z', _k: ((o && o.headers) || {})['X-Api-Key'] } } }] });
  d = await _trackerFetch(env, 'motive', 'MKEY', {});
  ok('motive: REAL {lat,lon} from vehicle.current_location + MPH (no convert) + vin + number', d.ok && d.positions.length === 1 && d.positions[0].lat === 47.565647 && d.positions[0].lng === -122.276261 && Math.round(d.positions[0].speed) === 65 && d.positions[0].vin === '1FT123' && d.positions[0].label === 'V-1000', JSON.stringify(d).slice(0, 200));

  // Webfleet: bare array, MICRO-degrees latitude_mdeg/longitude_mdeg (/1e6), speed km/h, course=heading
  globalThis.fetch = (u, o) => R([{ objectno: 'OBJ7', objectname: 'Van 7', latitude_mdeg: 52123456, longitude_mdeg: -1234567, speed: 80, course: 270, pos_time: '2026-07-31T00:00:00Z', postext: 'M1', _auth: ((o && o.headers) || {})['Authorization'] }]);
  d = await _trackerFetch(env, 'webfleet', JSON.stringify({ account: 'a', username: 'u', password: 'p', apikey: 'k' }), {});
  ok('webfleet: micro-degrees /1e6 -> decimal {lat,lng} + km/h->mph + course', d.ok && d.positions.length === 1 && Math.abs(d.positions[0].lat - 52.123456) < 1e-9 && Math.abs(d.positions[0].lng - (-1.234567)) < 1e-9 && Math.round(d.positions[0].speed) === 50 && d.positions[0].heading === 270, JSON.stringify(d).slice(0, 200));
  globalThis.fetch = (u) => R([{ objectno: 'X', objectname: 'nofix', latitude_mdeg: 0, longitude_mdeg: 0 }]);
  d = await _trackerFetch(env, 'webfleet', JSON.stringify({ account: 'a', username: 'u', password: 'p' }), {});
  ok('webfleet: 0/0 no-fix sentinel dropped (not shown as a real position)', d.ok && d.positions.length === 0, JSON.stringify(d));
  d = await _trackerFetch(env, 'webfleet', JSON.stringify({ account: 'a' }), {});
  ok('webfleet: missing credentials -> auth, NO position', d.ok === false && d.reason === 'auth' && !d.positions, JSON.stringify(d));

  // Zubie (Zinc v2): vehicles[].vehicle_location.point {lat,lon}, speed_mph (nullable), nickname/key/vin
  globalThis.fetch = (u, o) => R({ vehicles: [{ key: 'veh_1', nickname: 'Blue Car', vin: 'ZUB123', vehicle_location: { point: { lat: 35.2271, lon: -80.8431 }, speed_mph: 42, heading: 120, timestamp: '2025-07-01T09:32:11-05:00', motion_status: 'moving', _auth: ((o && o.headers) || {})['Zubie-Api-Key'] } }] });
  d = await _trackerFetch(env, 'zubie', 'ZKEY', {});
  ok('zubie: REAL {lat,lon} from vehicle_location.point + mph + vin + nickname', d.ok && d.positions.length === 1 && d.positions[0].lat === 35.2271 && d.positions[0].lng === -80.8431 && d.positions[0].speed === 42 && d.positions[0].vin === 'ZUB123' && d.positions[0].label === 'Blue Car', JSON.stringify(d).slice(0, 200));
  globalThis.fetch = (u) => R({ vehicles: [{ key: 'k', nickname: 'n', vehicle_location: { point: { lat: 35, lon: -80 }, speed_mph: null, heading: null, motion_status: 'stopped' } }] });
  d = await _trackerFetch(env, 'zubie', 'K', {});
  ok('zubie: null speed/heading coerced to 0 (never fabricated)', d.ok && d.positions[0].speed === 0 && d.positions[0].heading === 0 && d.positions[0].moving === false, JSON.stringify(d.positions[0]));

  // Azuga: {data:[{lat,lng,speed(km/h),cog,dateAndTime(epoch ms),trackeeName,trackeeId}]}
  globalThis.fetch = (u, o) => R({ generatedAtInMillis: 1672843335000, data: [{ trackeeId: 't1', trackeeName: 'Pickup', lat: 33.5, lng: -112.1, speed: 64, cog: 45, dateAndTime: 1672843335000, deviceId: 'dev1', address: 'Phoenix' }], error: null });
  d = await _trackerFetch(env, 'azuga', 'ABEARER', {});
  ok('azuga: REAL {lat,lng} from data[] + km/h->mph + cog heading + epoch-ms ts', d.ok && d.positions.length === 1 && d.positions[0].lat === 33.5 && d.positions[0].lng === -112.1 && Math.round(d.positions[0].speed) === 40 && d.positions[0].heading === 45 && d.positions[0].ts === '2023-01-04T14:42:15.000Z', JSON.stringify(d.positions[0]));

  // One Step GPS: confirmed endpoint/auth; DEFENSIVE field extraction (latest_device_point.*); never fabricates on failure
  globalThis.fetch = (u) => R([{ device_id: 'osg1', display_name: 'Fleet 1', latest_device_point: { lat: 29.76, lng: -95.37, angle: 180, dt_tracker: '2026-07-31T00:00:00Z' } }]);
  d = await _trackerFetch(env, 'onestepgps', 'OKEY', {});
  ok('onestepgps: defensive parse of latest_device_point {lat,lng} + name/id/heading', d.ok && d.positions.length === 1 && d.positions[0].lat === 29.76 && d.positions[0].lng === -95.37 && d.positions[0].label === 'Fleet 1' && d.positions[0].deviceId === 'osg1' && d.positions[0].heading === 180, JSON.stringify(d).slice(0, 200));
  globalThis.fetch = (u) => R({ code: 403, message: 'login required' });
  d = await _trackerFetch(env, 'onestepgps', 'BAD', {});
  ok('onestepgps: bad key (code 403) -> auth, NO position (honest, no fake)', d.ok === false && d.reason === 'auth' && !d.positions, JSON.stringify(d));

  globalThis.fetch = _rfD;
}

// Route: /api/trackers/positions polls a NEWLY-REAL provider end-to-end; unconnected + unsupported-row tenants stay live:false.
if (sess) {
  const _rfR = globalThis.fetch;
  const HT = { cookie: 'atlas_sid=' + sess.id, 'x-csrf-token': sess.csrf };
  // owner connects Geotab through the SAME encrypted /api/integrations/connect (creds -> secret_enc; never returned to the client)
  await worker.fetch(mkReq('POST', '/api/integrations/connect', { headers: HT, body: { provider: 'geotab', secret: JSON.stringify({ server: 'my.geotab.com', database: 'db', user: 'u', password: 'p' }), kind: 'tracker', meta: {} } }), env, ctx);
  globalThis.fetch = (u, o) => {
    const url = String(u); let b = {}; try { b = JSON.parse((o && o.body) || '{}'); } catch (e) {}
    if (url.indexOf('/apiv1') >= 0 && b.method === 'Authenticate') return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ({ result: { credentials: { sessionId: 'S' }, path: 'ThisServer' } }) });
    if (url.indexOf('/apiv1') >= 0 && b.params && b.params.typeName === 'DeviceStatusInfo') return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ({ result: [{ device: { id: 'g1' }, latitude: 29.76, longitude: -95.37, speed: 0, bearing: 0, dateTime: '2026-07-31T00:00:00Z', isDriving: false }] }) });
    return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ({ result: [] }) });
  };
  const rPos = await worker.fetch(mkReq('POST', '/api/trackers/positions', { headers: HT, body: {} }), env, ctx);
  const jPos = await rPos.json();
  ok('route: /api/trackers/positions live:true + REAL geotab position (end-to-end, encrypted cred)', jPos.ok === true && jPos.live === true && jPos.provider === 'geotab' && jPos.positions && jPos.positions.length === 1 && jPos.positions[0].lat === 29.76, JSON.stringify(jPos).slice(0, 180));
  globalThis.fetch = _rfR;

  // Universal GENERIC connector end-to-end (fresh tenant so the WHERE provider IN(...) LIMIT 1 is unambiguous): the encrypted
  // meta (api_url + auth spec + JSON dot-paths) round-trips through the DB and the route parses a REAL {lat,lng} from the
  // tenant's OWN REST feed -- proving ANY REST GPS platform connects for real (no simulation, token applied from secret).
  const rEnv3 = makeEnv(); __resetSchemaReady(); await ensurePlatformSchema(rEnv3);
  await worker.fetch(mkReq('POST', '/api/auth/signup', { body: { email: 'trk3@x.com', password: 'correcthorsebatterystaple', business: 'Trk3' } }), rEnv3, ctx);
  const s3 = rEnv3.DB._db.prepare('SELECT id,csrf FROM sessions ORDER BY created_at DESC LIMIT 1').get();
  const H3 = { cookie: 'atlas_sid=' + s3.id, 'x-csrf-token': s3.csrf };
  await worker.fetch(mkReq('POST', '/api/integrations/connect', { headers: H3, body: { provider: 'generic', secret: 'GKEY', kind: 'tracker', meta: { api_url: 'https://gps.example.com/v1/list', auth: { type: 'query', name: 'api-key' }, paths: { list: 'result.devices', lat: 'gps.coords.y', lng: 'gps.coords.x' }, speedUnit: 'kmh' } } }), rEnv3, ctx);
  const _rfG3 = globalThis.fetch; let gCapUrl = '';
  globalThis.fetch = (u) => { gCapUrl = String(u); return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: async () => '', json: async () => ({ result: { devices: [{ gps: { coords: { y: 30.2672, x: -97.7431 } } }] } }) }); };
  const rG = await worker.fetch(mkReq('POST', '/api/trackers/positions', { headers: H3, body: {} }), rEnv3, ctx);
  const jG = await rG.json();
  ok('route: GENERIC connector live:true + REAL {lat,lng} via stored meta dot-paths (encrypted end-to-end)', jG.ok === true && jG.live === true && jG.provider === 'generic' && jG.positions && jG.positions.length === 1 && jG.positions[0].lat === 30.2672 && jG.positions[0].lng === -97.7431, JSON.stringify(jG).slice(0, 200));
  ok('route: GENERIC honored the tenant api_url + query-param auth token from encrypted meta', gCapUrl.indexOf('https://gps.example.com/v1/list') >= 0 && gCapUrl.indexOf('api-key=GKEY') >= 0, gCapUrl);
  globalThis.fetch = _rfG3;

  // a fresh tenant with NO connected tracker -> live:false, no positions (the server never emits a simulated one)
  const rEnv2 = makeEnv(); __resetSchemaReady(); await ensurePlatformSchema(rEnv2);   // fresh DB -> full migration pass (the module _pReady flag would otherwise skip the ALTER-only columns signup INSERTs)
  await worker.fetch(mkReq('POST', '/api/auth/signup', { body: { email: 'trk2@x.com', password: 'correcthorsebatterystaple', business: 'Trk2' } }), rEnv2, ctx);
  const s2 = rEnv2.DB._db.prepare('SELECT id,csrf FROM sessions ORDER BY created_at DESC LIMIT 1').get();
  const H2 = { cookie: 'atlas_sid=' + s2.id, 'x-csrf-token': s2.csrf };
  const rNo = await worker.fetch(mkReq('POST', '/api/trackers/positions', { headers: H2, body: {} }), rEnv2, ctx);
  const jNo = await rNo.json();
  ok('route: no connected provider -> live:false, no positions (honest preview stays client-only)', jNo.ok === true && jNo.live === false && !jNo.positions, JSON.stringify(jNo));

  // a tenant whose ONLY integration is an unsupported brand ('lojack') is NEVER polled -> live:false (the TRK_PROVIDERS gate holds)
  await worker.fetch(mkReq('POST', '/api/integrations/connect', { headers: H2, body: { provider: 'lojack', secret: 'x', kind: 'tracker', meta: {} } }), rEnv2, ctx);
  const rLj = await worker.fetch(mkReq('POST', '/api/trackers/positions', { headers: H2, body: {} }), rEnv2, ctx);
  const jLj = await rLj.json();
  ok('route: unsupported-provider row (lojack) not polled -> live:false, no positions', jLj.ok === true && jLj.live === false && !jLj.positions, JSON.stringify(jLj));
}

// ---- #362 MFA step-up enforcement (opt-in, per-user mfa_stepup). Proves: OFF by default = byte-identical (no gate);
// enabling requires an active MFA method + proof; ON gates account-delete + payment-processor connect but NOT a
// tracker/mailer connect; password OR a fresh factor (incl. a backup code = break-glass) satisfies it; disabling MFA
// clears step-up so there is never a stepup-on/factor-off limbo. Uses password/backup-code proof for determinism --
// the same _mfaCheckAnyFactor path the disable route (tested elsewhere) uses for emailed/TOTP codes. ----
{
  const envSU = makeEnv(); __resetSchemaReady(); await ensurePlatformSchema(envSU);
  const PW = 'correcthorsebatterystaple';
  await worker.fetch(mkReq('POST', '/api/auth/signup', { body: { email: 'su@x.com', password: PW, business: 'StepUp Co' } }), envSU, ctx);
  const tidSU = envSU.DB._db.prepare('SELECT id FROM tenants LIMIT 1').get().id;
  const uidSU = envSU.DB._db.prepare('SELECT id FROM users WHERE tenant_id=? LIMIT 1').get(tidSU).id;
  const sSU = envSU.DB._db.prepare('SELECT id,csrf FROM sessions WHERE tenant_id=? ORDER BY created_at DESC LIMIT 1').get(tidSU);
  const HSU = { cookie: 'atlas_sid=' + sSU.id, 'x-csrf-token': sSU.csrf };
  const suFlag = () => Number(envSU.DB._db.prepare('SELECT mfa_stepup FROM users WHERE id=?').get(uidSU).mfa_stepup || 0);

  // (1) DEFAULT OFF: status stepup:false; a payout-processor connect is NOT gated (byte-identical to pre-#362)
  let js = await (await worker.fetch(mkReq('GET', '/api/auth/mfa/status', { headers: HSU }), envSU, ctx)).json();
  ok('stepup: default OFF (status.stepup=false, method=off)', js.ok === true && js.stepup === false && js.method === 'off', JSON.stringify(js));
  let jc = await (await worker.fetch(mkReq('POST', '/api/integrations/connect', { headers: HSU, body: { provider: 'paypal', secret: 'PPX', meta: { client_id: 'CID' } } }), envSU, ctx)).json();
  ok('stepup OFF: paypal connect succeeds with NO code (no gate when off)', jc.ok === true && !jc.mfa_required, JSON.stringify(jc));

  // (2) cannot enable step-up without an MFA method (no-lockout invariant)
  let je = await (await worker.fetch(mkReq('POST', '/api/auth/mfa/stepup', { headers: HSU, body: { on: true, password: PW } }), envSU, ctx)).json();
  ok('stepup: enable refused while MFA off (reason:no_mfa) -> never strands a factor-less user', je.ok === false && je.reason === 'no_mfa' && suFlag() === 0, JSON.stringify(je));

  // (3) set up TOTP (yields 10 backup codes), then enable step-up. Enabling REQUIRES proof (wrong -> mfa_required, flag 0)
  let jSetup = await (await worker.fetch(mkReq('POST', '/api/auth/mfa/totp/setup', { headers: HSU, body: {} }), envSU, ctx)).json();
  const keyBytes = _b32decode(jSetup.secret), backup = jSetup.backup_codes || [];
  await worker.fetch(mkReq('POST', '/api/auth/mfa/totp/confirm', { headers: HSU, body: { code: await _totpAt(keyBytes, Math.floor(Date.now() / 1000), 30, 6) } }), envSU, ctx);
  let jbad = await (await worker.fetch(mkReq('POST', '/api/auth/mfa/stepup', { headers: HSU, body: { on: true, password: 'WRONGPASS' } }), envSU, ctx)).json();
  ok('stepup: enable with WRONG proof -> mfa_required, flag stays 0', jbad.ok === false && jbad.mfa_required === true && suFlag() === 0, JSON.stringify(jbad));
  let jon = await (await worker.fetch(mkReq('POST', '/api/auth/mfa/stepup', { headers: HSU, body: { on: true, password: PW } }), envSU, ctx)).json();
  ok('stepup: enable with correct password -> ok, DB flag=1', jon.ok === true && jon.stepup === true && suFlag() === 1, JSON.stringify(jon));
  let js2 = await (await worker.fetch(mkReq('GET', '/api/auth/mfa/status', { headers: HSU }), envSU, ctx)).json();
  ok('stepup: status now reports stepup:true', js2.stepup === true, JSON.stringify(js2));

  // (4) ON: a payout-processor connect now REQUIRES proof; a NON-payment (tracker) connect is UNaffected
  let jg = await (await worker.fetch(mkReq('POST', '/api/integrations/connect', { headers: HSU, body: { provider: 'square', secret: 'SQX', meta: { location_id: 'L1' } } }), envSU, ctx)).json();
  ok('stepup ON: square connect WITHOUT proof -> mfa_required (payout gated)', jg.ok === false && jg.mfa_required === true, JSON.stringify(jg));
  let jgp = await (await worker.fetch(mkReq('POST', '/api/integrations/connect', { headers: HSU, body: { provider: 'square', secret: 'SQX', meta: { location_id: 'L1' }, password: PW } }), envSU, ctx)).json();
  ok('stepup ON: square connect WITH correct password -> succeeds', jgp.ok === true && !jgp.mfa_required, JSON.stringify(jgp));
  let jtk = await (await worker.fetch(mkReq('POST', '/api/integrations/connect', { headers: HSU, body: { provider: 'geotab', secret: JSON.stringify({ server: 's', database: 'd', user: 'u', password: 'p' }), kind: 'tracker', meta: {} } }), envSU, ctx)).json();
  ok('stepup ON: NON-payment connect (geotab tracker) is NOT gated -> succeeds without a code', jtk.ok === true && !jtk.mfa_required, JSON.stringify(jtk));

  // (5) break-glass: a BACKUP CODE (a fresh factor) satisfies the gate on a payout connect
  let jbg = await (await worker.fetch(mkReq('POST', '/api/integrations/connect', { headers: HSU, body: { provider: 'paypal', secret: 'PPX2', meta: { client_id: 'CID2' }, code: backup[0] } }), envSU, ctx)).json();
  ok('stepup ON: a BACKUP CODE satisfies the gate (break-glass) -> paypal connect succeeds', jbg.ok === true && !jbg.mfa_required, JSON.stringify(jbg));

  // (6) ON: account-delete requires proof; wrong -> mfa_required (NOT deleted); right password -> deleted
  const planOf = () => String((envSU.DB._db.prepare('SELECT plan FROM tenants WHERE id=?').get(tidSU) || {}).plan || '');
  let jd0 = await (await worker.fetch(mkReq('POST', '/api/account/delete', { headers: HSU, body: { confirm: 'DELETE', reason: 'x' } }), envSU, ctx)).json();
  ok('stepup ON: account-delete WITHOUT proof -> mfa_required (not deleted)', jd0.mfa_required === true && planOf() !== 'deleted', JSON.stringify(jd0) + ' plan=' + planOf());
  let jd1 = await (await worker.fetch(mkReq('POST', '/api/account/delete', { headers: HSU, body: { confirm: 'DELETE', reason: 'x', password: PW } }), envSU, ctx)).json();
  ok('stepup ON: account-delete WITH correct password -> deleted', jd1.ok === true && planOf() === 'deleted', JSON.stringify(jd1) + ' plan=' + planOf());
}

// (7) disabling MFA clears the step-up flag (no stepup-on/factor-off limbo)
{
  const envSD = makeEnv(); __resetSchemaReady(); await ensurePlatformSchema(envSD);
  const PW = 'correcthorsebatterystaple';
  await worker.fetch(mkReq('POST', '/api/auth/signup', { body: { email: 'sd@x.com', password: PW, business: 'StepDown Co' } }), envSD, ctx);
  const tidSD = envSD.DB._db.prepare('SELECT id FROM tenants LIMIT 1').get().id;
  const uidSD = envSD.DB._db.prepare('SELECT id FROM users WHERE tenant_id=? LIMIT 1').get(tidSD).id;
  const sSD = envSD.DB._db.prepare('SELECT id,csrf FROM sessions WHERE tenant_id=? ORDER BY created_at DESC LIMIT 1').get(tidSD);
  const HSD = { cookie: 'atlas_sid=' + sSD.id, 'x-csrf-token': sSD.csrf };
  await worker.fetch(mkReq('POST', '/api/auth/mfa/email/enable', { headers: HSD, body: {} }), envSD, ctx);
  await worker.fetch(mkReq('POST', '/api/auth/mfa/stepup', { headers: HSD, body: { on: true, password: PW } }), envSD, ctx);
  ok('stepup: enabled before disable (flag=1)', Number(envSD.DB._db.prepare('SELECT mfa_stepup FROM users WHERE id=?').get(uidSD).mfa_stepup) === 1);
  await worker.fetch(mkReq('POST', '/api/auth/mfa/disable', { headers: HSD, body: { password: PW } }), envSD, ctx);
  const after = envSD.DB._db.prepare('SELECT mfa_method, mfa_stepup FROM users WHERE id=?').get(uidSD);
  ok('stepup: disabling MFA clears BOTH method and the step-up flag (no limbo)', (after.mfa_method === null || after.mfa_method === undefined) && Number(after.mfa_stepup || 0) === 0, JSON.stringify(after));
}

// ---- #363 admin-plane CSRF (audit SEC-P1) + SSRF host guard (SEC-P2). The owner-SESSION admin bridge is cookie-auth'd,
// so a state-changing admin request must prove same-origin intent (session CSRF token OR allow-listed Origin); a forged
// cross-site POST (foreign Origin, no token) is rejected. Reads are not gated. And the hardened _hostBlocked closes the
// IPv6-mapped-IPv4 metadata bypass on the tenant-URL guard. ----
{
  const envAC = makeEnv(); __resetSchemaReady(); await ensurePlatformSchema(envAC);
  await worker.fetch(mkReq('POST', '/api/auth/signup', { body: { email: 'owner@x.com', password: 'correcthorsebatterystaple', business: 'Owner Co', setupToken: 'setup-tok' } }), envAC, ctx);   // owner@x.com == makeEnv OWNER_EMAIL (reserved) -> claim it with OWNER_SETUP_TOKEN so the owner-session bridge activates
  const tAC = envAC.DB._db.prepare('SELECT id FROM tenants LIMIT 1').get().id;
  const sAC = envAC.DB._db.prepare('SELECT id,csrf FROM sessions WHERE tenant_id=? ORDER BY created_at DESC LIMIT 1').get(tAC);
  const cookieAC = 'atlas_sid=' + sAC.id;
  const rEvil = await worker.fetch(mkReq('POST', '/api/admin/competitors', { headers: { cookie: cookieAC, origin: 'https://evil.example' }, body: { url: 'https://good.example/x' } }), envAC, ctx);
  ok('admin CSRF: owner-session mutation from a FOREIGN origin without a CSRF token -> 403 (forgery blocked)', rEvil.status === 403, 'status=' + rEvil.status);
  const rOkAC = await worker.fetch(mkReq('POST', '/api/admin/competitors', { headers: { cookie: cookieAC, origin: 'https://atlasrental.io' }, body: { url: 'https://good.example/watch' } }), envAC, ctx);
  ok('admin CSRF: owner-session mutation from an ALLOW-LISTED origin passes the CSRF gate (console not broken)', rOkAC.status !== 403, 'status=' + rOkAC.status);
  const rGetAC = await worker.fetch(mkReq('GET', '/api/admin/overview', { headers: { cookie: cookieAC, origin: 'https://evil.example' } }), envAC, ctx);
  ok('admin CSRF: owner-session GET (read) is never CSRF-gated', rGetAC.status === 200, 'status=' + rGetAC.status);
  const rSsrf = await worker.fetch(mkReq('POST', '/api/admin/competitors', { headers: { cookie: cookieAC, origin: 'https://atlasrental.io' }, body: { url: 'https://[::ffff:169.254.169.254]/latest/meta-data/' } }), envAC, ctx);
  ok('SSRF: IPv6-mapped metadata literal rejected by the hardened host guard -> 400', rSsrf.status === 400, 'status=' + rSsrf.status);
}

// ---- #363 MONEY-OUT path (audit MONEY-P1: refund/capture/release were untested). Real routes + real DB + mocked Stripe:
// a refund delta-DEDUCTS revenue by exactly the refunded amount, is IDEMPOTENT on a re-click (no double-subtract) and
// stamps the refund id; capturing the security HOLD moves NO revenue (revenue is a running total; only a refund moves it). ----
{
  const envMO = makeEnv(); __resetSchemaReady(); await ensurePlatformSchema(envMO);
  envMO.STRIPE_WEBHOOK_SECRET = 'whsec_harness';
  await worker.fetch(mkReq('POST', '/api/auth/signup', { body: { email: 'mo@x.com', password: 'correcthorsebatterystaple', business: 'MoneyOut Co' } }), envMO, ctx);
  const tMO = envMO.DB._db.prepare('SELECT id FROM tenants LIMIT 1').get().id;
  const sMO = envMO.DB._db.prepare('SELECT id,csrf FROM sessions WHERE tenant_id=? ORDER BY created_at DESC LIMIT 1').get(tMO);
  const HMO = { cookie: 'atlas_sid=' + sMO.id, 'x-csrf-token': sMO.csrf };
  await worker.fetch(mkReq('POST', '/api/integrations/connect', { headers: HMO, body: { provider: 'stripe', secret: 'sk_test_HARNESS' } }), envMO, ctx);   // tenant Stripe key, encrypted at rest via the real route
  await envMO.DB.prepare("INSERT INTO bookings (id,tenant_id,customer_id,asset_id,starts,ends,status,revenue_cents,data,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
    .bind('BKMO', tMO, 'C', 'A', 1, 2, 'confirmed', 50000, JSON.stringify({ custEmail: 'c@x.com', paid: { balance: { pi: 'pi_bal', amountCents: 30000 }, security: { pi: 'pi_sec', amountCents: 20000, hold: { at: 1 } } } }), 1, 1000).run();
  const _rfMO = globalThis.fetch;
  const _okR = (obj) => Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, json: async () => obj, text: async () => JSON.stringify(obj) });
  globalThis.fetch = (u) => { const su = String(u);
    if (su.indexOf('/refunds') >= 0) return _okR({ id: 're_mo1', object: 'refund', status: 'succeeded' });
    if (/\/payment_intents\/[^/]+\/capture$/.test(su)) return _okR({ id: 'pi_sec', status: 'succeeded' });
    if (/\/payment_intents\/[^/]+\/cancel$/.test(su)) return _okR({ id: 'pi_sec', status: 'canceled' });
    return Promise.resolve({ ok: false, status: 404, headers: { get: () => null }, json: async () => ({}), text: async () => '' });
  };
  const _rev = () => Number(envMO.DB._db.prepare("SELECT revenue_cents FROM bookings WHERE id='BKMO'").get().revenue_cents);
  const rRef = await worker.fetch(mkReq('POST', '/api/pay/refund', { headers: HMO, body: { booking: 'BKMO', kind: 'balance', amountCents: 10000 } }), envMO, ctx);
  const jRef = await rRef.json();
  ok('money-out: refund succeeds + revenue delta-deducted 50000 -> 40000 (exact, never recompute)', rRef.status === 200 && jRef.ok !== false && _rev() === 40000, 'status=' + rRef.status + ' rev=' + _rev());
  const dMO = JSON.parse(envMO.DB._db.prepare("SELECT data FROM bookings WHERE id='BKMO'").get().data);
  ok('money-out: refund stamped the Stripe refund id (charge.refunded webhook cannot re-decrement)', Array.isArray(dMO.refundIds) && dMO.refundIds.indexOf('re_mo1') >= 0, JSON.stringify(dMO.refundIds));
  const rRef2 = await worker.fetch(mkReq('POST', '/api/pay/refund', { headers: HMO, body: { booking: 'BKMO', kind: 'balance', amountCents: 10000 } }), envMO, ctx);
  ok('money-out: a re-clicked identical refund is IDEMPOTENT -> revenue stays 40000 (no double-subtract)', _rev() === 40000, 'rev=' + _rev() + ' status=' + rRef2.status);
  const rCap = await worker.fetch(mkReq('POST', '/api/pay/capture', { headers: HMO, body: { booking: 'BKMO', kind: 'security', amountCents: 20000 } }), envMO, ctx);
  ok('money-out: capturing the security HOLD moves NO revenue (still 40000)', rCap.status === 200 && _rev() === 40000, 'status=' + rCap.status + ' rev=' + _rev());
  globalThis.fetch = _rfMO;
}

// ---- #363 BILLING coverage (audit BILLING-P1/P2: the three auto-charging loops -- dunning, platform-txn double-grant,
// credit-CAS -- shipped untested). ----
{
  // (1) credit CAS: a spend deducts exactly once (free first); insufficient is refused, balance unchanged
  const envB = makeEnv(); __resetSchemaReady(); await ensurePlatformSchema(envB);
  const _wk = Math.floor((Date.now() / 86400000 + 4) / 7);   // current credit week (no refill)
  await envB.DB.prepare("INSERT INTO tenants (id,name,created_at,updated_at) VALUES ('TB1','CreditCo',1,1)").run();
  await envB.DB.prepare("UPDATE tenants SET tier='pro', credits_free=10, credits_purchased=5, credits_week=? WHERE id='TB1'").bind(_wk).run();
  const r1 = await _creditOp(envB, 'TB1', 'pro', 3);
  const row1 = envB.DB._db.prepare("SELECT credits_free,credits_purchased FROM tenants WHERE id='TB1'").get();
  ok('billing credit-CAS: spend 3 of 15 -> ok, free 10->7 (deducts free first, persisted via CAS)', r1.ok === true && r1.balance === 12 && Number(row1.credits_free) === 7 && Number(row1.credits_purchased) === 5, JSON.stringify(r1) + ' ' + JSON.stringify(row1));
  const r2 = await _creditOp(envB, 'TB1', 'pro', 100);
  ok('billing credit-CAS: spend 100 of remaining 12 -> refused (ok:false), balance unchanged', r2.ok === false && r2.balance === 12, JSON.stringify(r2));

  // (2) dunning sweep: a FAILED retry reschedules +4d + attempts++, a SUCCESS stamps last, and attempts>=10 hits the cap
  const envD = makeEnv(); __resetSchemaReady(); await ensurePlatformSchema(envD);
  envD.PLATFORM_STRIPE_KEY = 'sk_test_dun';
  const NOWD = 2000000000000;
  for (const [id, inv, att] of [['TDF', 'inv_fail', 2], ['TDC', 'inv_cap', 10], ['TDS', 'inv_ok', 0]]) {
    await envD.DB.prepare("INSERT INTO tenants (id,name,created_at,updated_at) VALUES (?,?,1,1)").bind(id, id).run();
    await envD.DB.prepare("UPDATE tenants SET plan='past_due', dunning_invoice=?, dunning_next=1, dunning_attempts=? WHERE id=?").bind(inv, att, id).run();
  }
  const _rfD = globalThis.fetch;
  globalThis.fetch = (u) => { const su = String(u);
    if (su.indexOf('inv_fail/pay') >= 0) return Promise.resolve({ ok: false, status: 402, headers: { get: () => null }, json: async () => ({ error: { message: 'card_declined' } }), text: async () => '' });
    if (su.indexOf('inv_ok/pay') >= 0) return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, json: async () => ({ id: 'inv_ok', status: 'paid' }), text: async () => '' });
    return Promise.resolve({ ok: false, status: 404, headers: { get: () => null }, json: async () => ({}), text: async () => '' });
  };
  await _runDunning(envD, NOWD);
  const dF = envD.DB._db.prepare("SELECT dunning_next,dunning_attempts,dunning_last FROM tenants WHERE id='TDF'").get();
  const dC = envD.DB._db.prepare("SELECT dunning_next FROM tenants WHERE id='TDC'").get();
  const dS = envD.DB._db.prepare("SELECT dunning_last FROM tenants WHERE id='TDS'").get();
  ok('billing dunning: a FAILED retry reschedules +4d + attempts 2->3', Number(dF.dunning_attempts) === 3 && Number(dF.dunning_next) === NOWD + 4 * 86400000 && Number(dF.dunning_last) === NOWD, JSON.stringify(dF));
  ok('billing dunning: attempts>=10 hits the SAFETY CAP -> dunning_next cleared (stops auto-retry)', dC.dunning_next === null, JSON.stringify(dC));
  ok('billing dunning: a SUCCESSFUL pay stamps dunning_last (invoice.paid flips plan separately)', Number(dS.dunning_last) === NOWD, JSON.stringify(dS));
  globalThis.fetch = _rfD;

  // (3) platform-txn idempotency: a REPLAYED credit-pack checkout grants the 500 pack exactly ONCE (UNIQUE stripe_id + .new gate)
  const envT = makeEnv(); __resetSchemaReady(); await ensurePlatformSchema(envT);
  envT.STRIPE_WEBHOOK_SECRET = 'whsec_harness';
  await envT.DB.prepare("INSERT INTO tenants (id,name,created_at,updated_at) VALUES ('TTX','TxCo',1,1)").run();
  await envT.DB.prepare("UPDATE tenants SET credits_purchased=0 WHERE id='TTX'").run();
  const _rfT = globalThis.fetch;
  globalThis.fetch = () => Promise.resolve({ ok: false, status: 0, headers: { get: () => null }, json: async () => ({}), text: async () => '' });   // stub the receipt email
  const evtC = { id: 'evt_credit1', type: 'checkout.session.completed', data: { object: { id: 'cs_credit1', object: 'checkout.session', amount_total: 2500, metadata: { billing: 'credits', tenant: 'TTX', email: 'c@x.com', pack: '500' } } } };
  const bodyC = JSON.stringify(evtC); const tsC = Math.floor(Date.now() / 1000);
  const sigC = 't=' + tsC + ',v1=' + createHmac('sha256', 'whsec_harness').update(tsC + '.' + bodyC).digest('hex');
  await worker.fetch(mkReq('POST', '/api/stripe/webhook', { headers: { 'stripe-signature': sigC }, body: bodyC }), envT, ctx);
  await worker.fetch(mkReq('POST', '/api/stripe/webhook', { headers: { 'stripe-signature': sigC }, body: bodyC }), envT, ctx);   // REPLAY
  const cpT = Number(envT.DB._db.prepare("SELECT credits_purchased FROM tenants WHERE id='TTX'").get().credits_purchased);
  ok('billing platform-txn: a REPLAYED credit-pack checkout grants the 500 pack exactly ONCE (not 1000)', cpT === 500, 'credits_purchased=' + cpT);
  globalThis.fetch = _rfT;
}

// ---- #363 BOOKING coverage (audit BOOK-P1: the double-book overlap gate -- the crown-jewel invariant -- was untested).
// A published qty=1 asset accepts one booking; a SECOND overlapping booking by a DIFFERENT customer (so it is not deduped)
// is rejected 409, and exactly one active row persists (the loser is not stored). ----
{
  const envBK = makeEnv(); __resetSchemaReady(); await ensurePlatformSchema(envBK);
  const settings = JSON.stringify({ publicSite: { published: true, assets: [{ name: 'Model S', id: 'A1', qty: 1 }], config: {} } });
  const money = JSON.stringify({ rateModel: 'day', tax: 0, rules: [], extras: [] });
  await envBK.DB.prepare("INSERT INTO tenants (id,name,subdomain,plan,tier,money,settings,created_at,updated_at) VALUES ('TBK','BkCo','bkco','active','pro',?,?,1,1)").bind(money, settings).run();
  const _rfBK = globalThis.fetch; globalThis.fetch = () => Promise.resolve({ ok: false, status: 0, headers: { get: () => null }, json: async () => ({}), text: async () => '' });   // stub the confirmation email
  const START = Date.now() + 7 * 86400000;
  const bk = (email) => mkReq('POST', '/api/public/bkco/book', { body: { asset: 'Model S', start: START, periods: 2, email: email, name: 'Cust', phone: '5551234567' } });
  const rB1 = await worker.fetch(bk('c1@x.com'), envBK, ctx); const jB1 = await rB1.json();
  ok('booking double-book: first booking of a qty=1 asset succeeds', rB1.status === 200 && jB1.ok === true && !!jB1.ref, 'status=' + rB1.status + ' ' + JSON.stringify(jB1).slice(0, 100));
  const rB2 = await worker.fetch(bk('c2@x.com'), envBK, ctx); const jB2 = await rB2.json();
  ok('booking double-book: a SECOND overlapping booking (qty=1, different customer) is rejected 409', rB2.status === 409, 'status=' + rB2.status + ' ' + JSON.stringify(jB2).slice(0, 100));
  const nBK = Number(envBK.DB._db.prepare("SELECT COUNT(*) c FROM bookings WHERE tenant_id='TBK' AND LOWER(status) NOT IN ('cancelled','completed')").get().c);
  ok('booking double-book: exactly ONE active booking persisted (the losing row was not kept)', nBK === 1, 'active=' + nBK);
  globalThis.fetch = _rfBK;
}

// ---- #363 LEGAL (audit LEGAL-P1): the owner's posted cancellation policy is DISCLOSED IN the portal agreement the customer
// reads before paying, not merely referenced -- so a non-refundable term is provably shown before payment. ----
{
  const envL = makeEnv(); __resetSchemaReady(); await ensurePlatformSchema(envL);
  const settingsL = JSON.stringify({ legal: { cancelPolicy: 'NON-REFUNDABLE within 48 hours of pickup.' } });
  await envL.DB.prepare("INSERT INTO tenants (id,name,settings,created_at,updated_at) VALUES ('TL','LegalCo',?,1,1)").bind(settingsL).run();
  await envL.DB.prepare("INSERT INTO bookings (id,tenant_id,customer_id,asset_id,starts,ends,status,revenue_cents,data,portal_token,created_at,updated_at) VALUES ('BKL','TL','C','A',?,?,'pending',0,?,'PORTALTOKENLEGAL1',1,1)")
    .bind(Date.now() + 86400000, Date.now() + 3 * 86400000, JSON.stringify({ asset: 'Model S', quote: { totalCents: 50000 }, paid: {} })).run();
  const jL = await (await worker.fetch(mkReq('GET', '/api/portal/PORTALTOKENLEGAL1/data'), envL, ctx)).json();
  ok('legal: the owner cancellation policy is DISCLOSED in the portal agreement (shown before pay)', typeof jL.agreement === 'string' && jL.agreement.indexOf('NON-REFUNDABLE within 48 hours') >= 0, 'agreement tail=' + String(jL.agreement || '').slice(-70));
}

// logout CSRF: /api/auth/logout revokes the session, and atlas_sid is SameSite=None, so a cross-site POST could otherwise
// force-logout a signed-in owner. A cookie-authenticated logout with NO CSRF token must be rejected AND must not revoke;
// WITH the token it still works. (Run LAST -- it revokes `sess`.)
if (sess) {
  const rNo = await worker.fetch(mkReq('POST', '/api/auth/logout', { headers: { cookie: 'atlas_sid=' + sess.id } }), env, ctx);   // forged: cookie, no token
  const revNo = env.DB._db.prepare('SELECT revoked_at FROM sessions WHERE id=?').get(sess.id).revoked_at;
  ok('logout CSRF: tokenless cross-site logout -> 403 (force-logout blocked)', rNo.status === 403, 'status=' + rNo.status);
  ok('logout CSRF: session NOT revoked by the tokenless request', revNo == null, 'revoked_at=' + revNo);
  const rYes = await worker.fetch(mkReq('POST', '/api/auth/logout', { headers: { cookie: 'atlas_sid=' + sess.id, 'x-csrf-token': sess.csrf } }), env, ctx);   // legit: cookie + token
  const revYes = env.DB._db.prepare('SELECT revoked_at FROM sessions WHERE id=?').get(sess.id).revoked_at;
  ok('logout CSRF: with token -> 200 (real logout still works)', rYes.status === 200, 'status=' + rYes.status);
  ok('logout CSRF: session revoked after a valid logout', revYes != null && Number(revYes) > 0, 'revoked_at=' + revYes);
}

console.log('\nD1 HARNESS: PASS=' + PASS + ' FAIL=' + FAIL + (FAIL ? '  -- FAILURES' : '  -- all green'));
process.exit(FAIL ? 1 : 0);
