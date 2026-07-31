// Real-D1 test harness. A D1-compatible adapter backed by node:sqlite, loaded from schema.sql + the worker's own
// migrations (ensurePlatformSchema), driving the ACTUAL worker routes against a real database. Because it runs real
// SQLite, the mock can NEVER drift from the SQL -- the drift in the hand-written regex mocks is exactly what silently
// blocked deploys for days (see commit 23c756f). This is where schema-batch / CAS-monotonic / RTBF become provable.
//
// Run: node --experimental-sqlite test/d1harness.mjs        (needs Node >= 22.5 for node:sqlite)
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import worker, { ensurePlatformSchema, _bkPatch, _schemaVer, __resetSchemaReady, rateLimit, sendSms, sendEmail, _qbSyncBooking, _xeroSyncBooking, _paypalCreateOrder, _paypalCapture, _paypalCreditBooking, _squareCreateCheckout, _squareVerifyPaid, _squareCreditBooking, _trackerFetch, TRK_PROVIDERS } from '../worker.js';

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

  ok('TRK_PROVIDERS lists exactly the 6 really-integrated providers', Array.isArray(TRK_PROVIDERS) && TRK_PROVIDERS.length === 6 && ['bouncie', 'samsara', 'traccar', 'geotab', 'gpswox', 'flespi'].every((p) => TRK_PROVIDERS.indexOf(p) >= 0), JSON.stringify(TRK_PROVIDERS));

  globalThis.fetch = _rfTrk;
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
