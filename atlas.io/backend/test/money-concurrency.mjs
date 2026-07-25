// Atlas worker MONEY regression gate (#346). Drives the REAL /api/stripe/webhook route (real signature verify, real
// revenue-merge success loop, real charge.refunded + _bkRMW CAS path) against a mock D1 whose bookings table honors the
// optimistic-lock "WHERE updated_at IS ?" semantics. Protects the money-critical revenue_cents behavior against regression:
//   - a booking payment MERGES into revenue_cents (never overwrites cash/G5),
//   - a webhook REPLAY / checkout.session+payment_intent DUAL-FIRE counts the payment exactly once,
//   - two DIFFERENT payment slots both survive,
//   - a refund (charge.refunded) nets out of revenue and records the PaymentIntent,
//   - the ORDERING GUARD: a success arriving AFTER a refund for the same PI does NOT re-add its revenue.
// True concurrent interleaving is proven separately by the offline harness (money_cas_harness.js); this locks the
// idempotency + ordering + merge invariants into CI so they can't silently regress. Run:  node test/money-concurrency.mjs
import worker from '../worker.js';
import crypto from 'node:crypto';

const SECRET = 'whsec_test_regression';
function sign(raw) { const t = Math.floor(Date.now() / 1000); const v1 = crypto.createHmac('sha256', SECRET).update(t + '.' + raw).digest('hex'); return 't=' + t + ',v1=' + v1; }

function makeDB() {
  const bookings = new Map();   // id -> {id,tenant_id,data,revenue_cents,status,updated_at}
  const txns = new Map();       // stripe_id -> 1  (recordTxn OR IGNORE dedup)
  let clock = 1;
  const now = () => (++clock) + 1000000000000;
  function stmt(sql) {
    let a = [];
    const api = {
      bind: (...x) => { a = x; return api; },
      first: async () => {
        if (/FROM bookings WHERE id=\? AND tenant_id=\?/.test(sql)) { const r = bookings.get(a[0]); if (!r || r.tenant_id !== a[1]) return null; return { id: r.id, data: r.data, revenue_cents: r.revenue_cents, status: r.status, updated_at: r.updated_at }; }
        if (/FROM tenants WHERE id=\?/.test(sql)) return null;                 // -> no receipt email attempted
        if (/FROM platform_transactions WHERE stripe_id=\?/.test(sql)) return txns.get(a[0]) ? { stripe_id: a[0] } : null;
        if (/sqlite_master/.test(sql)) return { n: 30 };
        return null;                                                          // platform_config / rate_limits / everything else -> defaults
      },
      all: async () => ({ results: [] }),
      run: async () => {
        // CAS update on bookings -- the load-bearing part of the mock
        if (/UPDATE bookings SET data=\?, revenue_cents=\?, status=\?, updated_at=\? WHERE id=\? AND tenant_id=\? AND updated_at IS \?/.test(sql)) {
          const data = a[0], rev = a[1], status = a[2], id = a[4], tid = a[5], expU = a[6];
          const r = bookings.get(id);
          if (!r || r.tenant_id !== tid) return { meta: { changes: 0 } };
          if (r.updated_at !== expU) return { meta: { changes: 0 } };         // CAS miss -> caller re-reads + retries
          r.data = data; r.revenue_cents = rev; r.status = status; r.updated_at = now();
          return { meta: { changes: 1 } };
        }
        if (/INSERT OR IGNORE INTO platform_transactions/.test(sql)) { const sid = a[8]; if (txns.has(sid)) return { meta: { changes: 0 } }; txns.set(sid, 1); return { meta: { changes: 1 } }; }
        return { meta: { changes: 1, last_row_id: 1 } };
      },
    };
    return api;
  }
  return {
    prepare: stmt,
    seed: (id, tid, data, rev, status) => bookings.set(id, { id: id, tenant_id: tid, data: JSON.stringify(data), revenue_cents: rev, status: status || 'confirmed', updated_at: now() }),
    rev: (id) => bookings.get(id).revenue_cents,
    data: (id) => JSON.parse(bookings.get(id).data),
    status: (id) => bookings.get(id).status,
  };
}

const env = { DB: null, STRIPE_WEBHOOK_SECRET: SECRET, SESSION_KEY: 's', ENC_KEY: 'e', OWNER_EMAIL: 'o@x.com' };
const ctx = { waitUntil() {}, passThroughOnException() {} };

async function webhook(evt) {
  const raw = JSON.stringify(evt);
  const req = new Request('https://atlasrental.io/api/stripe/webhook', { method: 'POST', headers: { 'Content-Type': 'application/json', 'stripe-signature': sign(raw) }, body: raw });
  const res = await worker.fetch(req, env, ctx);
  return res.status;
}
function coEvt(booking, tenant, kind, amount, pi, extra) { return { type: 'checkout.session.completed', data: { object: Object.assign({ id: 'cs_' + Math.random().toString(36).slice(2), object: 'checkout.session', amount_total: amount, payment_intent: pi, metadata: Object.assign({ booking, tenant, kind }, extra || {}) }) } }; }
function piEvt(booking, tenant, kind, amount, pi) { return { type: 'payment_intent.succeeded', data: { object: { id: pi, object: 'payment_intent', amount: amount, payment_intent: pi, metadata: { booking, tenant, kind } } } }; }
function refundEvt(booking, tenant, pi, reId, amount) { return { type: 'charge.refunded', data: { object: { id: 'ch_' + Math.random().toString(36).slice(2), object: 'charge', payment_intent: pi, amount_refunded: amount, refunds: { data: [{ id: reId, amount: amount, payment_intent: pi }] }, metadata: { booking, tenant } } } }; }

let PASS = 0, FAIL = 0;
function ok(name, cond, extra) { if (cond) { PASS++; console.log('PASS ' + name); } else { FAIL++; console.log('FAIL ' + name + (extra ? (' -- ' + extra) : '')); } }

const run = async () => {
  const db = makeDB(); env.DB = db;
  db.seed('b1', 't1', { paid: {} }, 0, 'pending');
  db.seed('b2', 't1', { paid: {} }, 0, 'pending');

  // 1. deposit payment merges into revenue
  await webhook(coEvt('b1', 't1', 'deposit', 10000, 'pi_D'));
  ok('deposit merges to revenue 10000', db.rev('b1') === 10000, 'rev=' + db.rev('b1'));
  ok('deposit confirms booking', db.status('b1') === 'confirmed');

  // 2. exact replay -> counted once
  await webhook(coEvt('b1', 't1', 'deposit', 10000, 'pi_D'));
  ok('replay is idempotent (still 10000)', db.rev('b1') === 10000, 'rev=' + db.rev('b1'));

  // 3. payment_intent.succeeded dual-fire for the same payment -> still once
  await webhook(piEvt('b1', 't1', 'deposit', 10000, 'pi_D'));
  ok('checkout+payment_intent dual-fire counts once (10000)', db.rev('b1') === 10000, 'rev=' + db.rev('b1'));

  // 4. a DIFFERENT slot (owner charge) both survive
  await webhook(coEvt('b1', 't1', 'charge', 5000, 'pi_C', { charge: 'c1' }));
  ok('second slot adds (15000)', db.rev('b1') === 15000, 'rev=' + db.rev('b1'));
  ok('both payments present', !!db.data('b1').paid.deposit && !!db.data('b1').paid['charge:c1']);

  // 5. direct-in-Stripe refund of the deposit nets out + records the PI
  await webhook(refundEvt('b1', 't1', 'pi_D', 're_1', 10000));
  ok('refund nets out of revenue (5000)', db.rev('b1') === 5000, 'rev=' + db.rev('b1'));
  ok('refundedPIs records pi_D', (db.data('b1').refundedPIs || []).indexOf('pi_D') >= 0);

  // 5b. refund replay -> no double decrement
  await webhook(refundEvt('b1', 't1', 'pi_D', 're_1', 10000));
  ok('refund replay no double-decrement (5000)', db.rev('b1') === 5000, 'rev=' + db.rev('b1'));

  // 6. ORDERING GUARD: refund arrives BEFORE the success for the same PI (out-of-order delivery)
  await webhook(refundEvt('b2', 't1', 'pi_X', 're_9', 10000));   // rev 0 -> 0, stamps refundedPIs
  ok('early refund leaves revenue 0', db.rev('b2') === 0, 'rev=' + db.rev('b2'));
  await webhook(coEvt('b2', 't1', 'deposit', 10000, 'pi_X'));    // late success for the refunded PI
  ok('ORDERING GUARD: late success does NOT re-add revenue (stays 0)', db.rev('b2') === 0, 'rev=' + db.rev('b2'));

  // 7. E1 resurrection guard: a late payment webhook on a CANCELLED booking must not revive it
  db.seed('b3', 't1', { paid: {}, status: 'Cancelled' }, 0, 'cancelled');
  await webhook(coEvt('b3', 't1', 'balance', 10000, 'pi_C'));
  ok('E1: late webhook does NOT resurrect a cancelled booking (revenue stays 0)', db.rev('b3') === 0, 'rev=' + db.rev('b3'));
  ok('E1: cancelled status column preserved', db.status('b3') === 'cancelled', 'st=' + db.status('b3'));
  ok('E1: payment still recorded for reconciliation', !!db.data('b3').paid.balance);

  console.log('\nMONEY-CONCURRENCY: PASS=' + PASS + ' FAIL=' + FAIL);
  if (FAIL > 0) process.exit(1);
};
run().catch((e) => { console.error('money-concurrency threw:', e); process.exit(1); });
