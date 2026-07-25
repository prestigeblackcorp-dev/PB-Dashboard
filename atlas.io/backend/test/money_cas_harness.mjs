// Concurrency + idempotency harness for the #346 money CAS batch.
// Transcribes the ACTUAL worker algorithms (_bkRMW + the 3 endpoint mutates + the webhook inline loop)
// and drives forced interleavings against a mock D1 with real CAS-on-updated_at semantics.
var PASS = 0, FAIL = 0, LOG = [];
function ok(name, cond, extra) { if (cond) { PASS++; LOG.push("PASS " + name); } else { FAIL++; LOG.push("FAIL " + name + (extra ? (" -- " + extra) : "")); } }

function makeDB() {
  var rows = {}, clock = { t: 1000 };
  return {
    rows: rows,
    now: function () { return ++clock.t; },
    seed: function (id, data, rev, status) { rows[id] = { data: JSON.stringify(data), revenue_cents: rev, status: status || 'confirmed', updated_at: ++clock.t }; },
    select: function (id) { var r = rows[id]; if (!r) return null; return { id: id, data: r.data, revenue_cents: r.revenue_cents, status: r.status, updated_at: r.updated_at }; },
    // CAS: commit ONLY if updated_at unchanged since the caller's read (matches "WHERE updated_at IS ?")
    cas: function (id, data, rev, status, expUpd) { var r = rows[id]; if (!r) return { changes: 0 }; if (r.updated_at !== expUpd) return { changes: 0 }; r.data = data; r.revenue_cents = rev; r.status = status; r.updated_at = ++clock.t; return { changes: 1 }; },
    d: function (id) { return JSON.parse(rows[id].data); }
  };
}

// ---- _bkRMW transcription (worker.js helper) ----
function bkRMW(db, id, mutate, onBeforeFirstWrite) {
  var d = null, committed = false, tries = 0;
  for (var i = 0; i < 6 && !committed; i++) {
    var row = db.select(id);
    if (!row) return { committed: false, missing: true, d: null, tries: tries };
    d = JSON.parse(row.data); d.paid = d.paid || {};
    var out = mutate(d, row) || {};
    var rev = (typeof out.rev === 'number') ? Math.max(0, Math.round(out.rev)) : (Number(row.revenue_cents) || 0);
    var st = (out.status != null) ? out.status : row.status;
    if (i === 0 && onBeforeFirstWrite) onBeforeFirstWrite();   // force a racing commit between our read and our CAS write
    var u = db.cas(id, JSON.stringify(d), rev, st, row.updated_at);
    committed = !!(u && u.changes); tries++;
  }
  return { committed: committed, d: d, missing: false, tries: tries };
}

// ---- endpoint mutate transcriptions ----
function payRMW(db, id, kind, op, outcome, refThisOp, refId, onRace) {
  return bkRMW(db, id, function (dd, rr) {
    var pp = (dd.paid && dd.paid[kind]) || null;
    if (pp) { if (op === 'capture') { pp.captured = outcome.captured; delete pp.hold; } else if (op === 'release') { pp.released = outcome.released; delete pp.hold; } else if (op === 'refund') { pp.refunded = outcome.refunded; } }
    if (refId) { dd.refundIds = Array.isArray(dd.refundIds) ? dd.refundIds : []; if (dd.refundIds.indexOf(refId) < 0) dd.refundIds.push(refId); }
    dd._t = db.now();
    return { rev: (Number(rr.revenue_cents) || 0) - refThisOp };
  }, onRace);
}
function cancelRMW(db, id, patches, refIds, released, keepCents, onRace) {
  return bkRMW(db, id, function (dd, rr) {
    dd.paid = dd.paid || {};
    patches.forEach(function (pt) { if (dd.paid[pt.key]) dd.paid[pt.key].refunded = pt.refunded; });
    if (released && dd.paid.security && dd.paid.security.hold) { dd.paid.security.released = { at: db.now() }; delete dd.paid.security.hold; }
    if (refIds.length) { dd.refundIds = Array.isArray(dd.refundIds) ? dd.refundIds : []; refIds.forEach(function (rid) { if (dd.refundIds.indexOf(rid) < 0) dd.refundIds.push(rid); }); }
    dd.status = 'Cancelled'; dd.cancelledAt = db.now(); dd.cancelFee = keepCents / 100; dd._t = db.now();
    return { rev: Math.min(keepCents, Number(rr.revenue_cents) || 0), status: 'cancelled' };
  }, onRace);
}
function chargeRefundedRMW(db, id, rfId, rfPi, amt, onRace) {
  return bkRMW(db, id, function (_bd, _brb) {
    _bd.refundIds = Array.isArray(_bd.refundIds) ? _bd.refundIds : [];
    if (rfPi) { _bd.refundedPIs = Array.isArray(_bd.refundedPIs) ? _bd.refundedPIs : []; if (_bd.refundedPIs.indexOf(rfPi) < 0) _bd.refundedPIs.push(rfPi); }
    var seen = !!(rfId && _bd.refundIds.indexOf(rfId) >= 0);
    if (!seen && rfId) _bd.refundIds.push(rfId);
    _bd._t = db.now();
    return { rev: seen ? (Number(_brb.revenue_cents) || 0) : ((Number(_brb.revenue_cents) || 0) - Math.abs(amt)) };
  }, onRace);
}
// ---- webhook success inline-loop transcription (incl. E1 resurrection guard) ----
function webhookSuccess(db, id, kind, charge, amt, pi, stripeId, hold, onRace) {
  var d = null, committed = false, wasNew = false, wasCancelled = false, addApplied = 0;
  for (var i = 0; i < 6 && !committed; i++) {
    var row = db.select(id); if (!row) return { committed: false, wasNew: false, wasCancelled: false, d: null };
    d = JSON.parse(row.data); d.paid = d.paid || {};
    var isSec = (kind === 'security');
    var pkKey = (kind === 'charge' && charge) ? ('charge:' + charge) : (kind || 'payment');
    var slotHad = !!d.paid[pkKey];
    if (slotHad && d.paid[pkKey] && d.paid[pkKey].pi && String(d.paid[pkKey].pi) !== String(pi)) d.paid[pkKey + '#' + String(d.paid[pkKey].pi).slice(0, 40)] = d.paid[pkKey];
    d.paid[pkKey] = { at: db.now(), amountCents: amt, stripe: stripeId || '', pi: pi, hold: (isSec && hold) };
    var piRefunded = !!(pi && Array.isArray(d.refundedPIs) && d.refundedPIs.indexOf(pi) >= 0);
    var isCanx = (String(row.status || '').toLowerCase() === 'cancelled') || !!(d.status && /cancel/i.test(String(d.status)));   // E1
    var addRev = (!slotHad && !piRefunded && !isCanx && !(isSec && hold) && kind !== 'security') ? (Number(amt) || 0) : 0;
    var rev = Math.max(0, (Number(row.revenue_cents) || 0) + addRev);
    if (!(isSec && hold)) { if (kind !== 'security' && kind !== 'charge' && !isCanx) d.status = 'Confirmed'; }   // E1: never resurrect
    d._t = db.now();
    if (i === 0 && onRace) onRace();
    var u = db.cas(id, JSON.stringify(d), rev, (isCanx ? row.status : 'confirmed'), row.updated_at);   // E1: keep cancelled status column
    committed = !!(u && u.changes);
    if (committed) { wasNew = !slotHad; wasCancelled = isCanx; addApplied = addRev; }
  }
  return { committed: committed, wasNew: wasNew, wasCancelled: wasCancelled, d: d, addRev: addApplied };
}
// ---- E2: _graftServerPay + _bookingMirrorWrite transcription ----
function graftServerPay(clientD, serverD) {
  if (!clientD || typeof clientD !== 'object' || !serverD || typeof serverD !== 'object') return;
  if (serverD.paid && typeof serverD.paid === 'object') { if (!clientD.paid || typeof clientD.paid !== 'object') clientD.paid = {}; for (var k in serverD.paid) clientD.paid[k] = serverD.paid[k]; }
  ['refundIds', 'refundedPIs'].forEach(function (f) { if (Array.isArray(serverD[f])) { var arr = Array.isArray(clientD[f]) ? clientD[f] : []; serverD[f].forEach(function (x) { if (arr.indexOf(x) < 0) arr.push(x); }); clientD[f] = arr; } });
  if (serverD.portal && typeof serverD.portal === 'object') { if (!clientD.portal || typeof clientD.portal !== 'object') clientD.portal = {}; ['reservePaidAt', 'balancePaidAt', 'depositPaidAt'].forEach(function (f) { if (serverD.portal[f] != null) clientD.portal[f] = serverD.portal[f]; }); }
}
// cols/vals model the whitelisted write; clientData is the parsed body.data object (or null). Models the E2c revenue_cents re-check.
function bookingMirrorWrite(db, id, cols, vals, clientData, onRace) {
  var dataIdx = cols.indexOf('data');
  if (dataIdx < 0 || !clientData || typeof clientData !== 'object') {
    var row0 = db.select(id); if (!row0) return false;
    var st0 = row0.status; for (var ci = 0; ci < cols.length; ci++) { if (cols[ci] === 'status') st0 = vals[ci]; }
    db.rows[id].revenue_cents = row0.revenue_cents; db.rows[id].status = st0; db.rows[id].updated_at = db.now();
    return true;
  }
  var revIdx = cols.indexOf('revenue_cents');
  for (var _i = 0; _i < 6; _i++) {
    var row = db.select(id); if (!row) return false;
    graftServerPay(clientData, JSON.parse(row.data));
    if (_i === 0 && onRace) onRace();
    // E2c: drop the frozen G5 revenue estimate this attempt if a payment has since set the column (>0)
    var wCols = cols, wVals = vals;
    if (revIdx >= 0 && (Number(row.revenue_cents) || 0) > 0) { wCols = cols.slice(); wVals = vals.slice(); wCols.splice(revIdx, 1); wVals.splice(revIdx, 1); }
    var dIdx = wCols.indexOf('data'), rIdx = wCols.indexOf('revenue_cents');
    var v = wVals.slice(); v[dIdx] = JSON.stringify(clientData);
    var revToWrite = (rIdx >= 0) ? v[rIdx] : row.revenue_cents;
    var st = row.status; for (var ci2 = 0; ci2 < wCols.length; ci2++) { if (wCols[ci2] === 'status') st = v[ci2]; }
    var u = db.cas(id, v[dIdx], revToWrite, st, row.updated_at);
    if (u && u.changes) return true;
  }
  return false;
}

// ============ SCENARIOS ============
var db, r, d;

// S1: /cancel racing a deposit webhook (cancel reads rev=0 first; deposit lands mid-op)
db = makeDB(); db.seed('b1', { paid: {} }, 0, 'confirmed');
r = cancelRMW(db, 'b1', [], [], false, 5000, function () { webhookSuccess(db, 'b1', 'deposit', null, 10000, 'pi_D', 'cs_1', false); });
d = db.d('b1');
ok('S1 cancel-vs-deposit: kept clamps to the deposit that landed (5000)', db.rows['b1'].revenue_cents === 5000, 'rev=' + db.rows['b1'].revenue_cents);
ok('S1 cancel-vs-deposit: deposit payment NOT clobbered', !!d.paid.deposit, JSON.stringify(d.paid));
ok('S1 cancel-vs-deposit: status cancelled', db.rows['b1'].status === 'cancelled');
ok('S1 cancel-vs-deposit: cancel retried once', r.tries === 2, 'tries=' + r.tries);

// S2: /api/pay/refund (deposit) racing a charge webhook (different slots)
db = makeDB(); db.seed('b2', { paid: { deposit: { pi: 'pi_D', amountCents: 10000 } } }, 10000, 'confirmed');
r = payRMW(db, 'b2', 'deposit', 'refund', { refunded: { at: 1, amountCents: 10000 } }, 10000, 're_1',
  function () { webhookSuccess(db, 'b2', 'charge', 'c1', 5000, 'pi_C', 'cs_C', false); });
d = db.d('b2');
ok('S2 refund-vs-charge: charge survives, deposit refunded out (rev=5000)', db.rows['b2'].revenue_cents === 5000, 'rev=' + db.rows['b2'].revenue_cents);
ok('S2 refund-vs-charge: deposit.refunded stamped', !!(d.paid.deposit && d.paid.deposit.refunded));
ok('S2 refund-vs-charge: charge:c1 payment present', !!d.paid['charge:c1']);
ok('S2 refund-vs-charge: refundIds has re_1', (d.refundIds || []).indexOf('re_1') >= 0);

// S3: charge.refunded (direct-in-Stripe) racing a charge webhook
db = makeDB(); db.seed('b3', { paid: { deposit: { pi: 'pi_D', amountCents: 10000 } } }, 10000, 'confirmed');
r = chargeRefundedRMW(db, 'b3', 're_2', 'pi_D', 10000, function () { webhookSuccess(db, 'b3', 'charge', 'c1', 5000, 'pi_C', 'cs_C', false); });
d = db.d('b3');
ok('S3 chargeRefunded-vs-charge: charge survives, deposit netted (rev=5000)', db.rows['b3'].revenue_cents === 5000, 'rev=' + db.rows['b3'].revenue_cents);
ok('S3 chargeRefunded-vs-charge: refundedPIs has pi_D', (d.refundedPIs || []).indexOf('pi_D') >= 0);
ok('S3 chargeRefunded-vs-charge: charge:c1 present', !!d.paid['charge:c1']);

// S4: ORDERING GUARD -- charge.refunded arrives BEFORE the success for the same PI
db = makeDB(); db.seed('b4', { paid: {} }, 0, 'confirmed');
chargeRefundedRMW(db, 'b4', 're_3', 'pi_D', 10000, null);          // refund lands first (rev 0 -> 0, stamps refundedPIs)
var w4 = webhookSuccess(db, 'b4', 'deposit', null, 10000, 'pi_D', 'cs_D', false);   // late success for the SAME pi
ok('S4 ordering-guard: late success does NOT re-add revenue (rev=0)', db.rows['b4'].revenue_cents === 0, 'rev=' + db.rows['b4'].revenue_cents);
ok('S4 ordering-guard: success addRev suppressed', w4.addRev === 0, 'addRev=' + w4.addRev);

// S5: receipt dedup -- checkout.session + payment_intent dual-fire (same pi)
db = makeDB(); db.seed('b5', { paid: {} }, 0, 'confirmed');
var a = webhookSuccess(db, 'b5', 'deposit', null, 10000, 'pi_D', 'cs_D', false);   // 1st delivery
var b = webhookSuccess(db, 'b5', 'deposit', null, 10000, 'pi_D', 'pi_D', false);   // 2nd (payment_intent.succeeded)
ok('S5 dedup: 1st delivery is new (receipt fires)', a.wasNew === true);
ok('S5 dedup: 2nd delivery NOT new (no duplicate receipt)', b.wasNew === false);
ok('S5 dedup: revenue counted once (10000)', db.rows['b5'].revenue_cents === 10000, 'rev=' + db.rows['b5'].revenue_cents);

// S6: /api/pay/refund single (no race) deducts exactly once
db = makeDB(); db.seed('b6', { paid: { deposit: { pi: 'pi_D', amountCents: 10000 } } }, 10000, 'confirmed');
payRMW(db, 'b6', 'deposit', 'refund', { refunded: { amountCents: 10000 } }, 10000, 're_1', null);
d = db.d('b6');
ok('S6 refund single: rev -> 0', db.rows['b6'].revenue_cents === 0, 'rev=' + db.rows['b6'].revenue_cents);
ok('S6 refund single: deposit.refunded set', !!(d.paid.deposit && d.paid.deposit.refunded));

// S7: capture + release move NO revenue (only refund does)
db = makeDB(); db.seed('b7', { paid: { security: { pi: 'pi_S', hold: true, amountCents: 5000 } } }, 10000, 'confirmed');
payRMW(db, 'b7', 'security', 'capture', { captured: { amountCents: 5000 } }, 0, '', null);
ok('S7 capture: revenue unchanged (10000)', db.rows['b7'].revenue_cents === 10000, 'rev=' + db.rows['b7'].revenue_cents);
d = db.d('b7'); ok('S7 capture: hold cleared + captured stamped', !d.paid.security.hold && !!d.paid.security.captured);
db.seed('b7b', { paid: { security: { pi: 'pi_S', hold: true, amountCents: 5000 } } }, 8000, 'confirmed');
payRMW(db, 'b7b', 'security', 'release', { released: { at: 1 } }, 0, '', null);
ok('S7 release: revenue unchanged (8000) -- clean hold release does NOT zero cash', db.rows['b7b'].revenue_cents === 8000, 'rev=' + db.rows['b7b'].revenue_cents);

// S8: /cancel keep-50%-of-captured with a real refund (no race)
db = makeDB(); db.seed('b8', { paid: { deposit: { pi: 'pi_D', amountCents: 10000 } } }, 10000, 'confirmed');
cancelRMW(db, 'b8', [{ key: 'deposit', refunded: { amountCents: 5000 } }], ['re_c'], false, 5000, null);
d = db.d('b8');
ok('S8 cancel keep50: rev = kept 5000', db.rows['b8'].revenue_cents === 5000, 'rev=' + db.rows['b8'].revenue_cents);
ok('S8 cancel keep50: deposit.refunded=5000', d.paid.deposit.refunded && d.paid.deposit.refunded.amountCents === 5000);
ok('S8 cancel keep50: refundIds has re_c', (d.refundIds || []).indexOf('re_c') >= 0);
ok('S8 cancel keep50: cancelFee=50', d.cancelFee === 50);

// S9: charge.refunded replay-of-in-app -- rf.id already in refundIds -> NO double decrement
db = makeDB(); db.seed('b9', { paid: { deposit: { pi: 'pi_D', amountCents: 10000, refunded: { amountCents: 10000 } } }, refundIds: ['re_x'] }, 0, 'confirmed');
chargeRefundedRMW(db, 'b9', 're_x', 'pi_D', 10000, null);   // webhook for the SAME refund the in-app path already applied
ok('S9 refund-id-seen: no double decrement (rev stays 0)', db.rows['b9'].revenue_cents === 0, 'rev=' + db.rows['b9'].revenue_cents);

// S10: two DIFFERENT slot webhooks race (deposit + charge) -- the #344 property still holds with the new guard
db = makeDB(); db.seed('b10', { paid: {} }, 0, 'confirmed');
webhookSuccess(db, 'b10', 'deposit', null, 10000, 'pi_D', 'cs_D', false, function () { webhookSuccess(db, 'b10', 'charge', 'c1', 5000, 'pi_C', 'cs_C', false); });
d = db.d('b10');
ok('S10 two-slot race: both revenue deltas survive (15000)', db.rows['b10'].revenue_cents === 15000, 'rev=' + db.rows['b10'].revenue_cents);
ok('S10 two-slot race: both payments present', !!d.paid.deposit && !!d.paid['charge:c1']);

// ---- _bkPatch transcription (portal/cron server-side blob mutations) ----
function bkPatch(db, id, patch, onRace) {
  for (var _i = 0; _i < 6; _i++) {
    var row = db.select(id); if (!row) return false;
    var fd = JSON.parse(row.data);
    if (patch(fd) === false) return true;
    if (_i === 0 && onRace) onRace();
    var u = db.cas(id, JSON.stringify(fd), row.revenue_cents, row.status, row.updated_at);
    if (u && u.changes) return true;
  }
  return false;
}
// E2b: a portal action (sign) via _bkPatch racing a payment webhook -> the webhook's d.paid + revenue survive, sign applied
var _dbp = makeDB(); _dbp.seed('e2b', { paid: {} }, 0, 'confirmed');
bkPatch(_dbp, 'e2b', function (fd) { fd.portal = fd.portal || {}; fd.portal.signedAt = 12345; }, function () {
  webhookSuccess(_dbp, 'e2b', 'deposit', null, 10000, 'pi_D', 'cs_D', false);   // webhook lands mid-sign
});
ok('E2b portal-sign vs webhook: webhook d.paid.deposit survives', !!_dbp.d('e2b').paid.deposit, JSON.stringify(_dbp.d('e2b').paid));
ok('E2b portal-sign vs webhook: webhook revenue survives (10000)', _dbp.rows['e2b'].revenue_cents === 10000, 'rev=' + _dbp.rows['e2b'].revenue_cents);
ok('E2b portal-sign vs webhook: signedAt applied', _dbp.d('e2b').portal.signedAt === 12345);

// ===== E1: webhook must NOT resurrect a cancelled booking =====
// E11: a late payment webhook lands on an already-cancelled booking
db = makeDB(); db.seed('e11', { paid: {}, status: 'Cancelled' }, 0, 'cancelled');
var w11 = webhookSuccess(db, 'e11', 'balance', null, 10000, 'pi_L', 'cs_L', false);
ok('E11 resurrection: revenue stays 0 (not re-added)', db.rows['e11'].revenue_cents === 0, 'rev=' + db.rows['e11'].revenue_cents);
ok('E11 resurrection: status column stays cancelled', db.rows['e11'].status === 'cancelled', 'st=' + db.rows['e11'].status);
ok('E11 resurrection: d.status stays Cancelled', db.d('e11').status === 'Cancelled');
ok('E11 resurrection: payment still recorded for reconciliation', !!db.d('e11').paid.balance);
ok('E11 resurrection: wasCancelled flagged (reconciliation note, not receipt)', w11.wasCancelled === true);

// E12: a webhook whose CAS commits AFTER a cancel (cancel lands mid-loop) -> sees cancelled on re-read, does not resurrect
db = makeDB(); db.seed('e12', { paid: { deposit: { pi: 'pi_D', amountCents: 10000 } } }, 10000, 'confirmed');
var w12 = webhookSuccess(db, 'e12', 'balance', null, 5000, 'pi_B', 'cs_B', false, function () {
  // owner cancels mid-flight: keep 0, refund handled elsewhere; sets status cancelled + rev 0 via _bkRMW-style CAS
  cancelRMW(db, 'e12', [{ key: 'deposit', refunded: { amountCents: 10000 } }], ['re_z'], false, 0, null);
});
ok('E12 cancel-then-webhook: not resurrected, revenue stays 0', db.rows['e12'].revenue_cents === 0, 'rev=' + db.rows['e12'].revenue_cents);
ok('E12 cancel-then-webhook: status cancelled', db.rows['e12'].status === 'cancelled', 'st=' + db.rows['e12'].status);
ok('E12 cancel-then-webhook: late balance still recorded', !!db.d('e12').paid.balance);

// E13: NO regression -- a normal (non-cancelled) payment still confirms + adds revenue
db = makeDB(); db.seed('e13', { paid: {}, status: 'Pending' }, 0, 'pending');
webhookSuccess(db, 'e13', 'deposit', null, 10000, 'pi_D', 'cs_D', false);
ok('E13 no-regression: normal payment confirms', db.rows['e13'].status === 'confirmed');
ok('E13 no-regression: normal payment adds revenue', db.rows['e13'].revenue_cents === 10000, 'rev=' + db.rows['e13'].revenue_cents);

// ===== E2: booking mirror-save must preserve server payment fields =====
// E21: owner edit is NEWER by _t but MISSING d.paid (client never synced the webhook) -> graft preserves server d.paid
db = makeDB(); db.seed('e21', { paid: { deposit: { pi: 'pi_D', amountCents: 10000 } }, note: '' }, 10000, 'confirmed');
var _cl21 = { note: 'owner edit', _t: db.now() + 999999, paid: {} };   // client blob lacks the webhook's payment
bookingMirrorWrite(db, 'e21', ['data', 'updated_at'], [JSON.stringify(_cl21), db.now()], _cl21, null);
ok('E21 mirror-graft: server d.paid.deposit PRESERVED (not erased)', !!db.d('e21').paid.deposit, JSON.stringify(db.d('e21').paid));
ok('E21 mirror-graft: owner note edit still lands', db.d('e21').note === 'owner edit');

// E22: mirror-write racing a webhook (webhook commits between the mirror's read and its write) -> CAS re-reads + re-grafts
db = makeDB(); db.seed('e22', { paid: {}, note: '' }, 0, 'confirmed');
var _cl22 = { note: 'owner edit', _t: db.now() + 999999, paid: {} };
bookingMirrorWrite(db, 'e22', ['data', 'updated_at'], [JSON.stringify(_cl22), db.now()], _cl22, function () {
  webhookSuccess(db, 'e22', 'deposit', null, 10000, 'pi_D', 'cs_D', false);   // webhook lands mid-write
});
ok('E22 mirror-vs-webhook: webhook d.paid.deposit survives the owner save', !!db.d('e22').paid.deposit, JSON.stringify(db.d('e22').paid));
ok('E22 mirror-vs-webhook: webhook revenue survives (10000)', db.rows['e22'].revenue_cents === 10000, 'rev=' + db.rows['e22'].revenue_cents);
ok('E22 mirror-vs-webhook: owner note edit still lands', db.d('e22').note === 'owner edit');

// E23: a status-only mirror write (no data blob) uses the plain path, leaves d.paid untouched
db = makeDB(); db.seed('e23', { paid: { deposit: { pi: 'pi_D', amountCents: 10000 } } }, 10000, 'confirmed');
bookingMirrorWrite(db, 'e23', ['status', 'updated_at'], ['Returned', db.now()], null, null);
ok('E23 status-only: status updated', db.rows['e23'].status === 'Returned');
ok('E23 status-only: d.paid untouched', !!db.d('e23').paid.deposit);

// ===== G5c: the frozen cash-quote revenue estimate must not clobber a real webhook payment =====
// G5a: no race -> the cash-quote estimate is written (normal offline-cash booking)
db = makeDB(); db.seed('g5a', { paid: {}, quote: { total: 500 }, status: 'Confirmed' }, 0, 'confirmed');
var _cl5a = { quote: { total: 500 }, status: 'Confirmed', paid: {} };
bookingMirrorWrite(db, 'g5a', ['data', 'revenue_cents', 'updated_at'], [JSON.stringify(_cl5a), 50000, db.now()], _cl5a, null);
ok('G5a no-race: cash-quote estimate recorded (50000)', db.rows['g5a'].revenue_cents === 50000, 'rev=' + db.rows['g5a'].revenue_cents);

// G5b: a $3 webhook lands between the mirror's read and write -> the frozen $500 estimate is DROPPED, the real 300 survives
db = makeDB(); db.seed('g5b', { paid: {}, quote: { total: 500 }, status: 'Confirmed' }, 0, 'confirmed');
var _cl5b = { quote: { total: 500 }, status: 'Confirmed', paid: {} };
bookingMirrorWrite(db, 'g5b', ['data', 'revenue_cents', 'updated_at'], [JSON.stringify(_cl5b), 50000, db.now()], _cl5b, function () {
  webhookSuccess(db, 'g5b', 'reserve', null, 300, 'pi_R', 'cs_R', false);   // real $3 online payment lands mid-write
});
ok('G5b clobber-guard: real webhook revenue survives (300, NOT the 50000 estimate)', db.rows['g5b'].revenue_cents === 300, 'rev=' + db.rows['g5b'].revenue_cents);
ok('G5b clobber-guard: webhook d.paid.reserve preserved', !!db.d('g5b').paid.reserve, JSON.stringify(db.d('g5b').paid));

// ---- summary ----
LOG.push(""); LOG.push("PASS=" + PASS + " FAIL=" + FAIL);
console.log(LOG.join("\n"));
if (FAIL > 0) process.exit(1);
