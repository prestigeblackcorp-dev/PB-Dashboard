// Atlas platform-STAFF capability simulation -- the security proof for WAVE-RBAC1.
// Runs under Node (CI gate) AND jsc (local). Imports the SAME pure model the worker
// enforces with (caps.mjs), so what passes here is what the live gate does.
//
//   node test/staff_caps.mjs      (CI)
//   jsc -m test/staff_caps.mjs    (local)
//
// Proves: (1) ZERO behaviour change -- the role presets agree route-by-route with the
// pre-RBAC gate (OWNER_ONLY / STAFF_READ / SUPPORT_WRITE); (2) the HARD RAIL -- no
// capability grant, not even ALL of them, can reach a destructive / real-money / secret /
// owner-management route; (3) persona scoping; (4) a full Support-HQ ticket+bug workflow at
// the permission layer; (5) forged / malformed caps can never grant.

import { STAFF_CAPS, OWNER_ONLY_CAPS, _defaultStaffCaps, _effectiveStaffCaps, _staffCan, _staffSeeMoney, _parseCaps, _capForRoute, ATLAS_CAPS_VERSION } from '../caps.mjs';

function log(s) { try { if (typeof console !== 'undefined' && console.log) console.log(s); else print(s); } catch (e) { try { print(s); } catch (_) { } } }
let fails = 0, passes = 0;
function ok(c, m) { if (c) { passes++; } else { fails++; log('  FAIL: ' + m); } }

// ---- the PRE-RBAC gate, copied VERBATIM from worker.js, to prove equivalence ----
const OWNER_ONLY = /^\/api\/admin\/(delete|purge|restore|grant|members|transactions|purchases|config|roles|staff|backup|export-tenant|social\/(connect|disconnect|publish)|payments\/(testcharge|testsub|dedup-subs|selftest|reconcile|recover|square-selftest)|payments-ledger|domains\/(testregister|selftest|dnsraw)|competitors|ai[/-]|counsel|brief|bans?|unban|attacks|alerts|security-log|errors|seo-health|site-uptime|funnel|analytics\/|monitor\/|pnl|founder-costs|push\/|owners?|owner\/)/;
const SUPPORT_WRITE = /^\/api\/admin\/(feedback\/update|ticket-reply|ticket-status|ticket-claim|ticket-workstate|ticket-note|inbox\/(status|reply))$/;   // WAVE-SUPPORT-DEPT1: kept verbatim in lockstep with worker.js -- claim/workstate/note join the support write-set; ticket-assign (supervisor) does NOT.
const STAFF_READ = /^\/api\/admin\/(config|overview|visits|visits-geo|growth-data|social|tickets|inbox|feedback)$/;
function legacyAllow(role, method, path) {
  if (role === 'owner') return true;
  if (method === 'GET') { const ownerOnly = OWNER_ONLY.test(path) && path !== '/api/admin/config'; return !ownerOnly && STAFF_READ.test(path); }
  return role === 'support' && SUPPORT_WRITE.test(path);
}
function capAllow(role, method, path, capsJson) { return _staffCan(_effectiveStaffCaps(role, capsJson), method, path); }

// ---- comprehensive admin route universe (staff-safe + owner-only + destructive) ----
const ROUTES = [
  ['GET', '/api/admin/config'], ['GET', '/api/admin/overview'], ['GET', '/api/admin/visits'], ['GET', '/api/admin/visits-geo'],
  ['GET', '/api/admin/growth-data'], ['GET', '/api/admin/social'], ['GET', '/api/admin/tickets'], ['GET', '/api/admin/inbox'], ['GET', '/api/admin/feedback'],
  ['POST', '/api/admin/ticket-reply'], ['POST', '/api/admin/ticket-status'], ['POST', '/api/admin/inbox/reply'], ['POST', '/api/admin/inbox/status'], ['POST', '/api/admin/feedback/update'],
  ['POST', '/api/admin/ticket-claim'], ['POST', '/api/admin/ticket-workstate'], ['POST', '/api/admin/ticket-note'], ['POST', '/api/admin/ticket-assign'], ['GET', '/api/admin/ticket-agents'],   // WAVE-SUPPORT-DEPT1: claim-to-own + lifecycle + notes (support preset) and reassign (supervisor-only); WAVE-SUPPORT-DEPT2: ticket-agents roster read (supervisor-only)
  ['GET', '/api/admin/members'], ['GET', '/api/admin/transactions'], ['GET', '/api/admin/purchases'], ['GET', '/api/admin/payments-ledger'],
  ['GET', '/api/admin/pnl'], ['GET', '/api/admin/founder-costs'], ['GET', '/api/admin/security-log'], ['GET', '/api/admin/errors'],
  ['GET', '/api/admin/bans'], ['GET', '/api/admin/attacks'], ['GET', '/api/admin/alerts'], ['GET', '/api/admin/counsel'], ['GET', '/api/admin/brief'],
  ['GET', '/api/admin/seo-health'], ['GET', '/api/admin/site-uptime'], ['GET', '/api/admin/monitor/uptime'], ['GET', '/api/admin/funnel'],
  ['GET', '/api/admin/analytics/funnel'], ['GET', '/api/admin/owners'], ['GET', '/api/admin/backup'], ['GET', '/api/admin/export-tenant'], ['GET', '/api/admin/report/compliance'],
  ['POST', '/api/admin/grant'], ['POST', '/api/admin/delete'], ['POST', '/api/admin/purge'], ['POST', '/api/admin/restore'],
  ['POST', '/api/admin/config'], ['POST', '/api/admin/staff'], ['POST', '/api/admin/staff/caps'], ['POST', '/api/admin/staff/revoke'],
  ['POST', '/api/admin/ban'], ['POST', '/api/admin/unban'], ['POST', '/api/admin/social'], ['POST', '/api/admin/social/connect'],
  ['POST', '/api/admin/payments/testcharge'], ['POST', '/api/admin/payments/recover'], ['POST', '/api/admin/payments/dedup-subs'],
  ['POST', '/api/admin/owner/freeze'], ['POST', '/api/admin/owner/reset-creds'], ['POST', '/api/admin/owner/delete'],
  ['POST', '/api/admin/ai/nl-query'], ['POST', '/api/admin/ai/copilot'], ['POST', '/api/admin/ai/ticket-draft'], ['POST', '/api/admin/ai/growth'],
  ['POST', '/api/admin/competitors'], ['POST', '/api/admin/ai/competitor-deep'], ['GET', '/api/admin/domains/selftest'], ['POST', '/api/admin/domains/testregister'],
];

log('Atlas staff-capability simulation  (caps v' + ATLAS_CAPS_VERSION + ')');

// ===== TEST 1: preset equivalence -- ZERO behaviour change for capless support/analyst =====
['support', 'analyst'].forEach(function (role) {
  ROUTES.forEach(function (r) {
    const legacy = legacyAllow(role, r[0], r[1]);
    const viaCap = capAllow(role, r[0], r[1], null);   // null caps -> role preset
    ok(legacy === viaCap, 'preset ' + role + ' ' + r[0] + ' ' + r[1] + ' : legacy=' + legacy + ' cap=' + viaCap);
  });
});
// owner is unconditionally allowed in both models
ROUTES.forEach(function (r) { ok(legacyAllow('owner', r[0], r[1]) === true, 'owner allowed ' + r[0] + ' ' + r[1]); });

// ===== TEST 2: HARD RAIL -- no grant (not even ALL caps) reaches a non-delegable route =====
const ALLCAPS = STAFF_CAPS.map(function (c) { return c.key; });
const DANGER = [
  ['POST', '/api/admin/grant'], ['POST', '/api/admin/delete'], ['POST', '/api/admin/purge'], ['GET', '/api/admin/backup'],
  ['GET', '/api/admin/export-tenant'], ['POST', '/api/admin/config'], ['POST', '/api/admin/staff'], ['POST', '/api/admin/staff/caps'],
  ['POST', '/api/admin/payments/testcharge'], ['POST', '/api/admin/payments/recover'], ['POST', '/api/admin/owner/reset-creds'],
  ['POST', '/api/admin/owner/delete'], ['POST', '/api/admin/ban'], ['GET', '/api/admin/security-log'], ['GET', '/api/admin/transactions'],
  ['GET', '/api/admin/payments-ledger'], ['GET', '/api/admin/pnl'], ['POST', '/api/admin/ai/nl-query'], ['POST', '/api/admin/social/connect'],
  ['POST', '/api/admin/domains/testregister'], ['POST', '/api/admin/competitors'],
];
DANGER.forEach(function (r) { ok(_staffCan(ALLCAPS, r[0], r[1]) === false, 'HARD RAIL: all-caps staff DENIED ' + r[0] + ' ' + r[1]); });

// ===== TEST 3: persona scoping =====
const ticketsOnly = ['hq.console', 'support.tickets.view', 'support.tickets.act'];
ok(_staffCan(ticketsOnly, 'GET', '/api/admin/tickets') === true, 'tickets-only: can view tickets');
ok(_staffCan(ticketsOnly, 'POST', '/api/admin/ticket-reply') === true, 'tickets-only: can reply tickets');
ok(_staffCan(ticketsOnly, 'GET', '/api/admin/feedback') === false, 'tickets-only: CANNOT view bugs');
ok(_staffCan(ticketsOnly, 'POST', '/api/admin/feedback/update') === false, 'tickets-only: CANNOT triage bugs');
ok(_staffCan(ticketsOnly, 'GET', '/api/admin/members') === false, 'tickets-only: CANNOT view members');
ok(_staffSeeMoney('support', JSON.stringify(ticketsOnly)) === false, 'tickets-only: CANNOT see money');
ok(_staffCan(ticketsOnly, 'POST', '/api/admin/ticket-claim') === true, 'tickets-only: can claim-to-own');
ok(_staffCan(ticketsOnly, 'POST', '/api/admin/ticket-workstate') === true, 'tickets-only: can drive the internal lifecycle');
ok(_staffCan(ticketsOnly, 'POST', '/api/admin/ticket-note') === true, 'tickets-only: can add internal notes');
ok(_staffCan(ticketsOnly, 'POST', '/api/admin/ticket-assign') === false, 'tickets-only: CANNOT reassign others (supervisor-only)');
ok(_staffCan(ticketsOnly, 'GET', '/api/admin/ticket-agents') === false, 'tickets-only: CANNOT read the agent roster (supervisor-only)');
const supervisor = ['hq.console', 'support.tickets.view', 'support.tickets.act', 'support.supervise'];
ok(_staffCan(supervisor, 'POST', '/api/admin/ticket-assign') === true, 'supervisor (support.supervise): CAN reassign a ticket to another agent');
ok(_staffCan(supervisor, 'GET', '/api/admin/ticket-agents') === true, 'supervisor: CAN read the agent roster for the reassign picker');
ok(_staffCan(supervisor, 'POST', '/api/admin/ticket-claim') === true, 'supervisor: can also claim');
ok(_staffCan(supervisor, 'POST', '/api/admin/grant') === false, 'supervisor: still blocked from comp/grant (hard rail)');
ok(_staffCan(supervisor, 'GET', '/api/admin/members') === false, 'supervisor: still cannot view members (not granted)');

const viewer = ['hq.console', 'ops.overview', 'support.tickets.view', 'support.inbox.view', 'support.bugs.view', 'analytics.view', 'social.view', 'members.view'];
ok(_staffCan(viewer, 'GET', '/api/admin/tickets') === true, 'viewer: can view tickets');
ok(_staffCan(viewer, 'POST', '/api/admin/ticket-reply') === false, 'viewer: CANNOT reply (read-only)');
ok(_staffCan(viewer, 'GET', '/api/admin/members') === true, 'viewer: can view members (granted)');
ok(_staffSeeMoney('support', JSON.stringify(viewer)) === false, 'viewer: no money');

const lead = ['hq.console', 'ops.overview', 'support.tickets.view', 'support.tickets.act', 'support.bugs.view', 'support.bugs.act', 'money.view'];
ok(_staffSeeMoney('support', JSON.stringify(lead)) === false, 'lead (support + money.view cap): CANNOT see money -- full company money data is ANALYST-ROLE ONLY, so the cap is inert on a non-analyst');
ok(_staffCan(lead, 'GET', '/api/admin/members') === false, 'lead: still cannot view members (not granted)');
ok(_staffCan(lead, 'POST', '/api/admin/grant') === false, 'lead: cannot comp/grant (hard rail)');
// ----- money visibility is ANALYST-ROLE ONLY (owner policy: "only analysts see full company data spreads") -----
ok(_staffSeeMoney('analyst', null) === true, 'analyst (capless preset): sees money');
ok(_staffSeeMoney('analyst', JSON.stringify(['ops.overview', 'money.view'])) === true, 'analyst + explicit money.view: sees money');
ok(_staffSeeMoney('analyst', JSON.stringify(['ops.overview'])) === false, 'analyst with money.view un-ticked: does NOT see money (owner can hide MRR even from an analyst)');
ok(_staffSeeMoney('support', JSON.stringify(['money.view'])) === false, 'support + money.view cap: NEVER sees money (analyst-role only)');
ok(_staffSeeMoney('support', null) === false, 'support (capless preset): no money');

// ===== TEST 4: Support-HQ workflow simulation -- a support agent handling a test ticket + bug =====
const agent = JSON.stringify(_defaultStaffCaps('support'));
ok(capAllow('support', 'GET', '/api/admin/tickets', agent), 'support agent: open the ticket queue');
ok(capAllow('support', 'GET', '/api/admin/feedback', agent), 'support agent: open the bug queue');
ok(capAllow('support', 'GET', '/api/admin/inbox', agent), 'support agent: open the inbox');
ok(capAllow('support', 'POST', '/api/admin/ticket-reply', agent), 'support agent: reply to a test ticket');
ok(capAllow('support', 'POST', '/api/admin/ticket-status', agent), 'support agent: close a test ticket');
ok(capAllow('support', 'POST', '/api/admin/feedback/update', agent), 'support agent: triage a test bug report');
ok(capAllow('support', 'POST', '/api/admin/ticket-claim', agent), 'support agent: claim a test ticket (claim-to-own)');
ok(capAllow('support', 'POST', '/api/admin/ticket-workstate', agent), 'support agent: advance a test ticket through its lifecycle');
ok(capAllow('support', 'POST', '/api/admin/ticket-note', agent), 'support agent: add an internal note to a test ticket');
ok(!capAllow('support', 'POST', '/api/admin/ticket-assign', agent), 'support agent: BLOCKED from reassigning others (supervisor-only)');
ok(!capAllow('support', 'GET', '/api/admin/ticket-agents', agent), 'support agent: BLOCKED from the agent roster (supervisor-only)');
ok(!capAllow('support', 'GET', '/api/admin/members', agent), 'support agent: BLOCKED from members directory');
ok(!capAllow('support', 'POST', '/api/admin/grant', agent), 'support agent: BLOCKED from comp/grant');
ok(!capAllow('support', 'GET', '/api/admin/payments-ledger', agent), 'support agent: BLOCKED from the money ledger');
ok(!capAllow('support', 'POST', '/api/admin/staff', agent), 'support agent: BLOCKED from minting staff');
ok(!capAllow('support', 'POST', '/api/admin/delete', agent), 'support agent: BLOCKED from deleting tenants');

// ===== TEST 5: forged / malformed caps can never grant =====
ok(_parseCaps(null) === null, 'parse: null -> preset');
ok(_parseCaps('') === null, 'parse: empty string -> preset');
ok(_parseCaps('not json') === null, 'parse: malformed JSON -> preset (fail safe)');
ok(JSON.stringify(_parseCaps('[]')) === '[]', 'parse: explicit [] -> empty (locked out)');
ok(JSON.stringify(_parseCaps(JSON.stringify(['support.tickets.view', '__forged__', 'x.staff', 'members.view']))) === JSON.stringify(['support.tickets.view', 'members.view']), 'parse: drops unknown + owner-only(x.*) keys');
ok(_staffCan(['x.staff', 'x.members.grant', 'x.settings.backup'], 'POST', '/api/admin/staff') === false, 'forged owner-only caps grant NOTHING');
ok(_staffCan(['x.settings.backup'], 'GET', '/api/admin/backup') === false, 'forged backup cap cannot reach backup');
ok(_staffCan([], 'GET', '/api/admin/tickets') === false, 'empty caps reach nothing');
ok(_staffCan(null, 'GET', '/api/admin/tickets') === false, 'null caps array reaches nothing');

// ===== TEST 6: taxonomy sanity =====
ok(STAFF_CAPS.length > 0 && OWNER_ONLY_CAPS.length > 0, 'taxonomy present');
const delegableKeys = {}; STAFF_CAPS.forEach(function (c) { delegableKeys[c.key] = 1; });
OWNER_ONLY_CAPS.forEach(function (c) { ok(!delegableKeys[c.key], 'owner-only cap not delegable: ' + c.key); });
ok(_capForRoute('POST', '/api/admin/ticket-reply') === 'support.tickets.act', '_capForRoute maps ticket-reply');
ok(_capForRoute('POST', '/api/admin/ticket-claim') === 'support.tickets.act', '_capForRoute maps ticket-claim to support.tickets.act');
ok(_capForRoute('POST', '/api/admin/ticket-assign') === 'support.supervise', '_capForRoute maps ticket-assign to the supervisor cap');
ok(_capForRoute('GET', '/api/admin/ticket-agents') === 'support.supervise', '_capForRoute maps ticket-agents to the supervisor cap');
ok(_capForRoute('POST', '/api/admin/grant') === null, '_capForRoute: dangerous route maps to NO cap');

log('');
log('staff_caps simulation: ' + passes + ' passed, ' + fails + ' failed');
if (fails > 0) { if (typeof process !== 'undefined' && process.exit) process.exit(1); else throw new Error(fails + ' assertion(s) failed'); }
