/* Atlas Rental.io - Platform-STAFF capability model (pure, dependency-free).
 *
 * Imported by worker.js (the ONLY real authority -- enforcement) AND by
 * test/staff_caps.mjs (the executable permission simulation). It has NO
 * Cloudflare / Node / crypto dependencies on purpose, so the exact same code
 * runs under Node (CI) and under jsc (local) and can be exhaustively simulated.
 *
 * SECURITY MODEL (default-deny, curated-delegable):
 *  - A platform staffer is NEVER the owner. The owner (env ADMIN_TOKEN or an
 *    owner session) bypasses all of this.
 *  - Enforcement is DEFAULT-DENY: a non-owner may reach an /api/admin/* route
 *    ONLY if some capability they HOLD lists that route.
 *  - Only a hand-picked SAFE subset of routes is delegable (it lives in
 *    STAFF_CAPS). Everything NOT listed here -- every destructive action, every
 *    real-money or config WRITE, every whole-DB export, raw cross-tenant PII
 *    query, security log, ban, owner-management / take-control, and staff
 *    management itself -- is simply absent, so NO capability grant can ever
 *    reach it. Those stay owner-only forever (OWNER_ONLY_CAPS documents them
 *    for the UI but is never consulted in enforcement).
 *  - BACKWARD COMPATIBLE: a staffer with no explicit caps falls back to their
 *    role preset (_defaultStaffCaps), and those presets reproduce EXACTLY the
 *    pre-existing support/analyst behaviour (STAFF_READ reads + SUPPORT_WRITE
 *    writes for support; reads + money for analyst). test/staff_caps.mjs proves
 *    this equivalence route-by-route.
 */

export const ATLAS_CAPS_VERSION = '2026.11.14-f0a';

// def: which role presets include this cap by DEFAULT (when a staffer has no
// explicit caps). 'both' = support+analyst; 'support' = support only (the write
// half); 'analyst' = analyst only; 'none' = grantable but in no preset.
// routes: [{m, p}] where m is an exact HTTP method or '*', p is a path regex
// (matched against the pathname only -- the worker's `path`, already query-less).
// money:true marks the pure "see money figures" flag (it unlocks NO route; it is
// consulted by the money-stripping handlers via _staffSeeMoney).
export const STAFF_CAPS = [
  // ---- Console bootstrap (feature flags; already staff-safe, server strips owner financials) ----
  { key: 'hq.console', group: 'Console', label: 'Open HQ (feature flags / bootstrap)', sens: 'safe', def: 'both',
    routes: [{ m: 'GET', p: '^/api/admin/config$' }] },
  { key: 'ops.overview', group: 'Overview', label: 'Overview dashboard (operational KPIs)', sens: 'safe', def: 'both',
    routes: [{ m: 'GET', p: '^/api/admin/overview$' }] },

  // ---- Support (the core staff job): split VIEW (read) vs ACT (reply/triage) ----
  { key: 'support.tickets.view', group: 'Support', label: 'Support tickets - view', sens: 'pii', def: 'both',
    routes: [{ m: 'GET', p: '^/api/admin/tickets$' }, { m: 'GET', p: '^/api/admin/ticket-customer$' }] },   // WAVE-SUPPORT-F0a: + the in-ticket customer-intelligence panel (account context for the ONE tenant on the ticket; revenue is money-gated in-handler)
  { key: 'support.tickets.act', group: 'Support', label: 'Support tickets - reply, claim, triage & notes', sens: 'pii', def: 'support',
    routes: [{ m: 'POST', p: '^/api/admin/ticket-reply$' }, { m: 'POST', p: '^/api/admin/ticket-status$' }, { m: 'POST', p: '^/api/admin/ticket-claim$' }, { m: 'POST', p: '^/api/admin/ticket-workstate$' }, { m: 'POST', p: '^/api/admin/ticket-note$' }] },   // WAVE-SUPPORT-DEPT1: an agent can claim-to-own, drive the internal lifecycle, and add internal notes on the tickets they work
  { key: 'support.supervise', group: 'Support', label: 'Support tickets - reassign & supervise (hand a ticket to another agent)', sens: 'pii', def: 'none',
    routes: [{ m: 'POST', p: '^/api/admin/ticket-assign$' }, { m: 'GET', p: '^/api/admin/ticket-agents$' }] },   // WAVE-SUPPORT-DEPT1: grantable, in NO preset -> owner + explicitly-designated supervisors only. Lets a lead reassign/force-unassign a ticket owned by another agent. WAVE-SUPPORT-DEPT2: + GET ticket-agents (the roster the reassign picker reads) so a configured supervisor clears the default-deny read gate without owner-only /api/admin/staff.
  { key: 'support.inbox.view', group: 'Support', label: 'Support inbox (inbound email) - view', sens: 'pii', def: 'both',
    routes: [{ m: 'GET', p: '^/api/admin/inbox$' }] },
  { key: 'support.inbox.act', group: 'Support', label: 'Support inbox - reply & change status', sens: 'pii', def: 'support',
    routes: [{ m: 'POST', p: '^/api/admin/inbox/reply$' }, { m: 'POST', p: '^/api/admin/inbox/status$' }] },
  { key: 'support.bugs.view', group: 'Support', label: 'Bug & idea inbox - view', sens: 'safe', def: 'both',
    routes: [{ m: 'GET', p: '^/api/admin/feedback$' }] },
  { key: 'support.bugs.act', group: 'Support', label: 'Bug & idea inbox - triage (set status)', sens: 'safe', def: 'support',
    routes: [{ m: 'POST', p: '^/api/admin/feedback/update$' }] },

  // ---- Analytics (non-money views) ----
  { key: 'analytics.view', group: 'Analytics', label: 'Website visits, signup funnel, geo', sens: 'safe', def: 'both',
    routes: [{ m: 'GET', p: '^/api/admin/visits$' }, { m: 'GET', p: '^/api/admin/visits-geo$' }, { m: 'GET', p: '^/api/admin/growth-data$' }] },
  { key: 'social.view', group: 'Analytics', label: 'Social accounts - view', sens: 'safe', def: 'both',
    routes: [{ m: 'GET', p: '^/api/admin/social$' }] },

  // ---- Grantable extras (NOT in any preset: off until the owner turns them on) ----
  { key: 'members.view', group: 'Members', label: 'Members directory (no revenue column unless money.view)', sens: 'pii', def: 'none',
    routes: [{ m: 'GET', p: '^/api/admin/members$' }] },
  { key: 'ops.system', group: 'System', label: 'System health, uptime, SEO, error log', sens: 'pii', def: 'none',
    routes: [{ m: 'GET', p: '^/api/admin/errors$' }, { m: 'GET', p: '^/api/admin/seo-health$' }, { m: 'GET', p: '^/api/admin/site-uptime$' }, { m: 'GET', p: '^/api/admin/monitor/' }, { m: 'GET', p: '^/api/admin/ai-selftest$' }] },
  { key: 'security.reports', group: 'Security', label: 'Compliance & audit reports (read-only)', sens: 'safe', def: 'none',
    routes: [{ m: 'GET', p: '^/api/admin/report/' }] },
  { key: 'ai.assist', group: 'AI', label: 'AI copilots (ticket/inbox/bug drafts, churn, onboarding, release notes)', sens: 'pii', def: 'none',
    routes: [{ m: 'POST', p: '^/api/admin/ai/(copilot|churn|onboarding-nudges|release-notes|ticket-draft|inbox-draft|triage-bugs)$' }] },

  // ---- Money visibility: a pure flag (unlocks NO route; see _staffSeeMoney) ----
  { key: 'money.view', group: 'Revenue', label: 'See revenue / MRR / money figures (analyst role only)', sens: 'money', def: 'analyst', money: true, roleLock: 'analyst',
    routes: [] },
];

// Display-only: the high-risk surfaces that are NOT delegable to staff. The owner
// panel renders these greyed ("Owner only") so the checklist is complete, but they
// are NEVER consulted in enforcement -- their absence from STAFF_CAPS is what keeps
// them owner-only. (Kept here so "nothing left out" is honoured in the UI.)
export const OWNER_ONLY_CAPS = [
  { key: 'x.revenue.ledger', group: 'Revenue', label: 'Purchases / live transactions ledger (card PII)', sens: 'money+pii' },
  { key: 'x.revenue.pnl', group: 'Revenue', label: 'Expenses, net profit, plan margins, cohort costs', sens: 'money' },
  { key: 'x.payments.config', group: 'Revenue', label: 'Payments setup, processor switch, test charges, reconcile', sens: 'real-money' },
  { key: 'x.paygate', group: 'Revenue', label: 'Payment-gate lockout & public-site takedown', sens: 'destructive' },
  { key: 'x.gmv', group: 'Revenue', label: 'GMV take-rate & Connect', sens: 'real-money' },
  { key: 'x.members.grant', group: 'Members', label: 'Comp / grant / extend / clear-sub', sens: 'real-money' },
  { key: 'x.members.delete', group: 'Members', label: 'Delete a tenant', sens: 'destructive' },
  { key: 'x.ai.rawquery', group: 'AI', label: 'AI data query / copilot over raw tenant data', sens: 'pii' },
  { key: 'x.ai.config', group: 'AI', label: 'AI Command Center + Sponge config', sens: 'config' },
  { key: 'x.security.log', group: 'Security', label: 'Security log (actor / IP / sign-ins)', sens: 'pii' },
  { key: 'x.security.bans', group: 'Security', label: 'Bans & attack feed (add/remove bans)', sens: 'destructive' },
  { key: 'x.social.connect', group: 'Analytics', label: 'Social connect / disconnect / publish (OAuth)', sens: 'config' },
  { key: 'x.growth.ai', group: 'Analytics', label: 'AI growth tools (strategy / outreach / posts)', sens: 'config' },
  { key: 'x.competitors', group: 'Analytics', label: 'Competitor watchlist & deep-read', sens: 'config' },
  { key: 'x.settings.toggles', group: 'Settings', label: 'Platform toggles (dev API, MFA, founder, etc.)', sens: 'config' },
  { key: 'x.settings.backup', group: 'Settings', label: 'Full backup download / tenant export (whole-DB PII)', sens: 'pii' },
  { key: 'x.settings.registrar', group: 'Settings', label: 'Domain registrar test-buy (spends real balance)', sens: 'real-money' },
  { key: 'x.settings.deleted', group: 'Settings', label: 'Deleted accounts - restore / purge (permanent)', sens: 'destructive' },
  { key: 'x.counsel', group: 'Overview', label: 'Atlas Counsel / morning brief (owner intelligence)', sens: 'config' },
  { key: 'x.alerts', group: 'Overview', label: 'Alerts feed', sens: 'config' },
  { key: 'x.staff', group: 'Staff', label: 'Staff management (mint / rotate / revoke / caps)', sens: 'escalation' },
  { key: 'x.takecontrol', group: 'Take Control', label: 'Owner management / account takeover (tier 2+)', sens: 'escalation' },
];

// Fast lookup set of every delegable cap key.
const _CAP_KEYS = (function () { var s = {}; for (var i = 0; i < STAFF_CAPS.length; i++) s[STAFF_CAPS[i].key] = STAFF_CAPS[i]; return s; })();

// Parse the stored caps JSON into an array of known, delegable cap keys (ignores
// anything unknown or non-delegable -- a stale/forged cap can never grant a route).
export function _parseCaps(capsJson) {
  var arr = null;
  if (Array.isArray(capsJson)) arr = capsJson;
  else if (typeof capsJson === 'string' && capsJson.trim()) { try { var p = JSON.parse(capsJson); if (Array.isArray(p)) arr = p; } catch (e) { arr = null; } }
  if (!arr) return null;   // null = "no explicit caps" -> caller uses the role preset
  var out = [];
  for (var i = 0; i < arr.length; i++) { var k = String(arr[i] || ''); if (_CAP_KEYS[k] && out.indexOf(k) < 0) out.push(k); }
  return out;   // may be [] (explicitly empty = a locked-out staffer who can reach nothing)
}

// The default cap set for a role preset (used when a staffer has NO explicit caps).
// These reproduce the pre-RBAC behaviour exactly.
export function _defaultStaffCaps(role) {
  var out = [];
  for (var i = 0; i < STAFF_CAPS.length; i++) {
    var c = STAFF_CAPS[i];
    if (c.def === 'both') out.push(c.key);
    else if (c.def === role) out.push(c.key);   // 'support' or 'analyst'
  }
  return out;
}

// Effective caps for a staffer: explicit caps if set (already filtered to the
// delegable universe by _parseCaps), else the role preset.
export function _effectiveStaffCaps(role, capsJson) {
  var parsed = _parseCaps(capsJson);
  return (parsed === null) ? _defaultStaffCaps(role) : parsed;
}

function _routeMatch(route, method, path) {
  if (route.m !== '*' && route.m !== method) return false;
  try { return new RegExp(route.p).test(path); } catch (e) { return false; }
}

// Does a staffer holding effCaps (an array of cap keys) have access to (method,path)?
// DEFAULT-DENY: true only if a held, delegable cap lists a matching route.
export function _staffCan(effCaps, method, path) {
  if (!effCaps || !effCaps.length) return false;
  var held = {}; for (var i = 0; i < effCaps.length; i++) held[effCaps[i]] = 1;
  for (var j = 0; j < STAFF_CAPS.length; j++) {
    var c = STAFF_CAPS[j];
    if (!held[c.key] || !c.routes || !c.routes.length) continue;
    for (var k = 0; k < c.routes.length; k++) { if (_routeMatch(c.routes[k], method, path)) return true; }
  }
  return false;
}

// Which cap key owns (method,path), or null if the route is not delegable at all.
// Diagnostic / audit only (enforcement uses _staffCan).
export function _capForRoute(method, path) {
  for (var j = 0; j < STAFF_CAPS.length; j++) {
    var c = STAFF_CAPS[j];
    if (!c.routes || !c.routes.length) continue;
    for (var k = 0; k < c.routes.length; k++) { if (_routeMatch(c.routes[k], method, path)) return c.key; }
  }
  return null;
}

// Can this staffer SEE money figures? Money is ANALYST-ROLE ONLY (owner policy): a
// non-analyst never sees it. Within the analyst role the money.view cap applies --
// the capless analyst preset includes it; an analyst whose owner un-ticked it does not.
export function _staffSeeMoney(role, capsJson) {
  if (role !== 'analyst') return false;   // POLICY (owner directive): full company money data (MRR / revenue / data spreads) is ANALYST-ROLE ONLY. A support (or any non-analyst) staffer NEVER sees money, even if money.view somehow sits in their caps -- the cap is inert off the analyst role. The owner is handled by the caller (_role==='owner' || _staffSeeMoney(...)).
  var parsed = _parseCaps(capsJson);
  if (parsed === null) return true;        // capless analyst -> the analyst preset includes money.view
  return parsed.indexOf('money.view') >= 0;  // an analyst whose owner un-ticked money.view does NOT see it
}
