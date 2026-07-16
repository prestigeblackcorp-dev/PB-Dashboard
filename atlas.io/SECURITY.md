# Atlas Rental.io — Security Phase

This is the permanent security checklist for Atlas Rental.io. It is the gate that must be
cleared before **any real customer data** is connected. It was produced by a 4-agent adversarial
red-team of `atlas/atlas.html` (auth/isolation, XSS/injection, PII/secrets, and a backend
hardening review).

## The one principle

The current app is a **client-only prototype**: all state lives in `localStorage` behind the
`Atlas.store` seam. Today **100% of trust lives in the browser** — identity, tenant, role,
owner/comp status, tier, credits, and every dollar amount are decided in client JS and are
therefore not security controls at all. This is fine for a demo (each person's data is only in
their own browser), but it means:

> **The Cloudflare Worker + D1 backend is the ONLY real authority. The client is an untrusted
> rendering layer.** Every check below must be enforced server-side from a verified session —
> never read from the request body or a client flag.

The `Atlas.store` seam is the swap point: each method becomes one authenticated, tenant-scoped
D1 query.

## Fixed now (client-side, shipped)

- **Atlas.io AI** — user input is HTML-escaped (no self-XSS); an intent guardrail refuses
  data-exfiltration / illegal / hateful / self-harm prompts before spending a credit.
- **Stored-XSS gaps closed** — asset name in the Overview list, custom fleet noun in the customer
  portal, and user-controlled toast strings (uploaded filenames, customer email) are now escaped.
- **CSV export** — cells beginning with `= + - @` are neutralized (spreadsheet formula injection).
- **Cards** — only `{brand, last4}` is stored; the CVC is never read; nothing is transmitted (demo).
- **Signing IP** — recorded but never rendered anywhere (operator, portal, or export); confirmed.
- **Repo** — no secrets are committed (verified across all tracked files).

## P0 — launch blockers (no real PII until ALL ship, server-side)

1. **Password hashing** — replace the prototype hash with Argon2id/scrypt/bcrypt + per-user salt; verify server-side. Never hash/compare on the client.  [DONE 2026-07-16: chained 600k, versioned + backward-compatible]
2. **Sessions** — signed, `HttpOnly; Secure; SameSite` cookie (or signed JWT) minted only after credential verification; absolute + idle expiry; rotate on privilege change; server-side revocation on logout.
3. **Owner/admin/comp status** — lives only in a server table keyed by the *authenticated* user; re-checked per request. A client-set email must never grant Diamond/owner, the domain marketplace, or comps.
4. **Tenant isolation** — `tenant_id` comes from the server session, never the request; every query carries `WHERE tenant_id = ?`; every write validates the row's tenant; deny-by-default; add automated cross-tenant IDOR tests.
5. **Team RBAC** — re-verify each member's role/caps server-side on every mutating endpoint (a forced/hidden button must still 403).
6. **Payments — PCI** — capture cards only via Stripe Elements/Checkout; the PAN never touches your JS/DOM/servers; secret keys live in Cloudflare secrets.
7. **Payments — amounts** — the server recomputes every price from the `money_rules` table; `plan`/`balancePaidAt`/`depositPaidAt` flip **only** from a verified Stripe webhook, never a client call.
8. **Payments — webhooks** — verify `Stripe-Signature`; dedupe on `webhook_events(stripe_event_id PK)`; send an idempotency key on every create.
9. **Transport/headers** — HTTPS-only + HSTS + `X-Content-Type-Options`, `X-Frame-Options: DENY` / `frame-ancestors 'none'`, `Referrer-Policy`, `Permissions-Policy`.
10. **Secrets** — all provider keys (Stripe, Anthropic, Resend, Twilio, registrar/reseller) in Cloudflare secrets; tenant "bring-your-own" keys stored **encrypted** server-side, never returned to the browser (UI shows only a masked "Connected").

## P1 — before advertising / onboarding real operators

11. **Atlas.io AI server-side** with the safety system-prompt + a moderation pass; credits decremented transactionally server-side; only the caller's own tenant rows as context.
12. **Comp registry + domain reseller** behind `POST /api/admin/*`, requiring `grant === 'admin'` from the server; every grant/revoke audited.
13. **Input validation** on every endpoint (type/length/range/enum/date-order; money as integer cents); enforce plan caps server-side.
14. **Rate limiting** per-IP + per-account (strict on login/signup/reset/e-sign/ai/payments) → 429.
15. **Output encoding** — keep escaping all user/customer strings; prefer `textContent`; CSP as backstop.
16. **PII at rest** — encrypt/tokenize customer contact, e-signatures, signing IP; store ID uploads + media in **R2**, served via short-lived (≤5 min) signed URLs after a tenant-scope check.
17. **Content-Security-Policy** — `script-src 'self' https://js.stripe.com` (no `'unsafe-inline'`). Requires extracting inline scripts to a same-origin file and replacing inline `on*=` handlers with event delegation.
18. **CSRF** — double-submit token + `SameSite=Lax` + `Origin`/`Referer` checks on state-changing requests.
19. **E-sign (ESIGN/UETA)** — capture the real IP + UA server-side; store a SHA-256 hash of the exact signed document; immutable sent→delivered→viewed→signed trail.
20. **SMS/marketing consent (TCPA)** — record consent + IP + timestamp + text in a server `consents` table; the sender refuses any number without a live consent row; honor STOP by writing `revoked_at`.

## P2 — operational safety (immediately post-launch)

21. **Audit log** — append-only `audit_log` for logins, permission/role/comp changes, payments, refunds, deletions, exports, admin actions.
22. **Monitoring/alerting** — login-failure spikes, 429 surges, webhook-signature failures, cross-tenant 403s, Worker error rate. Keep the "no whole-node reads / no client polling" cost discipline as a DoS-by-cost control.
23. **Backups** — scheduled D1 exports with retention + tested restore; R2 object versioning.
24. **GDPR/CCPA** — data export + hard delete across `customers/bookings/signatures/files/consents` (+ R2 objects); documented retention.
25. **CAN-SPAM** — sender physical address + enforced one-click unsubscribe (writes `consents.revoked_at`).
26. **PCI SAQ-A** — attainable only if #6 holds (all card data via Stripe-hosted fields); document the attestation.

## Compliance surface

PCI-DSS SAQ-A · TCPA · CAN-SPAM · GDPR/CCPA · ESIGN/UETA — each mapped to the items above.

_Last red-team: 2026-07-16 (4 agents). Re-run this phase before every launch milestone._
