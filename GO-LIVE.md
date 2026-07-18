# Atlas Rental.io — Go-Live Runbook (owner steps to be fully turnkey for real users)

Status (2026-07-17, SW v18): the front end is polished + honest, and **the server-side of the two missing systems — real payments and a customer-reachable booking site/portal — is now BUILT into the worker and tested (41/41 automated worker tests pass)**. It is **key-gated and honest**: with no keys it degrades gracefully (returns `{emailed:false}` / `{payUrl:null}`, never a fake success). What remains is **owner infrastructure** (deploy the worker + D1, add keys, turn `ATLAS_BACKEND=true`) — do those and it's live. Until then, keep Atlas a labeled demo / waitlist.

## What the go-live audit already fixed in code (shipped v17, verified)
- **Stopped the app from lying.** Every "Payment received / Deposit hold authorized / Connected / Secured by Stripe / IP recorded / compliance built-in / email sent" now tells the truth: payments show "test — no card charged", email actions say "not sent — mailer not live", the fabricated e-sign IP is gone (device + timestamp are real; real IP is stamped server-side at go-live), and Stripe/SMS "connect" states say "saved — live at go-live". New `EMAIL_LIVE` / `PAYMENTS_LIVE` flags gate all of it (both false until the matching backend is deployed).
- **PCI:** removed the raw card-number/CVC capture from the subscription modal (hosted Stripe Checkout does card entry at go-live).
- **First-run bugs:** onboarding no longer silently drops your first vehicle or business name; the New-Booking form no longer fabricates phantom demo vehicles for a real 0-asset account; day-one Overview/Customers show real empty states.
- **Legal:** signup now requires agreeing to Terms & Privacy + discloses the $49.99/mo auto-renewal, and records the acceptance; footer has Terms/Privacy links (host the docs — step 5).
- **Worker hardening:** per-provider AI timeout (a hung model can't stall a request), nightly cron GC of sessions/rate_limits/audit_log, and the platform-owner email is reserved (claim it with `OWNER_SETUP_TOKEN`).

## What the go-live BUILD added to the worker (shipped + tested, key-gated)
The customer-facing server product now exists in `atlas.io/backend/worker.js` (all additive, all honest-when-unconfigured):
- **Public booking site** — `GET /api/book/<slug>` serves a branded, self-contained booking page; `GET /api/public/<slug>` returns the published assets/prices/branding; `POST /api/public/<slug>/book` validates + **prices server-side** + writes a real pending booking to your tenant + emails you and the customer. Reachable through the existing `/api/*` route (no extra DNS needed).
- **Customer portal** — `GET /api/portal/<token>` serves the customer their booking + a Pay-deposit/balance button; `/data` + `/pay` back it.
- **Payments (Stripe)** — deposits/balances use **hosted Stripe Checkout** (card entry stays on Stripe → you stay PCI SAQ-A); `POST /api/stripe/webhook` **verifies the signature** and is the ONLY thing that flips a booking to paid + fires the receipt. Plus owner ops on a booking's PaymentIntent — `POST /api/pay/capture` (charge a damage deposit hold), `/api/pay/release` (release it), `/api/pay/refund` — each emails the customer. No key → no charge, honestly.
- **Lifecycle emails** — the daily cron (`scheduled()`) fires each tenant's configured reminder / thank-you / win-back emails (from `settings.comms.autos`), deduped per booking. Needs `RESEND_KEY` + the Cron Trigger (already in wrangler.toml).
- **SMS + real compliance (TCPA/CAN-SPAM)** — `sendSms()`→Twilio (graceful `no_sms`); every marketing email carries a **working one-tap unsubscribe** (link + `List-Unsubscribe` header) that hits `GET /api/unsub` (signature-verified) and is **honored** by later sends; `POST /api/sms/inbound` handles **STOP** (auto-suppress) / START. Owner `POST /api/sms/test`. Needs `TWILIO_SID`/`TWILIO_TOKEN` (+ the tenant's number) and the Twilio inbound webhook pointed at `atlasrental.io/api/sms/inbound`.
- **Mailer (Resend)** — booking confirmation to the customer + alert to you + payment receipt; no `RESEND_KEY` → returns "not sent" instead of faking it.
- **Publish flow (dashboard)** — Website → **Publish booking site** mirrors your brand/pricing/assets to the server (`PUT /api/tenant/profile`) and shows your real link. Everything is editable and re-publishes on demand.

## Cross-device dashboard sync — now BUILT + tested (was the last architectural gap)
The owner's own dashboard is no longer one-browser-only. On every save, bookings/assets/the profile **mirror to D1** (debounced, lossless — full fidelity in each row's `data`/`info` blob, config in the tenant `settings`), and on login `_srvHydrate` **merges newest-wins** (never blind-overwrite, never drops a local-only or newer-local record). Tested: the real client's save→mirror→D1 round-trips losslessly, mirrors are idempotent (no duplicate rows), and the merge keeps the right record on conflict. It is **inert until `ATLAS_BACKEND=true`** — so it changes nothing until you turn the backend on. To switch on: deploy the worker+D1, then set `ATLAS_BACKEND=true` in the client copies (`atlas/atlas.html`, `atlas.io/atlas.html`, `atlas.io/index.html`) and do the smoke test below (book on device A → confirm it appears on device B).

### Owner steps to light up the built systems
- Deploy `worker.js` + D1 with the schema (see step 4). **If your D1 already exists**, run the migration: `ALTER TABLE bookings ADD COLUMN portal_token TEXT; CREATE INDEX IF NOT EXISTS idx_bookings_portal ON bookings(portal_token); CREATE TABLE IF NOT EXISTS suppressions (tenant_id TEXT NOT NULL, contact TEXT NOT NULL, kind TEXT, reason TEXT, at INTEGER NOT NULL, PRIMARY KEY (tenant_id, contact));` (fresh installs get it automatically).
- Optional secret `APP_ORIGIN` (defaults to `https://atlasrental.io`) — the base URL used in unsubscribe links + booking/portal links.
- Add worker secrets: `RESEND_KEY` (+ `MAIL_FROM`, e.g. `bookings@atlasrental.io`) for email; connect **Stripe** per-tenant via the app's Connections (stored encrypted) and set `STRIPE_WEBHOOK_SECRET` for the webhook. Register the webhook in Stripe at `https://atlasrental.io/api/stripe/webhook` (events: `checkout.session.completed`, `payment_intent.succeeded`).
- In the dashboard: open **Website → Publish booking site**, then share the link (`https://atlasrental.io/api/book/<your-slug>`).

---
This runbook is the **owner-only** steps to switch the above on.

## 1. Turn on the AI (Atlas.io council + natural-language scheduler)  — 2 min
In the Cloudflare dashboard → Workers → your Atlas worker → **Settings → Variables** (encrypt them):
- `ANTHROPIC_KEY` = your Anthropic API key  (powers Atlas.io answers + the schedule builder's rich NL parsing)
- optional: `OPENAI_KEY`, `GEMINI_KEY`  (adds GPT + Gemini to the 3-model council)
Without these the app still works — it uses the built-in fallbacks (a local council + the client-side schedule parser). Adding them makes the AI fully live. **Redeploy the worker after adding.**

## 2. Take REAL customer payments  — the main gate
The Stripe **hosted-Checkout** flow (deposits at booking + pay-deposit/balance in the portal) and the signature-verified `/api/stripe/webhook` are **built + tested**. To go live:
1. Create a **Stripe** account; get your keys (test first with test keys).
2. In the dashboard **Connections**, connect Stripe (the secret is stored encrypted in the worker per tenant, never in the browser). Set `STRIPE_WEBHOOK_SECRET` in the worker env and register the webhook at `https://atlasrental.io/api/stripe/webhook`.
3. Do a real test booking → pay the deposit → confirm the webhook flips it to paid, before switching to live keys.
Do NOT enter card numbers into the app yourself — hosted Stripe Checkout handles cards so you stay in PCI SAQ-A scope. (Claude will not flip live-payment keys for you — that's an owner action.)

## 3. Send REAL customer notifications (confirmation / receipt)  — email
The worker's `sendEmail()` (Resend) + the booking-confirm / owner-alert / payment-receipt triggers are **built**. With no `RESEND_KEY` they honestly return "not sent". To make them real:
1. Create a **Resend** account + domain (SPF/DKIM verified) + API key.
2. Add `RESEND_KEY` (+ `MAIL_FROM`) to the worker env. Test it from **Settings → Messaging → Send myself a test email** (it calls `/api/email/test` and reports the true result).
SMS (reminders/win-back) is the same pattern once Twilio is wired.

## 3b. SMS (optional) — Twilio/etc. key + wire, same pattern as email. TCPA opt-in is already collected in the portal.

## 4. Per-tenant data  — confirm isolation
Owner data syncs to the worker DB keyed by tenant. Verify: sign in on a 2nd device / after clearing storage and confirm your assets + bookings load. (Claude's audit is confirming server-side tenant isolation + persistence; any gap is a code fix, deployed.)

## 5. Legal  — review for your jurisdiction  — 15 min
Settings → Contracts & Legal: generate (or upload) your Rental Agreement, Terms, and Privacy Policy, set your jurisdiction, and review with a local eye. Note the **$100 date-lock is non-refundable** policy belongs in your Cancellation/Refund terms. Real transactions = have these right.

## 6. Custom domain (optional)  — your own URL
The app is on atlasrental.io. To put a tenant on their own domain, use the domain/DNS connection in Settings (CNAME to the Pages host). SSL is automatic.

## 7. Ship as an app (optional)  — PWABuilder
The app is an installable PWA. To list on the App Store / Play Store, run it through **PWABuilder** (packages the manifest + SW into store-ready iOS/Android bundles).

## 8. Pre-launch smoke test  (do this as a real user before inviting anyone)
- [ ] Fresh sign-up → onboarding → add 2 assets → set your rate + tax + deposit
- [ ] Publish your website → open it → book a real asset as a customer → pay the deposit (Stripe test)
- [ ] See the booking in the dashboard → send the portal link → sign the agreement → collect balance → return/close
- [ ] Check the receipt + tax CSV numbers reconcile to the cent
- [ ] Do it once on a phone

When 1-3 and 8 are done, you can safely put Atlas in front of real paying customers.
