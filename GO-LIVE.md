# Atlas Rental.io — Go-Live Runbook (owner steps to be fully turnkey for real users)

Status (2026-07-17, SW v17): the **front end is polished and honest** — but a 36-finding go-live audit found that the three systems a rental SaaS cannot launch without are **not yet wired at runtime**: a durable multi-tenant backend, real payment rails, and a customer-reachable booking/portal. **Atlas is not ready for real paying users until those are stood up** (mostly owner infrastructure below). Do not put real customers on it yet; keep it a labeled demo / waitlist.

## What the go-live audit already fixed in code (shipped v17, verified)
- **Stopped the app from lying.** Every "Payment received / Deposit hold authorized / Connected / Secured by Stripe / IP recorded / compliance built-in / email sent" now tells the truth: payments show "test — no card charged", email actions say "not sent — mailer not live", the fabricated e-sign IP is gone (device + timestamp are real; real IP is stamped server-side at go-live), and Stripe/SMS "connect" states say "saved — live at go-live". New `EMAIL_LIVE` / `PAYMENTS_LIVE` flags gate all of it (both false until the matching backend is deployed).
- **PCI:** removed the raw card-number/CVC capture from the subscription modal (hosted Stripe Checkout does card entry at go-live).
- **First-run bugs:** onboarding no longer silently drops your first vehicle or business name; the New-Booking form no longer fabricates phantom demo vehicles for a real 0-asset account; day-one Overview/Customers show real empty states.
- **Legal:** signup now requires agreeing to Terms & Privacy + discloses the $49.99/mo auto-renewal, and records the acceptance; footer has Terms/Privacy links (host the docs — step 5).
- **Worker hardening:** per-provider AI timeout (a hung model can't stall a request), nightly cron GC of sessions/rate_limits/audit_log, and the platform-owner email is reserved (claim it with `OWNER_SETUP_TOKEN`).

## The 3 blockers that still need the backend build (NOT a config flip)
These are the bulk of the remaining server product; the front end is ready and waiting on them:
1. **Durable backend** — flip `ATLAS_BACKEND=true` only after the Worker+D1 is live, then wire the local→D1 write seam (`_srvMirror`/`_srvDelete` + full `_srvHydrate` + a tenant-profile route). Until then a business lives in one browser and a cache-clear/second-device loses it.
2. **Real payments** — Worker `/checkout` + `/stripe/webhook` (+ deposit hold/capture/refund), and the client's paid-stamps must flip only on a verified webhook. Then `PAYMENTS_LIVE=true`.
3. **Served customer surface** — a per-tenant public booking site + `/portal/{token}` served by the Worker/Pages, and a public `POST /api/public/book` intake. Today the "website" is a preview inside the owner's own dashboard.

---
This runbook is the **owner-only** steps to switch the above on.

## 1. Turn on the AI (Atlas.io council + natural-language scheduler)  — 2 min
In the Cloudflare dashboard → Workers → your Atlas worker → **Settings → Variables** (encrypt them):
- `ANTHROPIC_KEY` = your Anthropic API key  (powers Atlas.io answers + the schedule builder's rich NL parsing)
- optional: `OPENAI_KEY`, `GEMINI_KEY`  (adds GPT + Gemini to the 3-model council)
Without these the app still works — it uses the built-in fallbacks (a local council + the client-side schedule parser). Adding them makes the AI fully live. **Redeploy the worker after adding.**

## 2. Take REAL customer payments  — the main gate
Today the booking/portal "pay" flow records payments and moves the money math (deposits, holds, balances, charges) but does **not** yet capture a real card — it is safe/demo until you connect Stripe. To go live:
1. Create a **Stripe** account; get your **live** publishable + secret keys (test first with test keys).
2. Set the Stripe secret in the worker env (`STRIPE_SECRET`), publishable in the app's connections.
3. Confirm the checkout + deposit-hold + refund/release paths against a real test charge before flipping to live keys.
Do NOT enter card numbers into the app yourself — Stripe Checkout / Elements handles cards so you stay out of PCI scope. (Claude will not flip live-payment keys for you — that's an owner action.)

## 3. Send REAL customer notifications (confirmation / reminder / receipt)  — email
The Atlas worker has **no email sender yet**, so automated emails are honestly gated in the UI ("connect an email sender"). To make them real:
1. Create a **Resend** account + domain (SPF/DKIM verified) + API key.
2. Add `RESEND_KEY` to the worker env and (Claude task) wire a `/api/email` send + the booking/receipt triggers.
Until then, the owner is notified in-app (owner alerts) and can message customers manually; customers see their branded portal.

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
