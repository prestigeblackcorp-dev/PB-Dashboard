# Atlas Rental.io — Build & Feature Ledger

The single source of truth for **what's done, what needs connecting, and every feature** (built, planned, or considered). Living doc — ask Atlas/Claude to add anything and it gets appended here.

**Legend:** ✅ Done & live · 🔌 Built, needs *you* to connect (a key/account/OAuth) · 🟡 Partial · ⬜ To build · 💡 Idea/considered
**Last updated:** 2026‑07‑16 · Frontend `atlas/atlas.html` (live at atlasrental.io) · Backend `atlas.io/backend/worker.js` (Cloudflare Worker + D1)

---

## 1 · Base mechanisms & integrations (the plumbing to make the dashboard "complete")

| Mechanism | What it powers | Status | What's needed to finish |
|---|---|---|---|
| **Cloudflare Worker + D1** | Real multi‑tenant backend (per‑tenant data isolation, auth, CRUD) | 🔌 Built + hardened | **Paste‑deploy** `worker.js` to `atlas.prestigeblackcorp.workers.dev` (it's on your clipboard) |
| **Auth / sessions** | Sign‑up, sign‑in, tenant sessions | ✅ In worker (PBKDF2 600k, enumeration‑safe, CSRF) | — |
| **Encryption at rest** | Integration secrets (AES‑GCM, AAD‑bound to tenant+provider, key rotation) | ✅ In worker | optional `ENC_KEY_2` to rotate |
| **Stripe** (payments) | Booking payments, deposits/holds, subscription billing ($49.99/mo) | 🔌 Model built (PB worker proven); Atlas needs Connect | Add `STRIPE_SECRET` + `STRIPE_WEBHOOK_SECRET`; wire `/api/integrations/connect` → Stripe Connect |
| **Resend** (email) | Confirmations, contracts, reminders, win‑backs, outreach | 🔌 Endpoints modeled (PB worker proven) | Add `RESEND_KEY`; port the send + template endpoints into the Atlas worker |
| **Twilio** (SMS) | Text confirmations/reminders, 2‑way replies | 🔌 Modeled (PB worker proven) | Add `TWILIO_SID` + `TWILIO_TOKEN` + a from‑number; wire send endpoint |
| **Web Push (VAPID)** | Owner alerts (new booking, delivery soon) | 🟡 Pattern proven in PB `sw.js` | Add VAPID keys + `/push/subscribe` to the Atlas worker |
| **Meta (Facebook + Instagram) OAuth + Marketing API** | Dreaming → launch/optimize ad campaigns, DM outreach | ⬜ UI + drafts done; API not wired | Meta app + OAuth + ad‑account permission (your accounts) |
| **Google Ads API** | Dreaming → high‑intent search campaigns | ⬜ UI + drafts done; API not wired | Google Ads account + OAuth |
| **Atlas.io council (ANTHROPIC_KEY + OPENAI_KEY + GEMINI_KEY)** | The **live** Atlas.io AI: Claude + GPT + Gemini each answer, one synthesizes the single best answer, grounded in the owner's own business context (never other tenants') | 🔌 **`/api/aio` endpoint built + client wired** (safety-prompted, session-gated, audited; the chat already calls it and falls back to the built-in preview until keys exist) | Add all three keys to the worker &mdash; it goes live automatically, no code change |
| **Maps / live GPS** | Live fleet map, asset location | 🟡 Tracker brands + UI + test data | Connect a telematics provider feed (Bouncie/Samsara/etc.) per owner |
| **HTTPS + private repo (Cloudflare Pages)** | Secure `https://atlasrental.io`, stop stale‑cache, private source | ⬜ Plan ready | Move the site to Cloudflare Pages; point the domain; make the repo private |
| **PWA / installable** | Add‑to‑home‑screen, offline shell | ✅ Manifest + SW + icons | (optional) custom install prompt |
| **App stores (PWABuilder)** | iOS + Android listings | ⬜ | PWABuilder package + store accounts |

---

## 2 · Core modules — status

| Module | Status | Notes |
|---|---|---|
| Landing site (hero, features, pricing, how‑it‑works, Atlas.io section, SEO) | ✅ | |
| **1‑minute commercial** (real human voice baked in, interactive, universal — all rental types) + `?film` deep‑link | ✅ | 9 scenes: hook → book+pay → e‑sign → **AI website builder** → branded portal → Dreaming → live map+earnings → universal → CTA |
| Onboarding (account → identity → **multi‑select "what do you rent"** → money → connect → asset → invite → done) | ✅ | multi‑type + per‑type rates |
| **AI setup assistant** (finishes the dashboard from what it knows + asks city/goal/photo) | ✅ | powers Dreaming localization |
| Asset ("Asset management") — add (bulk), edit, photo, status, location, tenant/renter | ✅ | |
| Bookings — create/edit, statuses, filters, price engine, drill‑downs | ✅ | |
| Money engine (rate models, tax, deposit modes, discounts, per‑type rates, promos) | ✅ | + **metered/run‑hour billing** (units x rate, log a bill), + **payment plans** (half / 3 / 4 installments, portal schedule) |
| Contracts + e‑signature + legal docs (agreement/ToS/privacy, timestamps, IP) | ✅ | |
| Deposits / refundable holds | ✅ | full **authorize → release / capture / charge‑difference** hold flow on a booking (Stripe wires the real charge on connect) |
| Branded customer **member portal** | ✅ | self‑service; deeper flows ongoing |
| Branded **website builder** + promo box + reviews embed | ✅ | |
| Analytics + reports (tax/bookings/activity CSV, reconciled to bookings) | ✅ | |
| **Team + roles (RBAC)** — presets, granular perms, preview‑as, enforced client+ (server TODO) | ✅ (client) / 🔌 (server re‑check) | worker must re‑check the same perms |
| Promo codes | ✅ | |
| Outreach / email campaigns (segments, AI draft, unsubscribe) | 🟡 | UI/model; real send needs Resend wired |
| **Dreaming** (gaps → FB/IG/Google campaigns → broker/partner outreach, per type, "on since…") | ✅ (UI + drafts) / ⬜ (real launch/send) | |
| **Atlas.io assistant** (chat, nav edits, money/ops/growth answers with follow‑through buttons) + **council mode** (Claude+GPT+Gemini) | ✅ heuristic + follow‑through / 🔌 **live model wired** (`/api/aio`, auto‑live on keys) | |
| Trackers / live map | 🟡 | brands + UI + test data |
| Reviews + messaging preferences | ✅ | |
| Notifications (real, state‑derived) + owner web push | ✅ / 🟡 push | |
| Nav customization (hide/rename/collapse, by Settings or by asking Atlas.io) | ✅ | |
| Dark mode, hamburger + bottom nav, mobile‑first | ✅ | |

---

## 3 · Full feature inventory (every feature, by area)

### Getting started
- ✅ 7‑day free trial, no card · ✅ multi‑select asset types · ✅ per‑type rates · ✅ AI setup assistant · ✅ demo tenants · ✅ import/bulk‑add assets · 💡 CSV/marketplace importer · 💡 "clone last season's setup"

### Assets
- ✅ add/edit, bulk, status, location, tenant, **photo on card** · ✅ availability blocks · ✅ **maintenance/service log** (odometer‑aware) · ✅ **per‑asset document vault** (upload/download) · ✅ **condition photos at pickup + return** (before/after compare, feeds the damage claim)

### Bookings
- ✅ create/edit, statuses, filters, live price · ✅ drill‑downs · ✅ **calendar view** · ✅ **incident/damage record + charge** · ✅ **cancellation policy engine** (window‑aware fee) · ✅ **recurring/subscription rentals** · ✅ **waitlist + auto‑surface on cancellation** · ✅ **ID‑verification flag**

### Money & payments
- ✅ rate models (day/hour/week), tax, discounts (weekly/monthly), deposits, promos · 🔌 Stripe charge/hold/settle · ✅ **partial payments / payment plans** (half · 3 · 4) · ✅ **metered run‑hour billing** · 💡 true monthly tier · 💡 net‑30 accounts (B2B) · 💡 multi‑currency

### Contracts, deposits & risk
- ✅ e‑sign agreement + ToS + privacy, cumulative extension contracts, delivery proof/IP · ✅ **refundable hold flow** (authorize → release / capture / charge‑difference) · ✅ **ID verification** · ✅ **damage‑claim workflow** (document → keep deposit / capture hold → itemized **claim packet** PDF for the insurer → track filed/settled + recovered) · 💡 insurance add‑on marketplace

### Customer‑facing
- ✅ branded member portal · ✅ branded website + promo box · ✅ reviews · ✅ itemized receipts · ✅ **loyalty program** (points per $ spent, tiers, redeem → real coupon, shown in portal) · ✅ **referrals** (each customer gets a shareable code; referrer earns points when a referred first rental completes) · ✅ **gift cards** (issue stored‑value codes + printable certificate; redeem on a booking, balance draws down as a credit)

### Growth — Dreaming (idle‑time engine)
- ✅ gaps per asset type · ✅ FB/IG/Google campaign drafts (headline/audience/budget) · ✅ broker/partner outreach targets + drafts (per type) · ✅ "Dreaming is on since…" status · 🔌 Connect ad accounts to launch · ⬜ pull N *real* local contacts (brokers/GCs) · ⬜ watch bid boards for open jobs · ⬜ actually send (email/DM) on approval

### Atlas.io AI
- ✅ chat: pricing, idle, analytics, **"what did I make this month"**, deposits, cancellations, **damage/incident**, expansion, win‑back, Stripe, nav edits · ✅ follow‑through buttons everywhere · ✅ refuses to invent data on empty accounts · 🔌 **live model** &mdash; Claude + GPT + Gemini **council** via `/api/aio`, one synthesis, auto‑live when you add the 3 keys · ⬜ image understanding ("here's a photo of my asset") · ⬜ take real actions (apply a rule, send a campaign)

### Team & ops
- ✅ roles/RBAC + preview‑as · 🔌 server‑side perm re‑check · 💡 audit log per user · 💡 staff scheduling / shifts

### Platform
- ✅ PWA installable · ✅ dark mode · ✅ nav customization (+ by voice) · ✅ 30‑sec commercial + deep‑link · 🔌 push · ⬜ HTTPS via Cloudflare Pages · ⬜ app‑store listings · ✅ **QuickBooks/Xero export** (accounting CSV) · 💡 white‑label domains per tenant · 💡 Zapier/webhooks

---

## 4 · Next‑up priority (what to do to "complete" the dashboard)
1. **Paste‑deploy the worker** (on your clipboard) → real backend live.
2. **Connect Stripe** (payments + deposits + your own subscription billing).
3. **Wire Resend + Twilio** in the worker (confirmations, reminders, outreach actually send).
4. **HTTPS via Cloudflare Pages** (secure domain, kills the stale‑cache "old build" problem).
5. **Live Atlas.io council** (`ANTHROPIC_KEY` + `OPENAI_KEY` + `GEMINI_KEY`) — the `/api/aio` endpoint is built; adding the 3 keys makes the assistant a live Claude+GPT+Gemini synthesis (auto, no code change).
6. **Meta + Google OAuth** — so Dreaming can actually launch campaigns + message brokers.
7. **App‑store submission** (PWABuilder) when ready.

---

## 5 · Complete remaining backlog — every idea from our chat, nothing dropped
Cross‑checked against the whole build so far. If it isn't ✅ above, it's here with a status + what unblocks it.

### A. Self‑contained (buildable now — no keys, no accounts)
- 💡 **Per‑user audit log view** — the timestamped event log exists globally; add a per‑staff filter
- 💡 **Staff scheduling / shifts**
- 💡 **CSV / marketplace importer** — bulk‑import assets, bookings, customers
- 💡 **"Clone last season's setup"**
- 💡 **True monthly rate tier** — long‑term / subscription rentals as a first‑class rate
- 💡 **Operator / delivery add‑ons as first‑class line items**
- 💡 **Multi‑currency display**
- 💡 **Insurance add‑on marketplace** — offer coverage at checkout (display/config now; live quotes need a provider)

### B. Owner‑key / account‑gated (built or modeled — flips on when you connect)
- 🔌 **Stripe** — real charges, deposit/hold capture, your $49.99/mo subscription billing, per‑installment payment‑plan charges, B2B **net‑30** invoicing
- 🔌 **Resend (email) + Twilio (SMS)** — confirmations, reminders, win‑backs, outreach actually send
- 🔌 **Web Push (VAPID)** — owner alerts (new booking, delivery soon)
- 🔌 **Atlas.io council live** — `/api/aio` built; add `ANTHROPIC_KEY`+`OPENAI_KEY`+`GEMINI_KEY`
- ⬜ **Meta + Google Ads OAuth** — Dreaming launches real campaigns + DMs (UI + drafts done)
- 🟡 **Telematics live GPS** (Bouncie/Samsara/etc.) — map + trackers UI done; connect a per‑owner feed
- 💡 **White‑label domains per tenant** · 💡 **Zapier / webhooks**

### C. Infra / platform (your setup)
- 🔌 **Paste‑deploy the worker** (on your clipboard) — the ONE pending action → real backend live
- ⬜ **HTTPS via Cloudflare Pages + private repo** — kills the stale‑cache "old build" problem
- ⬜ **App‑store listings** (PWABuilder iOS + Android)

### D. Deeper efforts (larger, when you want them)
- ⬜ **Damage‑claim → insurer auto‑submit** — the claim packet is done; auto‑filing needs an insurer integration
- ⬜ **Dreaming: pull N real local contacts** (brokers/GCs) + **watch bid boards** — currently one templated draft per partner category

## 6 · Add a feature
Drop it below (or just tell Atlas.io / Claude and it gets slotted into the right area above with a status):
- ⬜ _…_
