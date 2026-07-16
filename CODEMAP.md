# Code Map — where the latest of everything lives

The single source of truth for every app, file, backend, and live URL across both products.
Last updated 2026-07-16.

There are **two products**:
- **Prestige Black** — the live rental + chauffeur business (your own).
- **Atlas Rental.io** — the white-label rental SaaS product (sell to other rental businesses).

---

## 1) Prestige Black (the live business)

- **Repo:** `prestigeblackcorp-dev/PB-Dashboard`
- **On your Mac:** `/Users/jalennguyen/claude/`
- **Live site:** `https://prestigeblackcorp-dev.github.io/PB-Dashboard/` (GitHub Pages, auto-deploys on push)
- **Version (bump all 3 in LOCKSTEP every deploy):** `PB_BUILD = v275` · `PB_SW = pb-v277` (index.html) · `CACHE = pb-v277` (sw.js)

| File | What it is | Size |
|---|---|---|
| `index.html` | **Owner Dashboard** — bookings, KPIs, portal charges, fleet, chauffeur dispatch, outreach, everything | 1.8 MB |
| `obsidian.html` | **Rider app** — "Obsidian by Prestige Black" (book a ride) | 225 KB |
| `driver.html` | **Chauffeur / driver app** | 180 KB |
| `portal.html` | **Customer member portal** — sign contracts, pay, upload photos | 255 KB |
| `sw.js` | Service worker (PWA offline cache + web push) | 10 KB |
| `pb-config.js` | Shared config — worker URL, Firebase keys, `PB_FLAGS` | 8 KB |
| `icon.png`, `obsidian-icon.png` | App icons | — |
| `ride.html` | Empty redirect stub → obsidian.html (legacy) | — |

### Backend — 4 Cloudflare Workers (edit the file → paste into Cloudflare → Deploy)

The workers are **not in this git repo** (they're paste-deployed), but they ARE on your Mac — the editable source files live in **`~/Downloads/`** and are snapshotted in **`~/Downloads/PB BACKUP/workers/`**:

| File (`~/Downloads/…`) | Worker | What it does |
|---|---|---|
| `prestige-black-booking-worker.js` | **MAIN** (~9,100 lines) | Bookings, Stripe, `/sync`, e-signing, chauffeur dispatch, push, portal, outreach, scheduled emails |
| `prestige-black-messaging-worker.js` | Messaging | Email/SMS sender (`/send-email`) |
| `prestige-black-scheduler-worker.js` | Scheduler | Cron sweeps / scheduled tasks |
| `prestige-black-verification-worker.js` | Verify | Driver/renter ID verification (Stripe Identity) |

- **Full-system backup:** `~/Downloads/PB BACKUP/` — a restorable snapshot of everything (site + workers + Shopify files) with a dated `_BACKUP_MANIFEST.txt` that records the current build of each piece. **This manifest is the authoritative "what's deployed" record** — check it for the latest per-file version.
- **`booking.live`** = the **Shopify** site — a separate product, NOT this repo. Its sections are also backed up in `PB BACKUP/` (`PB_Booking_live.js`, `pb-*-section.liquid`). Never edit repo files for booking.live issues.
- **Deploy:** client files → push to `main` → GitHub Pages serves them. Worker files → open the file, edit, copy it into the matching Cloudflare Worker → Deploy (nothing auto-deploys the workers).

---

## 2) Atlas Rental.io (the SaaS product)

- **Canonical app source:** `atlas/atlas.html` (single-file app, inside the PB-Dashboard repo's `/atlas/` folder)
- **Live now (temporary):** `https://prestigeblackcorp-dev.github.io/atlas-rental.io/`
- **Live target:** `https://atlasrental.io` — *pending the Cloudflare Pages migration* (domain doesn't resolve yet)
- **Live deploy repo:** `prestigeblackcorp-dev/atlas-rental.io` (auto-deploys the site + the OG card)

**App + deploy bundle** — everything to run/deploy Atlas is in **`atlas.io/`**:

| File | What it is |
|---|---|
| `atlas.io/atlas.html` + `atlas.io/index.html` | The complete app (identical; `index.html` = the bare-root copy the site serves) |
| `atlas.io/atlas-manifest.json` · `atlas-sw.js` | Installable PWA (manifest + service worker) |
| `atlas.io/atlas-icon.svg` · `apple-touch-icon.png` · `atlas-icon-192/512.png` · `favicon-16/32.png` | Full-bleed icon set (logo) |
| `atlas.io/og-card.jpg` | 1200×630 link-preview card (logo + slogan) |
| `atlas.io/CNAME` | `atlasrental.io` (custom domain) |
| `atlas.io/SECURITY.md` | The pre-launch security checklist |
| `atlas.io/README.md` | Deploy steps |

**Backend (Cloudflare Worker + D1)** — in **`atlas.io/backend/`**, live at **`https://atlas.prestigeblackcorp.workers.dev`**:

| File | What it is |
|---|---|
| `atlas.io/backend/worker.js` | The API — auth, sessions, tenant-scoped CRUD, encrypted keys, security headers |
| `atlas.io/backend/schema.sql` | D1 database schema (17 tenant-isolated tables) |
| `atlas.io/backend/schema-console.sql` | Comment-free schema for the Cloudflare D1 web console |
| `atlas.io/backend/wrangler.toml` | Deploy config |
| `atlas.io/backend/README.md` | 10-min deploy steps |

- **Local backup of all Atlas files:** `~/Downloads/ATLAS BACKUP/` (mirrors `atlas.io/`).
- **Deploy:** the site auto-deploys from the `atlas-rental.io` repo on push. Backend → paste `worker.js` into the Cloudflare Worker editor → Deploy.

---

## 3) Reference material

- **Infrastructure / go-live plan:** artifact at `https://claude.ai/code/artifact/f4258a8d-6cc9-43b2-bc84-3addb93c0ca6`
- **Atlas security checklist:** `atlas.io/SECURITY.md`
- **This map:** `CODEMAP.md` (repo root) — update it whenever a file/URL/version changes.

---

## Quick answers ("where's the latest…?")

- **The dashboard** → `index.html` (root). **The rider app** → `obsidian.html`. **Driver** → `driver.html`. **Customer portal** → `portal.html`.
- **The Atlas app** → `atlas/atlas.html` (source) = `atlas.io/atlas.html` (deploy copy).
- **Any backend** → PB workers = `~/Downloads/prestige-black-*-worker.js` (also in `~/Downloads/PB BACKUP/workers/`); Atlas worker = `atlas.io/backend/worker.js`.
- **Which build/worker is live** → `PB_BUILD` in `index.html` (currently v275) for the client; `~/Downloads/PB BACKUP/_BACKUP_MANIFEST.txt` for the authoritative per-worker version.
- **A full restorable snapshot of everything PB** → `~/Downloads/PB BACKUP/` (site + 4 workers + Shopify sections + manifest).
