# atlas.io — Atlas Rental.io full backup + deploy bundle

Everything for **Atlas Rental.io** in one folder: the complete app, its PWA files, the icon/logo,
the security spec, and the domain file — a full backup of everything built so far, and a
ready-to-deploy bundle for **atlasrental.io**.

## Contents
| File | What it is |
|---|---|
| `atlas.html` | The complete Atlas app (single file — the source of truth) |
| `index.html` | Identical copy named for the site root (so the bare domain serves Atlas) |
| `atlas-manifest.json` | PWA manifest (installable app) |
| `atlas-sw.js` | Service worker (offline + installable) |
| `atlas-icon.svg` | The Atlas logo / app icon |
| `CNAME` | `atlasrental.io` (GitHub Pages custom domain) |
| `.nojekyll` | Serve files as-is |
| `SECURITY.md` | The security-phase checklist (what to enforce before real data) |

## Deploy to atlasrental.io — 3 steps

**Step 1 — copy & paste.** Create a new public GitHub repo (e.g. `atlas-rentalio`) and upload
**every file in this folder** to its root. That's the whole app — nothing to build.

**Step 2 — turn on Pages.** Repo → **Settings → Pages → Source = "Deploy from a branch" →
`main` / `/ (root)` → Save.** (The `CNAME` file already sets the custom domain to
`atlasrental.io`.)

**Step 3 — point DNS** at your registrar (after you register `atlasrental.io`):
- Apex `atlasrental.io` — four **A** records:
  `185.199.108.153`, `185.199.109.153`, `185.199.110.153`, `185.199.111.153`
- `www` — a **CNAME** → `prestigeblackcorp-dev.github.io`

Wait for DNS, then Settings → Pages → tick **Enforce HTTPS**. Live at **https://atlasrental.io**.

## Notes
- `atlas.html` and `index.html` are the same app; the site serves `index.html` at the root, and
  `atlas.html` also works if you link to it directly. Edit `atlas.html` and copy it over
  `index.html` whenever you change the app.
- "Open my live dashboard" (owner console) points to the PB dashboard's current URL — change it in
  `openLiveDashboard` inside the file if that URL moves.
- Register the domain with **auto-renew + registrar lock** on so you keep it permanently.
