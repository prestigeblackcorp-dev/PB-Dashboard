# Atlas security operations

Short, practical runbook for the platform owner. It covers secret handling, key rotation, and the guarantees the
worker already enforces.

## Where secrets live

All secrets are Cloudflare Worker **secrets** (encrypted at rest, never in the repo, never in `wrangler.toml`).
Set or update one with `wrangler secret put NAME` (or the dashboard: Workers > atlas > Settings > Variables > *Encrypt*).
The full list the worker reads is in [`wrangler.toml`](wrangler.toml).

The worker never returns a secret. `/api/health` reports only booleans (is a key *set*), never values. Client
source (dashboard, booking page, portal) never receives a secret.

## Data-at-rest encryption

Tenant secrets stored in the DB (each tenant's own Stripe key, social tokens) are **AES-GCM** encrypted via
`encSecret`/`decSecret`, bound to the tenant with **AAD** (`aad = tenantId` / `'social:'+platform`) and a
**key version**, so ciphertext from one tenant cannot be replayed against another, and keys can rotate without a
flag day. Signing (sessions, unsubscribe, social state) uses HMAC over `SESSION_KEY`.

## Rotation procedure

Rotate on a schedule (recommend every 90 days) and immediately on any suspected exposure.

**`ENC_KEY` (data encryption) - zero-downtime, 2 steps:**
1. Add the new key as `ENC_KEY_2` (the worker already reads it as a second decrypt key):
   `wrangler secret put ENC_KEY_2` (32 bytes, base64). Deploy. Now the worker can *decrypt* with either key.
2. After one cycle (existing blobs re-encrypt on next write under the newest key), promote: set `ENC_KEY` to the
   new value, remove `ENC_KEY_2`. Deploy.

**`SESSION_KEY` (signing):** rotating invalidates live sessions + signed links (users re-log in). Do it during a
low-traffic window: `wrangler secret put SESSION_KEY` (48 bytes, base64), deploy.

**Provider keys** (`ANTHROPIC_KEY`, `RESEND_KEY`, `PLATFORM_STRIPE_KEY`, `TWILIO_*`, `DYNADOT_KEY`, ...): create a
new key in the provider, `wrangler secret put NAME`, deploy, then revoke the old key in the provider.

**`ADMIN_TOKEN` (master dashboard):** `wrangler secret put ADMIN_TOKEN`, deploy; re-unlock the dashboard with the
new value. (Prefer moving admin auth behind Cloudflare Access so identities are per-person and revocable - see the
Enterprise card.)

After any rotation: `curl https://atlasrental.io/api/health` and confirm the relevant capability still reports true.

## Guarantees the worker enforces (no action needed)

- **Least privilege at the edge:** the client is untrusted; identity, tenant, role, plan and price are all
  server-authoritative. A client cannot cross tenants or forge revenue.
- **Admin plane:** rate-limited (300/min/IP) before the token compare; RBAC gate (owner-only for delete/purge/
  grant/config/roles/backup/export); soft-delete + two-step purge instead of one-click wipe; admin actions retained
  1 year for forensics.
- **Injection:** any tenant/customer text (tickets, reviews, business names, scraped competitor pages) is treated
  as untrusted data in every AI prompt - never as instructions.
- **Payload discipline:** signatures/photos are offloaded, not inlined; the nightly cron counts oversized booking
  rows and `/api/health` surfaces `big_rows` so bloat is caught before it becomes a cost/perf problem.

## If a key is exposed

1. Rotate that key now (above). 2. Revoke the old one at the provider. 3. Check `audit_log` (admin backup/export)
for anomalous actions in the window. 4. If `SESSION_KEY` was exposed, rotate it to force re-auth everywhere.
