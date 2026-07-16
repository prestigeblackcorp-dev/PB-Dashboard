# Atlas Rental.io — backend (Cloudflare Worker + D1)

The secure server that becomes the **only** authority. The app (the HTML) is just the
screen; identity, tenant, role, plan and every dollar are decided here from a signed
session — never trusted from the browser. This is the foundation for the P0 security
items in [`../SECURITY.md`](../SECURITY.md).

## What's here
| File | What it is |
|---|---|
| `schema.sql` | D1 database — 17 tables, tenant-isolated (every row carries `tenant_id`) |
| `worker.js` | The API — signup/login, server-side sessions, CSRF, rate limiting, tenant-scoped CRUD, encrypted key storage, audit log, security headers |
| `wrangler.toml` | Deploy config |

## What already works (foundation, P0 items 1–5 + 9)
- **Passwords** hashed with PBKDF2-SHA256 (210k iterations) + per-user salt — never plaintext, never hashed on the client.
- **Sessions** are server-side rows; the browser only holds an opaque `HttpOnly; Secure; SameSite=Lax` cookie. Idle (24h) + absolute (30d) expiry, server-side revoke on logout.
- **Tenant isolation** — `tenant_id` comes from the session, never the request; every query is `WHERE tenant_id = ?`; cross-tenant writes 404.
- **Owner/comp status** re-checked server-side from `comp_grants` on every request (a client-set email can't grant itself admin).
- **CSRF** double-submit token + Origin check on every write. **Rate limits** on signup/login. **Security headers** (HSTS, X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy).
- **Integration keys** stored AES-GCM encrypted, never returned to the browser (UI shows a masked "Connected").

## Deploy (you do this, ~10 min, needs your Cloudflare account)

```bash
npm i -g wrangler
wrangler login                       # opens your Cloudflare account

wrangler d1 create atlas             # prints a database_id ->
#   paste it into wrangler.toml (database_id = "...")

wrangler d1 execute atlas --file=schema.sql   # build the tables

# secrets (paste when prompted):
wrangler secret put SESSION_KEY      # value: openssl rand -base64 48
wrangler secret put ENC_KEY          # value: openssl rand -base64 32
wrangler secret put OWNER_EMAIL      # value: prestigeblackcorp@gmail.com

wrangler deploy                      # -> https://atlas.<you>.workers.dev
```

Then smoke-test it's live:
```bash
curl -sX POST https://atlas.<you>.workers.dev/api/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"test-1234","business":"Test Fleet"}'
# -> {"ok":true,"csrf":"...","tenant_id":"t...","trial_ends":...}
```

## The last wire (I do this after you deploy)
Flip the app's `Atlas.store` seam from `localStorage` to `fetch()` against this Worker,
behind a flag (`PB_FLAGS`-style) so it's reversible. Each seam method becomes one
authenticated, tenant-scoped call. Until then the app runs exactly as it does today
(local demo), and **no real customer data is connected** — matching the "secure first"
rule.

## Endpoints (foundation)
```
POST /api/auth/signup           {email,password,business,fleet?}        -> sets session cookie
POST /api/auth/login            {email,password}                        -> sets session cookie
POST /api/auth/logout                                                   -> clears session
GET  /api/auth/me                                                       -> {user,tenant,csrf}
GET  /api/data/<collection>                                             -> {items:[...]}      (tenant-scoped)
POST /api/data/<collection>     {...fields}                             -> {ok,id}            (CSRF)
PUT  /api/data/<collection>/<id>{...fields}                             -> {ok}               (CSRF, tenant-checked)
DEL  /api/data/<collection>/<id>                                        -> {ok}               (CSRF, tenant-checked)
POST /api/admin/comp            {email,role}   (owner only)             -> grant free access
POST /api/integrations/connect  {provider,secret,kind,meta}            -> stores key ENCRYPTED
```
collections: `assets bookings customers charges ledger promos`

Payments (Stripe + webhooks), the reseller (Dynadot), email/SMS/AI plug into this same
router in their phases — each reads its key from the encrypted `integrations` table.
