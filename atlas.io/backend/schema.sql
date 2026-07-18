-- Atlas Rental.io - D1 schema (Cloudflare D1 / SQLite)
-- The ONE authority. Every tenant-scoped table carries tenant_id and is queried WHERE tenant_id = ?.
-- Apply:  wrangler d1 execute atlas --file=backend/schema.sql
-- Safe to re-run: every object uses IF NOT EXISTS.

PRAGMA foreign_keys = ON;

-- ---- Tenants (one rental business each) -------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  subdomain     TEXT UNIQUE,                 -- <subdomain>.atlasrental.io
  fleet_type    TEXT DEFAULT 'cars',
  plan          TEXT DEFAULT 'trial',        -- trial|starter|growth|pro (server-authoritative)
  trial_ends    INTEGER,                     -- epoch ms
  brand         TEXT DEFAULT '{}',           -- JSON: logo, colors, name, subdomain
  money         TEXT DEFAULT '{}',           -- JSON: money-rules (server recomputes from this)
  settings      TEXT DEFAULT '{}',           -- JSON: portal cfg, flags, comms
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);

-- ---- Users (belong to a tenant; a platform owner is flagged via comp_grants) -
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  pw_hash       TEXT NOT NULL,               -- PBKDF2/scrypt/argon2 output (never plaintext)
  pw_salt       TEXT NOT NULL,
  pw_algo       TEXT DEFAULT 'pbkdf2-sha256-210000',
  tenant_id     TEXT NOT NULL,
  role          TEXT DEFAULT 'owner',        -- owner|manager|staff (per-tenant RBAC)
  caps          TEXT DEFAULT '{}',           -- JSON: fine-grained capability overrides
  created_at    INTEGER NOT NULL,
  last_login    INTEGER,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);

-- ---- Sessions (server-side; cookie carries only the opaque id) ---------------
CREATE TABLE IF NOT EXISTS sessions (
  id            TEXT PRIMARY KEY,            -- 256-bit random
  user_id       TEXT NOT NULL,
  tenant_id     TEXT NOT NULL,
  csrf          TEXT NOT NULL,               -- double-submit token
  created_at    INTEGER NOT NULL,
  idle_at       INTEGER NOT NULL,            -- last activity (idle expiry)
  expires_at    INTEGER NOT NULL,            -- absolute expiry
  revoked_at    INTEGER,
  ip            TEXT,
  ua            TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- ---- Platform-owner comp registry (global, owner/admin only) -----------------
CREATE TABLE IF NOT EXISTS comp_grants (
  email         TEXT PRIMARY KEY,
  role          TEXT NOT NULL,               -- admin|gold|free
  granted_by    TEXT,
  granted_at    INTEGER NOT NULL
);

-- ---- Assets (vehicles / units / booths / equipment) --------------------------
CREATE TABLE IF NOT EXISTS assets (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  name          TEXT NOT NULL,
  type          TEXT,
  status        TEXT DEFAULT 'available',
  day_rate_cents INTEGER DEFAULT 0,
  info          TEXT DEFAULT '{}',           -- JSON: year/make/model/color/vin/photo
  blackouts     TEXT DEFAULT '[]',           -- JSON: [{from,to,reason}]
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets(tenant_id);

-- ---- Bookings ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bookings (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  customer_id   TEXT,
  asset_id      TEXT,
  starts        INTEGER,
  ends          INTEGER,
  status        TEXT DEFAULT 'pending',
  revenue_cents INTEGER DEFAULT 0,           -- server-recomputed from money-rules
  data          TEXT DEFAULT '{}',           -- JSON: quote, extras, charges, signatures refs
  portal_token  TEXT,                        -- random token for the customer's public /portal/<token> link
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_bookings_tenant ON bookings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_bookings_tenant_status ON bookings(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_bookings_portal ON bookings(portal_token);

-- ---- Customers ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS customers (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  name          TEXT,
  email         TEXT,
  phone         TEXT,
  data          TEXT DEFAULT '{}',
  created_at    INTEGER NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_customers_tenant ON customers(tenant_id);

-- ---- Charges sent to a customer's portal -------------------------------------
CREATE TABLE IF NOT EXISTS charges (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  booking_id    TEXT,
  label         TEXT,
  amount_cents  INTEGER NOT NULL,
  kind          TEXT DEFAULT 'charge',       -- charge|deposit(hold)|combo
  status        TEXT DEFAULT 'unpaid',       -- unpaid|paid|refunded
  stripe_ref    TEXT,
  created_at    INTEGER NOT NULL,
  paid_at       INTEGER,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_charges_tenant ON charges(tenant_id);

-- ---- Ledger: additional income + expenses ------------------------------------
CREATE TABLE IF NOT EXISTS ledger (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  kind          TEXT NOT NULL,               -- income|expense
  label         TEXT,
  amount_cents  INTEGER NOT NULL,
  on_date       TEXT,
  created_at    INTEGER NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_ledger_tenant ON ledger(tenant_id);

-- ---- Promo codes -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS promos (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  code          TEXT NOT NULL,
  disc_type     TEXT,                        -- pct|amount
  disc_value    INTEGER,
  scope         TEXT DEFAULT 'all',
  deadline      INTEGER,
  cap           INTEGER,
  used          INTEGER DEFAULT 0,
  active        INTEGER DEFAULT 1,
  created_at    INTEGER NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_promos_tenant_code ON promos(tenant_id, code);

-- ---- Domains sold through the reseller (Dynadot -> OpenSRS) -------------------
CREATE TABLE IF NOT EXISTS domains_sold (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  domain        TEXT NOT NULL,
  tld           TEXT,
  cost_cents    INTEGER,                     -- wholesale we paid
  price_cents   INTEGER,                     -- retail customer paid
  status        TEXT DEFAULT 'pending',      -- pending|registered|failed
  registrar_ref TEXT,                        -- provider order id
  registrar     TEXT DEFAULT 'dynadot',
  created_at    INTEGER NOT NULL,
  renews_at     INTEGER,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_domains_tenant ON domains_sold(tenant_id);

-- ---- Integrations: tenant "bring your own key" (stored ENCRYPTED) ------------
CREATE TABLE IF NOT EXISTS integrations (
  tenant_id     TEXT NOT NULL,
  provider      TEXT NOT NULL,               -- stripe|square|resend|twilio|anthropic|dynadot
  kind          TEXT,                        -- payments|email|sms|ai|domains
  secret_enc    TEXT,                        -- AES-GCM ciphertext; NEVER returned to client
  meta          TEXT DEFAULT '{}',           -- non-secret display (masked last4, account name)
  connected_at  INTEGER,
  PRIMARY KEY (tenant_id, provider)
);

-- ---- Atlas.io AI credits (server-decremented, per tenant) --------------------
CREATE TABLE IF NOT EXISTS ai_credits (
  tenant_id     TEXT PRIMARY KEY,
  balance       INTEGER DEFAULT 0,
  period_start  INTEGER,
  updated_at    INTEGER,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

-- ---- Audit log (append-only) -------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id     TEXT,
  actor         TEXT,                        -- user email/id
  action        TEXT NOT NULL,
  meta          TEXT DEFAULT '{}',
  ip            TEXT,
  ua            TEXT,
  at            INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id, at);

-- ---- Stripe webhook dedup ----------------------------------------------------
CREATE TABLE IF NOT EXISTS webhook_events (
  stripe_event_id TEXT PRIMARY KEY,
  at            INTEGER NOT NULL
);

-- ---- Consents (TCPA / CAN-SPAM) ----------------------------------------------
CREATE TABLE IF NOT EXISTS consents (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  email         TEXT,
  phone         TEXT,
  channel       TEXT,                        -- sms|email
  consent_text  TEXT,
  ip            TEXT,
  at            INTEGER NOT NULL,
  revoked_at    INTEGER,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_consents_tenant ON consents(tenant_id);

-- ---- Rate-limit buckets (per ip/account/action) ------------------------------
CREATE TABLE IF NOT EXISTS rate_limits (
  bucket        TEXT PRIMARY KEY,            -- e.g. login:1.2.3.4  or  ai:tenant123
  count         INTEGER DEFAULT 0,
  window_start  INTEGER NOT NULL
);
