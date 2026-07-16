CREATE TABLE IF NOT EXISTS tenants (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  subdomain     TEXT UNIQUE,
  fleet_type    TEXT DEFAULT 'cars',
  plan          TEXT DEFAULT 'trial',
  trial_ends    INTEGER,
  brand         TEXT DEFAULT '{}',
  money         TEXT DEFAULT '{}',
  settings      TEXT DEFAULT '{}',
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  pw_hash       TEXT NOT NULL,
  pw_salt       TEXT NOT NULL,
  pw_algo       TEXT DEFAULT 'pbkdf2-sha256-210000',
  tenant_id     TEXT NOT NULL,
  role          TEXT DEFAULT 'owner',
  caps          TEXT DEFAULT '{}',
  created_at    INTEGER NOT NULL,
  last_login    INTEGER,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
CREATE TABLE IF NOT EXISTS sessions (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL,
  tenant_id     TEXT NOT NULL,
  csrf          TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  idle_at       INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  revoked_at    INTEGER,
  ip            TEXT,
  ua            TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS comp_grants (
  email         TEXT PRIMARY KEY,
  role          TEXT NOT NULL,
  granted_by    TEXT,
  granted_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS assets (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  name          TEXT NOT NULL,
  type          TEXT,
  status        TEXT DEFAULT 'available',
  day_rate_cents INTEGER DEFAULT 0,
  info          TEXT DEFAULT '{}',
  blackouts     TEXT DEFAULT '[]',
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets(tenant_id);
CREATE TABLE IF NOT EXISTS bookings (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  customer_id   TEXT,
  asset_id      TEXT,
  starts        INTEGER,
  ends          INTEGER,
  status        TEXT DEFAULT 'pending',
  revenue_cents INTEGER DEFAULT 0,
  data          TEXT DEFAULT '{}',
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_bookings_tenant ON bookings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_bookings_tenant_status ON bookings(tenant_id, status);
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
CREATE TABLE IF NOT EXISTS charges (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  booking_id    TEXT,
  label         TEXT,
  amount_cents  INTEGER NOT NULL,
  kind          TEXT DEFAULT 'charge',
  status        TEXT DEFAULT 'unpaid',
  stripe_ref    TEXT,
  created_at    INTEGER NOT NULL,
  paid_at       INTEGER,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_charges_tenant ON charges(tenant_id);
CREATE TABLE IF NOT EXISTS ledger (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  kind          TEXT NOT NULL,
  label         TEXT,
  amount_cents  INTEGER NOT NULL,
  on_date       TEXT,
  created_at    INTEGER NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_ledger_tenant ON ledger(tenant_id);
CREATE TABLE IF NOT EXISTS promos (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  code          TEXT NOT NULL,
  disc_type     TEXT,
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
CREATE TABLE IF NOT EXISTS domains_sold (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  domain        TEXT NOT NULL,
  tld           TEXT,
  cost_cents    INTEGER,
  price_cents   INTEGER,
  status        TEXT DEFAULT 'pending',
  registrar_ref TEXT,
  registrar     TEXT DEFAULT 'dynadot',
  created_at    INTEGER NOT NULL,
  renews_at     INTEGER,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_domains_tenant ON domains_sold(tenant_id);
CREATE TABLE IF NOT EXISTS integrations (
  tenant_id     TEXT NOT NULL,
  provider      TEXT NOT NULL,
  kind          TEXT,
  secret_enc    TEXT,
  meta          TEXT DEFAULT '{}',
  connected_at  INTEGER,
  PRIMARY KEY (tenant_id, provider)
);
CREATE TABLE IF NOT EXISTS ai_credits (
  tenant_id     TEXT PRIMARY KEY,
  balance       INTEGER DEFAULT 0,
  period_start  INTEGER,
  updated_at    INTEGER,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE TABLE IF NOT EXISTS audit_log (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id     TEXT,
  actor         TEXT,
  action        TEXT NOT NULL,
  meta          TEXT DEFAULT '{}',
  ip            TEXT,
  ua            TEXT,
  at            INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id, at);
CREATE TABLE IF NOT EXISTS webhook_events (
  stripe_event_id TEXT PRIMARY KEY,
  at            INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS consents (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  email         TEXT,
  phone         TEXT,
  channel       TEXT,
  consent_text  TEXT,
  ip            TEXT,
  at            INTEGER NOT NULL,
  revoked_at    INTEGER,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_consents_tenant ON consents(tenant_id);
CREATE TABLE IF NOT EXISTS rate_limits (
  bucket        TEXT PRIMARY KEY,
  count         INTEGER DEFAULT 0,
  window_start  INTEGER NOT NULL
);
