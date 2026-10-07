-- API keys (scoped, revocable) + obfuscator quotas + result cache.
-- Keys are bound to a license plan; only hashes are stored.
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  license_key TEXT,
  plan TEXT NOT NULL DEFAULT 'day',
  key_hash TEXT NOT NULL UNIQUE,
  prefix TEXT NOT NULL,
  scopes TEXT NOT NULL DEFAULT 'obfuscate,validate,stats',
  daily_limit INTEGER,
  expires_at INTEGER,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);

CREATE TABLE IF NOT EXISTS obf_usage (
  identity TEXT NOT NULL,
  endpoint TEXT NOT NULL DEFAULT '',
  day TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (identity, endpoint, day)
);

CREATE TABLE IF NOT EXISTS obf_grants (
  id TEXT PRIMARY KEY,
  license_key TEXT NOT NULL,
  amount INTEGER NOT NULL,
  expires_at INTEGER,
  granted_by TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_obf_grants_key ON obf_grants(license_key);

-- NOTE (2026-10-07): prod already carries keys.plan (added out-of-band), so
-- the ALTER below was removed — it aborted the whole migration on prod
-- (duplicate column: plan) and blocked these tables. Tables are also
-- self-created at runtime (CREATE TABLE IF NOT EXISTS in index.js).
-- Fresh DBs: keys.plan is expected to exist; all reads fall back to 'day'.
CREATE INDEX IF NOT EXISTS idx_keys_plan ON keys(plan);

CREATE TABLE IF NOT EXISTS obf_cache (
  code_hash TEXT PRIMARY KEY,
  output TEXT NOT NULL,
  out_chars INTEGER NOT NULL,
  preset TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
