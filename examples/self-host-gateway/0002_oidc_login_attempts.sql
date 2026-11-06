-- Private gateway AUTH_DB only. Never apply this table to the New Relic app D1.
CREATE TABLE IF NOT EXISTS nr_gateway_oidc_login_attempts (
  state_hash TEXT PRIMARY KEY NOT NULL CHECK (length(state_hash) = 64 AND state_hash NOT GLOB '*[^a-f0-9]*'),
  encrypted_attempt TEXT NOT NULL CHECK (length(encrypted_attempt) <= 2048),
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
  consumed_at INTEGER CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE INDEX IF NOT EXISTS nr_gateway_oidc_login_expiry_idx
  ON nr_gateway_oidc_login_attempts(expires_at, state_hash)
  WHERE consumed_at IS NULL;
