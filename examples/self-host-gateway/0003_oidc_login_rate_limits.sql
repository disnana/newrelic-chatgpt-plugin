-- Private gateway AUTH_DB only. Never apply this table to the New Relic app D1.
-- bucket_hash is derived from a keyed opaque client identity and never stores a raw IP.
CREATE TABLE IF NOT EXISTS nr_gateway_oidc_login_rate_limits (
  bucket_hash TEXT PRIMARY KEY NOT NULL CHECK (length(bucket_hash) = 64 AND bucket_hash NOT GLOB '*[^a-f0-9]*'),
  window_start INTEGER NOT NULL CHECK (window_start >= 0),
  request_count INTEGER NOT NULL CHECK (request_count BETWEEN 1 AND 100000),
  updated_at INTEGER NOT NULL CHECK (updated_at >= window_start)
);

CREATE INDEX IF NOT EXISTS nr_gateway_oidc_rate_limit_expiry_idx
  ON nr_gateway_oidc_login_rate_limits(window_start, bucket_hash);
