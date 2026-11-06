-- Separate, additive store for the example gateway's browser login sessions.
-- Apply only to the gateway's private AUTH_DB, not the New Relic application DB.
CREATE TABLE nr_gateway_browser_sessions (
  session_hash TEXT PRIMARY KEY NOT NULL,
  subject TEXT NOT NULL,
  session_id TEXT NOT NULL UNIQUE,
  csrf_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  CHECK (length(session_hash) = 64),
  CHECK (length(csrf_hash) = 64),
  CHECK (length(session_id) = 32),
  CHECK (length(subject) BETWEEN 1 AND 256),
  CHECK (expires_at > created_at)
);

CREATE INDEX nr_gateway_browser_sessions_expiry_cleanup
  ON nr_gateway_browser_sessions (expires_at)
  WHERE revoked_at IS NULL;
CREATE INDEX nr_gateway_browser_sessions_revocation_cleanup
  ON nr_gateway_browser_sessions (revoked_at)
  WHERE revoked_at IS NOT NULL;
