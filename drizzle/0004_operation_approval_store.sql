-- Additive, fail-closed groundwork for browser-confirmed operation proposals.
-- No write tool or provider dispatch is enabled by this migration.
ALTER TABLE nr_connections ADD COLUMN connection_generation TEXT NOT NULL DEFAULT '';
UPDATE nr_connections
SET connection_generation = lower(hex(randomblob(16)))
WHERE connection_generation = '';

ALTER TABLE nr_preferences ADD COLUMN selection_generation TEXT NOT NULL DEFAULT '';
UPDATE nr_preferences
SET selection_generation = lower(hex(randomblob(16)))
WHERE selection_generation = '';

CREATE TABLE nr_approval_sessions (
  session_key_hash TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL,
  auth_mode TEXT NOT NULL CHECK (auth_mode IN ('sites', 'signed_proxy')),
  browser_binding_hash TEXT NOT NULL,
  csrf_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE INDEX nr_approval_sessions_user_expiry
  ON nr_approval_sessions (user_id, expires_at);

CREATE TABLE nr_operation_proposals (
  proposal_id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL,
  session_key_hash TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'claimed', 'outcome_unknown', 'completed', 'failed', 'cancelled', 'stale')),
  tool_name TEXT NOT NULL,
  operation TEXT NOT NULL CHECK (operation IN ('write', 'destructive')),
  billing TEXT NOT NULL CHECK (billing IN ('none', 'core_compute', 'advanced_compute', 'unknown')),
  region TEXT NOT NULL CHECK (region IN ('us', 'eu', 'jp')),
  account_id TEXT NOT NULL,
  connection_generation TEXT NOT NULL,
  selection_generation TEXT NOT NULL,
  schema_hash TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  arguments_hash TEXT NOT NULL,
  encrypted_arguments TEXT NOT NULL,
  effect_summary TEXT NOT NULL,
  approval_nonce_hash TEXT,
  challenge_expires_at INTEGER,
  claim_id TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  approved_at INTEGER,
  claimed_at INTEGER,
  finished_at INTEGER,
  result_code TEXT
);

CREATE INDEX nr_operation_proposals_user_state_expiry
  ON nr_operation_proposals (user_id, status, expires_at);
CREATE INDEX nr_operation_proposals_session_state
  ON nr_operation_proposals (session_key_hash, status);
