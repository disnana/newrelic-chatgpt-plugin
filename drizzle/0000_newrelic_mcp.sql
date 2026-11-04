CREATE TABLE nr_oauth_states (
  state_hash TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL,
  encrypted_verifier TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  region TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX nr_oauth_states_expiry ON nr_oauth_states (expires_at);
CREATE INDEX nr_oauth_states_user ON nr_oauth_states (user_id);

CREATE TABLE nr_connections (
  user_id TEXT PRIMARY KEY NOT NULL,
  encrypted_access_token TEXT NOT NULL,
  encrypted_refresh_token TEXT NOT NULL,
  access_expires_at INTEGER NOT NULL,
  connected_at INTEGER NOT NULL,
  region TEXT NOT NULL
);

CREATE TABLE nr_preferences (
  user_id TEXT PRIMARY KEY NOT NULL,
  account_id TEXT NOT NULL,
  account_name TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE nr_rate_limits (
  user_id TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  call_count INTEGER NOT NULL,
  PRIMARY KEY (user_id, window_start)
);
