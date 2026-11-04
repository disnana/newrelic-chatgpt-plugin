CREATE TABLE nr_refresh_locks (
  user_id TEXT PRIMARY KEY NOT NULL,
  owner TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
