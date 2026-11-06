CREATE TABLE nr_usage_consents (
  user_id TEXT NOT NULL,
  capability TEXT NOT NULL CHECK (capability IN ('core_compute', 'advanced_compute', 'preview')),
  granted_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, capability)
);

CREATE INDEX nr_usage_consents_expiry ON nr_usage_consents (expires_at);
