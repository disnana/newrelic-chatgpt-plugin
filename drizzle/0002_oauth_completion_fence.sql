-- Preserve a claimed OAuth state until token exchange finishes. Disconnect deletes
-- the state, which fences the conditional connection write in newrelic.js.
ALTER TABLE nr_oauth_states ADD COLUMN consumed_at INTEGER;
