-- Additive indexes for bounded cleanup introduced after 0004 was published.
-- Partial indexes preserve chronological ordering across the cleanup state set.
CREATE INDEX nr_operation_proposals_expiry_cleanup
  ON nr_operation_proposals (expires_at)
  WHERE status IN ('pending', 'approved');
CREATE INDEX nr_operation_proposals_claim_cleanup
  ON nr_operation_proposals (claimed_at)
  WHERE status = 'claimed';
CREATE INDEX nr_operation_proposals_terminal_cleanup
  ON nr_operation_proposals (COALESCE(finished_at, expires_at))
  WHERE status IN ('stale', 'cancelled', 'outcome_unknown', 'completed', 'failed');
CREATE INDEX nr_approval_sessions_retention_cleanup
  ON nr_approval_sessions (COALESCE(revoked_at, expires_at));
