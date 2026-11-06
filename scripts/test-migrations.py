from pathlib import Path
import sqlite3


root = Path(__file__).resolve().parent.parent
sql = (root / "drizzle" / "0000_newrelic_mcp.sql").read_text(encoding="utf-8")
connection = sqlite3.connect(":memory:")
connection.executescript(sql)
connection.executescript((root / "drizzle" / "0001_refresh_locks.sql").read_text(encoding="utf-8"))
connection.executescript((root / "drizzle" / "0002_oauth_completion_fence.sql").read_text(encoding="utf-8"))

# Existing private connection and account state must survive the new additive
# consent migration unchanged.
connection.execute(
    "INSERT INTO nr_connections VALUES (?, ?, ?, ?, ?, ?)",
    ("existing-user", "encrypted-access", "encrypted-refresh", 100, 50, "us"),
)
connection.execute("INSERT INTO nr_preferences VALUES (?, ?, ?, ?)", ("existing-user", "123", "prod", 60))
connection.commit()
connection.executescript((root / "drizzle" / "0003_usage_consents.sql").read_text(encoding="utf-8"))
connection.executescript((root / "drizzle" / "0004_operation_approval_store.sql").read_text(encoding="utf-8"))

tables = {
    row[0]
    for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    )
}
expected = {
    "nr_oauth_states", "nr_connections", "nr_preferences", "nr_rate_limits", "nr_refresh_locks",
    "nr_usage_consents", "nr_approval_sessions", "nr_operation_proposals",
}
assert tables == expected, (tables, expected)

columns = {row[1] for row in connection.execute("PRAGMA table_info(nr_connections)")}
assert {
    "user_id",
    "encrypted_access_token",
    "encrypted_refresh_token",
    "access_expires_at",
    "connected_at",
    "region",
    "connection_generation",
} == columns

state_columns = {row[1] for row in connection.execute("PRAGMA table_info(nr_oauth_states)")}
assert "consumed_at" in state_columns

indexes = {row[1] for row in connection.execute("PRAGMA index_list(nr_oauth_states)")}
assert {"nr_oauth_states_expiry", "nr_oauth_states_user"} <= indexes

consent_columns = {row[1] for row in connection.execute("PRAGMA table_info(nr_usage_consents)")}
assert {"user_id", "capability", "granted_at", "expires_at"} == consent_columns
assert connection.execute("SELECT encrypted_access_token FROM nr_connections WHERE user_id = ?", ("existing-user",)).fetchone()[0] == "encrypted-access"
assert connection.execute("SELECT account_id FROM nr_preferences WHERE user_id = ?", ("existing-user",)).fetchone()[0] == "123"
assert connection.execute("SELECT connection_generation FROM nr_connections WHERE user_id = ?", ("existing-user",)).fetchone()[0]
assert connection.execute("SELECT selection_generation FROM nr_preferences WHERE user_id = ?", ("existing-user",)).fetchone()[0]
preference_columns = {row[1] for row in connection.execute("PRAGMA table_info(nr_preferences)")}
assert {"user_id", "account_id", "account_name", "updated_at", "selection_generation"} == preference_columns
session_columns = {row[1] for row in connection.execute("PRAGMA table_info(nr_approval_sessions)")}
assert {"session_key_hash", "user_id", "auth_mode", "browser_binding_hash", "csrf_hash", "created_at", "expires_at", "revoked_at"} == session_columns
proposal_columns = {row[1] for row in connection.execute("PRAGMA table_info(nr_operation_proposals)")}
assert {
    "proposal_id", "user_id", "session_key_hash", "status", "tool_name", "operation", "billing", "region",
    "account_id", "connection_generation", "selection_generation", "schema_hash", "policy_hash", "arguments_hash",
    "encrypted_arguments", "effect_summary", "approval_nonce_hash", "challenge_expires_at", "claim_id", "created_at",
    "expires_at", "approved_at", "claimed_at", "finished_at", "result_code",
} == proposal_columns
try:
    connection.execute("INSERT INTO nr_usage_consents VALUES (?, ?, ?, ?)", ("existing-user", "unknown", 1, 2))
except sqlite3.IntegrityError:
    pass
else:
    raise AssertionError("unknown consent capabilities must be rejected")

print("D1 migrations passed SQLite syntax, additive-data preservation, consent checks, and schema checks")
