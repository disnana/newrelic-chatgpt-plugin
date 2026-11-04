from pathlib import Path
import sqlite3


root = Path(__file__).resolve().parent.parent
sql = (root / "drizzle" / "0000_newrelic_mcp.sql").read_text(encoding="utf-8")
connection = sqlite3.connect(":memory:")
connection.executescript(sql)
connection.executescript((root / "drizzle" / "0001_refresh_locks.sql").read_text(encoding="utf-8"))

tables = {
    row[0]
    for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    )
}
expected = {"nr_oauth_states", "nr_connections", "nr_preferences", "nr_rate_limits", "nr_refresh_locks"}
assert tables == expected, (tables, expected)

columns = {row[1] for row in connection.execute("PRAGMA table_info(nr_connections)")}
assert {
    "user_id",
    "encrypted_access_token",
    "encrypted_refresh_token",
    "access_expires_at",
    "connected_at",
    "region",
} == columns

indexes = {row[1] for row in connection.execute("PRAGMA index_list(nr_oauth_states)")}
assert {"nr_oauth_states_expiry", "nr_oauth_states_user"} <= indexes

print("D1 migration SQL passed SQLite syntax and schema checks")
