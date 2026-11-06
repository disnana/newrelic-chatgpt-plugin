# Changelog

## 0.3.0 — Unreleased

- 個人用ChatGPT SitesとPluginのセルフホスティング用ソースを整理。
- OAuth PKCE、暗号化保存、同時refreshのロックと条件付き保存。
- NRQLの制限、CSRF検証、応答サイズ制御とメトリクス検索の絞り込み。
- モックCI、タグ限定の配布ZIPとSHA-256生成を追加。
- 新規ユーザーのエンドツーエンド導入、本番D1の並行更新は未検証。

## 0.4.0 (development, not released)
- Separate revoked grants from transient OAuth, permission, configuration, encryption and concurrency errors; preserve credentials on failures
- Bound read-only 401 recovery, refresh rotation and cross-instance D1 leases; validate token/MCP response envelopes
- Add live capability catalog and schema/metadata-pinned generic read adapter, with fail-closed policy and account gates
- Keep billable, write/destructive, unknown and unreviewed functionality disabled; Preview additionally requires opt-in
- Document 41 official reference tools, billing limits and Advent feature availability without claiming live parity
- Preserve Scylla investigation workflows; move model-initiated disconnect to owner UI confirmation
