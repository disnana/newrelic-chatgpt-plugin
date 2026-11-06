# Changelog

## 0.3.0 — Unreleased

- 個人用ChatGPT SitesとPluginのセルフホスティング用ソースを整理。
- OAuth PKCE、暗号化保存、同時refreshのロックと条件付き保存。
- NRQLの制限、CSRF検証、応答サイズ制御とメトリクス検索の絞り込み。
- モックCI、タグ限定の配布ZIPとSHA-256生成を追加。
- 新規ユーザーのエンドツーエンド導入、本番D1の並行更新は未検証。

## 0.4.0 (development, not released)
- Separate revoked grants from transient OAuth, permission, configuration, encryption and concurrency errors; preserve credentials on failures
- Bound read-only 401 recovery, diagnose a repeated 401 after refresh, and fence late OAuth completion after disconnect
- Add an incremental D1 migration for one-time OAuth completion claims; retain refresh rotation and cross-instance leases
- Enforce default-off Core/Advanced Compute settings; validate schemas, bound request streams and cap UTF-8 tool output
- Add live capability catalog and schema/metadata-pinned generic read adapter, with fail-closed policy and account gates
- Keep write/destructive, unknown and unreviewed functionality disabled; Core/Advanced Compute reads require matching opt-ins and Preview adds another gate
- Document 41 official reference tools, billing limits and Advent feature availability without claiming live parity
- Preserve Scylla investigation workflows; retain Sites-only identity assumptions and document that general self-host authentication is not implemented
- Add JavaScript checkJs type/null checking, full dependency audit and expanded mocked OAuth/MCP regression coverage
