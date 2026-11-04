# テスト

`npm run build` の後、`node scripts/validate-artifact.mjs`、`node scripts/test-mcp.mjs`、`python3 scripts/test-migrations.py` を実行する。合成認証情報とD1モックを使用し、実アカウントのデータを公開フィクスチャに使わない。

実環境のユーザー分離、並行トークン更新、認可期限切れ、OAuth拒否、公式MCP障害、iPhone上の公開版、複雑なNRQL構文の包括的な検証は未完了。既存テストの成功を一般公開の安全性保証と扱わない。
