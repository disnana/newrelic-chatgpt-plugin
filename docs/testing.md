# テスト

Node.js 22以降、Python 3、bashを使う。ロックされた開発依存を入れ、以下のCI相当チェックを実行する。

```sh
npm ci
npm run build
npm run validate
npm run typecheck
npm run lint
npm test
npm audit --audit-level=high
python3 scripts/test-migrations.py
python3 -m unittest discover -s ops/scylla-gate -p 'test_*.py' -v
python3 scripts/check-distribution.py
python3 scripts/package-release.py
```

TypeScript `checkJs` はJavaScript Workerの型・null検査に使います。上流のOAuth/MCP応答、スキーマポリシー、ユーザー間分離、disconnect時のOAuth race、課金カテゴリ/オプトイン、別々のOAuth・通常APIレート枠、深い上流メタデータ、API/JSON-RPCの最終Unicode応答上限はモックでテストし、実アカウントに接続しません。依存監査の対象はdev dependencyを含みます。

実環境のユーザー分離、複数インスタンスD1でのrefresh/disconnect race、認可期限切れ、OAuth拒否、公式MCP障害、iPhone上の公開版、複雑なNRQL構文の包括的な検証は未完了。既存テストの成功を一般公開の安全性保証と扱わない。
