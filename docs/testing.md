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

TypeScript `checkJs` はJavaScript Workerの型・null検査に使います。上流のOAuth/MCP応答、スキーマポリシー、ユーザー間分離、disconnect時のOAuth race、ユーザー別Core/Advanced/Preview許可の既定値・30日期限・Origin制限・解除、モック中のtools/list後の失効・期限切れとtool call間の解除に対するdispatch直前の再確認、別々のOAuth・通常APIレート枠、深い上流メタデータ、API/JSON-RPCの最終Unicode応答上限、signed-proxy JWT検証と認証ルート、期限切れ保存値をstatus表示だけではrefreshしないこと、明示再接続リンクと空の認証モード拒否、OAuth失敗時のallowlist済み非秘密診断コード表示と任意のprovider error text/codeの非開示は合成データのモックでテストし、実アカウントに接続しません。依存監査の対象はdev dependencyを含みます。

書き込み承認の試作は、固定された架空の対象だけを使うブラウザー内リハーサルです。mockテストはowner/session binding、nonce、claim、期限、引数・スキーマ・ポリシーの変更、キャンセル、outcome_unknown後の再試行禁止を確認します。UI用DOMスタブテストは連打、確認中の無効化、期限切れ・stale状態からの復旧を確認します。`test-operation-approval-store.mjs` はNode.js SQLiteでmigration 0000–0004とD1-backed session/proposal状態遷移をテストし、session/CSRF binding、generation drift、nonce hash、同時approval CAS、single-use claimを検証します。GatewayとWorkerの結合も合成鍵・偽バックエンドだけで確認し、Provider dispatchは0回です。これらは本番のブラウザ認証、外部IdP、実際の対象所有権・影響やProvider動作を検証しません。Workerのwrite/destructive経路は引き続き停止しています。

実環境のユーザー分離、複数インスタンスD1でのrefresh/disconnect race、認可期限切れ、OAuth拒否、公式MCP障害、iPhone上の公開版、複雑なNRQL構文の包括的な検証は未完了。既存テストの成功を一般公開の安全性保証と扱わない。
