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

書き込み承認の試作は、固定された架空の対象だけを使うブラウザー内リハーサルです。mockテストはowner/session binding、nonce、claim、期限、引数・スキーマ・ポリシーの変更、キャンセル、outcome_unknown後の再試行禁止を確認します。UI用DOMスタブテストは連打、確認中の無効化、期限切れ・stale状態からの復旧を確認します。`test-site-ui.mjs` は実際のSiteページスクリプトを偽DOM上で動かし、tools/listボタンが明示クリックまで呼ばれないこと、20件ページ送り、スキーマの個別取得とエラー表示、provider説明をプレーンテキストとしてのみ表示すること、telemetry/tool callをしないこと、approval CSRFと単回チャレンジ、曖昧な承認結果後の再送禁止を確認します。`test-mcp.mjs` は40件の合成tools/list、長い説明、20KBスキーマを使い、ページ上限、snapshot不一致の拒否、schemaHash一致、canonical JSONチャンク、応答byte上限、文字境界の進行、秘密パターンを含むobject keyの拒否を検証します。`test-operation-approval-store.mjs` はNode.js SQLiteでmigration 0000–0005とD1-backed session/proposal状態遷移をテストし、session/CSRF binding、generation drift、nonce hash、同時approval CAS、single-use claim、未bind提案の取消し、別browser sessionからの取消し防止、24時間/30日の既定保持ルール、ordered cleanup index、cleanup 100件上限と冪等性を検証します。`test-self-host-sessions.mjs` は別の合成SQLiteを使い、gateway session/CSRF cookie hash、origin/fetch metadata、sid rotation、revoke/expiry、ordered purgeとprivate gateway統合を確認します。`test-site-ui.mjs` はNew Relic localhost-paste完了画面がself-host CSRF headerを送ることも検証します。GatewayとWorkerの結合も合成鍵・偽バックエンドだけで確認し、Provider dispatchは0回です。これらは本番のブラウザ認証、外部IdP、実際の対象所有権・影響やProvider動作を検証しません。Workerのwrite/destructive経路は引き続き停止しています。Cleanupはscheduled handlerから呼べますが、フラグ既定falseで、このrepoにはcron triggerがありません。

`test-mcp-policy.mjs` は nullable type arrays、true/false boolean schemas、root `$defs`の単一ローカル参照、JSON Pointer `~0`/`~1` escaping、fingerprint固定、制約適用、および外部・nested・循環・missing refsの拒否を確認します。最上位の`false`入力・出力スキーマは実行不可として停止し、false出力が「schemaなし」と混同されないことも確認します。複雑さ上限に達した際のfatal errorがunion分岐の不一致として抑制されないこと、JSON Schemaに沿ったUnicode code-pointの文字長と大整数のinteger判定もテストします。上限は合成データで確認し、実際のNew Relic schemaがこれらの形式を使うかは未確認です。

実環境のユーザー分離、複数インスタンスD1でのrefresh/disconnect race、認可期限切れ、OAuth拒否、公式MCP障害、iPhone上の公開版、複雑なNRQL構文の包括的な検証は未完了。既存テストの成功を一般公開の安全性保証と扱わない。
