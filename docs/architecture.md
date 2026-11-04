# アーキテクチャ

ChatGPTのSite連携MCPはWorker `/mcp` に到達する。Siteの認証済みユーザー識別子をハッシュ化したキーでD1のOAuth state、暗号化済みトークン、選択アカウントを分ける。New Relic公式OAuthは認可コードとPKCEを使用し、認可後のlocalhost URLをSite内のページから受け取る。Workerは公式New Relic MCPを呼び出し、結果をChatGPTに返す。

現状は所有者のみで動作確認した構成。ユーザー間分離、公開Siteの認証境界、公式OAuthクライアントの第三者提供条件は未検証。Site側の接続解除はD1の保存情報を削除するが、New Relic側の認可を失効しない。

ソース: `worker/index.js` はMCPとHTTP、`worker/newrelic.js` はOAuth・D1・公式MCP通信、`worker/nrql.js` はクエリ検証、`worker/*.html` はUI、`drizzle/` はD1スキーマ。既知の公開阻害事項は `security-review.md` を参照。

公式MCPの `include-tags` で discovery、data-access、alerting を要求し、ツール定義のページ送りを最大10ページ・500件に制限する。公式ツールと同等の全機能は提供していない。対応外の機能を推測で呼び出さず、名前は候補との完全一致で決める。メトリクス名は上流から得た範囲を検索するため、返らなかった名前が存在しないとは限らない。複数ステップ調査では一部失敗を明示する。

参考: https://docs.newrelic.com/docs/agentic-ai/mcp/tool-reference/ 。公式MCPは多数の専門ツールを持ち、一般的な呼び出しもCore Compute消費の対象となり得る。AI分析の一部はAdvanced Compute対象。公開前に料金とユーザー向け表示を確認する。
