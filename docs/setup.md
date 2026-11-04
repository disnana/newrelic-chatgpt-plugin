# New Relic × ChatGPT 個人セットアップ版（非公式・実験版）

Disnanaによる非公式のNew Relic連携です。各利用者が自分だけのChatGPT SiteとMCPプラグインを作成し、自分のNew Relic OAuthで接続するためのソースです。サイトは所有者限定で使用してください。一般公開版・審査済み製品ではありません。

## 必要なもの

- ChatGPT SitesでWorker、D1、MCPプラグインを作成できるアカウント
- New Relicアカウント。組織のNew Relic MCP Server機能とユーザーの読み取り権限が必要
- Siteごとに独立した32バイトの暗号鍵。秘密値は会話・Git・ログ・ZIPに入れない

## ChatGPT Sitesでのセットアップ

1. このZIPを新しいChatGPT会話に添付し、Sitesを指定して次の指示を送る。

> 添付ZIPを展開し、既存SiteのIDを使わず新しい所有者限定のChatGPT Siteとして構築してください。Worker ESM、D1 binding DB、MCP capabilityを使用し、drizzleのmigrationを順に適用してください。NEW_RELIC_TOKEN_ENCRYPTION_KEYにはSiteごとに暗号学的に安全な32バイトのbase64url鍵を生成し、値を会話・ログ・ソースへ出さずSiteのSecretに設定してください。ビルドとテスト後、所有者限定で公開し、このSiteに紐づくプラグインを接続してください。一般公開しないでください。

2. Sites側の環境が鍵の安全な生成・設定を扱えない場合は、その処理を止めてください。鍵をチャットに貼らず、利用できる安全なSecret設定方法を確認してください。
3. 所有者限定で公開したSiteを開き、New Relicのリージョンを選んで接続する。認証後のlocalhost画面ではアドレス欄のURL全体をSite内の認証完了ページに貼る。認可コードを含むURLをチャットや他人に送らない。
4. アカウントを選び、ChatGPT通常チャットでSiteに紐づくプラグインの接続状態を確認する。新規環境・iPhoneでの全手順は未検証。

## 手動ビルドと検証

Node.js 22以降とPython 3が必要です。展開先で次を実行します。

```sh
npm run build
node scripts/validate-artifact.mjs
node scripts/test-mcp.mjs
python3 scripts/test-migrations.py
```

`.openai/hosting.json` にはSite IDを含めていません。新しいSiteの作成後にSitesの正式な手順でIDを設定します。D1の初期migrationとrefresh lock用migrationが必要です。

## セキュリティと既知の制約

- 認証情報はSite側のD1にAES-GCMで暗号化して保存します。鍵を失うと保存済みトークンは復号できません。
- ログアウトはSite内のトークンを削除します。New Relic側の許可取消しは別途必要です。
- ローカルのモック試験はありますが、本番D1の同時refresh、2人の実ユーザー間分離、全NRQL構文、障害時の処理は未検証です。正規表現主体のNRQL制限は完全な安全境界ではありません。
- localhostへの認可URLは、同じ端末上の別アプリがポートを使用している場合などのリスクがあります。PKCEでコードを接続操作に紐付けますが、この方法の第三者配布に関するNew Relicの許諾とOpenAIの審査適合性は未確認です。
- 上流データをChatGPTに送ります。監視ログには機密情報や悪意ある文字列が含まれ得ます。自動マスクの完全性は保証されません。
- New Relic公式MCPの全機能と同等ではありません。公式MCPの使用にはNew Relicの利用条件、アクセス制御、利用量に応じた計測・料金が適用されます。
- 各自の個人用Siteとして利用し、第三者に公開する場合はOAuthクライアントの利用条件と運用方針を確認してください。独自ソースはMITです。

詳細は docs/security-review.md、docs/testing.md、docs/plugin-submission.md を参照してください。
