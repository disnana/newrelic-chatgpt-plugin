# OAuth

公式Authorization Code + PKCEを使用。SiteユーザーIDをハッシュ化しstateとトークンの保存先を分離する。stateは10分・1回限りで、ユーザーとredirect URIを検証する。

公開クライアントIDは秘密ではない。個人のaccess/refresh tokenや暗号鍵は配布物に含まない。トークンはAES-GCMでD1に保存する。各自のSiteごとに独立した32バイトのbase64url暗号鍵をSecretに設定する。鍵をチャットに貼らない。

現在はlocalhost callbackのURL全体をSite内の認証完了ページへ貼り付ける方式。URLにcodeがなくaccess_deniedがある場合は認証未完了。New RelicのFeature Controlや組織権限を確認する。URLをチャット・Issueに貼らない。

refreshはD1のユーザー別リースと条件付き保存で競合を制御する。モックでは同時更新と接続変更後の上書き拒否を確認。本番でのリース期限切れ、障害復旧、別ユーザーの全経路は未検証。

Siteからの接続解除はローカル保存情報の削除であり、New Relic側の許可取消しは別操作。公式OAuthクライアント利用条件が変わる場合がある。

https://docs.newrelic.com/docs/agentic-ai/mcp/overview/

## v0.4.0 の修正と公式の時間制限

公式 overview は access token の有効期限を5分、自動 refresh 後も24時間で再ログインが必要と説明しています。永続的な無期限ログインは保証しません。scope は公式記載の `observability:read offline offline_access` を維持し、書き込み scope は追加しません。

今回のコード上の問題は、HTTP 403、invalid_client、復号失敗、保存競合をすべて再認証としていた点と、上流文中の auth / token 部分一致を認証失効と扱っていた点です。これらを区別し、明示的な401のみ読み取り時の一回更新再試行を許可します。invalid_grant / access_denied は再認証、設定・鍵・競合・ネットワーク・一時障害は別の診断になります。既存トークンは失敗だけで削除しません。

429 の明示的拒否は一回だけ再試行します。timeout / 5xx 時のトークン交換は、上流だけ rotation 済みの可能性があるため自動再送しません。D1 ユーザー別 lease と compare-and-swap を使って新旧トークンを一度に保存します。上流更新と D1 保存を跨ぐ分散トランザクションは不可能で、その間の障害は残存リスクです。

ユーザーの実接続で起きている更新失敗の根本原因は、旧版の安全な診断情報だけでは確定できません。コードで確認した誤分類と、実接続の原因を混同しません。

## 副作用のない接続状態確認

Workerの `/api/status` と `get_connection_status` は、保存済みD1メタデータだけを返し、New Relicへ接続せず、トークン更新もしません。`statusSource: local_metadata` と `tokenRefreshDue` は保存値の目安であり、トークンがNew Relic側で受理されるか・OAuth grantが有効かは証明しません。接続解除も行いません。

実際のrefresh失敗コードを取得するには、期限切れトークンでNew RelicへOAuth refresh requestを送る必要があり、refresh tokenがローテーションされる可能性があります。`get_connection_status` の旧到達性プローブも公式MCPを初期化し、設定次第で利用量を消費する可能性がありました。安全な診断と課金禁止の条件を守るため、この環境ではライブ状態確認やrefreshを再実行していません。過去に表示された非秘密の `refreshError.code` があれば、それだけで分類できます。トークン・認可URL・コールバックURLは共有しないでください。
