# トラブルシューティング

| 症状 | 確認すること |
| --- | --- |
| access_denied / 管理者による無効化 | New Relic MCP ServerのFeature Controlと組織ロール。プラグインから回避できない |
| `oauth_timeout` | Siteから公式token URLへの通信が制限時間内に応答しなかった状態。認証情報は保持される。Siteの外向き通信と一時的な障害を確認し、直るまで待ってから新しい接続フローを開始する。同じlocalhost callback URLは再利用しない |
| `oauth_network_error` | SiteのOAuth通信がネットワーク例外になった状態。認証情報は保持される。生の例外内容は表示・記録しない。新しい接続フローを開始する前にSiteの外向き通信とNew Relicの状態を確認する |
| Feature Controlに項目なし | 対象組織・権限・利用可能機能を確認。Previews & Trialsも確認するが、表示は契約と提供状況に依存する |
| localhostで接続エラー | 認可後のURLを専用Siteページに貼る方式では想定される。code/stateをチャットに貼らない |
| 応答サイズ超過 | ツール一覧とデータ結果に別上限がある。取得期間・件数を減らす |
| メトリクスが見つからない | 検索は上流から返された一覧内の一致。存在しないと断定しない |
| 期限切れ | Siteから再接続。更新中の場合は少し待って再試行 |
| DB / Secretエラー | 新規SiteのDB binding、両方のmigration、Secret設定を確認 |
| ツールが出ない | Siteを所有者限定で公開し、生成されたPluginを接続。必要に応じ新しいチャットで確認 |

トークン・認可URL・実ログをIssueに投稿しない。既知の制約はsecurity-review.mdを参照。
