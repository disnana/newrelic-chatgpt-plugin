# セキュリティレビュー（進行中）

対象: Site Worker、OAuth、D1、公式MCP接続。コード確認に基づく一次レビューであり、共有ホストサービスやPluginディレクトリ公開を承認する監査結果ではない。OSSソースの公開と、第三者の認証情報を預かるサービス運用を区別する。

## 制約と共有ホスト運用の未検証事項

- 高（修正中）: refresh tokenローテーションにユーザー別D1リースと条件付き保存を追加し、ローカルモックの同時更新2件で上流への更新が1回になることを確認した。本番D1での並行性、リース期限切れ、ネットワーク失敗後に上流だけ更新された場合は未検証。
- 高: NRQL制限は完全な構文解析器ではない。入れ子、JOIN、複数の時間・件数条件など検証しにくい構文を拒否する対策を追加したが、7日・100件という制限を安全な強制境界として保証できない。正式な構文解析か、構造化された制限付きクエリへの変更が必要。
- 高: 公開利用を前提としたChatGPT/Sitesの認証・ユーザー識別の境界と2人の独立した実ユーザー間分離は未検証。プラットフォームがユーザーIDヘッダーを保証する範囲とMCP利用者への割当を確認する。
- 高: 公開OAuthクライアントとlocalhost手動コールバックの第三者向け利用条件、New Relicのredirect URI登録、モバイルのローカルポート競合、レビュー用認証を確認できていない。ユーザーに認可URLのコピーを求める現方式の一般公開適合性は未確認。
- 中: 固定窓レート制限はD1への書き込み後に判定し、グローバルなIP/edge負荷上限を持たない。Site側の匿名アクセスや大量ユーザーに対する制御は未検証。
- 中: 監視ログやメトリクスには秘密情報やプロンプトインジェクションが含まれ得る。正規表現によるマスクだけで完全な除去は保証できない。
- 中: トークン暗号化には全ユーザー共通の環境変数キーを使う。鍵ローテーション、バックアップ、漏洩時対応、削除・保持期間は未確定。
- 中: New Relicへの接続解除はSite内の保存情報を削除するが、New Relic側の認可失効は行わない。

## 今回の修正

- Web操作の接続解除とアカウント選択に同一Origin検証を追加。アカウント選択はJSON送信を要求する。
- MCP endpointは `application/json` と最大サイズのストリーム読み取りを要求し、`/api/status` とOAuth start/callbackにもユーザー単位のレート上限を追加。
- アカウント一覧で上流の生応答を重複返却せず、必要な一覧のみ返す。
- メトリクス検索は取得済み一覧を検索語で絞り、要求件数に制限する。上流の一覧が完全であるとは仮定しない。
- 信頼できない上流エラー本文をそのまま返さず、公式ツール名の部分一致による誤選択を避ける。ログ本文は命令ではなくデータとして扱うようツール説明に明記した。

## 検証が必要な事項

第三者アカウントとの分離、並行refresh、OAuth期限切れ、複雑なNRQL、CSRF、プロンプトインジェクション、大容量ストリーム、公式MCP障害時の振る舞い。実際の認証情報や実データは公開用の試験データに使わない。

## v0.4.0 scoped code review (2026-11-06)

OAuth/transport and generic adapter received separate implementation and review passes. Review caught and fixed an OAuth route regression, malformed JSON Schema constraint acceptance, unvalidated provider response extras, metadata policy drift, misleading reachability diagnostics, disconnect/completion ordering, status-refresh rate-limit bypass, shared OAuth/read quotas, oversized stored account names, unbounded schema fingerprint recursion, and response-size envelope gaps. Regression and 28 OAuth/transport mock tests plus policy tests pass locally. This is a scoped review, not independent certification or production assurance.

Generic execution requires an exact tool-name policy, bounded SHA-256 fingerprinting of input/output schema and annotations/metadata, supported schema validation, selected-account binding and explicit Core Compute, Advanced Compute or unknown billing classification. Unknown, overly complex or changed tools fail closed. Provider descriptions/annotations cannot authorize execution. Write/destructive approval is not implemented. Core Compute reads require `NEW_RELIC_ENABLE_METERED_READS=true`; Advanced Compute reads require `NEW_RELIC_ENABLE_ADVANCED_COMPUTE=true`. Preview additionally requires `NEW_RELIC_ENABLE_PREVIEW=true`. Legacy high-level read operations default to blocked, exact known Core/Advanced tool names are classified separately, and unknown legacy names are blocked even after the Core opt-in.

The MCP route now rejects `text/plain` form posts, but does not replace a trusted identity gateway or independent browser/session authorization. The generic policy does not schema-pin legacy high-level tools. Legacy NRQL limits and header-based hosting identity still have the risks listed above. A general self-host authentication gateway is not included; only the trusted ChatGPT Sites identity path is supported. Runtime entitlement/plan restrictions cannot reliably be distinguished from an opaque provider tool error; do not claim entitlement from catalog visibility alone. Redaction is best effort for arbitrary telemetry and cannot guarantee removal of every secret. No API keys or OAuth grants were generated, no production settings were changed, and no live rotation or multi-user deployment was tested.
