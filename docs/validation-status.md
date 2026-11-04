# 検証状況

- ローカル: Node.js v24.22.1でbuild、Worker ESM、MCP/OAuth/NRQL回帰、SQLite migration、配布検査、ZIP生成を実行し成功。
- Node.js 22: GitHub CIに設定済み。GitHub上では未実行。
- 新規ユーザーのSites構築: 未実施。本人のSites作成権限、D1、Secret設定、所有者限定公開、本人のNew Relic OAuth承認が必要。
- 本番の既存Site・Plugin: このOSS整備で設定や公開範囲を変更していない。
- GitHub ActionsのVERSION変更Release: 未実行。タグ作成は所有者の明示許可後。
- 新規SiteのNRQL・切断・モバイル: 未検証。既存所有者環境で確認した動作と区別する。


所有者の許可により初期化用READMEのコミットをmainに作成。実装はfeat/oss-bootstrapのDraft PRで確認する。VERSION変更のmain反映でCI後にReleaseを自動作成する。
