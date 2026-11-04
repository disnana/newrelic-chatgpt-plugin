# 検証状況

- GitHub Actions: Node.js 22のCIでbuild、Worker ESM、MCP/OAuth/NRQL回帰、D1 migration、配布検査、ZIP生成が成功。
- 検証run: https://github.com/disnana/newrelic-chatgpt-plugin/actions/runs/41840419320 （commit b7571f26381d240d2e382a0a80fad8c6426fd098）。
- ローカル: Node.js v24.22.1で同じ検査とZIPのクリーン展開後の再ビルド・テストに成功。
- 新規ユーザーのSites構築: 未実施。本人のSites作成権限、D1、Secret設定、所有者限定公開、New Relic OAuth承認が必要。
- 既存の個人用Site・Plugin: このOSS整備で設定や公開範囲を変更していない。
- VERSION変更Release: workflowを実装したが実際のタグ/Release作成は未実行。VERSIONのmain反映でCI後に自動作成する。
- 新規SiteのNRQL・接続解除・モバイル経路、本番D1の並行性: 未検証。

所有者の許可により初期化用READMEだけをmainに追加し、実装はfeat/oss-bootstrapのDraft PRで確認する。PRマージでVERSION 0.3.0が追加され、初回Releaseが作成されるため、レビューしてからマージする。
