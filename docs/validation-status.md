# Validation status (2026-11-06)

## Local checks

The v0.4.0 branch was validated locally with Node.js 24.22.1 and Python 3.12. The checks cover mocked OAuth token exchange/refresh, concurrent refresh, a callback racing between OAuth-state fencing and credential deletion, separate OAuth and ordinary API rate buckets, status-refresh limiting, known Core/Advanced and unknown-tool billing gates, deeply nested schema metadata, oversized account-name handling, escaped API responses and JSON-RPC ID bounds, migration syntax, and existing Scylla Gate regressions.

- Worker build and artifact validation: passed.
- `npm test`: passed, including MCP security and OAuth/transport mocks. No live provider validation was performed.
- `npm run typecheck`: passed with TypeScript 5.9.3 `checkJs` and null checks.
- Syntax/lint checks: passed.
- D1 migrations and Python regression tests: passed.
- Dependency audit: `npm audit --audit-level=high` passed with 0 reported vulnerabilities.
- Distribution checks and local v0.4.0 ZIP generation: passed.
- GitHub Actions for the final PR commit: pending until the draft PR is created.

## Live-provider boundary

Authenticated `tools/list` and New Relic data reads were not available for this change because the connected provider currently reports a refresh failure. The public unauthenticated endpoint returned 401 in earlier read-only research; that is not authenticated capability evidence. No authenticated tool was executed, no billable action was performed, and no production setting, deployment or formal Release was changed.

The documentation inventory contains 41 tool names, but the authenticated account's actual tool count and schemas remain unknown. The v0.4.0 generic adapter has 0 live-verified tools. Official feature/API availability and account pricing remain subject to the documented evidence limits.

## Remaining deployment and release checks

- A fresh ChatGPT Site installation, real OAuth renewal and real D1 concurrency still need owner-controlled verification after separate deployment approval.
- A general-purpose self-host authentication gateway is not implemented. The current identity path assumes trusted ChatGPT Sites identity headers; do not expose it as a multi-user public service.
- Write/destructive approval workflow is not implemented, and those operations remain disabled.
- Preview, account entitlements and per-account Core/Advanced Compute pricing were not verified.
- No production deployment or formal Release is included. `VERSION` remains 0.4.0 for the draft PR; merging a version change to main can trigger the existing Release workflow.
